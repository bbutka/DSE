"""
clingo_runner.py
================
Thin wrapper around the clingo Python API.

Loads one or more .lp files plus optional extra_facts string, grounds,
solves, and returns the atoms from the best (optimal) model found.
"""

from __future__ import annotations

import threading
from typing import List, Optional, Dict, Any

import clingo


class ClingoRunner:
    """
    Wrapper around clingo.Control for DSE phases.

    Parameters
    ----------
    timeout : int
        Hard wall-clock timeout in seconds.  0 = no limit.
    """

    def __init__(self, timeout: int = 60) -> None:
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def solve(
        self,
        lp_files: List[str],
        extra_facts: str = "",
        minimize_override: Optional[str] = None,
        num_solutions: int = 0,
        opt_mode: str = "optN",
    ) -> Dict[str, Any]:
        """
        Solve with the given LP files and optional extra facts.

        Parameters
        ----------
        lp_files : list[str]
            Absolute paths to .lp files to load.
        extra_facts : str
            Additional ASP facts/rules to inject (grounded as "extra" program).
        minimize_override : str | None
            If set, appended to extra_facts so callers can inject a custom
            #minimize statement for different strategy variants.
        num_solutions : int
            0 = enumerate all optimal models; 1 = stop at first model.
        opt_mode : str
            Clingo optimisation mode string ("optN", "opt", "enum").

        Returns
        -------
        dict with keys:
            status  : "SAT" | "UNSAT" | "TIMEOUT" | "ERROR"
            atoms   : list of clingo.Symbol from the best (last) model
            cost    : int — objective value of the optimal model (or -1)
            message : str — diagnostic message
        """
        result: Dict[str, Any] = {
            "status": "ERROR",
            "atoms": [],
            "cost": -1,
            "message": "",
        }

        try:
            flags = [
                f"--opt-mode={opt_mode}",
                f"-n {num_solutions}",
                "--warn=none",
            ]
            ctl = clingo.Control(flags)

            # Load files
            for path in lp_files:
                try:
                    ctl.load(path)
                except RuntimeError as exc:
                    result["status"] = "ERROR"
                    result["message"] = f"Failed to load {path}: {exc}"
                    return result

            # Inject extra facts
            combined_extra = extra_facts
            if minimize_override:
                combined_extra = combined_extra + "\n" + minimize_override

            if combined_extra.strip():
                ctl.add("extra", [], combined_extra)

            # Ground
            programs = [("base", [])]
            if combined_extra.strip():
                programs.append(("extra", []))
            ctl.ground(programs)

            # Solve with optional timeout
            last_model: List[clingo.Symbol] = []
            last_cost: List[int] = [-1]
            solve_done = threading.Event()

            def on_model(model: clingo.Model) -> None:
                nonlocal last_model
                last_model = list(model.symbols(shown=True))
                if model.cost:
                    last_cost[0] = model.cost[0] if model.cost else -1

            if self.timeout > 0:
                solve_result = [None]

                def _solve() -> None:
                    solve_result[0] = ctl.solve(on_model=on_model)
                    solve_done.set()

                t = threading.Thread(target=_solve, daemon=True)
                t.start()
                finished = solve_done.wait(self.timeout)
                if not finished:
                    result["status"] = "TIMEOUT"
                    result["message"] = f"Clingo timed out after {self.timeout}s"
                    result["atoms"] = last_model  # partial results
                    return result
                sr = solve_result[0]
            else:
                sr = ctl.solve(on_model=on_model)

            if sr is None:
                result["status"] = "ERROR"
                result["message"] = "Solve returned None"
                return result

            if sr.unsatisfiable:
                result["status"] = "UNSAT"
                result["message"] = "Problem is unsatisfiable"
                return result

            result["status"] = "SAT"
            result["atoms"] = last_model
            result["cost"]  = last_cost[0]
            return result

        except Exception as exc:  # noqa: BLE001
            result["status"] = "ERROR"
            result["message"] = str(exc)
            return result

    def solve_scenario(
        self,
        lp_files: List[str],
        scenario_facts: str,
    ) -> Dict[str, Any]:
        """
        Variant for Phase 3 scenarios — no optimisation, just satisfiability.

        Loads files, adds scenario_facts as a separate program, grounds and
        solves for a single model.  Respects the instance timeout.
        """
        result: Dict[str, Any] = {
            "status": "ERROR",
            "atoms": [],
            "cost": -1,
            "message": "",
        }

        try:
            ctl = clingo.Control(["-n", "1", "--warn=none"])

            for path in lp_files:
                try:
                    ctl.load(path)
                except RuntimeError as exc:
                    result["status"] = "ERROR"
                    result["message"] = f"Failed to load {path}: {exc}"
                    return result

            if scenario_facts.strip():
                ctl.add("scenario", [], scenario_facts)

            programs = [("base", [])]
            if scenario_facts.strip():
                programs.append(("scenario", []))
            ctl.ground(programs)

            found: List[clingo.Symbol] = []

            def on_model(m: clingo.Model) -> None:
                found.extend(m.symbols(shown=True))

            if self.timeout > 0:
                solve_done = threading.Event()
                solve_result = [None]

                def _solve() -> None:
                    solve_result[0] = ctl.solve(on_model=on_model)
                    solve_done.set()

                t = threading.Thread(target=_solve, daemon=True)
                t.start()
                finished = solve_done.wait(self.timeout)
                if not finished:
                    result["status"] = "TIMEOUT"
                    result["message"] = f"Scenario timed out after {self.timeout}s"
                    result["atoms"] = found  # partial results if any
                    return result
                sr = solve_result[0]
            else:
                sr = ctl.solve(on_model=on_model)

            if sr is None:
                result["status"] = "ERROR"
                result["message"] = "Solve returned None"
                return result

            if sr.unsatisfiable:
                result["status"] = "UNSAT"
                result["message"] = "Scenario is unsatisfiable"
                return result

            result["status"] = "SAT"
            result["atoms"] = found
            return result

        except Exception as exc:  # noqa: BLE001
            result["status"] = "ERROR"
            result["message"] = str(exc)
            return result
