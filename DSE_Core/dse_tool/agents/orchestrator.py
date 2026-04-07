"""
orchestrator.py
===============
Coordinates the integrated DSE pipeline across three strategy variants
and feeds results to the GUI through a progress queue.

In paper terms, Phases 1 and 2 construct an upstream protected baseline,
Phase 3 evaluates resilience over that baseline, and runtime is an
optional post-Phase-2 extension rather than part of the core RASACC
assessment flow.

Phase 1 uses CP-SAT by default in this package, with CBC available as an
optional math backend and the legacy ASP/Clingo solver retained as an
optional fallback when the math backend is unavailable or returns an
unsatisfiable result.

Runs in a background thread. The GUI polls for completion by checking
orchestrator.done and orchestrator.solutions.
"""

from __future__ import annotations

import os
import queue
import threading
import traceback
from typing import List, Optional

from ..core.asp_generator import NetworkModel, ASPGenerator
from ..core.solution_parser import (
    Phase1Result, Phase2Result, SolutionResult, ScenarioResult,
    RuntimeAdaptiveResult, JointPhase2RuntimeResult,
)
from ..core.solution_ranker import SolutionRanker
from ..core.comparison import generate_report_text
from .phase1_mathopt_agent import Phase1MathOptAgent
from .phase1_agent import Phase1Agent
from .phase2_agent import Phase2Agent
from .phase3_agent import Phase3Agent, generate_scenarios
from .runtime_agent import RuntimeAgent, RUNTIME_SCENARIOS


# ---------------------------------------------------------------------------
# Fallback data (TC9 known-good results) used when all solvers fail
# ---------------------------------------------------------------------------

def _make_fallback_solution(strategy: str, label: str) -> SolutionResult:
    """
    Create a minimal placeholder SolutionResult when clingo fails.

    No fake metrics are injected â€” the result clearly signals failure
    without polluting the GUI with data from a different topology.
    """
    p1 = Phase1Result(
        strategy=strategy,
        satisfiable=False,
        optimal=False,
    )

    p2 = Phase2Result(satisfiable=False)

    sc = ScenarioResult(
        name="baseline",
        compromised=[],
        failed=[],
        satisfiable=False,
    )

    sol = SolutionResult(
        strategy=strategy,
        label=label,
        phase1=p1,
        phase2=p2,
        scenarios=[sc],
        complete=True,
        error=f"Phase 1 solver failed for strategy '{strategy}'",
    )
    return sol


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

STRATEGY_LABELS = {
    "max_security":  "Solution 1: Maximum Security",
    "min_resources": "Solution 2: Minimum Footprint",
    "balanced":      "Solution 3: Balanced Trade-off",
}

def _default_solver_threads() -> int:
    cpu_count = max(1, os.cpu_count() or 1)
    if cpu_count >= 16:
        return 8
    if cpu_count >= 8:
        return 4
    if cpu_count >= 4:
        return 2
    return 1


DEFAULT_SOLVER_CONFIG = {
    "phase1_backend": "cpsat",
    "ilp_solver": "cpsat",
    "cpsat_threads": _default_solver_threads(),
    "cbc_threads": _default_solver_threads(),
    "clingo_threads": _default_solver_threads(),
    "clingo_parallel_mode": "compete",
}


class DSEOrchestrator:
    """
    Coordinates Phase 1, 2, and 3 agents across three strategy variants.

    Parameters
    ----------
    network_model : NetworkModel
        The topology to analyse.
    clingo_files_dir : str
        Absolute path to the Clingo/ directory.
    testcase_lp : str
        Absolute path to the instance .lp file.
    progress_queue : queue.Queue
        Thread-safe queue for (level, message) tuples consumed by the GUI.
    full_phase3 : bool
        If True run all 18 Phase 3 scenarios per strategy.
    phase_timeout : int
        Per-phase timeout in seconds.
    """

    def __init__(
        self,
        network_model: NetworkModel,
        clingo_files_dir: str,
        testcase_lp: str,
        progress_queue: queue.Queue,
        full_phase3: bool = False,
        phase_timeout: int = 60,
        solver_config: Optional[dict] = None,
        run_adaptive_runtime: bool = False,
        run_joint_runtime: bool = False,
        runtime_scenarios: Optional[list] = None,
    ) -> None:
        self.network_model    = network_model
        self.clingo_dir       = clingo_files_dir
        self.testcase_lp      = testcase_lp
        self.progress_queue   = progress_queue
        self.full_phase3      = full_phase3
        self.phase_timeout    = phase_timeout
        self.solver_config    = dict(DEFAULT_SOLVER_CONFIG)
        if solver_config:
            self.solver_config.update(solver_config)
        self.run_adaptive_runtime = run_adaptive_runtime
        self.run_joint_runtime    = run_joint_runtime
        self.runtime_scenarios    = runtime_scenarios

        self.solutions:   List[SolutionResult] = []
        self.report_text: str                  = ""
        self.done:        bool                 = False
        self.error:       str                  = ""
        self._stop_flag:  bool                 = False

    # ------------------------------------------------------------------
    # Thread entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        """
        Main orchestration entry point.  Call this in a daemon thread.

        Runs three strategy variants sequentially and stores results.
        """
        self._post("PHASE", "=== DSE Analysis Starting ===")
        try:
            # Generate extra instance facts from the network model
            gen           = ASPGenerator(self.network_model)
            instance_facts = gen.generate()

            self._instance_facts = instance_facts

            # Validate topology for structural UNSAT risks
            topo_warnings = gen.validate_topology()
            for w in topo_warnings:
                self._post("WARNING", f"[Topology] {w}")

            strategies = ["max_security", "min_resources", "balanced"]
            for i, strategy in enumerate(strategies, 1):
                if self._stop_flag:
                    self._post("WARNING", "Analysis stopped by user.")
                    break
                self._post(
                    "PHASE",
                    f"--- Strategy {i}/3: {STRATEGY_LABELS.get(strategy, strategy)} ---"
                )
                sol = self._run_strategy(strategy, instance_facts)
                self.solutions.append(sol)

            # Score all solutions
            if self.solutions:
                caps = self.network_model.system_caps
                ranker = SolutionRanker(
                    self.solutions,
                    max_luts=caps.get("max_luts", 0),
                    max_power=caps.get("max_power", 0),
                )
                ranker.rank()

                # Generate report (topology-aware resource caps)
                caps = self.network_model.system_caps
                self.report_text = generate_report_text(
                    self.solutions,
                    network_name=self.network_model.name,
                    max_luts=caps.get("max_luts", 0),
                    max_power=caps.get("max_power", 0),
                    max_ffs=caps.get("max_ffs", 0),
                )

            self._post("SUCCESS", "=== DSE Analysis Complete ===")

        except Exception:  # noqa: BLE001
            tb = traceback.format_exc()
            self.error = tb
            self._post("ERROR", f"Orchestrator fatal error:\n{tb}")

        finally:
            self.done = True

    def stop(self) -> None:
        """Request the orchestrator to stop after the current strategy."""
        self._stop_flag = True

    # ------------------------------------------------------------------
    # Per-strategy execution
    # ------------------------------------------------------------------

    def _run_strategy(self, strategy: str, instance_facts: str) -> SolutionResult:
        """Run Phases 1, 2, 3 (and optionally runtime) for one strategy."""
        label = STRATEGY_LABELS.get(strategy, strategy)
        sol   = SolutionResult(strategy=strategy, label=label)

        # â”€â”€ Phase 1 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        self._post("INFO", f"[Orchestrator] Phase 1 starting for {strategy}...")
        p1 = self._run_phase1(strategy, instance_facts)
        sol.phase1 = p1

        if not p1.satisfiable:
            self._post(
                "WARNING",
                f"[Orchestrator] Phase 1 UNSAT for {strategy} â€” using fallback."
            )
            fallback = _make_fallback_solution(strategy, label)
            fallback.error = f"Phase 1 unsatisfiable for strategy '{strategy}'"
            return fallback

        # â”€â”€ RuntimeAgent (shared by joint + adaptive if needed) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        rt_agent = None
        if self.run_joint_runtime or self.run_adaptive_runtime:
            rt_agent = RuntimeAgent(
                clingo_dir=self.clingo_dir,
                testcase_lp=self.testcase_lp,
                progress_queue=self.progress_queue,
                timeout=self.phase_timeout,
                extra_instance_facts=instance_facts,
                solver_config=self.solver_config,
            )

        # â”€â”€ Phase 2 (or Joint Runtime replacing Phase 2) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        extra_runtime_facts = ""
        if self.run_joint_runtime:
            self._post("INFO", f"[Orchestrator] Joint runtime starting for {strategy}...")
            joint = rt_agent.solve_joint(p1)
            sol.joint_runtime = joint

            if joint.satisfiable:
                p2 = joint.to_phase2_result()
                extra_runtime_facts = joint.as_runtime_facts()
            else:
                self._post(
                    "WARNING",
                    f"[Orchestrator] Joint runtime UNSAT for {strategy} â€” "
                    f"falling back to standalone Phase 2."
                )
                sol.joint_runtime = None
                p2 = None

            # If joint failed, run standalone Phase 2 as fallback
            if p2 is None:
                self._post("INFO", f"[Orchestrator] Phase 2 (fallback) starting for {strategy}...")
                p2_agent = Phase2Agent(
                    clingo_dir=self.clingo_dir,
                    testcase_lp=self.testcase_lp,
                    phase1_result=p1,
                    strategy=strategy,
                    progress_queue=self.progress_queue,
                    timeout=self.phase_timeout,
                    extra_instance_facts=instance_facts,
                    solver_config=self.solver_config,
                )
                p2 = p2_agent.run()
        else:
            self._post("INFO", f"[Orchestrator] Phase 2 starting for {strategy}...")
            p2_agent = Phase2Agent(
                clingo_dir=self.clingo_dir,
                testcase_lp=self.testcase_lp,
                phase1_result=p1,
                strategy=strategy,
                progress_queue=self.progress_queue,
                timeout=self.phase_timeout,
                extra_instance_facts=instance_facts,
                solver_config=self.solver_config,
            )
            p2 = p2_agent.run()

        sol.phase2 = p2

        # â”€â”€ Adaptive Runtime (optional, after Phase 2 or joint) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if self.run_adaptive_runtime and p2.satisfiable:
            self._post("INFO", f"[Orchestrator] Adaptive runtime starting for {strategy}...")
            scenarios = self.runtime_scenarios or list(RUNTIME_SCENARIOS)
            try:
                sol.runtime_results = rt_agent.solve_adaptive(
                    p1, p2, scenarios=scenarios,
                    extra_runtime_facts=extra_runtime_facts,
                )
            except RuntimeError as exc:
                self._post("WARNING", f"[Orchestrator] Adaptive runtime failed: {exc}")
                if not sol.error:
                    sol.error = f"Adaptive runtime failed: {exc}"

        # â”€â”€ Phase 3 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        self._post("INFO", f"[Orchestrator] Phase 3 starting for {strategy}...")
        p3_agent = Phase3Agent(
            clingo_dir=self.clingo_dir,
            testcase_lp=self.testcase_lp,
            phase1_result=p1,
            phase2_result=p2,
            strategy=strategy,
            progress_queue=self.progress_queue,
            full_scenarios=self.full_phase3,
            timeout=self.phase_timeout,
            extra_instance_facts=instance_facts,
            solver_config=self.solver_config,
        )
        # Use model-attached scenarios if present, otherwise auto-generate
        model_scenarios = getattr(self.network_model, "scenarios", None) or []
        if not model_scenarios:
            model_scenarios = generate_scenarios(
                self.network_model, full=self.full_phase3
            )
        sol.scenarios = p3_agent.run(model_scenarios=model_scenarios)
        sol.complete  = True

        return sol

    def _run_phase1(self, strategy: str, instance_facts: str) -> Phase1Result:
        """Run Phase 1 with configured backend selection and fallback."""
        phase1_backend = (self.solver_config.get("phase1_backend") or "cpsat").lower()
        fallback_backend = (self.solver_config.get("phase1_fallback_backend") or "asp").lower()

        if phase1_backend == "asp":
            return self._run_phase1_asp(strategy, instance_facts)

        p1 = self._run_phase1_mathopt(strategy, phase1_backend)
        if p1.satisfiable:
            return p1

        if fallback_backend in {"cbc", "cpsat"} and fallback_backend != phase1_backend:
            self._post(
                "WARNING",
                f"[Orchestrator] Phase 1 {phase1_backend.upper()} backend unavailable/UNSAT for {strategy} - "
                f"falling back to {fallback_backend.upper()}.",
            )
            mathopt_p1 = self._run_phase1_mathopt(strategy, fallback_backend)
            if mathopt_p1.satisfiable:
                return mathopt_p1
            p1 = mathopt_p1

        if fallback_backend == "asp":
            self._post(
                "WARNING",
                f"[Orchestrator] Phase 1 math backend unavailable/UNSAT for {strategy} - falling back to ASP.",
            )
            asp_p1 = self._run_phase1_asp(strategy, instance_facts)
            if asp_p1.satisfiable:
                return asp_p1
            return asp_p1

        return p1

    def _run_phase1_mathopt(self, strategy: str, solver_name: str) -> Phase1Result:
        agent_solver_config = dict(self.solver_config)
        agent_solver_config["ilp_solver"] = solver_name
        p1_agent = Phase1MathOptAgent(
            network_model=self.network_model,
            strategy=strategy,
            progress_queue=self.progress_queue,
            timeout=self.phase_timeout,
            solver_config=agent_solver_config,
        )
        return p1_agent.run()

    def _run_phase1_asp(self, strategy: str, instance_facts: str) -> Phase1Result:
        strategy_overrides = self.solver_config.get("strategy_overrides") if self.solver_config else None
        p1_agent = Phase1Agent(
            clingo_dir=self.clingo_dir,
            testcase_lp=self.testcase_lp,
            strategy=strategy,
            progress_queue=self.progress_queue,
            extra_instance_facts=instance_facts,
            timeout=self.phase_timeout,
            strategy_overrides=strategy_overrides,
            solver_config=self.solver_config,
        )
        return p1_agent.run()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _post(self, level: str, msg: str) -> None:
        try:
            self.progress_queue.put_nowait((level, msg))
        except queue.Full:
            pass

