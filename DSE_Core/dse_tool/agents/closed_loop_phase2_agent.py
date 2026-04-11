"""
closed_loop_phase2_agent.py
===========================
Exact outer-loop Phase 2 optimizer using Phase 3 outcomes as the objective.

This agent enumerates feasible Phase 2 placements, evaluates each placement
through Phase 3 on a fixed scenario set, and selects the candidate with the
best downstream resilience score. It is intended as an opt-in alternative to
the heuristic Phase 2 proxy objective.
"""

from __future__ import annotations

import os
import queue
from dataclasses import dataclass
from itertools import combinations
from typing import Iterable, List, Optional, Tuple

from ..core.clingo_runner import ClingoRunner
from ..core.solution_parser import Phase1Result, Phase2Result, ScenarioResult, SolutionParser
from .phase3_agent import Phase3Agent, generate_scenarios
from .phase3_fast_agent import Phase3FastAgent


@dataclass
class ClosedLoopPhase2Selection:
    """Chosen Phase 2 candidate together with its evaluated Phase 3 outcomes."""

    phase2_result: Phase2Result
    scenarios: List[ScenarioResult]
    score: Tuple[int, ...]
    candidates_evaluated: int = 0
    feasible_candidates: int = 0


class ClosedLoopPhase2Agent:
    """
    Enumerate exact Phase 2 placements and rank them by downstream Phase 3 score.

    Score ordering (lower is better):
      1. unsatisfied/timeout Phase 3 scenarios
      2. worst-case scenario risk
      3. count of non-functional scenarios
      4. count of essential capability losses
      5. average scenario risk
      6. Phase 2 placement cost
    """

    PHASE2_LP_NAMES = ["zta_policy_enc.lp"]

    def __init__(
        self,
        *,
        network_model,
        clingo_dir: str,
        testcase_lp: str,
        phase1_result: Phase1Result,
        strategy: str = "max_security",
        progress_queue: Optional[queue.Queue] = None,
        timeout: int = 60,
        full_scenarios: bool = False,
        extra_instance_facts: str = "",
        solver_config: Optional[dict] = None,
    ) -> None:
        self.network_model = network_model
        self.clingo_dir = clingo_dir
        self.testcase_lp = testcase_lp
        self.phase1_result = phase1_result
        self.strategy = strategy
        self.progress_queue = progress_queue
        self.timeout = timeout
        self.full_scenarios = full_scenarios
        self.extra_instance_facts = extra_instance_facts
        self.solver_config = solver_config or {}

    def run(self, model_scenarios: Optional[List[dict]] = None) -> ClosedLoopPhase2Selection:
        if not self.phase1_result.satisfiable:
            p2 = Phase2Result(satisfiable=False, unsat_reason="Phase 1 unsatisfiable")
            return ClosedLoopPhase2Selection(
                phase2_result=p2,
                scenarios=[],
                score=(10**9, 10**9, 10**9, 10**9, 10**9, 10**9),
            )

        scenarios = model_scenarios or generate_scenarios(self.network_model, full=self.full_scenarios)
        total_candidates = self._candidate_count()
        self._post(
            f"[Phase 2/{self.strategy}] Closed-loop optimization: "
            f"evaluating {total_candidates} placement candidate(s) over {len(scenarios)} Phase 3 scenario(s)..."
        )

        best_selection: ClosedLoopPhase2Selection | None = None
        candidates_evaluated = 0
        feasible_candidates = 0

        for idx, (selected_fws, selected_ps) in enumerate(self._iter_candidate_placements(), 1):
            candidates_evaluated += 1
            self._post(
                f"[Phase 2/{self.strategy}] Closed-loop candidate {idx}/{total_candidates}: "
                f"FW={list(selected_fws)} PS={list(selected_ps)}"
            )

            p2 = self._solve_fixed_candidate(selected_fws, selected_ps)
            if not p2.satisfiable:
                continue

            feasible_candidates += 1
            phase3_backend = (self.solver_config.get("phase3_backend") or "asp").lower()
            if phase3_backend == "python":
                phase3 = Phase3FastAgent(
                    network_model=self.network_model,
                    phase1_result=self.phase1_result,
                    phase2_result=p2,
                    strategy=self.strategy,
                    progress_queue=self.progress_queue,
                    full_scenarios=self.full_scenarios,
                    timeout=self.timeout,
                    extra_instance_facts=self.extra_instance_facts,
                    solver_config=self.solver_config,
                )
            else:
                phase3 = Phase3Agent(
                    clingo_dir=self.clingo_dir,
                    testcase_lp=self.testcase_lp,
                    phase1_result=self.phase1_result,
                    phase2_result=p2,
                    strategy=self.strategy,
                    progress_queue=self.progress_queue,
                    full_scenarios=self.full_scenarios,
                    timeout=self.timeout,
                    extra_instance_facts=self.extra_instance_facts,
                    solver_config=self.solver_config,
                )
            scenario_results = phase3.run(model_scenarios=scenarios)
            p2.closed_loop_function_deficiencies = self._collect_function_deficiencies(scenario_results)
            score = self._score_candidate(scenario_results, p2)
            p2.closed_loop_score = score
            p2.closed_loop_candidates_evaluated = candidates_evaluated

            if best_selection is None or score < best_selection.score:
                best_selection = ClosedLoopPhase2Selection(
                    phase2_result=p2,
                    scenarios=scenario_results,
                    score=score,
                    candidates_evaluated=candidates_evaluated,
                    feasible_candidates=feasible_candidates,
                )
                self._post(
                    f"[Phase 2/{self.strategy}] Closed-loop new best: "
                    f"score={score} cost={p2.total_cost} FW={sorted(set(p2.placed_fws))} PS={sorted(set(p2.placed_ps))}"
                )

        if best_selection is None:
            p2 = Phase2Result(satisfiable=False, unsat_reason="No feasible Phase 2 placement")
            return ClosedLoopPhase2Selection(
                phase2_result=p2,
                scenarios=[],
                score=(10**9, 10**9, 10**9, 10**9, 10**9, 10**9),
                candidates_evaluated=candidates_evaluated,
                feasible_candidates=0,
            )

        best_selection.phase2_result.closed_loop_candidates_evaluated = candidates_evaluated
        best_selection.candidates_evaluated = candidates_evaluated
        best_selection.feasible_candidates = feasible_candidates
        self._post(
            f"[Phase 2/{self.strategy}] Closed-loop selected candidate after {candidates_evaluated} evaluation(s): "
            f"score={best_selection.score}, cost={best_selection.phase2_result.total_cost}, "
            f"FW={sorted(set(best_selection.phase2_result.placed_fws))}, "
            f"PS={sorted(set(best_selection.phase2_result.placed_ps))}"
        )
        return best_selection

    def _candidate_count(self) -> int:
        fw_count = len(getattr(self.network_model, "cand_fws", []))
        ps_count = len(getattr(self.network_model, "cand_ps", []))
        if ps_count <= 0:
            return 0
        return (2 ** fw_count) * ((2 ** ps_count) - 1)

    def _iter_candidate_placements(self) -> Iterable[Tuple[Tuple[str, ...], Tuple[str, ...]]]:
        all_fws = tuple(getattr(self.network_model, "cand_fws", []) or [])
        all_ps = tuple(getattr(self.network_model, "cand_ps", []) or [])
        for fw_subset in self._powerset(all_fws):
            for ps_subset in self._nonempty_powerset(all_ps):
                yield fw_subset, ps_subset

    @staticmethod
    def _powerset(items: Tuple[str, ...]) -> Iterable[Tuple[str, ...]]:
        for r in range(len(items) + 1):
            yield from combinations(items, r)

    @staticmethod
    def _nonempty_powerset(items: Tuple[str, ...]) -> Iterable[Tuple[str, ...]]:
        for r in range(1, len(items) + 1):
            yield from combinations(items, r)

    def _solve_fixed_candidate(self, selected_fws: Tuple[str, ...], selected_ps: Tuple[str, ...]) -> Phase2Result:
        lp_files = self._build_lp_list()
        all_extra = self.extra_instance_facts or ""
        p1_facts = self.phase1_result.as_p1_facts()
        if p1_facts:
            all_extra = (all_extra + "\n" + p1_facts) if all_extra else p1_facts
        fixed = self._fixed_placement_facts(selected_fws, selected_ps)
        all_extra = (all_extra + "\n" + fixed) if all_extra else fixed

        runner = self._make_runner(timeout=self.timeout)
        result_raw = runner.solve(
            lp_files=lp_files,
            extra_facts=all_extra,
            num_solutions=1,
            opt_mode="opt",
        )
        if result_raw["status"] != "SAT":
            return Phase2Result(satisfiable=False, unsat_reason=result_raw.get("message", result_raw["status"]))

        r = SolutionParser.parse_phase2(result_raw["atoms"])
        r.satisfiable = True
        r.optimal = True
        return r

    def _fixed_placement_facts(self, selected_fws: Tuple[str, ...], selected_ps: Tuple[str, ...]) -> str:
        selected_fw_set = set(selected_fws)
        selected_ps_set = set(selected_ps)
        lines: List[str] = []
        for fw in getattr(self.network_model, "cand_fws", []) or []:
            if fw in selected_fw_set:
                lines.append(f"place_fw({fw}).")
            else:
                lines.append(f":- place_fw({fw}).")
        for ps in getattr(self.network_model, "cand_ps", []) or []:
            if ps in selected_ps_set:
                lines.append(f"place_ps({ps}).")
            else:
                lines.append(f":- place_ps({ps}).")
        return "\n".join(lines)

    @staticmethod
    def _score_candidate(scenarios: List[ScenarioResult], phase2_result: Phase2Result) -> Tuple[int, ...]:
        sat = [s for s in scenarios if s.satisfiable]
        unsat_count = len(scenarios) - len(sat)
        if not sat:
            return (unsat_count, 10**9, 10**9, 10**9, 10**9, phase2_result.total_cost)

        worst_risk = max(s.total_risk_scaled for s in sat)
        non_functional = sum(1 for s in sat if s.system_non_functional)
        essential_caps_lost = sum(len(s.essential_caps_lost) for s in sat)
        avg_risk = sum(s.total_risk_scaled for s in sat) // len(sat)
        return (
            unsat_count,
            worst_risk,
            non_functional,
            essential_caps_lost,
            avg_risk,
            phase2_result.total_cost,
        )

    @staticmethod
    def _collect_function_deficiencies(scenarios: List[ScenarioResult]) -> List[dict]:
        """Collect structured function-level findings without applying repairs."""
        deficiencies: List[dict] = []
        for scenario in scenarios:
            if scenario.function_deficiencies:
                deficiencies.extend(scenario.function_deficiencies)
            else:
                deficiencies.extend(scenario.derive_function_deficiencies())
        return deficiencies

    def _build_lp_list(self) -> list[str]:
        files = []
        if not self.extra_instance_facts and self.testcase_lp and os.path.isfile(self.testcase_lp):
            files.append(self.testcase_lp)
        for name in self.PHASE2_LP_NAMES:
            path = os.path.join(self.clingo_dir, name)
            if os.path.isfile(path):
                files.append(path)
        return files

    def _make_runner(self, timeout: int) -> ClingoRunner:
        return ClingoRunner(
            timeout=timeout,
            threads=self.solver_config.get("clingo_threads"),
            parallel_mode=self.solver_config.get("clingo_parallel_mode"),
            configuration=self.solver_config.get("clingo_configuration"),
        )

    def _post(self, msg: str) -> None:
        if self.progress_queue is not None:
            try:
                self.progress_queue.put_nowait(("INFO", msg))
            except queue.Full:
                pass
