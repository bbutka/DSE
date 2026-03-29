"""
orchestrator.py
===============
Coordinates the three phase agents across three strategy variants and
feeds results to the GUI through a progress queue.

Runs in a background thread.  The GUI polls for completion by checking
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
    Phase1Result, Phase2Result, SolutionResult, ScenarioResult
)
from ..core.solution_ranker import SolutionRanker
from ..core.comparison import generate_report_text
from .phase1_agent import Phase1Agent
from .phase2_agent import Phase2Agent
from .phase3_agent import Phase3Agent, generate_scenarios


# ---------------------------------------------------------------------------
# Fallback data (TC9 known-good results) used when all solvers fail
# ---------------------------------------------------------------------------

def _make_fallback_solution(strategy: str, label: str) -> SolutionResult:
    """
    Create a minimal placeholder SolutionResult when clingo fails.

    No fake metrics are injected — the result clearly signals failure
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
    ) -> None:
        self.network_model    = network_model
        self.clingo_dir       = clingo_files_dir
        self.testcase_lp      = testcase_lp
        self.progress_queue   = progress_queue
        self.full_phase3      = full_phase3
        self.phase_timeout    = phase_timeout
        self.solver_config    = solver_config or {}

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
        """Run Phases 1, 2, 3 for one strategy and return a SolutionResult."""
        label = STRATEGY_LABELS.get(strategy, strategy)
        sol   = SolutionResult(strategy=strategy, label=label)

        # ── Phase 1 ───────────────────────────────────────────────────────
        self._post("INFO", f"[Orchestrator] Phase 1 starting for {strategy}...")
        strategy_overrides = self.solver_config.get("strategy_overrides") if self.solver_config else None
        p1_agent = Phase1Agent(
            clingo_dir=self.clingo_dir,
            testcase_lp=self.testcase_lp,
            strategy=strategy,
            progress_queue=self.progress_queue,
            extra_instance_facts=instance_facts,
            timeout=self.phase_timeout,
            strategy_overrides=strategy_overrides,
        )
        p1 = p1_agent.run()
        sol.phase1 = p1

        if not p1.satisfiable:
            self._post(
                "WARNING",
                f"[Orchestrator] Phase 1 UNSAT for {strategy} — using fallback."
            )
            fallback = _make_fallback_solution(strategy, label)
            fallback.error = f"Phase 1 unsatisfiable for strategy '{strategy}'"
            return fallback

        # ── Phase 2 ───────────────────────────────────────────────────────
        self._post("INFO", f"[Orchestrator] Phase 2 starting for {strategy}...")
        p2_agent = Phase2Agent(
            clingo_dir=self.clingo_dir,
            testcase_lp=self.testcase_lp,
            phase1_result=p1,
            strategy=strategy,
            progress_queue=self.progress_queue,
            timeout=self.phase_timeout,
            extra_instance_facts=instance_facts,
        )
        p2 = p2_agent.run()
        sol.phase2 = p2

        # ── Phase 3 ───────────────────────────────────────────────────────
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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _post(self, level: str, msg: str) -> None:
        try:
            self.progress_queue.put_nowait((level, msg))
        except queue.Full:
            pass
