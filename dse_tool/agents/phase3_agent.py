"""
phase3_agent.py
===============
Phase 3 worker: resilience analysis across a representative set of
fault / compromise scenarios.

Runs a subset of the 18 full scenarios defined in runClingo_tc9.py.
At least 6 scenarios are always run; the full 18 can optionally be enabled.
"""

from __future__ import annotations

import os
import queue
from typing import List, Optional

from ..core.clingo_runner import ClingoRunner
from ..core.solution_parser import (
    Phase1Result, Phase2Result, ScenarioResult, SolutionParser
)


# ---------------------------------------------------------------------------
# Scenario definitions (subset of the 18 in runClingo_tc9.py)
# ---------------------------------------------------------------------------

CORE_SCENARIOS = [
    {"name": "baseline",               "compromised": [],                   "failed": []},
    {"name": "sys_cpu_compromise",     "compromised": ["sys_cpu"],          "failed": []},
    {"name": "dma_compromise",         "compromised": ["dma"],              "failed": []},
    {"name": "full_group_compromise",  "compromised": ["c1","c2","c3","c4","c5"], "failed": []},
    {"name": "noc0_failure",           "compromised": [],                   "failed": ["noc0"]},
    {"name": "ps0_compromise",         "compromised": ["ps0"],              "failed": []},
]

FULL_SCENARIOS = [
    {"name": "baseline",               "compromised": [],                   "failed": []},
    {"name": "sys_cpu_compromise",     "compromised": ["sys_cpu"],          "failed": []},
    {"name": "dma_compromise",         "compromised": ["dma"],              "failed": []},
    {"name": "c1_compromise",          "compromised": ["c1"],               "failed": []},
    {"name": "c6_compromise",          "compromised": ["c6"],               "failed": []},
    {"name": "c8_compromise",          "compromised": ["c8"],               "failed": []},
    {"name": "full_group_compromise",  "compromised": ["c1","c2","c3","c4","c5"], "failed": []},
    {"name": "noc0_failure",           "compromised": [],                   "failed": ["noc0"]},
    {"name": "noc1_failure",           "compromised": [],                   "failed": ["noc1"]},
    {"name": "c8_failure",             "compromised": [],                   "failed": ["c8"]},
    {"name": "dma_compromise_noc1",    "compromised": ["dma"],              "failed": ["noc1"]},
    {"name": "ps0_compromise",         "compromised": ["ps0"],              "failed": []},
    {"name": "ps1_compromise",         "compromised": ["ps1"],              "failed": []},
    {"name": "ps0_failure",            "compromised": [],                   "failed": ["ps0"]},
    {"name": "all_ps_failure",         "compromised": [],                   "failed": ["ps0","ps1"]},
    {"name": "pep_group_bypass",       "compromised": ["pep_group"],        "failed": []},
    {"name": "pep_standalone_bypass",  "compromised": ["pep_standalone"],   "failed": []},
    {"name": "ps0_comp_ps1_fail",      "compromised": ["ps0"],              "failed": ["ps1"]},
]


class Phase3Agent:
    """
    Runs Phase 3 resilience analysis for a given Phase 1 + Phase 2 result.

    Parameters
    ----------
    clingo_dir : str
        Absolute path to the Clingo/ directory.
    testcase_lp : str
        Absolute path to the testCase instance .lp file.
    phase1_result : Phase1Result
    phase2_result : Phase2Result
    strategy : str
        Strategy name (for progress log labels).
    progress_queue : queue.Queue | None
        Thread-safe queue for progress messages.
    full_scenarios : bool
        If True run all 18 scenarios; if False run core 6.
    timeout : int
        Per-scenario timeout in seconds.
    """

    PHASE3_LP_NAMES = [
        "resilience_tc9_enc.lp",
    ]

    def __init__(
        self,
        clingo_dir: str,
        testcase_lp: str,
        phase1_result: Phase1Result,
        phase2_result: Phase2Result,
        strategy: str = "max_security",
        progress_queue: Optional[queue.Queue] = None,
        full_scenarios: bool = False,
        timeout: int = 30,
    ) -> None:
        self.clingo_dir     = clingo_dir
        self.testcase_lp    = testcase_lp
        self.phase1_result  = phase1_result
        self.phase2_result  = phase2_result
        self.strategy       = strategy
        self.progress_queue = progress_queue
        self.full_scenarios = full_scenarios
        self.timeout        = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, model_scenarios: Optional[List[dict]] = None) -> List[ScenarioResult]:
        """
        Execute all scenarios and return a list of ScenarioResult objects.

        Parameters
        ----------
        model_scenarios : list[dict] | None
            Custom scenarios from the network model.  When non-empty overrides
            the hard-coded CORE_SCENARIOS / FULL_SCENARIOS lists.
        """
        if model_scenarios:
            scenarios = model_scenarios
        else:
            scenarios = FULL_SCENARIOS if self.full_scenarios else CORE_SCENARIOS
        n = len(scenarios)
        self._post(f"[Phase 3/{self.strategy}] Running {n} scenario(s)...")

        lp_files = self._build_lp_list()
        p1       = self.phase1_result
        p2       = self.phase2_result

        # Build base facts string shared across all scenarios
        base_facts = p1.as_p1_facts()
        if p2.satisfiable:
            p2_facts = p2.as_phase3_facts()
            if p2_facts:
                base_facts += "\n" + p2_facts

        results: List[ScenarioResult] = []
        runner = ClingoRunner(timeout=self.timeout)

        for i, sc in enumerate(scenarios, 1):
            self._post(
                f"[Phase 3/{self.strategy}] Scenario {i}/{n}: {sc['name']}..."
            )
            scenario_facts = base_facts
            for node in sc.get("compromised", []):
                scenario_facts += f"\ncompromised({node})."
            for node in sc.get("failed", []):
                scenario_facts += f"\nfailed({node})."

            raw = runner.solve_scenario(
                lp_files=lp_files,
                scenario_facts=scenario_facts,
            )

            if raw["status"] == "SAT":
                res = SolutionParser.parse_scenario(raw["atoms"], sc)
            else:
                # UNSAT scenario — create a placeholder
                res = ScenarioResult(
                    name=sc["name"],
                    compromised=sc.get("compromised", []),
                    failed=sc.get("failed", []),
                    satisfiable=False,
                )

            results.append(res)

        # Summary
        sat_results = [r for r in results if r.satisfiable]
        if sat_results:
            worst = max(sat_results, key=lambda r: r.total_risk)
            self._post(
                f"[Phase 3/{self.strategy}] Done — "
                f"Worst blast radius: {max(r.max_blast_radius for r in sat_results)}, "
                f"Worst scenario: {worst.name} (risk={worst.total_risk:.1f})"
            )
        else:
            self._post(f"[Phase 3/{self.strategy}] Done — all scenarios UNSAT")

        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_lp_list(self) -> List[str]:
        """Build the LP file list for Phase 3."""
        files = []
        if self.testcase_lp and os.path.isfile(self.testcase_lp):
            files.append(self.testcase_lp)
        for name in self.PHASE3_LP_NAMES:
            path = os.path.join(self.clingo_dir, name)
            if os.path.isfile(path):
                files.append(path)
            else:
                self._post(f"[Phase 3] WARNING: LP file not found: {path}")
        return files

    def _post(self, msg: str) -> None:
        if self.progress_queue is not None:
            try:
                self.progress_queue.put_nowait(("INFO", msg))
            except queue.Full:
                pass
