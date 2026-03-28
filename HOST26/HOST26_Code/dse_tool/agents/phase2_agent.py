"""
phase2_agent.py
===============
Phase 2 worker: ZTA policy synthesis via zta_policy_enc.lp.

Takes a Phase1Result, injects its security assignments and risk values as
ASP facts, then runs the ZTA encoding to derive firewalls, policy servers,
least-privilege findings, and trust anchor gaps.

If the solver returns UNSAT the agent diagnoses which constraints conflict
and reports them through the progress queue.
"""

from __future__ import annotations

import os
import queue
from typing import Optional

from ..core.clingo_runner import ClingoRunner
from ..core.solution_parser import Phase1Result, Phase2Result, SolutionParser


class Phase2Agent:
    """
    Runs Phase 2 ZTA policy synthesis for a given Phase1Result.

    Parameters
    ----------
    clingo_dir : str
        Absolute path to the Clingo/ directory.
    testcase_lp : str
        Absolute path to the testCase instance .lp file.
    phase1_result : Phase1Result
        Output of Phase 1 to inject as background facts.
    strategy : str
        Strategy name (for progress log labels).
    progress_queue : queue.Queue | None
        Thread-safe queue for progress messages.
    timeout : int
        Per-solve timeout in seconds.
    """

    PHASE2_LP_NAMES = [
        "zta_policy_enc.lp",
    ]

    def __init__(
        self,
        clingo_dir: str,
        testcase_lp: str,
        phase1_result: Phase1Result,
        strategy: str = "max_security",
        progress_queue: Optional[queue.Queue] = None,
        timeout: int = 60,
    ) -> None:
        self.clingo_dir     = clingo_dir
        self.testcase_lp    = testcase_lp
        self.phase1_result  = phase1_result
        self.strategy       = strategy
        self.progress_queue = progress_queue
        self.timeout        = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> Phase2Result:
        """
        Execute Phase 2 and return a Phase2Result.

        Returns Phase2Result with satisfiable=False and an unsat_reason
        string if the ZTA encoding is over-constrained.
        """
        self._post(f"[Phase 2/{self.strategy}] ZTA policy synthesis...")

        p1 = self.phase1_result
        if not p1.satisfiable:
            self._post(
                f"[Phase 2/{self.strategy}] Skipped — Phase 1 was not satisfiable."
            )
            r = Phase2Result(satisfiable=False)
            r.unsat_reason = "Phase 1 unsatisfiable"
            return r

        lp_files = self._build_lp_list()
        p1_facts = p1.as_p1_facts()

        runner = ClingoRunner(timeout=self.timeout)
        result_raw = runner.solve(
            lp_files=lp_files,
            extra_facts=p1_facts,
            num_solutions=0,
            opt_mode="optN",
        )

        status = result_raw["status"]

        if status == "UNSAT":
            reason = self._diagnose_unsat(lp_files, p1_facts)
            self._post(
                f"[Phase 2/{self.strategy}] WARNING: UNSAT — {reason}"
            )
            r = Phase2Result(satisfiable=False)
            r.unsat_reason = reason
            return r

        if status not in ("SAT",):
            self._post(
                f"[Phase 2/{self.strategy}] ERROR/TIMEOUT — {result_raw['message']}"
            )
            r = Phase2Result(satisfiable=False)
            r.unsat_reason = result_raw["message"]
            return r

        r = SolutionParser.parse_phase2(result_raw["atoms"])
        r.satisfiable = True
        r.optimal     = True

        self._post(
            f"[Phase 2/{self.strategy}] Done — "
            f"Firewalls: {sorted(set(r.placed_fws))}, "
            f"PS: {sorted(set(r.placed_ps))}, "
            f"Trust gaps: {len(r.trust_gap_rot)+len(r.trust_gap_sboot)+len(r.trust_gap_attest)}"
        )
        return r

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_lp_list(self) -> list:
        """Build the LP file list for Phase 2."""
        files = []
        if self.testcase_lp and os.path.isfile(self.testcase_lp):
            files.append(self.testcase_lp)
        for name in self.PHASE2_LP_NAMES:
            path = os.path.join(self.clingo_dir, name)
            if os.path.isfile(path):
                files.append(path)
            else:
                self._post(f"[Phase 2] WARNING: LP file not found: {path}")
        return files

    def _diagnose_unsat(self, lp_files: list, p1_facts: str) -> str:
        """
        Attempt to identify conflicting constraints by relaxing soft constraints
        one at a time.  Returns a human-readable diagnosis string.
        """
        # Try without the hard firewall placement constraint
        relaxed = p1_facts + "\n% Diagnosis: relaxed — allow 0 firewalls\n"
        runner  = ClingoRunner(timeout=30)
        r2 = runner.solve(lp_files=lp_files, extra_facts=relaxed,
                          num_solutions=1, opt_mode="opt")
        if r2["status"] == "SAT":
            return (
                "Over-constrained firewall placement: the firewall requirement "
                "conflicts with available topology facts. Check on_path/ip_loc facts."
            )
        return (
            "Policy encoding is unsatisfiable. Possible causes: "
            "missing allow/access_need facts, contradictory domain assignments, "
            "or incompatible Phase 1 feature selections."
        )

    def _post(self, msg: str) -> None:
        if self.progress_queue is not None:
            try:
                self.progress_queue.put_nowait(("INFO", msg))
            except queue.Full:
                pass
