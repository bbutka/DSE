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
        extra_instance_facts: str = "",
        solver_config: Optional[dict] = None,
    ) -> None:
        self.clingo_dir           = clingo_dir
        self.testcase_lp          = testcase_lp
        self.phase1_result        = phase1_result
        self.strategy             = strategy
        self.progress_queue       = progress_queue
        self.timeout              = timeout
        self.extra_instance_facts = extra_instance_facts
        self.solver_config        = solver_config or {}

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
        # Combine generated instance facts (topology) with Phase 1 output
        all_extra = self.extra_instance_facts
        if all_extra and p1_facts:
            all_extra = all_extra + "\n" + p1_facts
        elif p1_facts:
            all_extra = p1_facts

        runner = self._make_runner(timeout=self.timeout)
        result_raw = runner.solve(
            lp_files=lp_files,
            extra_facts=all_extra,
            num_solutions=1,
            opt_mode="optN",
        )

        status = result_raw["status"]

        if status == "UNSAT":
            reason = self._diagnose_unsat(lp_files, all_extra)
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
        if not self.extra_instance_facts and self.testcase_lp and os.path.isfile(self.testcase_lp):
            files.append(self.testcase_lp)
        for name in self.PHASE2_LP_NAMES:
            path = os.path.join(self.clingo_dir, name)
            if os.path.isfile(path):
                files.append(path)
            else:
                self._post(f"[Phase 2] WARNING: LP file not found: {path}")
        return files

    def _diagnose_unsat(self, lp_files: list, all_extra: str) -> str:
        """
        Attempt to identify conflicting constraints by selectively
        relaxing hard constraints one at a time.

        Returns a human-readable diagnosis string.
        """
        runner = self._make_runner(timeout=20)
        issues: list = []

        # Test 1: Relax the critical-IP firewall constraint
        #   :- master(M), low_trust_domain(M), critical(IP),
        #      reachable(M, IP), not protected(M, IP).
        relax_fw = (
            all_extra + "\n"
            "% DIAG: override critical-IP FW constraint\n"
            "protected(M, IP) :- master(M), receiver(IP).\n"
        )
        r1 = runner.solve(lp_files=lp_files, extra_facts=relax_fw,
                          num_solutions=1, opt_mode="opt")
        if r1["status"] == "SAT":
            issues.append(
                "critical-IP firewall constraint: a low-trust master can "
                "reach a critical IP with no on-path firewall candidate. "
                "Check on_path(FW, Master, IP) and ip_loc(IP, FW) facts."
            )

        # Test 2: Relax the safety-critical isolation constraint
        #   :- safety_critical(C), not isolated(C, _).
        relax_iso = (
            all_extra + "\n"
            "% DIAG: override safety-critical isolation\n"
            "isolated(C, attack_confirmed) :- safety_critical(C).\n"
        )
        r2 = runner.solve(lp_files=lp_files, extra_facts=relax_iso,
                          num_solutions=1, opt_mode="opt")
        if r2["status"] == "SAT":
            issues.append(
                "safety-critical isolation constraint: a safety-critical "
                "component cannot be isolated in any security mode. "
                "Check that deny rules cover all low-trust masters."
            )

        # Test 3: Relax the FW-governance constraint
        #   :- place_fw(FWL), ip_loc(IP, FWL), not governs_ip(_, IP).
        relax_gov = (
            all_extra + "\n"
            "% DIAG: override governance constraint\n"
            "governs_ip(ps_diag, IP) :- ip_loc(IP, _).\n"
            "place_ps(ps_diag).\n"
            "cand_ps(ps_diag).\n"
            "ps_cost(ps_diag, 0).\n"
        )
        r3 = runner.solve(lp_files=lp_files, extra_facts=relax_gov,
                          num_solutions=1, opt_mode="opt")
        if r3["status"] == "SAT":
            issues.append(
                "FW governance constraint: a placed firewall has no "
                "governing policy server. Check governs(PS, FW) facts "
                "cover all candidate firewalls that must be placed."
            )

        if issues:
            return "UNSAT root cause(s): " + " | ".join(issues)

        return (
            "Policy encoding is unsatisfiable. Possible causes: "
            "missing allow/access_need facts, contradictory domain assignments, "
            "incompatible Phase 1 feature selections, or structural topology gap. "
            "Use 'Show ASP Facts' to dump instance facts and run clingo manually."
        )

    def _post(self, msg: str) -> None:
        if self.progress_queue is not None:
            try:
                self.progress_queue.put_nowait(("INFO", msg))
            except queue.Full:
                pass

    def _make_runner(self, timeout: int) -> ClingoRunner:
        return ClingoRunner(
            timeout=timeout,
            threads=self.solver_config.get("clingo_threads"),
            parallel_mode=self.solver_config.get("clingo_parallel_mode"),
            configuration=self.solver_config.get("clingo_configuration"),
        )
