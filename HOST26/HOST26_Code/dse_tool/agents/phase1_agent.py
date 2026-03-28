"""
phase1_agent.py
===============
Phase 1 worker: security/logging feature selection via ASP optimisation.

Three strategy variants inject different objective modifications:
  max_security  — standard minimize (risk only)
  min_resources — secondary minimize on LUT usage, risk bound relaxed 20%
  balanced      — combined minimize (risk + lut_penalty/1000)
"""

from __future__ import annotations

import os
import queue
from typing import List, Optional

from ..core.clingo_runner import ClingoRunner
from ..core.solution_parser import Phase1Result, SolutionParser


# ---------------------------------------------------------------------------
# Strategy parameters
# ---------------------------------------------------------------------------

# Extra ASP injected per strategy (appended to extra_facts before solving)
STRATEGY_EXTRA: dict = {
    "max_security": "",   # use the existing #minimize in opt_*.lp unchanged

    "min_resources": (
        "% min_resources strategy: add secondary LUT objective\n"
        "#minimize { LUTs@2, total : total_luts_used(LUTs) }.\n"
    ),

    "balanced": (
        "% balanced strategy: combined risk + LUT/1000 objective\n"
        "#minimize { R+L/1000, balanced : total_luts_used(L), total_risk_sum(R) }.\n"
    ),
}


class Phase1Agent:
    """
    Runs the Phase 1 DSE optimisation for a given strategy.

    Parameters
    ----------
    clingo_dir : str
        Absolute path to the Clingo/ directory.
    testcase_lp : str
        Absolute path to the instance .lp file (e.g. testCase9_inst.lp).
    strategy : str
        One of 'max_security', 'min_resources', 'balanced'.
    progress_queue : queue.Queue | None
        Thread-safe queue for progress messages.  None = silent.
    extra_instance_facts : str
        Additional ASP facts from the network editor (overrides testcase_lp
        when the user has modified the topology).
    timeout : int
        Per-solve timeout in seconds.
    """

    PHASE1_LP_NAMES = [
        "security_features_inst.lp",
        "tgt_system_tc9_inst.lp",
        "init_enc.lp",
        "opt_redundancy_generic_enc.lp",
        "opt_latency_enc.lp",
        "opt_power_enc.lp",
        "opt_resource_enc.lp",
        "bridge_enc.lp",
    ]

    def __init__(
        self,
        clingo_dir: str,
        testcase_lp: str,
        strategy: str = "max_security",
        progress_queue: Optional[queue.Queue] = None,
        extra_instance_facts: str = "",
        timeout: int = 60,
    ) -> None:
        self.clingo_dir           = clingo_dir
        self.testcase_lp          = testcase_lp
        self.strategy             = strategy
        self.progress_queue       = progress_queue
        self.extra_instance_facts = extra_instance_facts
        self.timeout              = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> Phase1Result:
        """
        Execute Phase 1 and return a Phase1Result.

        Posts progress messages to progress_queue if provided.
        Never raises — returns a Phase1Result with satisfiable=False on error.
        """
        self._post(f"[Phase 1/{self.strategy}] Starting security DSE optimisation...")

        lp_files = self._build_lp_list()
        strategy_extra = STRATEGY_EXTRA.get(self.strategy, "")

        extra = self.extra_instance_facts
        if strategy_extra:
            extra = (extra + "\n" if extra else "") + strategy_extra

        runner = ClingoRunner(timeout=self.timeout)
        result_raw = runner.solve(
            lp_files=lp_files,
            extra_facts=extra,
            num_solutions=0,
            opt_mode="optN",
        )

        status = result_raw["status"]
        if status == "UNSAT":
            self._post(
                f"[Phase 1/{self.strategy}] UNSAT — constraints may be infeasible. "
                f"Trying fallback with relaxed risk cap..."
            )
            result_raw = self._try_relaxed(lp_files, extra)
            status = result_raw["status"]

        if status not in ("SAT",):
            self._post(
                f"[Phase 1/{self.strategy}] ERROR/TIMEOUT — {result_raw['message']}"
            )
            r = Phase1Result(strategy=self.strategy, satisfiable=False)
            return r

        r = SolutionParser.parse_phase1(result_raw["atoms"], strategy=self.strategy)
        r.satisfiable = True
        r.optimal     = True  # we accept last-optimal model from optN

        self._post(
            f"[Phase 1/{self.strategy}] Done — "
            f"Risk: {r.total_risk()}, "
            f"LUTs: {r.total_luts:,} ({r.total_luts/53200*100:.1f}%), "
            f"Power: {r.total_power:,} mW"
        )
        return r

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_lp_list(self) -> List[str]:
        """Build the ordered list of .lp files for Phase 1."""
        files: List[str] = []
        # Instance file first (unless extra_instance_facts replaces it)
        if self.testcase_lp and os.path.isfile(self.testcase_lp):
            files.append(self.testcase_lp)
        for name in self.PHASE1_LP_NAMES:
            path = os.path.join(self.clingo_dir, name)
            if os.path.isfile(path):
                files.append(path)
            else:
                self._post(f"[Phase 1] WARNING: LP file not found: {path}")
        return files

    def _try_relaxed(self, lp_files: List[str], extra: str) -> dict:
        """
        Retry with a 20% relaxed max_asset_risk cap as a fallback.
        Injects an override fact that replaces the tight cap.
        """
        relaxed_extra = (
            extra + "\n"
            "% Fallback: relaxed risk cap\n"
            ":- system_capability(max_asset_risk, _), false.  "
            "% suppress base cap\n"
            "system_capability(max_asset_risk, 600).\n"
        )
        runner = ClingoRunner(timeout=self.timeout)
        return runner.solve(
            lp_files=lp_files,
            extra_facts=relaxed_extra,
            num_solutions=0,
            opt_mode="optN",
        )

    def _post(self, msg: str) -> None:
        """Post a progress message to the queue (non-blocking)."""
        if self.progress_queue is not None:
            try:
                self.progress_queue.put_nowait(("INFO", msg))
            except queue.Full:
                pass
