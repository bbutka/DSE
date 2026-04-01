"""
phase3_agent.py
===============
Phase 3 worker: resilience analysis across dynamically generated
fault / compromise scenarios.

Scenarios are auto-generated from the network topology when no custom
scenarios are provided.  Falls back to a baseline-only scenario if the
topology has no components.
"""

from __future__ import annotations

import os
import queue
from typing import List, Optional, TYPE_CHECKING

from ..core.solution_parser import (
    Phase1Result, Phase2Result, ScenarioResult, SolutionParser
)

if TYPE_CHECKING:
    from ..core.asp_generator import NetworkModel
    from ..core.clingo_runner import ClingoRunner


# ---------------------------------------------------------------------------
# Auto-scenario generation from topology (WP3)
# ---------------------------------------------------------------------------

def _valid_asp_components(model: "NetworkModel") -> set:
    """
    Return the set of component names that will exist as ground atoms in
    the ASP program (i.e. emitted by ASPGenerator as component/1,
    master/1, or receiver/1).

    Scenario facts referencing names outside this set are silently
    ignored by Clingo, producing misleading baseline-equivalent results.
    """
    valid: set = set()
    for c in model.components:
        if c.comp_type not in ("bus",):
            valid.add(c.name)
    for bus in model.buses:
        valid.add(bus)
    for fw in model.cand_fws:
        valid.add(fw)
    for ps in model.cand_ps:
        valid.add(ps)
    return valid


def generate_scenarios(model: "NetworkModel", full: bool = False) -> List[dict]:
    """
    Dynamically generate resilience scenarios from a NetworkModel.

    Parameters
    ----------
    model : NetworkModel
        The loaded topology.
    full : bool
        If True, generate an expanded set including single-receiver
        compromises, PEP bypasses, and combined scenarios.

    Returns
    -------
    list[dict]
        Each dict has keys ``name``, ``compromised``, ``failed``.
        All component names are validated against the ASP-emittable set.
    """
    valid_names = _valid_asp_components(model)

    scenarios: List[dict] = [
        {"name": "baseline", "compromised": [], "failed": []},
    ]
    seen_names: set = {"baseline"}

    def _add(name: str, compromised: list, failed: list) -> None:
        if name not in seen_names:
            # Validate: all referenced nodes must be ASP-emittable
            valid_comp = [c for c in compromised if c in valid_names]
            valid_fail = [f for f in failed if f in valid_names]
            if len(valid_comp) != len(compromised) or len(valid_fail) != len(failed):
                # Skip scenarios with invalid component names rather than
                # producing a misleading baseline-equivalent result
                return
            seen_names.add(name)
            scenarios.append({
                "name": name,
                "compromised": list(compromised),
                "failed": list(failed),
            })

    masters = [c for c in model.components if c.is_master]
    receivers = [c for c in model.components
                 if c.comp_type not in ("bus", "policy_server", "firewall")
                 and not c.is_master]

    # Single-master compromise (always)
    for m in masters:
        _add(f"{m.name}_compromise", [m.name], [])

    # Bus failures (always)
    for bus in model.buses:
        _add(f"{bus}_failure", [], [bus])

    # PS compromise (always)
    for ps in model.cand_ps:
        _add(f"{ps}_compromise", [ps], [])

    # Redundancy group full compromise (always)
    for grp in model.redundancy_groups:
        _add(f"group_{grp.group_id}_compromise", list(grp.members), [])

    if full:
        # Single-receiver compromises
        for r in receivers:
            _add(f"{r.name}_compromise", [r.name], [])

        # PEP bypass (compromise the firewall)
        for fw in model.cand_fws:
            _add(f"{fw}_bypass", [fw], [])

        # Combined: master compromise + bus failure
        for m in masters:
            for bus in model.buses:
                _add(f"{m.name}_comp_{bus}_fail", [m.name], [bus])

        # PS failure
        for ps in model.cand_ps:
            _add(f"{ps}_failure", [], [ps])

        # All-PS failure
        if len(model.cand_ps) >= 2:
            _add("all_ps_failure", [], list(model.cand_ps))
            # One compromised, one failed
            _add(
                f"{model.cand_ps[0]}_comp_{model.cand_ps[1]}_fail",
                [model.cand_ps[0]], [model.cand_ps[1]],
            )

        # Highest-exploitability component compromise
        high_exploit = sorted(receivers,
                              key=lambda c: c.exploitability, reverse=True)
        for c in high_exploit[:3]:
            _add(f"{c.name}_exploit_compromise", [c.name], [])

    return scenarios


# Legacy scenario lists (kept for backwards compatibility only)
CORE_SCENARIOS = [
    {"name": "baseline", "compromised": [], "failed": []},
]

FULL_SCENARIOS = CORE_SCENARIOS


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
        If True run expanded scenarios; if False run core set.
    timeout : int
        Per-scenario timeout in seconds.
    """

    PHASE3_LP_NAMES = [
        "resilience_enc.lp",
    ]

    # Legacy fallback removed — resilience_tc9_enc.lp lacks WP4/5/6
    # features and would silently produce degraded analysis.
    _LEGACY_LP_NAMES: list = []

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
        extra_instance_facts: str = "",
    ) -> None:
        self.clingo_dir           = clingo_dir
        self.testcase_lp          = testcase_lp
        self.phase1_result        = phase1_result
        self.extra_instance_facts = extra_instance_facts
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
            Custom scenarios from the network model.  When non-empty
            overrides auto-generated scenarios.
        """
        if model_scenarios:
            scenarios = model_scenarios
        else:
            scenarios = [{"name": "baseline", "compromised": [], "failed": []}]

        n = len(scenarios)
        self._post(f"[Phase 3/{self.strategy}] Running {n} scenario(s)...")

        lp_files = self._build_lp_list()
        p1       = self.phase1_result
        p2       = self.phase2_result

        # Build base facts string shared across all scenarios
        base_facts = self.extra_instance_facts or ""
        p1_facts = p1.as_p1_facts()
        if p1_facts:
            base_facts = (base_facts + "\n" + p1_facts) if base_facts else p1_facts
        if p2.satisfiable:
            p2_facts = p2.as_phase3_facts()
            if p2_facts:
                base_facts += "\n" + p2_facts

        results: List[ScenarioResult] = []
        from ..core.clingo_runner import ClingoRunner
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
        if not self.extra_instance_facts and self.testcase_lp and os.path.isfile(self.testcase_lp):
            files.append(self.testcase_lp)

        found = False
        for name in self.PHASE3_LP_NAMES:
            path = os.path.join(self.clingo_dir, name)
            if os.path.isfile(path):
                files.append(path)
                found = True

        # Fallback to legacy filename
        if not found:
            for name in self._LEGACY_LP_NAMES:
                path = os.path.join(self.clingo_dir, name)
                if os.path.isfile(path):
                    files.append(path)
                    found = True
                    break

        if not found:
            self._post("[Phase 3] WARNING: No resilience encoding LP file found")

        return files

    def _post(self, msg: str) -> None:
        if self.progress_queue is not None:
            try:
                self.progress_queue.put_nowait(("INFO", msg))
            except queue.Full:
                pass
