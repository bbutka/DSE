"""
runtime_agent.py
================
Runtime monitoring agent: adaptive scenario evaluation and joint
Phase 2 + runtime synthesis.

Runtime extends the protected baseline from Phases 1 and 2 with
monitoring and response logic. It is a post-Phase-2 operational
extension, not the same concept as Phase 1 CIA-A availability risk and
not part of the core RASACC resilience workflow described in the paper.

**TC9-only in this merge.** The LP files, scenario definitions, and
diagnostic logic are all tc9-specific. Non-tc9 topologies are rejected
up front before solving.

Two public methods with distinct integration shapes:

  solve_adaptive()  â€” requires Phase1Result + Phase2Result
  solve_joint()     â€” requires Phase1Result only, replaces Phase 2
"""

from __future__ import annotations

import os
import queue
from typing import Iterable, List, Optional

from ..core.clingo_runner import ClingoRunner
from ..core.solution_parser import (
    Phase1Result,
    Phase2Result,
    RuntimeScenario,
    RuntimeAdaptiveResult,
    JointPhase2RuntimeResult,
    SolutionParser,
)


# ---------------------------------------------------------------------------
# TC9 runtime scenarios (module-level constant)
# ---------------------------------------------------------------------------

RUNTIME_SCENARIOS: tuple[RuntimeScenario, ...] = (
    RuntimeScenario(
        name="baseline",
        observations=(),
        description="No anomaly evidence; should remain in normal mode.",
    ),
    RuntimeScenario(
        name="dma_rate_spike",
        observations=(
            ("dma", "rate_spike", 1),
            ("dma", "cross_domain", 1),
        ),
        description="DMA bursts across bus domains; should raise suspicion and tighten access.",
    ),
    RuntimeScenario(
        name="dma_privilege_creep",
        observations=(
            ("dma", "privilege_creep", 1),
            ("dma", "policy_violation", 1),
        ),
        description="DMA begins using low-need paths; should escalate beyond baseline.",
    ),
    RuntimeScenario(
        name="c8_sequence_anomaly",
        observations=(
            ("c8", "sequence_violation", 1),
            ("c8", "policy_violation", 1),
        ),
        description="Safety-critical timer shows anomalous access ordering.",
    ),
    RuntimeScenario(
        name="ps0_policy_tamper",
        observations=(
            ("ps0", "policy_violation", 3),
            ("pep_group", "bypass_alert", 1),
        ),
        description="Policy server tamper signal plus PEP bypass alert on the compute bus.",
    ),
)


# ---------------------------------------------------------------------------
# RuntimeAgent
# ---------------------------------------------------------------------------

class RuntimeAgent:
    """
    Runs runtime adaptive monitoring and joint synthesis for tc9.

    Constructor matches Phase1Agent/Phase2Agent pattern.

    Parameters
    ----------
    clingo_dir : str
        Absolute path to the Clingo/ directory.
    testcase_lp : str
        Absolute path to the testCase instance .lp file.
        If extra_instance_facts is non-empty, testcase_lp is ignored.
    progress_queue : queue.Queue | None
        Thread-safe queue for progress messages.
    timeout : int
        Per-solve timeout in seconds.
    extra_instance_facts : str
        Generated instance facts that replace testcase_lp.
        Must be tc9-equivalent topology.
    """

    ADAPTIVE_LP_NAMES = [
        "runtime_monitor_tc9_inst.lp",
        "runtime_adaptive_tc9_enc.lp",
    ]

    JOINT_LP_NAMES = [
        "zta_policy_runtime_enc.lp",
    ]

    DIAGNOSTIC_LP_NAMES = [
        "runtime_monitor_tc9_inst.lp",
    ]

    def __init__(
        self,
        clingo_dir: str,
        testcase_lp: str,
        progress_queue: Optional[queue.Queue] = None,
        timeout: int = 60,
        extra_instance_facts: str = "",
    ) -> None:
        self.clingo_dir = clingo_dir
        self.testcase_lp = testcase_lp
        self.progress_queue = progress_queue
        self.timeout = timeout
        self.extra_instance_facts = extra_instance_facts

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def solve_adaptive(
        self,
        phase1_result: Phase1Result,
        phase2_result: Phase2Result,
        scenarios: Optional[List[RuntimeScenario]] = None,
        extra_runtime_facts: str = "",
    ) -> List[RuntimeAdaptiveResult]:
        """
        Evaluate runtime monitoring scenarios against a decided control plane.

        Requires completed Phase 1 + Phase 2.  Raises RuntimeError on
        UNSAT/timeout/load error for any scenario.

        Parameters
        ----------
        phase1_result : Phase1Result
        phase2_result : Phase2Result
        scenarios : list[RuntimeScenario] | None
            Defaults to RUNTIME_SCENARIOS.
        extra_runtime_facts : str
            Additional facts (e.g., from joint.as_runtime_facts()).
        """
        if scenarios is None:
            scenarios = list(RUNTIME_SCENARIOS)

        self._assert_tc9_runtime_topology(scenarios)

        self._post("[Runtime/adaptive] Starting adaptive scenario evaluation...")
        results: List[RuntimeAdaptiveResult] = []

        for scenario in scenarios:
            self._post(f"[Runtime/adaptive] Scenario: {scenario.name}")
            facts = self._build_runtime_facts(
                phase1_result, phase2_result, scenario, extra_runtime_facts
            )
            lp_files = self._build_adaptive_lp_list()

            runner = ClingoRunner(timeout=self.timeout)
            raw = runner.solve(
                lp_files=lp_files,
                extra_facts=facts,
                num_solutions=0,
                opt_mode="opt",
            )

            status = raw["status"]
            if status == "UNSAT":
                diag = self._diagnose_coverage_gaps(
                    phase1_result, phase2_result, scenario, extra_runtime_facts
                )
                raise RuntimeError(
                    f"Runtime adaptive solve UNSAT for scenario '{scenario.name}'. "
                    f"Diagnosis: {diag}. "
                    f"Ensure every active PS, PEP, and safety-critical node is covered "
                    f"by at least one deployed or candidate monitor."
                )
            if status == "TIMEOUT":
                raise RuntimeError(
                    f"Runtime adaptive solve timed out after {self.timeout}s "
                    f"for scenario '{scenario.name}'."
                )
            if status == "ERROR":
                raise RuntimeError(
                    f"Runtime adaptive solve error for scenario '{scenario.name}': "
                    f"{raw['message']}"
                )
            if status != "SAT":
                raise RuntimeError(
                    f"Runtime adaptive solve returned unexpected status '{status}' "
                    f"for scenario '{scenario.name}'."
                )

            result = SolutionParser.parse_runtime_adaptive(raw["atoms"], scenario)
            results.append(result)
            self._post(
                f"[Runtime/adaptive] {scenario.name}: mode={result.current_mode}, "
                f"monitors={result.placed_monitors}"
            )

        self._post(f"[Runtime/adaptive] Done â€” {len(results)} scenarios evaluated.")
        return results

    def solve_joint(
        self,
        phase1_result: Phase1Result,
    ) -> JointPhase2RuntimeResult:
        """
        Co-optimize FW/PS placement with monitor placement.

        Requires only Phase 1.  Replaces Phase 2.
        Never raises â€” returns JointPhase2RuntimeResult(satisfiable=False)
        on failure.
        """
        self._post("[Runtime/joint] Starting joint Phase 2 + runtime synthesis...")

        try:
            self._assert_tc9_runtime_topology(RUNTIME_SCENARIOS)
            lp_files = self._build_joint_lp_list()
            p1_facts = phase1_result.as_p1_facts()
            # Combine instance facts with Phase 1 output (same pattern as Phase2Agent)
            facts = self.extra_instance_facts
            if facts and p1_facts:
                facts = facts + "\n" + p1_facts
            elif p1_facts:
                facts = p1_facts

            runner = ClingoRunner(timeout=self.timeout)
            raw = runner.solve(
                lp_files=lp_files,
                extra_facts=facts,
                num_solutions=0,
                opt_mode="optN",
            )

            status = raw["status"]
            if status not in ("SAT",):
                self._post(
                    f"[Runtime/joint] {status} â€” {raw['message']}"
                )
                return JointPhase2RuntimeResult(satisfiable=False)

            result = SolutionParser.parse_runtime_joint(raw["atoms"])
            result.satisfiable = True
            result.optimal = True  # last model from optN

            self._post(
                f"[Runtime/joint] Done â€” "
                f"FWs={result.placed_fws}, PS={result.placed_ps}, "
                f"Monitors={result.placed_monitors}, "
                f"Joint cost={result.total_joint_runtime_cost}"
            )
            return result

        except Exception as exc:
            self._post(f"[Runtime/joint] ERROR â€” {exc}")
            return JointPhase2RuntimeResult(satisfiable=False)

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    @staticmethod
    def generate_runtime_report(
        p1: Phase1Result,
        p2: Phase2Result,
        results: List[RuntimeAdaptiveResult],
    ) -> str:
        """Generate a text report for adaptive runtime results."""
        lines: List[str] = []
        lines.append("=" * 78)
        lines.append("  Runtime Adaptive Monitoring Summary")
        lines.append("=" * 78)
        lines.append("")
        lines.append(f"  Phase 1 baseline risk: {p1.total_risk()}")
        lines.append(f"  Phase 2 deployed firewalls: {', '.join(sorted(set(p2.placed_fws))) or 'none'}")
        lines.append(f"  Phase 2 deployed policy servers: {', '.join(sorted(set(p2.placed_ps))) or 'none'}")
        lines.append("")

        for result in results:
            lines.append("-" * 78)
            lines.append(f"  Scenario: {result.scenario.name}")
            lines.append(f"  Description: {result.scenario.description}")
            lines.append(f"  Current mode: {result.current_mode}")
            lines.append(f"  Monitors placed: {', '.join(result.placed_monitors)}")
            lines.append(f"  Monitor cost: {result.monitor_total_cost}")
            if result.scenario.observations:
                lines.append("  Observed signals:")
                for node, signal, severity in result.scenario.observations:
                    lines.append(f"    {node:<18} {signal:<20} severity={severity}")
            else:
                lines.append("  Observed signals: none")
            if result.mode_triggers:
                lines.append("  Mode triggers:")
                for left, right in result.mode_triggers:
                    lines.append(f"    {left:<18} {right}")
            if result.response_actions:
                lines.append("  Response actions:")
                for left, right in result.response_actions:
                    lines.append(f"    {left:<18} {right}")
            if result.adaptive_denies:
                lines.append(f"  Adaptive denies: {len(result.adaptive_denies)}")
                for master, target, mode in result.adaptive_denies[:10]:
                    lines.append(f"    {mode:<18} deny {master} -> {target}")
            if result.missed_signals:
                lines.append("  Missed signals:")
                for left, right in result.missed_signals:
                    lines.append(f"    {left:<18} {right}")
            hot_nodes = sorted(
                result.anomaly_scores.items(), key=lambda item: (-item[1], item[0])
            )[:5]
            if hot_nodes:
                lines.append("  Highest anomaly scores:")
                for node, score in hot_nodes:
                    lines.append(
                        f"    {node:<18} score={score:<4} "
                        f"trust={result.trust_states.get(node, '?'):<12} "
                        f"obs={result.observability.get(node, 0)}"
                    )
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def generate_joint_runtime_report(
        p1: Phase1Result,
        joint: JointPhase2RuntimeResult,
        runtime_results: List[RuntimeAdaptiveResult],
    ) -> str:
        """Generate a text report for joint runtime results."""
        lines: List[str] = []
        lines.append("=" * 78)
        lines.append("  Joint Policy + Runtime Synthesis Summary")
        lines.append("=" * 78)
        lines.append("")
        lines.append(f"  Phase 1 baseline risk: {p1.total_risk()}")
        lines.append(f"  Joint optimal: {joint.optimal}")
        lines.append(f"  Firewalls: {', '.join(joint.placed_fws)}")
        lines.append(f"  Policy servers: {', '.join(joint.placed_ps)}")
        lines.append(f"  Monitors: {', '.join(joint.placed_monitors)}")
        lines.append(f"  ZTA cost: {joint.total_zta_cost}")
        lines.append(f"  Monitor cost: {joint.monitor_total_cost}")
        lines.append(f"  Joint cost: {joint.total_joint_runtime_cost}")
        lines.append(f"  Response-readiness score: {joint.response_readiness_score}")
        lines.append(f"  Detection-strength score: {joint.detection_strength_score}")
        lines.append(f"  Weighted detection latency: {joint.weighted_detection_latency}")
        lines.append(f"  False-positive cost: {joint.false_positive_cost}")
        lines.append("")
        lines.append("  Highest observability scores:")
        for node, score in sorted(
            joint.observability.items(), key=lambda item: (-item[1], item[0])
        )[:10]:
            lines.append(
                f"    {node:<18} obs={score:<3} "
                f"latency={joint.detection_latency.get(node, '?')}"
            )
        lines.append("")
        lines.append(RuntimeAgent.generate_runtime_report(
            p1, joint.to_phase2_result(), runtime_results
        ))
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_adaptive_lp_list(self) -> List[str]:
        files: List[str] = []
        if not self.extra_instance_facts and self.testcase_lp and os.path.isfile(self.testcase_lp):
            files.append(self.testcase_lp)
        for name in self.ADAPTIVE_LP_NAMES:
            path = os.path.join(self.clingo_dir, name)
            if os.path.isfile(path):
                files.append(path)
            else:
                self._post(f"[Runtime] WARNING: LP file not found: {path}")
        return files

    def _topology_text(self) -> str:
        if self.extra_instance_facts:
            return self.extra_instance_facts
        if self.testcase_lp and os.path.isfile(self.testcase_lp):
            try:
                with open(self.testcase_lp, "r", encoding="utf-8") as fh:
                    return fh.read()
            except OSError:
                return ""
        return ""

    def _assert_tc9_runtime_topology(
        self,
        scenarios: Iterable[RuntimeScenario],
    ) -> None:
        """
        Fail fast when runtime is invoked on a non-tc9 topology.

        The runtime LP files are tc9-specific and require a fixed set of
        component / PEP / PS identifiers to ground correctly.
        """
        text = self._topology_text()
        required_nodes = {node for sc in scenarios for node, _, _ in sc.observations}
        required_nodes.update({"dma", "c8", "ps0", "pep_group"})

        def has_node(name: str) -> bool:
            patterns = (
                f"component({name}).",
                f"component({name},",
                f"master({name}).",
                f"receiver({name}).",
                f"policy_server({name}).",
                f"cand_ps({name}).",
                f"cand_fw({name}).",
                f"active_policy_enforcement_point({name}).",
            )
            return any(pattern in text for pattern in patterns)

        missing = sorted(node for node in required_nodes if not has_node(node))
        if missing:
            raise RuntimeError(
                "RuntimeAgent is tc9-specific in this package. "
                f"Missing required tc9 runtime nodes: {', '.join(missing)}."
            )

    def _build_joint_lp_list(self) -> List[str]:
        files: List[str] = []
        if not self.extra_instance_facts and self.testcase_lp and os.path.isfile(self.testcase_lp):
            files.append(self.testcase_lp)
        for name in self.JOINT_LP_NAMES:
            path = os.path.join(self.clingo_dir, name)
            if os.path.isfile(path):
                files.append(path)
            else:
                self._post(f"[Runtime] WARNING: LP file not found: {path}")
        return files

    def _build_runtime_facts(
        self,
        p1: Phase1Result,
        p2: Phase2Result,
        scenario: RuntimeScenario,
        extra_facts: str = "",
    ) -> str:
        lines: List[str] = []
        p1_facts = p1.as_p1_facts()
        if p1_facts:
            lines.append(p1_facts)
        if p2.satisfiable:
            lines.append(p2.as_phase3_facts())
        if self.extra_instance_facts:
            lines.append(self.extra_instance_facts)
        if extra_facts:
            lines.append(extra_facts)
        for node, signal, severity in scenario.observations:
            lines.append(f"observed({node}, {signal}, {severity}).")
        return "\n".join(line for line in lines if line)

    def _diagnose_coverage_gaps(
        self,
        p1: Phase1Result,
        p2: Phase2Result,
        scenario: RuntimeScenario,
        extra_facts: str,
    ) -> str:
        """Diagnose why runtime adaptive solve went UNSAT."""
        diag_lp = []
        if not self.extra_instance_facts and self.testcase_lp and os.path.isfile(self.testcase_lp):
            diag_lp.append(self.testcase_lp)
        for name in self.DIAGNOSTIC_LP_NAMES:
            path = os.path.join(self.clingo_dir, name)
            if os.path.isfile(path):
                diag_lp.append(path)

        inline = """
covered(N) :- deployed_monitor(M), monitor_covers(M, N).
covered(N) :- place_monitor(M), monitor_covers(M, N).
{ place_monitor(M) : cand_monitor(M) }.
coverage_gap(safety_critical, C) :- safety_critical(C), not covered(C).
coverage_gap(policy_server,   PS) :- policy_server(PS), not covered(PS).
coverage_gap(pep, PEP) :- policy_enforcement_point(PEP), not covered(PEP).
#show coverage_gap/2.
#show place_monitor/1.
"""
        facts = self._build_runtime_facts(p1, p2, scenario, extra_facts)
        combined = facts + "\n" + inline

        runner = ClingoRunner(timeout=20)
        raw = runner.solve(
            lp_files=diag_lp,
            extra_facts=combined,
            num_solutions=1,
            opt_mode="opt",
        )

        if raw["status"] != "SAT":
            return "diagnostic solve also failed â€” topology may be fundamentally misconfigured"

        gaps = []
        monitors_needed = []
        for sym in raw["atoms"]:
            if sym.name == "coverage_gap":
                gaps.append(str(sym))
            elif sym.name == "place_monitor":
                monitors_needed.append(str(sym.arguments[0]))

        if gaps:
            return f"uncoverable nodes: {', '.join(gaps)}"

        return (
            f"monitor budget exhausted â€” coverage requires monitors "
            f"{sorted(monitors_needed)} but combined cost exceeds max_monitor_cost"
        )

    def _post(self, msg: str) -> None:
        if self.progress_queue is not None:
            try:
                self.progress_queue.put_nowait(("INFO", msg))
            except queue.Full:
                pass

