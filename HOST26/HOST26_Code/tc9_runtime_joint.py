from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import clingo

from runClingo_tc9 import Phase1Result, Phase2Result, phase1_optimise
from tc9_runtime_adaptive import (
    RUNTIME_SCENARIOS,
    RuntimeAdaptiveResult,
    generate_runtime_report,
    solve_runtime_scenario,
)


BASE_DIR = Path(__file__).resolve().parent

JOINT_PHASE2_FILES = [
    BASE_DIR / "testCases" / "testCase9_inst.lp",
    BASE_DIR / "Clingo" / "zta_policy_runtime_enc.lp",
]


@dataclass
class JointPhase2RuntimeResult:
    placed_fws: list[str] = field(default_factory=list)
    placed_ps: list[str] = field(default_factory=list)
    placed_monitors: list[str] = field(default_factory=list)
    protected: list[tuple[str, str]] = field(default_factory=list)
    governs_ip: list[tuple[str, str]] = field(default_factory=list)
    total_zta_cost: int = 0
    monitor_total_cost: int = 0
    total_joint_runtime_cost: int = 0
    response_readiness_score: int = 0
    detection_strength_score: int = 0
    weighted_detection_latency: int = 0
    false_positive_cost: int = 0
    observability: dict[str, int] = field(default_factory=dict)
    detection_latency: dict[str, int] = field(default_factory=dict)
    satisfiable: bool = False
    optimal: bool = False

    def to_phase2_result(self) -> Phase2Result:
        result = Phase2Result()
        result.placed_fws = list(self.placed_fws)
        result.placed_ps = list(self.placed_ps)
        result.protected = list(self.protected)
        result.governs_ip = list(self.governs_ip)
        result.total_cost = self.total_zta_cost
        result.satisfiable = self.satisfiable
        result.optimal = self.optimal
        return result

    def as_runtime_facts(self) -> str:
        lines: list[str] = []
        for fw in sorted(set(self.placed_fws)):
            lines.append(f"deployed_pep({fw}).")
        for ps in sorted(set(self.placed_ps)):
            lines.append(f"deployed_ps({ps}).")
        for monitor in sorted(set(self.placed_monitors)):
            lines.append(f"deployed_monitor({monitor}).")
        return "\n".join(lines)


def solve_joint_phase2_runtime(p1: Phase1Result) -> JointPhase2RuntimeResult:
    ctl = clingo.Control(["-n", "0", "--opt-mode=optN", "--warn=none"])
    for path in JOINT_PHASE2_FILES:
        ctl.load(str(path))
    ctl.add("p1", [], p1.as_p1_facts())
    ctl.ground([("base", []), ("p1", [])])

    result = JointPhase2RuntimeResult()
    last_model: list[clingo.Symbol] = []

    def on_model(model: clingo.Model) -> None:
        nonlocal last_model
        last_model = list(model.symbols(shown=True))
        result.optimal = model.optimality_proven

    solve_result = ctl.solve(on_model=on_model)
    result.satisfiable = not solve_result.unsatisfiable
    result.optimal = result.satisfiable and not solve_result.unknown and result.optimal
    if solve_result.unsatisfiable or not last_model:
        raise RuntimeError("Joint Phase 2 runtime solve returned no model")

    for sym in last_model:
        name = sym.name
        args = sym.arguments
        if name == "place_fw" and len(args) == 1:
            result.placed_fws.append(str(args[0]))
        elif name == "place_ps" and len(args) == 1:
            result.placed_ps.append(str(args[0]))
        elif name == "place_monitor" and len(args) == 1:
            result.placed_monitors.append(str(args[0]))
        elif name == "protected" and len(args) == 2:
            result.protected.append((str(args[0]), str(args[1])))
        elif name == "governs_ip" and len(args) == 2:
            result.governs_ip.append((str(args[0]), str(args[1])))
        elif name == "total_zta_cost" and len(args) == 1:
            result.total_zta_cost = args[0].number
        elif name == "monitor_total_cost" and len(args) == 1:
            result.monitor_total_cost = args[0].number
        elif name == "total_joint_runtime_cost" and len(args) == 1:
            result.total_joint_runtime_cost = args[0].number
        elif name == "response_readiness_score" and len(args) == 1:
            result.response_readiness_score = args[0].number
        elif name == "detection_strength_score" and len(args) == 1:
            result.detection_strength_score = args[0].number
        elif name == "weighted_detection_latency" and len(args) == 1:
            result.weighted_detection_latency = args[0].number
        elif name == "false_positive_cost" and len(args) == 1:
            result.false_positive_cost = args[0].number
        elif name == "observability_score" and len(args) == 2:
            result.observability[str(args[0])] = args[1].number
        elif name == "detection_latency" and len(args) == 2:
            result.detection_latency[str(args[0])] = args[1].number

    result.placed_fws.sort()
    result.placed_ps.sort()
    result.placed_monitors.sort()
    result.protected.sort()
    result.governs_ip.sort()
    return result


def solve_joint_runtime_pipeline() -> tuple[Phase1Result, JointPhase2RuntimeResult, list[RuntimeAdaptiveResult]]:
    p1 = phase1_optimise()
    joint = solve_joint_phase2_runtime(p1)
    phase2_for_runtime = joint.to_phase2_result()
    joint_facts = "\n".join(
        line
        for line in [joint.as_runtime_facts()]
        if line
    )
    runtime_results = [
        solve_runtime_scenario(p1, phase2_for_runtime, scenario, extra_facts=joint_facts)
        for scenario in RUNTIME_SCENARIOS
    ]
    return p1, joint, runtime_results


def generate_joint_runtime_report(
    p1: Phase1Result,
    joint: JointPhase2RuntimeResult,
    runtime_results: list[RuntimeAdaptiveResult],
) -> str:
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append("  testCase9 Joint Policy + Runtime Synthesis Summary")
    lines.append("=" * 78)
    lines.append("")
    lines.append(f"  Phase 1 baseline risk: {p1.total_risk()}")
    lines.append(f"  Joint Phase 2 optimal: {joint.optimal}")
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
    lines.append("  Highest observability scores in the synthesized design:")
    for node, score in sorted(joint.observability.items(), key=lambda item: (-item[1], item[0]))[:10]:
        lines.append(
            f"    {node:<18} obs={score:<3} latency={joint.detection_latency.get(node, '?')}"
        )
    lines.append("")
    lines.append(generate_runtime_report(p1, joint.to_phase2_result(), runtime_results))
    return "\n".join(lines)
