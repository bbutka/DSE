from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import clingo

from runClingo_tc9 import Phase1Result, Phase2Result, phase1_optimise, phase2_zta


BASE_DIR = Path(__file__).resolve().parent

RUNTIME_FILES = [
    BASE_DIR / "testCases" / "testCase9_inst.lp",
    BASE_DIR / "Clingo" / "runtime_monitor_tc9_inst.lp",
    BASE_DIR / "Clingo" / "runtime_adaptive_tc9_enc.lp",
]


@dataclass(frozen=True)
class RuntimeScenario:
    name: str
    observations: tuple[tuple[str, str, int], ...]
    description: str


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


@dataclass
class RuntimeAdaptiveResult:
    scenario: RuntimeScenario
    placed_monitors: list[str] = field(default_factory=list)
    covered: list[str] = field(default_factory=list)
    monitor_total_cost: int = 0
    observability: dict[str, int] = field(default_factory=dict)
    missed_signals: list[tuple[str, str]] = field(default_factory=list)
    unknown_signals: list[tuple[str, str]] = field(default_factory=list)  # unknown signal kind
    alert_scores: dict[str, int] = field(default_factory=dict)
    anomaly_scores: dict[str, int] = field(default_factory=dict)
    trust_states: dict[str, str] = field(default_factory=dict)
    current_mode: str = "unknown"
    mode_triggers: list[tuple[str, str]] = field(default_factory=list)
    response_actions: list[tuple[str, str]] = field(default_factory=list)
    adaptive_denies: list[tuple[str, str, str]] = field(default_factory=list)
    adaptive_allows: list[tuple[str, str, str]] = field(default_factory=list)
    effective_allows: list[tuple[str, str, str]] = field(default_factory=list)
    effective_denies: list[tuple[str, str, str]] = field(default_factory=list)


def _runtime_facts(
    p1: Phase1Result,
    p2: Phase2Result,
    scenario: RuntimeScenario,
    extra_facts: str = "",
) -> str:
    lines: list[str] = []
    lines.append(p1.as_p1_facts())
    if p2.satisfiable:
        lines.append(p2.as_phase3_facts())
    if extra_facts:
        lines.append(extra_facts)
    for node, signal, severity in scenario.observations:
        lines.append(f"observed({node}, {signal}, {severity}).")
    return "\n".join(line for line in lines if line)


def _diagnose_coverage_gaps(
    p1: Phase1Result,
    p2: Phase2Result,
    scenario: RuntimeScenario,
    extra_facts: str,
) -> str:
    """Run two relaxed solves to diagnose why the main solve went UNSAT.

    Pass 1 (no budget constraint): finds any monitor set that satisfies
    coverage.  If gaps remain → nodes cannot be covered at all.
    If gaps are absent → budget was the limiting factor.
    """
    relaxed_files = [
        BASE_DIR / "testCases" / "testCase9_inst.lp",
        BASE_DIR / "Clingo" / "runtime_monitor_tc9_inst.lp",
    ]
    # Pass 1: unconstrained — ignore budget, find best coverage
    inline_pass1 = """
covered(N) :- deployed_monitor(M), monitor_covers(M, N).
covered(N) :- place_monitor(M), monitor_covers(M, N).
{ place_monitor(M) : cand_monitor(M) }.
coverage_gap(safety_critical, C) :- safety_critical(C), not covered(C).
coverage_gap(policy_server,   PS) :- policy_server(PS), not covered(PS).
coverage_gap(pep, PEP) :- policy_enforcement_point(PEP), not covered(PEP).
#show coverage_gap/2.
#show place_monitor/1.
"""
    ctl2 = clingo.Control(["-n", "1", "--warn=none"])
    for path in relaxed_files:
        ctl2.load(str(path))
    ctl2.add("runtime", [], _runtime_facts(p1, p2, scenario, extra_facts))
    ctl2.add("diag", [], inline_pass1)
    ctl2.ground([("base", []), ("runtime", []), ("diag", [])])
    gaps: list[str] = []
    monitors_needed: list[str] = []
    def on_model(m: clingo.Model) -> None:
        for sym in m.symbols(shown=True):
            if sym.name == "coverage_gap":
                gaps.append(str(sym))
            elif sym.name == "place_monitor":
                monitors_needed.append(str(sym.arguments[0]))
    ctl2.solve(on_model=on_model)

    if gaps:
        return f"uncoverable nodes: {', '.join(gaps)}"

    # Pass 2: budget was the cause — report what's needed vs what's allowed
    total_needed = sum(
        cost
        for m in monitors_needed
        for path in [BASE_DIR / "Clingo" / "runtime_monitor_tc9_inst.lp"]
        # read cost from the model facts; approximate via known values
        for cost in [0]  # placeholder — actual cost is already in gaps message
    )
    return (
        f"monitor budget exhausted — coverage requires monitors "
        f"{sorted(monitors_needed)} but combined cost exceeds max_monitor_cost"
    )


def solve_runtime_scenario(
    p1: Phase1Result,
    p2: Phase2Result,
    scenario: RuntimeScenario,
    extra_facts: str = "",
) -> RuntimeAdaptiveResult:
    # Use -n 0 / --opt-mode=opt: branch-and-bound finds exactly one optimal model.
    # -n 1 returns the first model found without completing the B&B search,
    # so the monitor placement is not guaranteed to be coverage-optimal.
    # optN enumerates all optimal models; last_model is non-deterministic.
    ctl = clingo.Control(["-n", "0", "--opt-mode=opt", "--warn=none"])
    for path in RUNTIME_FILES:
        ctl.load(str(path))
    ctl.add("runtime", [], _runtime_facts(p1, p2, scenario, extra_facts))
    ctl.ground([("base", []), ("runtime", [])])

    result = RuntimeAdaptiveResult(scenario=scenario)
    last_model: list[clingo.Symbol] = []

    def on_model(model: clingo.Model) -> None:
        nonlocal last_model
        last_model = list(model.symbols(shown=True))

    solve_result = ctl.solve(on_model=on_model)
    if solve_result.unsatisfiable or not last_model:
        gaps = _diagnose_coverage_gaps(p1, p2, scenario, extra_facts)
        raise RuntimeError(
            f"Runtime adaptive solve UNSAT for scenario '{scenario.name}'. "
            f"Coverage gaps found: {gaps}. "
            f"Ensure every active PS, PEP, and safety-critical node is covered "
            f"by at least one deployed or candidate monitor."
        )

    for sym in last_model:
        name = sym.name
        args = sym.arguments
        if name in {"place_monitor", "active_monitor"} and len(args) == 1:
            result.placed_monitors.append(str(args[0]))
        elif name == "covered" and len(args) == 1:
            result.covered.append(str(args[0]))
        elif name == "monitor_total_cost" and len(args) == 1:
            result.monitor_total_cost = args[0].number
        elif name == "observability_score" and len(args) == 2:
            result.observability[str(args[0])] = args[1].number
        elif name == "missed_signal" and len(args) == 2:
            result.missed_signals.append((str(args[0]), str(args[1])))
        elif name == "alert_score" and len(args) == 2:
            result.alert_scores[str(args[0])] = args[1].number
        elif name == "anomaly_score" and len(args) == 2:
            result.anomaly_scores[str(args[0])] = args[1].number
        elif name == "trust_state" and len(args) == 2:
            result.trust_states[str(args[0])] = str(args[1])
        elif name == "current_mode" and len(args) == 1:
            result.current_mode = str(args[0])
        elif name == "mode_trigger" and len(args) == 2:
            result.mode_triggers.append((str(args[0]), str(args[1])))
        elif name == "response_action" and len(args) == 2:
            result.response_actions.append((str(args[0]), str(args[1])))
        elif name == "adaptive_deny" and len(args) == 3:
            result.adaptive_denies.append((str(args[0]), str(args[1]), str(args[2])))
        elif name == "adaptive_allow" and len(args) == 3:
            result.adaptive_allows.append((str(args[0]), str(args[1]), str(args[2])))
        elif name == "effective_allow" and len(args) == 3:
            result.effective_allows.append((str(args[0]), str(args[1]), str(args[2])))
        elif name == "effective_deny" and len(args) == 3:
            result.effective_denies.append((str(args[0]), str(args[1]), str(args[2])))
        elif name == "unknown_signal" and len(args) == 2:
            result.unknown_signals.append((str(args[0]), str(args[1])))

    result.placed_monitors = sorted(set(result.placed_monitors))
    result.covered.sort()
    result.missed_signals.sort()
    result.unknown_signals.sort()
    result.mode_triggers.sort()
    result.response_actions.sort()
    result.adaptive_denies.sort()
    result.adaptive_allows.sort()
    result.effective_allows.sort()
    result.effective_denies.sort()
    return result


def solve_all_runtime_scenarios() -> tuple[Phase1Result, Phase2Result, list[RuntimeAdaptiveResult]]:
    p1 = phase1_optimise()
    p2 = phase2_zta(p1)
    results = [solve_runtime_scenario(p1, p2, scenario) for scenario in RUNTIME_SCENARIOS]
    return p1, p2, results


def _format_pairs(rows: Iterable[tuple[str, str]]) -> list[str]:
    return [f"    {left:<18} {right}" for left, right in rows]


def generate_runtime_report(
    p1: Phase1Result,
    p2: Phase2Result,
    results: list[RuntimeAdaptiveResult],
) -> str:
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append("  testCase9 Runtime Adaptive Monitoring Summary")
    lines.append("=" * 78)
    lines.append("")
    lines.append(f"  Phase 1 baseline risk: {p1.total_risk()}")
    lines.append(f"  Phase 2 deployed firewalls: {', '.join(sorted(set(p2.placed_fws))) or 'none'}")
    lines.append(f"  Phase 2 deployed policy servers: {', '.join(sorted(set(p2.placed_ps))) or 'none'}")
    lines.append("")
    lines.append("  This runtime extension adds monitor placement, anomaly scoring,")
    lines.append("  dynamic trust update, and automatic mode transition on top of the")
    lines.append("  existing LUT-based Phase 1 and policy-synthesis Phase 2 pipeline.")
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
            lines.extend(_format_pairs(result.mode_triggers))
        if result.response_actions:
            lines.append("  Response actions:")
            lines.extend(_format_pairs(result.response_actions))
        if result.adaptive_denies:
            lines.append(f"  Adaptive denies: {len(result.adaptive_denies)}")
            for master, target, mode in result.adaptive_denies[:10]:
                lines.append(f"    {mode:<18} deny {master} -> {target}")
        if result.missed_signals:
            lines.append("  Missed signals:")
            lines.extend(_format_pairs(result.missed_signals))
        hot_nodes = sorted(result.anomaly_scores.items(), key=lambda item: (-item[1], item[0]))[:5]
        if hot_nodes:
            lines.append("  Highest anomaly scores:")
            for node, score in hot_nodes:
                lines.append(
                    f"    {node:<18} score={score:<4} trust={result.trust_states.get(node, '?'):<12} "
                    f"obs={result.observability.get(node, 0)}"
                )
        lines.append("")

    return "\n".join(lines)
