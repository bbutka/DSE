"""Utilities for reporting baseline-vs-revised architecture comparisons."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .architecture_delta import ArchitectureDelta, compare_network_models
from .asp_generator import NetworkModel
from .solution_parser import SolutionResult


@dataclass
class ArchitectureSolutionLedger:
    """Separate ledgers for one analyzed architecture."""

    strategy: str = "unknown"
    phase1_security_overhead: Dict[str, int] = field(default_factory=dict)
    phase2_zta_cost: int = 0
    security_score: float = 0.0
    resource_score: float = 0.0
    power_score: float = 0.0
    resilience_score: float = 0.0
    baseline_total_risk: Optional[float] = None
    worst_scenario_name: str = ""
    worst_scenario_risk: Optional[float] = None


@dataclass
class ArchitectureComparisonSummary:
    """Combined architecture and solution comparison summary."""

    baseline_name: str
    candidate_name: str
    delta: ArchitectureDelta
    baseline_ledger: ArchitectureSolutionLedger = field(default_factory=ArchitectureSolutionLedger)
    candidate_ledger: ArchitectureSolutionLedger = field(default_factory=ArchitectureSolutionLedger)


def _solution_ledger(solution: Optional[SolutionResult]) -> ArchitectureSolutionLedger:
    if not solution:
        return ArchitectureSolutionLedger()

    phase1 = solution.phase1
    phase2 = solution.phase2
    baseline = next((s for s in solution.scenarios if s.name == "baseline" and s.satisfiable), None)
    worst = solution.worst_scenario()

    return ArchitectureSolutionLedger(
        strategy=solution.strategy,
        phase1_security_overhead=(
            phase1.security_overhead_summary()
            if phase1 and phase1.satisfiable
            else {}
        ),
        phase2_zta_cost=(
            phase2.zta_overhead_cost()
            if phase2 and phase2.satisfiable
            else 0
        ),
        security_score=solution.security_score,
        resource_score=solution.resource_score,
        power_score=solution.power_score,
        resilience_score=solution.resilience_score,
        baseline_total_risk=(baseline.total_risk if baseline else None),
        worst_scenario_name=(worst.name if worst else ""),
        worst_scenario_risk=(worst.total_risk if worst else None),
    )


def build_architecture_comparison_summary(
    baseline_model: NetworkModel,
    candidate_model: NetworkModel,
    baseline_solution: Optional[SolutionResult] = None,
    candidate_solution: Optional[SolutionResult] = None,
) -> ArchitectureComparisonSummary:
    """Build a full baseline-vs-candidate comparison summary."""

    return ArchitectureComparisonSummary(
        baseline_name=baseline_model.name,
        candidate_name=candidate_model.name,
        delta=compare_network_models(baseline_model, candidate_model),
        baseline_ledger=_solution_ledger(baseline_solution),
        candidate_ledger=_solution_ledger(candidate_solution),
    )


def format_architecture_comparison(summary: ArchitectureComparisonSummary) -> str:
    """Render a compact text report for architecture comparisons."""

    lines: List[str] = []
    lines.append("ARCHITECTURE COMPARISON")
    lines.append(f"Baseline:  {summary.baseline_name}")
    lines.append(f"Candidate: {summary.candidate_name}")
    lines.append("")

    delta = summary.delta
    lines.append("Structural Delta")
    if not delta.has_changes():
        lines.append("  No structural changes.")
    else:
        if delta.added_components:
            lines.append(f"  Added components: {', '.join(delta.added_components)}")
        if delta.removed_components:
            lines.append(f"  Removed components: {', '.join(delta.removed_components)}")
        if delta.added_buses:
            lines.append(f"  Added buses/ports: {', '.join(delta.added_buses)}")
        if delta.removed_buses:
            lines.append(f"  Removed buses/ports: {', '.join(delta.removed_buses)}")
        if delta.added_redundancy_groups:
            lines.append(f"  Added redundancy groups: {', '.join(delta.added_redundancy_groups)}")
        if delta.removed_redundancy_groups:
            lines.append(f"  Removed redundancy groups: {', '.join(delta.removed_redundancy_groups)}")
        if delta.added_services:
            lines.append(f"  Added services: {', '.join(delta.added_services)}")
        if delta.removed_services:
            lines.append(f"  Removed services: {', '.join(delta.removed_services)}")
        if delta.added_capabilities:
            lines.append(f"  Added capabilities: {', '.join(delta.added_capabilities)}")
        if delta.removed_capabilities:
            lines.append(f"  Removed capabilities: {', '.join(delta.removed_capabilities)}")

    def ledger_block(title: str, ledger: ArchitectureSolutionLedger) -> None:
        lines.append("")
        lines.append(title)
        lines.append(f"  Strategy: {ledger.strategy}")
        if ledger.phase1_security_overhead:
            ov = ledger.phase1_security_overhead
            lines.append(
                "  Phase 1 security overhead: "
                f"LUTs={ov.get('luts', 0):,}, "
                f"FFs={ov.get('ffs', 0):,}, "
                f"Power={ov.get('power_mw', 0):,} mW"
            )
        else:
            lines.append("  Phase 1 security overhead: N/A")
        lines.append(f"  Phase 2 ZTA cost: {ledger.phase2_zta_cost:,}")
        lines.append(
            "  Scores: "
            f"security={ledger.security_score:.1f}, "
            f"resources={ledger.resource_score:.1f}, "
            f"power={ledger.power_score:.1f}, "
            f"resilience={ledger.resilience_score:.1f}"
        )
        if ledger.baseline_total_risk is not None:
            lines.append(f"  Baseline Phase 3 total risk: {ledger.baseline_total_risk:.1f}")
        if ledger.worst_scenario_name:
            risk = f"{ledger.worst_scenario_risk:.1f}" if ledger.worst_scenario_risk is not None else "N/A"
            lines.append(f"  Worst scenario: {ledger.worst_scenario_name} (risk={risk})")

    ledger_block("Baseline Ledgers", summary.baseline_ledger)
    ledger_block("Candidate Ledgers", summary.candidate_ledger)

    return "\n".join(lines)
