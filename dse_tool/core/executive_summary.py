"""
executive_summary.py
====================
Synthesises all Phase 1 / 2 / 3 data across all three strategy variants
into a concise executive summary that highlights:

  1. Key findings (what matters)
  2. The "long pole" — the single biggest bottleneck for improving
     security and/or resilience
  3. Architecture verdict — can this topology meet security goals with
     parameter tweaks, or does it need structural redesign?

The summary is topology-agnostic: no hardcoded component names.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional

from .solution_parser import SolutionResult, ScenarioResult, AMP_DENOM


# ───────────────────────────────────────────────────────────────────────
# Data structures for the summary
# ───────────────────────────────────────────────────────────────────────

@dataclass
class BottleneckFinding:
    """A single identified bottleneck / long-pole item."""
    category: str          # TOPOLOGY | TRUST | FEATURE | POLICY | CAPABILITY
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    component: str         # component name or "system"
    description: str       # human-readable explanation
    recommendation: str    # actionable fix
    impact_estimate: str   # what improves if fixed


@dataclass
class ExecutiveSummary:
    """Complete executive summary output."""
    # One-paragraph verdict
    verdict: str = ""
    architecture_adequate: bool = True
    architecture_reasons: List[str] = field(default_factory=list)

    # Headline metrics (best strategy)
    best_strategy: str = ""
    best_risk: int = 0
    best_resilience: float = 0.0
    best_luts: int = 0
    best_lut_pct: float = 0.0

    # Key findings (ordered by importance)
    findings: List[str] = field(default_factory=list)

    # Bottleneck analysis
    long_pole: Optional[BottleneckFinding] = None
    bottlenecks: List[BottleneckFinding] = field(default_factory=list)

    # Cross-strategy invariants (issues present in ALL strategies)
    invariant_risks: List[str] = field(default_factory=list)

    # Capability assessment
    capability_summary: str = ""
    capabilities_at_risk: List[str] = field(default_factory=list)

    # Architecture change recommendations
    arch_recommendations: List[str] = field(default_factory=list)


# ───────────────────────────────────────────────────────────────────────
# Analyser
# ───────────────────────────────────────────────────────────────────────

class ExecutiveSummaryAnalyser:
    """
    Analyses a complete set of DSE results and produces an ExecutiveSummary.

    Parameters
    ----------
    solutions : list[SolutionResult]
        The three strategy solutions from the orchestrator.
    max_luts : int
        FPGA LUT budget for percentage calculations.
    max_power : int
        Power budget in mW.
    """

    def __init__(
        self,
        solutions: List[SolutionResult],
        max_luts: int = 53200,
        max_power: int = 15000,
    ) -> None:
        self.solutions = solutions
        self._max_luts  = max_luts  if max_luts  > 0 else 53200
        self._max_power = max_power if max_power > 0 else 15000

    def analyse(self) -> ExecutiveSummary:
        """Run the full analysis and return an ExecutiveSummary."""
        s = ExecutiveSummary()

        sat_sols = [sol for sol in self.solutions
                    if sol.phase1 and sol.phase1.satisfiable]
        if not sat_sols:
            s.verdict = (
                "No feasible solution found for any strategy. "
                "The system constraints (latency budgets, resource caps) "
                "are likely over-constrained for the current topology."
            )
            s.architecture_adequate = False
            s.architecture_reasons.append(
                "Phase 1 UNSAT across all strategies — fundamental constraint conflict"
            )
            return s

        # ── Best strategy identification ──────────────────────────────
        best = max(sat_sols, key=lambda sol: sol.security_score)
        s.best_strategy = best.label or best.strategy
        s.best_risk = best.phase1.total_risk() if best.phase1 else 0
        s.best_resilience = best.resilience_score
        s.best_luts = best.phase1.total_luts if best.phase1 else 0
        s.best_lut_pct = (s.best_luts / self._max_luts * 100
                          if self._max_luts > 0 else 0)

        # ── Cross-strategy analysis ───────────────────────────────────
        self._analyse_cross_strategy(s, sat_sols)
        self._analyse_risk_hotspots(s, sat_sols)
        self._analyse_policy(s, sat_sols)
        self._analyse_resilience(s, sat_sols)
        self._analyse_capabilities(s, sat_sols)
        self._analyse_trust_gaps(s, sat_sols)
        self._identify_long_pole(s, sat_sols)
        self._generate_verdict(s, sat_sols)

        return s

    # ──────────────────────────────────────────────────────────────────
    # Analysis sub-routines
    # ──────────────────────────────────────────────────────────────────

    def _analyse_cross_strategy(
        self, s: ExecutiveSummary, sols: List[SolutionResult],
    ) -> None:
        """Find issues that persist across ALL strategies (structural)."""
        # Components that are high-risk in every strategy
        risk_sets = []
        for sol in sols:
            if sol.phase1:
                per_asset = sol.phase1.max_risk_per_asset()
                # Find assets with risk > 3 (non-trivial)
                high = {a for a, r in per_asset.items() if r > 3}
                risk_sets.append(high)

        if risk_sets:
            common_high = risk_sets[0]
            for rs in risk_sets[1:]:
                common_high &= rs
            if common_high:
                s.invariant_risks.append(
                    f"Assets with elevated risk across ALL strategies: "
                    f"{', '.join(sorted(common_high))}"
                )
                s.findings.append(
                    f"{len(common_high)} asset(s) remain high-risk regardless of "
                    f"strategy — these are structural bottlenecks that security "
                    f"feature selection alone cannot resolve"
                )

        # Check if risk spread is narrow (all strategies similar)
        risks = [sol.phase1.total_risk() for sol in sols if sol.phase1]
        if risks and max(risks) > 0:
            spread = (max(risks) - min(risks)) / max(risks) * 100
            if spread < 15:
                s.invariant_risks.append(
                    f"Risk spread across strategies is only {spread:.0f}% — "
                    f"the topology constrains the solution space"
                )

    def _analyse_risk_hotspots(
        self, s: ExecutiveSummary, sols: List[SolutionResult],
    ) -> None:
        """Identify the highest-risk components and why."""
        best = max(sols, key=lambda sol: sol.security_score)
        if not best.phase1:
            return

        per_asset = best.phase1.max_risk_per_asset()
        if not per_asset:
            return

        # Sort by risk descending
        sorted_assets = sorted(per_asset.items(), key=lambda x: -x[1])
        top3 = sorted_assets[:3]

        # Check for latency-constrained components forced to weak features
        latency_constrained = []
        for comp, feat in best.phase1.security.items():
            if feat in ("mac",):
                # Check if other strategies assign stronger features
                stronger_elsewhere = False
                for other in sols:
                    if other is not best and other.phase1:
                        of = other.phase1.security.get(comp, "")
                        if of in ("zero_trust", "dynamic_mac"):
                            stronger_elsewhere = True
                            break
                if not stronger_elsewhere:
                    # ALL strategies use mac → this is latency-forced
                    latency_constrained.append(comp)

        if latency_constrained:
            s.bottlenecks.append(BottleneckFinding(
                category="FEATURE",
                severity="HIGH",
                component=", ".join(latency_constrained),
                description=(
                    f"{len(latency_constrained)} component(s) are forced to minimal "
                    f"MAC protection across ALL strategies due to tight latency budgets"
                ),
                recommendation=(
                    "Relax latency budgets or redesign the data path to allow "
                    "stronger security features (dynamic_mac or zero_trust)"
                ),
                impact_estimate="Could reduce per-component risk by 2-4 points each",
            ))

        # Components using mac in best strategy
        mac_comps = [c for c, f in best.phase1.security.items() if f == "mac"]
        no_log = [c for c, f in best.phase1.logging.items() if f == "no_logging"]

        if mac_comps:
            s.findings.append(
                f"{len(mac_comps)} component(s) use minimal MAC protection: "
                f"{', '.join(sorted(mac_comps))}"
            )
        if no_log:
            s.findings.append(
                f"{len(no_log)} component(s) have no logging — "
                f"incidents on these components are undetectable"
            )

    def _analyse_policy(
        self, s: ExecutiveSummary, sols: List[SolutionResult],
    ) -> None:
        """Analyse ZTA policy effectiveness across strategies."""
        p2_unsat = [sol for sol in sols if sol.phase2 and not sol.phase2.satisfiable]
        if p2_unsat:
            s.findings.append(
                f"Phase 2 (ZTA policy) is UNSAT for {len(p2_unsat)} strategy(ies) — "
                f"the topology cannot support a valid zero-trust architecture "
                f"under those configurations"
            )
            if len(p2_unsat) == len(sols):
                s.architecture_adequate = False
                s.architecture_reasons.append(
                    "ZTA policy synthesis fails for ALL strategies — topology "
                    "lacks firewall coverage or governance paths"
                )
                s.bottlenecks.append(BottleneckFinding(
                    category="TOPOLOGY",
                    severity="CRITICAL",
                    component="system",
                    description="No valid ZTA policy exists for this topology",
                    recommendation=(
                        "Add firewall candidates on critical bus paths and "
                        "ensure policy server governance covers all PEPs"
                    ),
                    impact_estimate="Unblocks Phase 2 and Phase 3 entirely",
                ))
                return

        # Excess privileges (consistent across strategies = topology issue)
        excess_counts = []
        for sol in sols:
            if sol.phase2 and sol.phase2.satisfiable:
                excess_counts.append(len(sol.phase2.excess_privileges))
        if excess_counts and min(excess_counts) > 5:
            s.findings.append(
                f"Minimum {min(excess_counts)} excess privilege(s) across all "
                f"strategies — over-connected topology grants more access than needed"
            )
            s.bottlenecks.append(BottleneckFinding(
                category="TOPOLOGY",
                severity="MEDIUM",
                component="bus interconnect",
                description=(
                    f"Even the tightest strategy has {min(excess_counts)} excess "
                    f"privileges — buses expose more IPs than any master needs"
                ),
                recommendation=(
                    "Segment the bus architecture: split shared buses into "
                    "isolated segments with dedicated firewall PEPs"
                ),
                impact_estimate="Reduces attack surface and excess privileges",
            ))

        # FW deployment comparison
        fw_counts = []
        for sol in sols:
            if sol.phase2 and sol.phase2.satisfiable:
                fw_counts.append(len(set(sol.phase2.placed_fws)))
        if fw_counts:
            if max(fw_counts) == 0:
                s.findings.append(
                    "No firewalls deployed in any strategy — all traffic is unmediated"
                )

    def _analyse_resilience(
        self, s: ExecutiveSummary, sols: List[SolutionResult],
    ) -> None:
        """Analyse resilience patterns across strategies."""
        for sol in sols:
            if not sol.scenarios:
                continue
            sat_sc = [sc for sc in sol.scenarios if sc.satisfiable]
            if not sat_sc:
                continue

            # Blast radius analysis
            max_br = max(sc.max_blast_radius for sc in sat_sc)
            total_nodes = max(len(sat_sc[0].blast_radii), 1) if sat_sc else 1

            if max_br >= total_nodes * 0.8:
                # Find if FWs make a difference
                has_eff = any(sc.effective_blast_radii for sc in sat_sc)
                if has_eff:
                    max_eff = max(
                        (max(sc.effective_blast_radii.values(), default=0)
                         for sc in sat_sc), default=0
                    )
                    reduction = max_br - max_eff
                    if reduction > 0:
                        s.findings.append(
                            f"Firewalls reduce worst-case blast radius from "
                            f"{max_br} to {max_eff} nodes "
                            f"({reduction} node reduction) in {sol.label}"
                        )
                    else:
                        s.findings.append(
                            f"Worst-case blast radius is {max_br}/{total_nodes} "
                            f"nodes — firewalls provide no containment benefit. "
                            f"The topology is too flat."
                        )
                        s.bottlenecks.append(BottleneckFinding(
                            category="TOPOLOGY",
                            severity="HIGH",
                            component="bus fabric",
                            description=(
                                f"Blast radius reaches {max_br}/{total_nodes} "
                                f"nodes even with firewalls deployed — the bus "
                                f"topology provides insufficient isolation"
                            ),
                            recommendation=(
                                "Introduce hierarchical bus segmentation or "
                                "add bridge firewalls between bus segments to "
                                "create containment zones"
                            ),
                            impact_estimate=(
                                "Could reduce blast radius by 40-60% with proper "
                                "segmentation"
                            ),
                        ))
                break  # one strategy suffices for blast analysis

        # Check control plane vulnerability
        for sol in sols:
            if not sol.scenarios:
                continue
            sat_sc = [sc for sc in sol.scenarios if sc.satisfiable]
            cp_comp_count = sum(1 for sc in sat_sc if sc.cp_compromised)
            if cp_comp_count > 0:
                s.findings.append(
                    f"{cp_comp_count} scenario(s) compromise the control plane "
                    f"in {sol.label} — all policy enforcement is bypassed"
                )
            break

    def _analyse_capabilities(
        self, s: ExecutiveSummary, sols: List[SolutionResult],
    ) -> None:
        """Analyse functional resilience / mission capability impact."""
        any_caps = False
        ess_lost_all: Dict[str, int] = {}  # cap_name → count of strategies where lost
        nonfunc_counts: List[int] = []

        for sol in sols:
            if not sol.scenarios:
                continue
            sat_sc = [sc for sc in sol.scenarios if sc.satisfiable]
            if not sat_sc:
                continue

            has_caps = any(
                sc.capabilities_ok or sc.capabilities_degraded or sc.capabilities_lost
                for sc in sat_sc
            )
            if not has_caps:
                continue
            any_caps = True

            nf = sum(1 for sc in sat_sc if sc.system_non_functional)
            nonfunc_counts.append(nf)

            for sc in sat_sc:
                for cap in sc.essential_caps_lost:
                    ess_lost_all[cap] = ess_lost_all.get(cap, 0) + 1

        if not any_caps:
            s.capability_summary = "No mission capabilities defined — functional resilience not assessed."
            return

        # Essential capabilities at risk across strategies
        for cap, count in sorted(ess_lost_all.items(), key=lambda x: -x[1]):
            s.capabilities_at_risk.append(cap)
            s.bottlenecks.append(BottleneckFinding(
                category="CAPABILITY",
                severity="CRITICAL",
                component=cap,
                description=(
                    f"Essential capability '{cap}' is lost in {count} "
                    f"scenario(s) across strategies"
                ),
                recommendation=(
                    f"Add redundancy for '{cap}' dependencies: "
                    f"alternative access paths, redundant service members, "
                    f"or fallback components"
                ),
                impact_estimate=(
                    f"Prevents system non-functional state in those scenarios"
                ),
            ))

        if nonfunc_counts:
            worst_nf = max(nonfunc_counts)
            best_nf = min(nonfunc_counts)
            total_sc = max(
                len([sc for sc in sol.scenarios if sc.satisfiable])
                for sol in sols if sol.scenarios
            )
            if worst_nf > 0:
                s.capability_summary = (
                    f"System goes non-functional in {best_nf}-{worst_nf} of "
                    f"{total_sc} scenarios. Essential capabilities at risk: "
                    f"{', '.join(sorted(ess_lost_all.keys())) or 'none'}."
                )
            else:
                s.capability_summary = (
                    f"System remains functional across all {total_sc} scenarios. "
                    f"Mission capability coverage is adequate."
                )
        else:
            s.capability_summary = "Capability data insufficient for assessment."

    def _analyse_trust_gaps(
        self, s: ExecutiveSummary, sols: List[SolutionResult],
    ) -> None:
        """Identify missing trust anchors that would improve security."""
        for sol in sols:
            if not sol.phase2 or not sol.phase2.satisfiable:
                continue
            p2 = sol.phase2
            total_gaps = (len(p2.trust_gap_rot) + len(p2.trust_gap_sboot)
                          + len(p2.trust_gap_attest))
            if total_gaps > 3:
                # Find the most impactful gaps
                gap_comps = set(p2.trust_gap_rot + p2.trust_gap_sboot + p2.trust_gap_attest)
                s.bottlenecks.append(BottleneckFinding(
                    category="TRUST",
                    severity="HIGH" if total_gaps > 5 else "MEDIUM",
                    component=", ".join(sorted(gap_comps)[:5]),
                    description=(
                        f"{total_gaps} trust anchor gaps detected — components "
                        f"lack RoT, secure boot, or attestation"
                    ),
                    recommendation=(
                        "Prioritize adding hardware RoT and secure boot to "
                        "high-domain receivers; add attestation to all masters"
                    ),
                    impact_estimate=(
                        "Enables attested access in elevated security modes; "
                        "reduces unattested privileged access warnings"
                    ),
                ))
            break  # gaps are topology-level, same across strategies

    def _identify_long_pole(
        self, s: ExecutiveSummary, sols: List[SolutionResult],
    ) -> None:
        """Select the single most impactful bottleneck as the 'long pole'."""
        if not s.bottlenecks:
            return

        # Priority: CRITICAL > HIGH > MEDIUM > LOW
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        # Within same severity: TOPOLOGY > CAPABILITY > TRUST > POLICY > FEATURE
        category_order = {
            "TOPOLOGY": 0, "CAPABILITY": 1, "TRUST": 2,
            "POLICY": 3, "FEATURE": 4,
        }

        s.bottlenecks.sort(key=lambda b: (
            severity_order.get(b.severity, 9),
            category_order.get(b.category, 9),
        ))
        s.long_pole = s.bottlenecks[0]

    def _generate_verdict(
        self, s: ExecutiveSummary, sols: List[SolutionResult],
    ) -> None:
        """Generate the overall verdict and architecture assessment."""
        # Architecture adequacy checks
        arch_issues = 0

        # Check 1: Phase 2 feasibility
        p2_sat = sum(1 for sol in sols if sol.phase2 and sol.phase2.satisfiable)
        if p2_sat == 0:
            s.architecture_adequate = False
            s.architecture_reasons.append(
                "ZTA policy is infeasible for all strategies"
            )
            arch_issues += 3

        # Check 2: Essential capability loss
        if s.capabilities_at_risk:
            arch_issues += 2
            s.architecture_reasons.append(
                f"Essential capabilities ({', '.join(s.capabilities_at_risk)}) "
                f"are lost under realistic scenarios"
            )

        # Check 3: Topology-category bottlenecks
        topo_bottlenecks = [b for b in s.bottlenecks if b.category == "TOPOLOGY"]
        critical_topo = [b for b in topo_bottlenecks if b.severity == "CRITICAL"]
        if critical_topo:
            s.architecture_adequate = False
            arch_issues += 3
        elif len(topo_bottlenecks) >= 2:
            arch_issues += 1

        # Check 4: Invariant high risk across strategies
        if len(s.invariant_risks) >= 2:
            arch_issues += 1

        # Check 5: Blast radius vs firewall benefit
        for b in s.bottlenecks:
            if "no containment benefit" in b.description.lower():
                arch_issues += 2
                s.architecture_reasons.append(
                    "Bus topology is too flat for effective firewall isolation"
                )

        # Generate recommendations
        if arch_issues >= 4:
            s.architecture_adequate = False
            s.arch_recommendations.append(
                "Restructure bus topology: introduce hierarchical segmentation "
                "with dedicated security domains per bus segment"
            )
        if s.capabilities_at_risk:
            s.arch_recommendations.append(
                f"Add redundancy for essential capability dependencies: "
                f"{', '.join(s.capabilities_at_risk)}"
            )
        if any(b.category == "TRUST" for b in s.bottlenecks):
            s.arch_recommendations.append(
                "Deploy hardware trust anchors (RoT, secure boot, attestation) "
                "to close the trust gap before production"
            )
        for b in s.bottlenecks:
            if b.category == "FEATURE" and b.severity in ("CRITICAL", "HIGH"):
                s.arch_recommendations.append(
                    f"Redesign data paths for latency-constrained components "
                    f"({b.component}) to allow stronger security features"
                )
                break

        if not s.arch_recommendations:
            s.arch_recommendations.append(
                "Current architecture is adequate — focus on parameter tuning "
                "and trust anchor deployment"
            )

        # Build verdict paragraph
        if s.architecture_adequate:
            s.verdict = (
                f"The current architecture is ADEQUATE for the security requirements. "
                f"The recommended strategy ({s.best_strategy}) achieves a total "
                f"risk of {s.best_risk} using {s.best_luts:,} LUTs "
                f"({s.best_lut_pct:.1f}% of budget). "
            )
            if s.long_pole:
                s.verdict += (
                    f"The primary bottleneck is {s.long_pole.category.lower()}-level: "
                    f"{s.long_pole.description}. "
                    f"Addressing this would have the highest impact on "
                    f"{'resilience' if s.long_pole.category in ('TOPOLOGY', 'CAPABILITY') else 'security'}."
                )
            if s.capability_summary:
                s.verdict += f" {s.capability_summary}"
        else:
            s.verdict = (
                f"The current architecture has FUNDAMENTAL LIMITATIONS that "
                f"cannot be resolved by parameter tuning alone. "
            )
            for reason in s.architecture_reasons[:3]:
                s.verdict += f"{reason}. "
            s.verdict += (
                f"A structural redesign is recommended before committing to "
                f"production silicon."
            )


# ───────────────────────────────────────────────────────────────────────
# Text formatter
# ───────────────────────────────────────────────────────────────────────

def format_executive_summary(summary: ExecutiveSummary) -> str:
    """Format an ExecutiveSummary into a human-readable text report."""
    SEP  = "=" * 72
    SEP2 = "-" * 72
    lines: List[str] = []

    lines.append(SEP)
    lines.append("  EXECUTIVE SECURITY & RESILIENCE SUMMARY")
    lines.append(SEP)
    lines.append("")

    # ── Verdict ────────────────────────────────────────────────────
    lines.append("VERDICT")
    lines.append(SEP2)
    # Wrap verdict text
    words = summary.verdict.split()
    current_line = "  "
    for word in words:
        if len(current_line) + len(word) + 1 > 70:
            lines.append(current_line)
            current_line = "  " + word
        else:
            current_line += " " + word if current_line.strip() else "  " + word
    if current_line.strip():
        lines.append(current_line)
    lines.append("")

    arch_tag = "ADEQUATE" if summary.architecture_adequate else "REDESIGN RECOMMENDED"
    lines.append(f"  Architecture Assessment: >>> {arch_tag} <<<")
    lines.append("")

    # ── Headline Metrics ──────────────────────────────────────────
    lines.append("HEADLINE METRICS (Best Strategy)")
    lines.append(SEP2)
    lines.append(f"  Strategy   : {summary.best_strategy}")
    lines.append(f"  Total Risk : {summary.best_risk}")
    lines.append(f"  Resilience : {summary.best_resilience:.1f}/100")
    lines.append(f"  LUTs       : {summary.best_luts:,} ({summary.best_lut_pct:.1f}% of budget)")
    lines.append("")

    # ── Key Findings ──────────────────────────────────────────────
    if summary.findings:
        lines.append("KEY FINDINGS")
        lines.append(SEP2)
        for i, finding in enumerate(summary.findings, 1):
            lines.append(f"  {i}. {finding}")
        lines.append("")

    # ── Cross-Strategy Invariants ─────────────────────────────────
    if summary.invariant_risks:
        lines.append("STRUCTURAL ISSUES (persist across ALL strategies)")
        lines.append(SEP2)
        for inv in summary.invariant_risks:
            lines.append(f"  * {inv}")
        lines.append("")

    # ── Long Pole ─────────────────────────────────────────────────
    if summary.long_pole:
        lp = summary.long_pole
        lines.append("LONG POLE — Primary Bottleneck")
        lines.append(SEP2)
        lines.append(f"  Category    : {lp.category}")
        lines.append(f"  Severity    : {lp.severity}")
        lines.append(f"  Component(s): {lp.component}")
        lines.append(f"  Issue       : {lp.description}")
        lines.append(f"  Fix         : {lp.recommendation}")
        lines.append(f"  Impact      : {lp.impact_estimate}")
        lines.append("")

    # ── All Bottlenecks ─────────────────────────────────────���─────
    if len(summary.bottlenecks) > 1:
        lines.append("ALL BOTTLENECKS (ranked by severity)")
        lines.append(SEP2)
        for i, b in enumerate(summary.bottlenecks, 1):
            marker = " <<<< LONG POLE" if b is summary.long_pole else ""
            lines.append(f"  {i}. [{b.severity}] {b.category}: {b.description}{marker}")
            lines.append(f"     Fix: {b.recommendation}")
        lines.append("")

    # ── Capability Assessment ─────────────────────────────────────
    if summary.capability_summary:
        lines.append("MISSION CAPABILITY ASSESSMENT")
        lines.append(SEP2)
        lines.append(f"  {summary.capability_summary}")
        if summary.capabilities_at_risk:
            lines.append(f"  Essential capabilities at risk: {', '.join(summary.capabilities_at_risk)}")
        lines.append("")

    # ── Architecture Recommendations ──────────────────────────────
    lines.append("RECOMMENDATIONS")
    lines.append(SEP2)
    if not summary.architecture_adequate:
        lines.append("  >>> ARCHITECTURE REDESIGN REQUIRED <<<")
        lines.append("")
        for reason in summary.architecture_reasons:
            lines.append(f"  Reason: {reason}")
        lines.append("")
    for i, rec in enumerate(summary.arch_recommendations, 1):
        lines.append(f"  {i}. {rec}")
    lines.append("")
    lines.append(SEP)

    return "\n".join(lines)
