"""
comparison.py
=============
Auto-generates human-readable pros and cons for each SolutionResult by
comparing its metrics against the other solutions in the set.
"""

from __future__ import annotations

from typing import List, Tuple, Dict

from .solution_parser import SolutionResult
from .solution_ranker import SolutionRanker, MAX_LUTS, MAX_POWER_MW


class ComparisonEngine:
    """
    Generates pros/cons lists for each solution variant.

    Usage
    -----
    engine = ComparisonEngine(solutions)
    for i, (pros, cons) in enumerate(engine.generate_all()):
        ...
    """

    def __init__(self, solutions: List[SolutionResult]) -> None:
        self.solutions = solutions
        self._ranker   = SolutionRanker(solutions)
        self._ranks    = self._ranker.relative_ranks()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_all(self) -> List[Tuple[List[str], List[str]]]:
        """
        Return a list of (pros, cons) tuples — one per solution.
        """
        return [self._generate_for(i) for i in range(len(self.solutions))]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _rank(self, idx: int, metric: str) -> int:
        return self._ranks.get((idx, metric), 99)

    def _generate_for(self, idx: int) -> Tuple[List[str], List[str]]:
        sol  = self.solutions[idx]
        pros: List[str] = []
        cons: List[str] = []
        p1   = sol.phase1
        p2   = sol.phase2

        # ── Security ───────────────────────────────────────────────────────
        if p1 and p1.satisfiable:
            risk = p1.total_risk()
            if self._rank(idx, "security_score") == 0:
                pros.append(
                    f"Best security posture — lowest overall risk score ({risk})"
                )
            elif self._rank(idx, "security_score") == len(self.solutions) - 1:
                cons.append(
                    f"Weakest security posture — highest overall risk score ({risk})"
                )

            # Feature quality commentary
            zt_count = sum(1 for f in p1.security.values() if f == "zero_trust")
            mac_count = sum(1 for f in p1.security.values() if f == "mac")
            if zt_count == len(p1.security) and p1.security:
                pros.append(
                    "Maximum protection — zero_trust assigned to all components"
                )
            if mac_count > 0:
                cons.append(
                    f"Reduced security — {mac_count} component(s) use minimal MAC "
                    f"feature (vulnerability=30)"
                )

        # ── Resource usage ─────────────────────────────────────────────────
        if p1 and p1.satisfiable:
            lut_pct = (p1.total_luts / MAX_LUTS * 100) if MAX_LUTS > 0 else 0
            if self._rank(idx, "resource_score") == 0:
                pros.append(
                    f"Lowest FPGA resource footprint — "
                    f"{p1.total_luts:,} LUTs ({lut_pct:.1f}% of {MAX_LUTS:,} available)"
                )
            elif self._rank(idx, "resource_score") == len(self.solutions) - 1:
                cons.append(
                    f"Highest FPGA resource footprint — "
                    f"{p1.total_luts:,} LUTs ({lut_pct:.1f}% of {MAX_LUTS:,} available)"
                )

        # ── Power ──────────────────────────────────────────────────────────
        if p1 and p1.satisfiable:
            pwr_pct = (p1.total_power / MAX_POWER_MW * 100) if MAX_POWER_MW > 0 else 0
            if self._rank(idx, "power_score") == 0:
                pros.append(
                    f"Most power-efficient — "
                    f"{p1.total_power:,} mW ({pwr_pct:.1f}% of {MAX_POWER_MW:,} mW budget)"
                )
            elif self._rank(idx, "power_score") == len(self.solutions) - 1:
                cons.append(
                    f"Highest power draw — "
                    f"{p1.total_power:,} mW ({pwr_pct:.1f}% of {MAX_POWER_MW:,} mW budget)"
                )

        # ── Latency ────────────────────────────────────────────────────────
        # Latency is enforced as a hard constraint; violations indicate
        # a component forced to use a weaker feature.
        if p1 and p1.satisfiable:
            # Check for c8 latency bottleneck (tight budget forces weaker feature)
            c8_feat = p1.security.get("c8", "")
            if c8_feat and c8_feat != "zero_trust":
                cons.append(
                    f"c8 latency budget forces weaker '{c8_feat}' security feature "
                    f"(zero_trust latency=7+22=29 cycles exceeds c8 budget)"
                )
        else:
            cons.append("Phase 1 solver did not find a feasible solution")

        # ── Policy ─────────────────────────────────────────────────────────
        if p2 and p2.satisfiable:
            n_excess = len(p2.excess_privileges)
            if self._rank(idx, "policy_score") == 0:
                pros.append(
                    f"Most precise policy — fewest over-privileged grants "
                    f"({n_excess} excess privilege(s) detected)"
                )
            elif self._rank(idx, "policy_score") == len(self.solutions) - 1:
                cons.append(
                    f"Least precise policy — most over-privileged grants "
                    f"({n_excess} excess privilege(s) detected)"
                )
            n_fw = len(set(p2.placed_fws))
            if n_fw == 2:
                pros.append("Full firewall coverage — all PEP locations deployed")
            elif n_fw == 0:
                cons.append("No firewalls deployed — all traffic unmediated by PEPs")

            # Trust gap warnings
            total_gaps = (len(p2.trust_gap_rot) + len(p2.trust_gap_sboot)
                          + len(p2.trust_gap_attest))
            if total_gaps > 0:
                cons.append(
                    f"{total_gaps} trust anchor gap(s) detected "
                    f"(missing RoT/secure-boot/attestation)"
                )
        elif p2 and not p2.satisfiable:
            cons.append(
                "ZTA policy synthesis returned UNSAT — "
                "check for over-constrained access rules"
            )

        # ── Resilience ─────────────────────────────────────────────────────
        if sol.scenarios:
            if self._rank(idx, "resilience_score") == 0:
                worst = sol.worst_scenario()
                w_risk = f"{worst.total_risk:.1f}" if worst else "N/A"
                pros.append(
                    f"Best resilience — lowest worst-case scenario risk "
                    f"(worst: {w_risk})"
                )
            elif self._rank(idx, "resilience_score") == len(self.solutions) - 1:
                worst = sol.worst_scenario()
                w_risk = f"{worst.total_risk:.1f}" if worst else "N/A"
                cons.append(
                    f"Poorest resilience — highest worst-case scenario risk "
                    f"(worst: {w_risk})"
                )
            avg_br = sol.avg_blast_radius()
            if avg_br > 5:
                cons.append(
                    f"High average blast radius ({avg_br:.1f} nodes) — "
                    f"lateral movement risk under compromise"
                )

        # Ensure at least one entry in each list for display
        if not pros:
            pros.append("No significant advantages over other solutions")
        if not cons:
            cons.append("No significant disadvantages over other solutions")

        return pros, cons


def generate_report_text(
    solutions: List[SolutionResult],
    network_name: str = "custom",
    date_str: str = "",
) -> str:
    """
    Generate the full human-readable DSE analysis report.

    Parameters
    ----------
    solutions : list[SolutionResult]
        The three strategy solutions from the orchestrator.
    network_name : str
        Name of the network being analysed.
    date_str : str
        Report date string (e.g. "2026-03-28").
    """
    import datetime
    if not date_str:
        date_str = datetime.date.today().isoformat()

    engine = ComparisonEngine(solutions)
    all_pros_cons = engine.generate_all()

    SEP  = "=" * 78
    SEP2 = "-" * 78
    lines: List[str] = []

    lines.append(SEP)
    lines.append("  DSE SECURITY ANALYSIS REPORT")
    lines.append(SEP)
    lines.append(f"  Date:    {date_str}")
    lines.append(f"  Network: {network_name}")
    lines.append(SEP)
    lines.append("")

    # ── Executive summary ───────────────────────────────────────────────────
    lines.append("EXECUTIVE SUMMARY")
    lines.append(SEP2)
    best_idx = 0
    best_sec = -1.0
    for i, sol in enumerate(solutions):
        s = sol.security_score
        if s > best_sec:
            best_sec = s
            best_idx = i

    best_sol = solutions[best_idx] if solutions else None
    lines.append(
        f"  Top Recommendation: {best_sol.label if best_sol else 'N/A'}"
    )
    if best_sol and best_sol.phase1 and best_sol.phase1.satisfiable:
        lines.append(
            f"  Key Finding: Total risk {best_sol.phase1.total_risk()}, "
            f"LUTs {best_sol.phase1.total_luts:,} "
            f"({best_sol.phase1.total_luts / 53200 * 100:.1f}% of 53,200)"
        )
    lines.append("")

    # ── Per-solution details ────────────────────────────────────────────────
    strategy_labels = ["Maximum Security", "Minimum Footprint", "Balanced Trade-off"]
    for i, sol in enumerate(solutions):
        label = strategy_labels[i] if i < len(strategy_labels) else sol.label
        lines.append(SEP)
        lines.append(f"  SOLUTION {i+1}: {label}")
        lines.append(SEP)
        p1 = sol.phase1
        p2 = sol.phase2

        if not p1 or not p1.satisfiable:
            lines.append("  [Phase 1 returned no feasible solution]")
            if sol.error:
                lines.append(f"  Error: {sol.error}")
            lines.append("")
            continue

        # Risk profile
        lines.append("")
        lines.append("  RISK PROFILE")
        lines.append(SEP2)
        lines.append(
            f"    Total risk:   {p1.total_risk()}"
        )
        per_asset = p1.max_risk_per_asset()
        for asset, risk in sorted(per_asset.items()):
            lines.append(f"    {asset:<12}  risk = {risk}")
        lines.append("")

        # Resource usage
        lines.append("  RESOURCE USAGE")
        lines.append(SEP2)
        lines.append(
            f"    LUTs:   {p1.total_luts:>6,}  ({p1.total_luts/53200*100:.1f}% of 53,200)"
        )
        lines.append(
            f"    FFs:    {p1.total_ffs:>6,}  ({p1.total_ffs/106400*100:.1f}% of 106,400)"
        )
        lines.append(
            f"    Power:  {p1.total_power:>6,} mW  ({p1.total_power/15000*100:.1f}% of 15,000 mW)"
        )
        lines.append("")

        # Feature assignments
        lines.append("  FEATURE ASSIGNMENTS")
        lines.append(SEP2)
        lines.append(f"    {'Component':<12}  {'Security':<16}  {'Logging':<22}  {'Risk'}")
        lines.append(f"    {'-'*12}  {'-'*16}  {'-'*22}  {'-'*5}")
        all_comps = sorted(set(list(p1.security.keys()) + list(p1.logging.keys())))
        for comp in all_comps:
            sec  = p1.security.get(comp, "—")
            log  = p1.logging.get(comp, "—")
            risk = per_asset.get(f"{comp}r1", "—")
            lines.append(f"    {comp:<12}  {sec:<16}  {log:<22}  {risk}")
        lines.append("")

        # Policy analysis
        if p2:
            lines.append("  POLICY ANALYSIS")
            lines.append(SEP2)
            lines.append(f"    Satisfiable: {p2.satisfiable}")
            if p2.satisfiable:
                lines.append(f"    Firewalls placed:  {sorted(set(p2.placed_fws))}")
                lines.append(f"    Policy servers:    {sorted(set(p2.placed_ps))}")
                lines.append(f"    Excess privileges: {len(p2.excess_privileges)}")
                lines.append(f"    Missing privileges:{len(p2.missing_privileges)}")
                lines.append(f"    Trust gaps (RoT):  {p2.trust_gap_rot}")
                lines.append(f"    Trust gaps (sboot):{p2.trust_gap_sboot}")
            else:
                lines.append(f"    UNSAT: {p2.unsat_reason or 'over-constrained policy'}")
            lines.append("")

        # Resilience
        if sol.scenarios:
            lines.append("  RESILIENCE ANALYSIS")
            lines.append(SEP2)
            for sc in sol.scenarios:
                if not sc.satisfiable:
                    lines.append(f"    {sc.name:<35}  UNSAT")
                    continue
                cp_tag = ""
                if sc.cp_compromised:
                    cp_tag = " [CP-COMPROMISED]"
                elif sc.cp_degraded:
                    cp_tag = " [CP-DEGRADED]"
                svc_tag = ""
                if sc.services_unavail:
                    svc_tag = f" svcs_unavail={sc.services_unavail}"
                lines.append(
                    f"    {sc.name:<35}  risk={sc.total_risk:.1f}"
                    f"  blast={sc.max_blast_radius}{cp_tag}{svc_tag}"
                )
            lines.append("")

        # Pros and cons
        pros, cons = all_pros_cons[i]
        lines.append("  PROS")
        lines.append(SEP2)
        for p in pros:
            lines.append(f"    [+] {p}")
        lines.append("")
        lines.append("  CONS")
        lines.append(SEP2)
        for c in cons:
            lines.append(f"    [-] {c}")
        lines.append("")

    # ── Comparison table ────────────────────────────────────────────────────
    lines.append(SEP)
    lines.append("  COMPARISON TABLE")
    lines.append(SEP)
    header = f"  {'Metric':<30}  {'Sol 1':>10}  {'Sol 2':>10}  {'Sol 3':>10}"
    lines.append(header)
    lines.append("  " + "-" * 60)

    def _p1v(sol: SolutionResult, attr: str, default: str = "N/A") -> str:
        if sol.phase1 and sol.phase1.satisfiable:
            return str(getattr(sol.phase1, attr, default))
        return default

    metrics_rows = [
        ("Total Risk",          [str(s.phase1.total_risk()) if s.phase1 and s.phase1.satisfiable else "N/A"
                                  for s in solutions]),
        ("LUTs Used",           [f"{s.phase1.total_luts:,}" if s.phase1 and s.phase1.satisfiable else "N/A"
                                  for s in solutions]),
        ("Power (mW)",          [f"{s.phase1.total_power:,}" if s.phase1 and s.phase1.satisfiable else "N/A"
                                  for s in solutions]),
        ("Firewalls Placed",    [str(len(set(s.phase2.placed_fws))) if s.phase2 and s.phase2.satisfiable else "N/A"
                                  for s in solutions]),
        ("Excess Privileges",   [str(len(s.phase2.excess_privileges)) if s.phase2 and s.phase2.satisfiable else "N/A"
                                  for s in solutions]),
        ("Security Score",      [f"{s.security_score:.1f}" for s in solutions]),
        ("Resource Score",      [f"{s.resource_score:.1f}" for s in solutions]),
        ("Resilience Score",    [f"{s.resilience_score:.1f}" for s in solutions]),
        ("Policy Score",        [f"{s.policy_score:.1f}" for s in solutions]),
    ]
    for label, vals in metrics_rows:
        v1 = vals[0] if len(vals) > 0 else "N/A"
        v2 = vals[1] if len(vals) > 1 else "N/A"
        v3 = vals[2] if len(vals) > 2 else "N/A"
        lines.append(f"  {label:<30}  {v1:>10}  {v2:>10}  {v3:>10}")
    lines.append("")

    # ── Recommendations ─────────────────────────────────────────────────────
    lines.append(SEP)
    lines.append("  RECOMMENDATIONS")
    lines.append(SEP)
    lines.append(
        "  1. Deploy all candidate PEP locations (pep_group, pep_standalone) "
        "to ensure full\n"
        "     Zero Trust mediation of all bus master–IP traffic."
    )
    lines.append(
        "  2. Assign hardware RoT and secure boot to all high-domain IPs (c3-c8)\n"
        "     to close trust anchor gaps identified in Phase 2."
    )
    lines.append(
        "  3. Restrict DMA to write-only on the compute group and read-only on c8;\n"
        "     remove the c7 topology link or enforce deny-by-default at pep_standalone."
    )
    lines.append(
        "  4. Consider c8 latency budget relaxation (increase from 5/15 to 10/22 cycles)\n"
        "     to allow zero_trust assignment and reduce its standalone risk."
    )
    lines.append(
        "  5. Use Solution 1 (Maximum Security) for production deployment;\n"
        "     use Solution 3 (Balanced) if LUT budget is constrained."
    )
    lines.append("")
    lines.append(SEP)

    return "\n".join(lines)
