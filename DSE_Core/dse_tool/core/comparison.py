"""
comparison.py
=============
Auto-generates human-readable pros and cons for each SolutionResult by
comparing its metrics against the other solutions in the set.

Fully topology-agnostic — resource budgets are parameterized via
``max_luts``, ``max_power``, ``max_ffs`` (no hardcoded PYNQ-Z2 constants).
"""

from __future__ import annotations

from typing import List, Tuple, Dict

from .solution_parser import SolutionResult
from .solution_ranker import SolutionRanker, MAX_LUTS, MAX_POWER_MW


def _function_deficiencies(sol: SolutionResult) -> List[dict]:
    """Return structured function-support findings available for reporting."""
    deficiencies: List[dict] = []
    for sc in sol.scenarios or []:
        if not sc.satisfiable:
            continue
        if sc.function_deficiencies:
            deficiencies.extend(sc.function_deficiencies)
        else:
            deficiencies.extend(sc.derive_function_deficiencies())
    return deficiencies


def _format_function_deficiency(deficiency: dict) -> str:
    function = deficiency.get("function", "unknown")
    issue = deficiency.get("issue", deficiency.get("finding", "unknown"))
    scenario = deficiency.get("scenario", "unknown")
    status = deficiency.get("status", "")
    score = deficiency.get("score", 0)
    domain = deficiency.get("failed_domain", "")
    values = deficiency.get("failed_domain_values", [])
    domain_text = ""
    if domain:
        value_text = ",".join(str(v) for v in values) if values else "n/a"
        domain_text = f" under {domain}={value_text}"
    return (
        f"{function}: {issue}{domain_text} "
        f"in {scenario} (status={status or 'unknown'}, score={score})"
    )


def _repair_intents(sol: SolutionResult) -> List[dict]:
    if sol.phase2 and sol.phase2.closed_loop_repair_intents:
        return list(sol.phase2.closed_loop_repair_intents)
    return []


def _format_repair_intent(intent: dict) -> str:
    function = intent.get("function", "unknown")
    repair = intent.get("repair", "unknown")
    status = intent.get("status", "pending")
    axis = intent.get("required_diversity_axis", "")
    domains = intent.get("minimum_independent_domains", "")
    axis_text = f" on {axis}" if axis else ""
    domains_text = f" ({domains} independent domains)" if domains else ""
    return f"{function}: {repair}{axis_text}{domains_text}, {status}"


def _format_candidate_values(label: str, values: list) -> List[str]:
    if not values:
        return []
    text_values = [str(value) for value in values[:6]]
    suffix = f", ... {len(values) - 6} more" if len(values) > 6 else ""
    return [f"    {label}: {', '.join(text_values)}{suffix}"]


def _format_architecture_repair_candidate(candidate: dict, idx: int) -> List[str]:
    source = candidate.get("source_label") or candidate.get("source_strategy") or "unknown"
    delta = candidate.get("delta")
    lines = [f"  Candidate {idx}: derived from {source}"]
    if candidate.get("promotion_status"):
        lines.append(f"    Promotion: {candidate['promotion_status']}")
    for intent in candidate.get("repair_intents") or []:
        lines.append(f"    Intent: {_format_repair_intent(intent)}")
    if not delta:
        return lines

    lines.extend(_format_candidate_values("Added buses", getattr(delta, "added_buses", [])))
    lines.extend(_format_candidate_values("Removed buses", getattr(delta, "removed_buses", [])))
    lines.extend(_format_candidate_values("Added links", getattr(delta, "added_links", [])))
    lines.extend(_format_candidate_values("Removed links", getattr(delta, "removed_links", [])))
    lines.extend(_format_candidate_values("Added components", getattr(delta, "added_components", [])))
    lines.extend(_format_candidate_values("Removed components", getattr(delta, "removed_components", [])))
    reevaluation = candidate.get("reevaluation")
    if reevaluation:
        improved = reevaluation.get("improved_functions", [])
        improved_text = ", ".join(improved) if improved else "none"
        lines.append(
            f"    Re-evaluation: {reevaluation.get('scenario_count', 0)} scenario(s), "
            f"improved functions: {improved_text}"
        )
        original = reevaluation.get("original_function_summary", {})
        repaired = reevaluation.get("repaired_function_summary", {})
        for function in sorted(set(original) | set(repaired)):
            orig = original.get(function, {})
            rep = repaired.get(function, {})
            lines.append(
                "    "
                f"{function}: "
                f"{orig.get('worst_status', 'n/a')}@{orig.get('worst_score', 'n/a')} "
                f"-> {rep.get('worst_status', 'n/a')}@{rep.get('worst_score', 'n/a')}"
            )
    return lines


class ComparisonEngine:
    """
    Generates pros/cons lists for each solution variant.

    Usage
    -----
    engine = ComparisonEngine(solutions, max_luts=53200, max_power=15000)
    for i, (pros, cons) in enumerate(engine.generate_all()):
        ...
    """

    def __init__(
        self,
        solutions: List[SolutionResult],
        max_luts: int = 0,
        max_power: int = 0,
        max_ffs: int = 0,
    ) -> None:
        self.solutions = solutions
        # Topology-aware caps; fall back to module-level defaults
        self._max_luts  = max_luts  if max_luts  > 0 else MAX_LUTS
        self._max_power = max_power if max_power > 0 else MAX_POWER_MW
        self._max_ffs   = max_ffs   if max_ffs   > 0 else 106_400
        self._ranker    = SolutionRanker(
            solutions, max_luts=self._max_luts, max_power=self._max_power,
        )
        self._ranks     = self._ranker.relative_ranks()

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
        n    = len(self.solutions)

        # ── Security ───────────────────────────────────────────────────────
        if p1 and p1.satisfiable:
            risk = p1.total_risk()
            if self._rank(idx, "security_score") == 0:
                pros.append(
                    f"Best security posture — lowest overall security score ({risk})"
                )
            elif self._rank(idx, "security_score") == n - 1:
                cons.append(
                    f"Weakest security posture — highest overall security score ({risk})"
                )

            # Feature quality commentary
            zt_count = sum(1 for f in p1.security.values() if f == "zero_trust")
            mac_count = sum(1 for f in p1.security.values() if f == "mac")
            no_log_count = sum(1 for f in p1.realtime.values() if f == "no_realtime")
            if zt_count == len(p1.security) and p1.security:
                pros.append(
                    "Maximum protection — zero_trust assigned to all components"
                )
            if mac_count > 0:
                cons.append(
                    f"Reduced security — {mac_count} component(s) use minimal MAC "
                    f"feature (exposure=25)"
                )
            if no_log_count > 0:
                cons.append(
                    f"Limited observability — {no_log_count} component(s) have no realtime detection"
                )

        # ── Resource usage ─────────────────────────────────────────────────
        if p1 and p1.satisfiable:
            max_luts = self._max_luts
            lut_pct = (p1.total_luts / max_luts * 100) if max_luts > 0 else 0
            if self._rank(idx, "resource_score") == 0:
                pros.append(
                    f"Lowest FPGA resource footprint — "
                    f"{p1.total_luts:,} LUTs ({lut_pct:.1f}% of {max_luts:,} available)"
                )
            elif self._rank(idx, "resource_score") == n - 1:
                cons.append(
                    f"Highest FPGA resource footprint — "
                    f"{p1.total_luts:,} LUTs ({lut_pct:.1f}% of {max_luts:,} available)"
                )

        # ── Power ──────────────────────────────────────────────────────────
        if p1 and p1.satisfiable:
            max_pwr = self._max_power
            pwr_pct = (p1.total_power / max_pwr * 100) if max_pwr > 0 else 0
            if self._rank(idx, "power_score") == 0:
                pros.append(
                    f"Most power-efficient — "
                    f"{p1.total_power:,} mW ({pwr_pct:.1f}% of {max_pwr:,} mW budget)"
                )
            elif self._rank(idx, "power_score") == n - 1:
                cons.append(
                    f"Highest power draw — "
                    f"{p1.total_power:,} mW ({pwr_pct:.1f}% of {max_pwr:,} mW budget)"
                )

        # ── Latency ────────────────────────────────────────────────────────
        if p1 and p1.satisfiable:
            # Check for latency-constrained components forced to weaker features
            for comp, feat in p1.security.items():
                if feat != "zero_trust":
                    # Only flag if other solutions give this component a better feature
                    other_feats = []
                    for other_sol in self.solutions:
                        if other_sol is not sol and other_sol.phase1 and other_sol.phase1.satisfiable:
                            of = other_sol.phase1.security.get(comp, "")
                            if of == "zero_trust":
                                other_feats.append(of)
                    if other_feats:
                        cons.append(
                            f"{comp} latency budget forces weaker '{feat}' "
                            f"(other strategies achieve zero_trust)"
                        )
                        break  # one example is enough
        elif p1 is None or not p1.satisfiable:
            cons.append("Phase 1 solver did not find a feasible solution")

        # ── Policy ─────────────────────────────────────────────────────────
        if p2 and p2.satisfiable:
            n_excess = len(p2.excess_privileges)
            if self._rank(idx, "policy_score") == 0:
                pros.append(
                    f"Most precise policy — fewest over-privileged grants "
                    f"({n_excess} excess privilege(s) detected)"
                )
            elif self._rank(idx, "policy_score") == n - 1:
                cons.append(
                    f"Least precise policy — most over-privileged grants "
                    f"({n_excess} excess privilege(s) detected)"
                )
            n_fw = len(set(p2.placed_fws))
            if n_fw == 0:
                cons.append("No firewalls deployed — all traffic unmediated by PEPs")
            elif n_fw > 0:
                pros.append(f"{n_fw} firewall(s) deployed for policy enforcement")

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
            sat_sc = [s for s in sol.scenarios if s.satisfiable]
            if self._rank(idx, "resilience_score") == 0:
                worst = sol.worst_scenario()
                w_risk = f"{worst.total_risk:.1f}" if worst else "N/A"
                pros.append(
                    f"Best resilience — lowest worst-case scenario score "
                    f"within the modeled scenario set (worst: {w_risk})"
                )
            elif self._rank(idx, "resilience_score") == n - 1:
                worst = sol.worst_scenario()
                w_risk = f"{worst.total_risk:.1f}" if worst else "N/A"
                cons.append(
                    f"Poorest resilience — highest worst-case scenario score "
                    f"within the modeled scenario set (worst: {w_risk})"
                )
            avg_br = sol.avg_blast_radius()
            if avg_br > 5:
                cons.append(
                    f"High average blast radius ({avg_br:.1f} nodes) — "
                    f"lateral movement risk under compromise"
                )

            # Capability-based resilience commentary
            nonfunc = sum(1 for s in sat_sc if s.system_non_functional)
            degraded = sum(1 for s in sat_sc
                          if s.system_degraded and not s.system_non_functional)
            ess_lost_names = set()
            for s in sat_sc:
                ess_lost_names.update(s.essential_caps_lost)
            if nonfunc > 0:
                cons.append(
                    f"{nonfunc} scenario(s) render system non-functional "
                    f"(essential capabilities lost: {', '.join(sorted(ess_lost_names)) or 'N/A'})"
                )
            elif degraded > 0:
                cons.append(
                    f"{degraded} scenario(s) degrade system functionality"
                )
            if nonfunc == 0 and degraded == 0 and sat_sc:
                # Check if capabilities were actually assessed
                any_caps = any(
                    s.capabilities_ok or s.capabilities_degraded or s.capabilities_lost
                    for s in sat_sc
                )
                if any_caps:
                    pros.append(
                        "All mission capabilities retained across all scenarios"
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
    max_luts: int = 0,
    max_power: int = 0,
    max_ffs: int = 0,
    architecture_repair_candidates: List[dict] | None = None,
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
    max_luts : int
        FPGA LUT budget (0 = use module default).
    max_power : int
        Power budget in mW (0 = use module default).
    max_ffs : int
        FPGA FF budget (0 = use module default).
    """
    import datetime
    if not date_str:
        date_str = datetime.date.today().isoformat()

    engine = ComparisonEngine(
        solutions, max_luts=max_luts, max_power=max_power, max_ffs=max_ffs,
    )
    all_pros_cons = engine.generate_all()

    max_luts  = engine._max_luts
    max_ffs   = engine._max_ffs
    max_power = engine._max_power

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
        lut_pct = best_sol.phase1.total_luts / max_luts * 100 if max_luts else 0
        lines.append(
            f"  Key Finding: Objective security score {best_sol.phase1.total_risk()}, "
            f"LUTs {best_sol.phase1.total_luts:,} "
            f"({lut_pct:.1f}% of {max_luts:,})"
        )
    lines.append("")
    if best_sol:
        lines.append("  Analysis Notes:")
        for note in best_sol.analysis_notes():
            lines.append(f"    - {note}")
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
        lines.append("  SECURITY SCORE PROFILE")
        lines.append(SEP2)
        lines.append(
            f"    Objective score:  {p1.total_risk()}"
        )
        per_asset = p1.max_risk_per_asset()
        for asset, risk in sorted(per_asset.items()):
            lines.append(f"    {asset:<12}  score = {risk}")
        lines.append("")

        # Resource usage
        lines.append("  RESOURCE USAGE")
        lines.append(SEP2)
        lut_pct = p1.total_luts / max_luts * 100 if max_luts else 0
        ff_pct = p1.total_ffs / max_ffs * 100 if max_ffs else 0
        pwr_pct = p1.total_power / max_power * 100 if max_power else 0
        lines.append(
            f"    LUTs:   {p1.total_luts:>6,}  ({lut_pct:.1f}% of {max_luts:,})"
        )
        lines.append(
            f"    FFs:    {p1.total_ffs:>6,}  ({ff_pct:.1f}% of {max_ffs:,})"
        )
        lines.append(
            f"    Power:  {p1.total_power:>6,} mW  ({pwr_pct:.1f}% of {max_power:,} mW)"
        )
        lines.append("")

        # Feature assignments
        lines.append("  FEATURE ASSIGNMENTS")
        lines.append(SEP2)
        lines.append(f"    {'Component':<16}  {'Security':<16}  {'Detection':<22}  {'Risk'}")
        lines.append(f"    {'-'*16}  {'-'*16}  {'-'*22}  {'-'*5}")
        all_comps = sorted(set(list(p1.security.keys()) + list(p1.realtime.keys())))
        for comp in all_comps:
            sec  = p1.security.get(comp, "—")
            log  = p1.realtime.get(comp, "—")
            # Find risk for any asset on this component
            comp_risk = "—"
            for asset_key, r in per_asset.items():
                if asset_key.startswith(comp):
                    comp_risk = str(r)
                    break
            lines.append(f"    {comp:<16}  {sec:<16}  {log:<22}  {comp_risk}")
        lines.append("")

        # Policy analysis
        if p2:
            lines.append("  POLICY ANALYSIS")
            lines.append(SEP2)
            lines.append(f"    Satisfiable: {p2.satisfiable}")
            if p2.satisfiable:
                lines.append(f"    Firewalls placed:  {sorted(set(p2.placed_fws))}")
                lines.append(f"    Policy servers:    {sorted(set(p2.placed_ps))}")
                if getattr(p2, "closed_loop_score", ()):
                    lines.append(f"    Phase 2 mode:      exact closed-loop")
                    lines.append(f"    Closed-loop score: {tuple(p2.closed_loop_score)}")
                    lines.append(
                        f"    Candidates eval:   {p2.closed_loop_candidates_evaluated}"
                    )
                elif p2.resilience_objective_penalty() > 0:
                    lines.append(f"    Phase 2 mode:      heuristic control-plane")
                    lines.append(
                        f"    Resilience proxy:  {p2.resilience_objective_penalty()}"
                    )
                lines.append(f"    Excess privileges: {len(p2.excess_privileges)}")
                lines.append(f"    Missing privileges:{len(p2.missing_privileges)}")
                if p2.trust_gap_rot:
                    lines.append(f"    Trust gaps (RoT):  {sorted(p2.trust_gap_rot)}")
                if p2.trust_gap_sboot:
                    lines.append(f"    Trust gaps (sboot):{sorted(p2.trust_gap_sboot)}")
                if p2.trust_gap_attest:
                    lines.append(f"    Trust gaps (attest):{sorted(p2.trust_gap_attest)}")
                avg_t = p2.avg_policy_tightness()
                avg_cov = p2.avg_effective_policy_tightness(mode="normal")
                if avg_t > 0:
                    lines.append(f"    Policy precision:  {avg_t:.1f}/100")
                if avg_cov > 0:
                    lines.append(f"    Policy coverage:   {avg_cov:.1f}/100")
                if not getattr(p2, "closed_loop_score", ()):
                    lines.append("    Guidance:          exact closed-loop Phase 2 is recommended for high-assurance studies")
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
                # Capability status
                cap_tag = ""
                if sc.system_non_functional:
                    cap_tag = " [NON-FUNCTIONAL]"
                elif sc.system_degraded:
                    cap_tag = " [DEGRADED]"
                elif sc.system_functional:
                    cap_tag = " [FUNCTIONAL]"
                lines.append(
                    f"    {sc.name:<35}  score={sc.total_risk:.1f}"
                    f"  blast={sc.max_blast_radius}{cp_tag}{svc_tag}{cap_tag}"
                )
            lines.append("")

            # Capability summary across scenarios
            sat_sc = [s for s in sol.scenarios if s.satisfiable]
            any_caps = any(
                s.capabilities_ok or s.capabilities_degraded or s.capabilities_lost
                for s in sat_sc
            )
            if any_caps:
                lines.append("  MISSION CAPABILITY SUMMARY")
                lines.append(SEP2)
                nf = sum(1 for s in sat_sc if s.system_non_functional)
                dg = sum(1 for s in sat_sc
                         if s.system_degraded and not s.system_non_functional)
                ok = len(sat_sc) - nf - dg
                lines.append(
                    f"    Scenarios: {ok} functional, {dg} degraded, {nf} non-functional"
                    f"  (of {len(sat_sc)} total)"
                )
                # List essential capabilities lost across any scenario
                ess_lost = set()
                all_lost = set()
                for s in sat_sc:
                    ess_lost.update(s.essential_caps_lost)
                    all_lost.update(s.capabilities_lost)
                if ess_lost:
                    lines.append(
                        f"    Essential caps at risk: {', '.join(sorted(ess_lost))}"
                    )
                if all_lost - ess_lost:
                    lines.append(
                        f"    Other caps at risk:     {', '.join(sorted(all_lost - ess_lost))}"
                    )
                lines.append("")

            function_defs = _function_deficiencies(sol)
            if function_defs:
                lines.append("  FUNCTION SUPPORT FINDINGS")
                lines.append(SEP2)
                for deficiency in function_defs[:8]:
                    lines.append(f"    - {_format_function_deficiency(deficiency)}")
                if len(function_defs) > 8:
                    lines.append(f"    - ... {len(function_defs) - 8} more finding(s)")
                lines.append("")

            repair_intents = _repair_intents(sol)
            if repair_intents:
                lines.append("  ARCHITECTURE REPAIR INTENTS")
                lines.append(SEP2)
                for intent in repair_intents:
                    lines.append(f"    - {_format_repair_intent(intent)}")
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
    lines.append("  " + "-" * 64)

    metrics_rows = [
        ("Objective Score",      [str(s.phase1.total_risk()) if s.phase1 and s.phase1.satisfiable else "N/A"
                                  for s in solutions]),
        ("LUTs Used",           [f"{s.phase1.total_luts:,}" if s.phase1 and s.phase1.satisfiable else "N/A"
                                  for s in solutions]),
        ("Power (mW)",          [f"{s.phase1.total_power:,}" if s.phase1 and s.phase1.satisfiable else "N/A"
                                  for s in solutions]),
        ("ZTA Cost",            [str(s.phase2.total_cost) if s.phase2 and s.phase2.satisfiable else "N/A"
                                  for s in solutions]),
        ("Firewalls Placed",    [str(len(set(s.phase2.placed_fws))) if s.phase2 and s.phase2.satisfiable else "N/A"
                                  for s in solutions]),
        ("Excess Privileges",   [str(len(s.phase2.excess_privileges)) if s.phase2 and s.phase2.satisfiable else "N/A"
                                  for s in solutions]),
        ("Security Score",      [f"{s.security_score:.1f}" for s in solutions]),
        ("Resource Score",      [f"{s.resource_score:.1f}" for s in solutions]),
        ("Power Score",         [f"{s.power_score:.1f}" for s in solutions]),
        ("Resilience Score",    [f"{s.resilience_score:.1f}" for s in solutions]),
        ("Policy Score",        [f"{s.policy_score:.1f}" for s in solutions]),
    ]

    # Add capability retention if data available
    def _cap_retention(sol: SolutionResult) -> str:
        sat = [sc for sc in sol.scenarios if sc.satisfiable] if sol.scenarios else []
        scores = []
        for sc in sat:
            total = len(sc.capabilities_ok) + len(sc.capabilities_degraded) + len(sc.capabilities_lost)
            if total > 0:
                pct = (len(sc.capabilities_ok) + 0.5 * len(sc.capabilities_degraded)) / total * 100
                scores.append(pct)
        return f"{sum(scores)/len(scores):.1f}%" if scores else "N/A"

    metrics_rows.append(("Cap. Retention",
                          [_cap_retention(s) for s in solutions]))

    def _nonfunc(sol: SolutionResult) -> str:
        sat = [sc for sc in sol.scenarios if sc.satisfiable] if sol.scenarios else []
        return str(sum(1 for sc in sat if sc.system_non_functional)) if sat else "N/A"

    metrics_rows.append(("Non-Func Scenarios",
                          [_nonfunc(s) for s in solutions]))

    metrics_rows.append(("Function Deficiencies",
                          [str(len(_function_deficiencies(s))) for s in solutions]))

    metrics_rows.append(("Repair Intents",
                          [str(len(_repair_intents(s))) for s in solutions]))

    for label, vals in metrics_rows:
        v1 = vals[0] if len(vals) > 0 else "N/A"
        v2 = vals[1] if len(vals) > 1 else "N/A"
        v3 = vals[2] if len(vals) > 2 else "N/A"
        lines.append(f"  {label:<30}  {v1:>10}  {v2:>10}  {v3:>10}")
    lines.append("")

    # Architecture repair candidates generated from closed-loop findings
    if architecture_repair_candidates:
        lines.append(SEP)
        lines.append("  ARCHITECTURE REPAIR CANDIDATES")
        lines.append(SEP)
        for idx, candidate in enumerate(architecture_repair_candidates, 1):
            lines.extend(_format_architecture_repair_candidate(candidate, idx))
            lines.append("")

    # ── Topology-aware recommendations ──────────────────────────────────────
    lines.append(SEP)
    lines.append("  RECOMMENDATIONS")
    lines.append(SEP)

    # Generate recommendations from actual data
    rec_num = 1
    best = solutions[best_idx] if solutions else None

    # Firewall recommendation
    if best and best.phase2 and best.phase2.satisfiable:
        n_fw = len(set(best.phase2.placed_fws))
        if n_fw > 0:
            lines.append(
                f"  {rec_num}. Deploy all candidate PEP locations "
                f"({', '.join(sorted(set(best.phase2.placed_fws)))}) to ensure full\n"
                f"     Zero Trust mediation of all bus master-IP traffic."
            )
            rec_num += 1

    # Trust gap recommendation
    if best and best.phase2 and best.phase2.satisfiable:
        all_gaps = (best.phase2.trust_gap_rot + best.phase2.trust_gap_sboot
                    + best.phase2.trust_gap_attest)
        if all_gaps:
            gap_comps = sorted(set(all_gaps))
            lines.append(
                f"  {rec_num}. Assign hardware trust anchors (RoT, secure boot, attestation) to:\n"
                f"     {', '.join(gap_comps)}"
            )
            rec_num += 1

    # Excess privilege recommendation
    if best and best.phase2 and best.phase2.excess_privileges:
        lines.append(
            f"  {rec_num}. Review {len(best.phase2.excess_privileges)} excess privilege(s) — "
            f"restrict to least-privilege access where possible."
        )
        rec_num += 1

    # Capability resilience recommendation
    ess_at_risk = set()
    if best and best.scenarios:
        for sc in best.scenarios:
            if sc.satisfiable:
                ess_at_risk.update(sc.essential_caps_lost)
    if ess_at_risk:
        lines.append(
            f"  {rec_num}. Critical: essential capabilities ({', '.join(sorted(ess_at_risk))}) "
            f"are lost\n"
            f"     under some scenarios — add redundancy or alternative access paths."
        )
        rec_num += 1

    function_defs = _function_deficiencies(best) if best else []
    if function_defs:
        sample = _format_function_deficiency(function_defs[0])
        lines.append(
            f"  {rec_num}. Review {len(function_defs)} function-support finding(s);\n"
            f"     first finding: {sample}."
        )
        rec_num += 1

    repair_intents = _repair_intents(best) if best else []
    if repair_intents:
        lines.append(
            f"  {rec_num}. Queue architecture repair: {_format_repair_intent(repair_intents[0])}."
        )
        rec_num += 1

    # Latency-constrained component recommendation
    if best and best.phase1 and best.phase1.satisfiable:
        mac_comps = [c for c, f in best.phase1.security.items() if f == "mac"]
        if mac_comps:
            lines.append(
                f"  {rec_num}. Consider relaxing latency budgets for {', '.join(sorted(mac_comps))}\n"
                f"     to allow stronger security feature assignment."
            )
            rec_num += 1

    # Generic best-solution recommendation
    lines.append(
        f"  {rec_num}. Use {best.label if best else 'the best-scoring strategy'} for production deployment;\n"
        f"     use a balanced strategy if resource budget is constrained."
    )

    lines.append("")
    lines.append(SEP)

    return "\n".join(lines)


def export_csv(
    solutions: List[SolutionResult],
    path: str,
    max_luts: int = 0,
    max_power: int = 0,
    max_ffs: int = 0,
) -> None:
    """
    Export per-strategy metrics to a CSV file.

    Parameters
    ----------
    solutions : list[SolutionResult]
        The three strategy solutions from the orchestrator.
    path : str
        Output CSV file path.
    max_luts, max_power, max_ffs : int
        FPGA resource budgets (0 = use module defaults).
    """
    import csv

    _max_luts  = max_luts  if max_luts  > 0 else MAX_LUTS
    _max_power = max_power if max_power > 0 else MAX_POWER_MW
    _max_ffs   = max_ffs   if max_ffs   > 0 else 106_400

    fieldnames = [
        "Strategy", "Label",
        "Phase1_SAT", "Phase2_SAT",
        "Total_Risk", "Security_Score", "Resource_Score",
        "Power_Score", "Latency_Score", "Resilience_Score", "Policy_Score",
        "LUTs", "LUT_Pct", "FFs", "FF_Pct", "Power_mW", "Power_Pct",
        "DSPs", "LUTRAM", "BRAM",
        "FWs_Placed", "PSs_Placed", "Excess_Privileges", "Missing_Privileges",
        "Trust_Gaps_RoT", "Trust_Gaps_SBoot", "Trust_Gaps_Attest",
        "Scenarios_Total", "Scenarios_SAT",
        "Worst_Scenario", "Worst_Scenario_Risk", "Max_Blast_Radius",
        "Avg_Blast_Radius",
        "Cap_OK", "Cap_Degraded", "Cap_Lost", "Non_Functional_Scenarios",
        "CIA_C", "CIA_I", "CIA_A",
    ]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for sol in solutions:
            p1 = sol.phase1
            p2 = sol.phase2
            sat_sc = [s for s in sol.scenarios if s.satisfiable] if sol.scenarios else []
            worst = sol.worst_scenario()

            # Capability aggregation
            cap_ok = cap_deg = cap_lost = nf = 0
            for sc in sat_sc:
                cap_ok   += len(sc.capabilities_ok)
                cap_deg  += len(sc.capabilities_degraded)
                cap_lost += len(sc.capabilities_lost)
                if sc.system_non_functional:
                    nf += 1

            lut_pct = (p1.total_luts / _max_luts * 100) if (p1 and p1.satisfiable and _max_luts) else 0
            ff_pct  = (p1.total_ffs  / _max_ffs  * 100) if (p1 and p1.satisfiable and _max_ffs)  else 0
            pwr_pct = (p1.total_power / _max_power * 100) if (p1 and p1.satisfiable and _max_power) else 0

            row = {
                "Strategy":           sol.strategy,
                "Label":              sol.label,
                "Phase1_SAT":         p1.satisfiable if p1 else False,
                "Phase2_SAT":         p2.satisfiable if p2 else False,
                "Total_Risk":         p1.total_risk() if (p1 and p1.satisfiable) else "N/A",
                "Security_Score":     round(sol.security_score, 1),
                "Resource_Score":     round(sol.resource_score, 1),
                "Power_Score":        round(sol.power_score, 1),
                "Latency_Score":      round(sol.latency_score, 1),
                "Resilience_Score":   round(sol.resilience_score, 1),
                "Policy_Score":       round(sol.policy_score, 1),
                "LUTs":               p1.total_luts if (p1 and p1.satisfiable) else 0,
                "LUT_Pct":            round(lut_pct, 1),
                "FFs":                p1.total_ffs if (p1 and p1.satisfiable) else 0,
                "FF_Pct":             round(ff_pct, 1),
                "Power_mW":           p1.total_power if (p1 and p1.satisfiable) else 0,
                "Power_Pct":          round(pwr_pct, 1),
                "DSPs":               p1.total_dsps if (p1 and p1.satisfiable) else 0,
                "LUTRAM":             p1.total_lutram if (p1 and p1.satisfiable) else 0,
                "BRAM":               p1.total_bram if (p1 and p1.satisfiable) else 0,
                "FWs_Placed":         len(set(p2.placed_fws)) if (p2 and p2.satisfiable) else 0,
                "PSs_Placed":         len(set(p2.placed_ps)) if (p2 and p2.satisfiable) else 0,
                "Excess_Privileges":  len(p2.excess_privileges) if (p2 and p2.satisfiable) else 0,
                "Missing_Privileges": len(p2.missing_privileges) if (p2 and p2.satisfiable) else 0,
                "Trust_Gaps_RoT":     len(p2.trust_gap_rot) if (p2 and p2.satisfiable) else 0,
                "Trust_Gaps_SBoot":   len(p2.trust_gap_sboot) if (p2 and p2.satisfiable) else 0,
                "Trust_Gaps_Attest":  len(p2.trust_gap_attest) if (p2 and p2.satisfiable) else 0,
                "Scenarios_Total":    len(sol.scenarios) if sol.scenarios else 0,
                "Scenarios_SAT":      len(sat_sc),
                "Worst_Scenario":     worst.name if worst else "N/A",
                "Worst_Scenario_Risk": round(worst.total_risk, 1) if worst else 0,
                "Max_Blast_Radius":   max((s.max_blast_radius for s in sat_sc), default=0),
                "Avg_Blast_Radius":   round(sol.avg_blast_radius(), 1),
                "Cap_OK":             cap_ok,
                "Cap_Degraded":       cap_deg,
                "Cap_Lost":           cap_lost,
                "Non_Functional_Scenarios": nf,
                "CIA_C":              sol.cia_scores.get("C", 0),
                "CIA_I":              sol.cia_scores.get("I", 0),
                "CIA_A":              sol.cia_scores.get("A", 0),
            }
            writer.writerow(row)

