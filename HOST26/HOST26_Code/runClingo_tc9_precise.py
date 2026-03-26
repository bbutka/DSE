from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Iterable

import clingo

import runClingo_tc9 as legacy
from tc9_precise_math import PrecisePhase1Math, compute_precise_phase1_math, load_tc9_math_facts


@dataclass(frozen=True)
class Phase1Candidate:
    approx_cost: tuple[int, ...]
    security: dict[str, str]
    logging: dict[str, str]
    resources: dict[str, int]
    precise_math: PrecisePhase1Math


@dataclass(frozen=True)
class PrecisePhase1Selection:
    phase1: legacy.Phase1Result
    precise_math: PrecisePhase1Math
    approx_frontier_size: int
    approx_opt_cost: tuple[int, ...]


def _format_fraction(value: Fraction) -> str:
    return f"{float(value):.6f} ({value.numerator}/{value.denominator})"


def _collect_phase1_candidates() -> list[Phase1Candidate]:
    facts = load_tc9_math_facts(legacy.BASE_DIR)
    ctl = clingo.Control(["-n", "0", "--opt-mode=optN", "--warn=none"])
    for file_path in legacy.PHASE1_FILES:
        ctl.load(file_path)
    ctl.ground([("base", [])])

    models: list[Phase1Candidate] = []

    def on_model(model: clingo.Model) -> None:
        security: dict[str, str] = {}
        logging: dict[str, str] = {}
        resources: dict[str, int] = {}

        for symbol in model.symbols(shown=True):
            name = symbol.name
            args = symbol.arguments
            if name == "selected_security" and len(args) == 2 and str(args[0]) in legacy.COMPONENTS:
                security[str(args[0])] = str(args[1])
            elif name == "selected_logging" and len(args) == 2 and str(args[0]) in legacy.COMPONENTS:
                logging[str(args[0])] = str(args[1])
            elif name.startswith("total_") and len(args) == 1:
                resources[name] = args[0].number

        precise_math = compute_precise_phase1_math(facts, security, logging)
        models.append(
            Phase1Candidate(
                approx_cost=tuple(model.cost),
                security=security,
                logging=logging,
                resources=resources,
                precise_math=precise_math,
            )
        )

    result = ctl.solve(on_model=on_model)
    if result.unsatisfiable or not models:
        raise RuntimeError("Phase 1 UNSAT")
    return models


def _candidate_sort_key(candidate: Phase1Candidate) -> tuple:
    resources = candidate.resources
    return (
        candidate.precise_math.total_risk,
        resources.get("total_luts_used", 0),
        resources.get("total_ffs_used", 0),
        resources.get("total_dsps_used", 0),
        resources.get("total_lutram_used", 0),
        resources.get("total_bram_used", 0),
        resources.get("total_power_used", 0),
        tuple(sorted(candidate.security.items())),
        tuple(sorted(candidate.logging.items())),
    )


def phase1_precise() -> PrecisePhase1Selection:
    print("[Phase 1 precise] Enumerating approximate-optimal frontier...")
    candidates = _collect_phase1_candidates()
    min_cost = min(candidate.approx_cost for candidate in candidates)
    frontier = [candidate for candidate in candidates if candidate.approx_cost == min_cost]
    chosen = min(frontier, key=_candidate_sort_key)

    phase1 = legacy.Phase1Result()
    phase1.security = dict(chosen.security)
    phase1.logging = dict(chosen.logging)
    phase1.total_luts = chosen.resources.get("total_luts_used", 0)
    phase1.total_ffs = chosen.resources.get("total_ffs_used", 0)
    phase1.total_dsps = chosen.resources.get("total_dsps_used", 0)
    phase1.total_lutram = chosen.resources.get("total_lutram_used", 0)
    phase1.total_bram = chosen.resources.get("total_bram_used", 0)
    phase1.total_power = chosen.resources.get("total_power_used", 0)
    phase1.optimal = True

    facts = load_tc9_math_facts(legacy.BASE_DIR)
    for asset, component in sorted(facts.asset_to_component.items(), key=lambda item: item[0]):
        for operation, rounded in sorted(chosen.precise_math.rounded_risk[asset].items()):
            phase1.new_risk.append((component, asset, operation, rounded))

    print(
        f"[Phase 1 precise] Frontier={len(frontier)} approx_cost={min_cost} "
        f"chosen_exact_total={chosen.precise_math.total_risk}"
    )
    return PrecisePhase1Selection(
        phase1=phase1,
        precise_math=chosen.precise_math,
        approx_frontier_size=len(frontier),
        approx_opt_cost=min_cost,
    )


def phase2_optimal(p1: legacy.Phase1Result) -> legacy.Phase2Result:
    print("[Phase 2 optimal] Solving for minimum-cost ZTA placement...")
    ctl = clingo.Control(["-n", "0", "--opt-mode=optN", "--warn=none"])
    for file_path in legacy.PHASE2_FILES:
        ctl.load(file_path)
    ctl.add("p1", [], p1.as_p1_facts())
    ctl.ground([("base", []), ("p1", [])])

    models: list[list[clingo.Symbol]] = []

    def on_model(model: clingo.Model) -> None:
        models.append(list(model.symbols(shown=True)))

    result = ctl.solve(on_model=on_model)
    if result.unsatisfiable or not models:
        parsed = legacy.Phase2Result()
        parsed.satisfiable = False
        return parsed

    best_symbols = models[-1]
    parsed = legacy.Phase2Result()
    parsed.satisfiable = True
    for symbol in best_symbols:
        name = symbol.name
        args = symbol.arguments
        if name == "place_fw" and len(args) == 1:
            parsed.placed_fws.append(str(args[0]))
        elif name == "place_ps" and len(args) == 1:
            parsed.placed_ps.append(str(args[0]))
        elif name == "final_allow" and len(args) == 3:
            parsed.final_allows.append((str(args[0]), str(args[1]), str(args[2])))
        elif name == "final_deny" and len(args) == 3:
            parsed.final_denies.append((str(args[0]), str(args[1]), str(args[2])))
        elif name == "asset_policy" and len(args) == 4:
            parsed.asset_policies.append((str(args[0]), str(args[1]), str(args[2]), str(args[3])))
        elif name == "role_allow" and len(args) == 4:
            parsed.role_allows.append((str(args[0]), str(args[1]), str(args[2]), str(args[3])))
        elif name == "isolated" and len(args) == 2:
            parsed.isolated.append((str(args[0]), str(args[1])))
        elif name == "protected" and len(args) == 2:
            parsed.protected.append((str(args[0]), str(args[1])))
        elif name == "governs_ip" and len(args) == 2:
            parsed.governs_ip.append((str(args[0]), str(args[1])))
        elif name == "excess_privilege" and len(args) == 3:
            parsed.excess_privileges.append((str(args[0]), str(args[1]), str(args[2])))
        elif name == "missing_privilege" and len(args) == 3:
            parsed.missing_privileges.append((str(args[0]), str(args[1]), str(args[2])))
        elif name == "policy_tightness" and len(args) == 2:
            parsed.policy_tightness[str(args[0])] = args[1].number
        elif name == "over_privileged" and len(args) == 1:
            parsed.over_privileged.append(str(args[0]))
        elif name == "role_excess" and len(args) == 3:
            parsed.role_excess.append((str(args[0]), str(args[1]), str(args[2])))
        elif name == "operational_excess" and len(args) == 3:
            parsed.operational_excess.append((str(args[0]), str(args[1]), str(args[2])))
        elif name == "trust_gap_rot" and len(args) == 1:
            parsed.trust_gap_rot.append(str(args[0]))
        elif name == "trust_gap_sboot" and len(args) == 1:
            parsed.trust_gap_sboot.append(str(args[0]))
        elif name == "trust_gap_attest" and len(args) == 1:
            parsed.trust_gap_attest.append(str(args[0]))
        elif name == "unattested_privileged_access" and len(args) == 2:
            parsed.unattested_access.append((str(args[0]), str(args[1])))
        elif name == "unsigned_ps" and len(args) == 1:
            parsed.unsigned_ps.append(str(args[0]))
        elif name == "trust_gap_keys" and len(args) == 1:
            parsed.trust_gap_keys.append(str(args[0]))
        elif name == "trust_level" and len(args) == 2:
            parsed.trust_levels[str(args[0])] = str(args[1])
        elif name == "unexplained_exception" and len(args) == 3:
            parsed.unexplained_exceptions.append((str(args[0]), str(args[1]), str(args[2])))
        elif name == "critical_exception" and len(args) == 5:
            parsed.critical_exceptions.append(tuple(str(value) for value in args))
        elif name == "total_zta_cost" and len(args) == 1:
            parsed.total_cost = args[0].number

    print(
        f"[Phase 2 optimal] FWs={sorted(parsed.placed_fws)} "
        f"PS={sorted(parsed.placed_ps)} cost={parsed.total_cost}"
    )
    return parsed


def phase3_scenario_precise(sc: dict, p1: legacy.Phase1Result) -> legacy.ScenarioResult:
    ctl = clingo.Control(["-n", "1", "--warn=none"])
    for file_path in legacy.PHASE3_FILES:
        ctl.load(file_path)

    facts = p1.as_p1_facts()
    for node in sc["compromised"]:
        facts += f"\ncompromised({node})."
    for node in sc["failed"]:
        facts += f"\nfailed({node})."
    ctl.add("scenario", [], facts)
    ctl.ground([("base", []), ("scenario", [])])

    result = legacy.ScenarioResult(
        name=sc["name"],
        compromised=sc["compromised"],
        failed=sc["failed"],
    )
    found: list[clingo.Symbol] = []
    solve_result = ctl.solve(on_model=lambda model: found.extend(model.symbols(shown=True)))
    result.satisfiable = not solve_result.unsatisfiable

    for symbol in found:
        name = symbol.name
        args = symbol.arguments
        if name == "scenario_asset_risk" and len(args) == 2:
            result.scenario_risks[str(args[0])] = args[1].number
        elif name == "scenario_total_risk" and len(args) == 1:
            result.total_risk_scaled = args[0].number
        elif name == "blast_radius" and len(args) == 2:
            result.blast_radii[str(args[0])] = args[1].number
        elif name == "asset_unavailable" and len(args) == 1:
            result.unavailable.append(str(args[0]))
        elif name == "node_cut_off" and len(args) == 1:
            result.cut_off.append(str(args[0]))
        elif name == "service_ok" and len(args) == 1:
            result.services_ok.append(str(args[0]))
        elif name == "service_degraded" and len(args) == 1:
            result.services_degraded.append(str(args[0]))
        elif name == "service_unavailable" and len(args) == 1:
            result.services_unavail.append(str(args[0]))
        elif name == "service_live_count" and len(args) == 2:
            result.service_counts[str(args[0])] = args[1].number
        elif name == "active_ps_count" and len(args) == 1:
            result.active_ps_count = args[0].number
        elif name == "ungovernerd_pep" and len(args) == 1:
            result.ungoverned_peps.append(str(args[0]))
        elif name == "control_plane_degraded" and not args:
            result.cp_degraded = True
        elif name == "control_plane_compromised" and not args:
            result.cp_compromised = True
        elif name == "pep_bypassed" and len(args) == 1:
            result.peps_bypassed.append(str(args[0]))
        elif name == "ps_compromised" and len(args) == 1:
            result.ps_compromised.append(str(args[0]))
        elif name == "direct_exposure" and len(args) == 3:
            result.direct_exp.append((str(args[0]), str(args[1])))
        elif name == "indirect_exposure_cross" and len(args) == 3:
            result.cross_exp.append((str(args[0]), str(args[1])))
        elif name == "unmediated_exposure" and len(args) == 3:
            result.unmediated_exp.append((str(args[0]), str(args[1])))

    return result


def phase3_all_precise(p1: legacy.Phase1Result) -> list[legacy.ScenarioResult]:
    print("[Phase 3 precise] Running scenarios...")
    results: list[legacy.ScenarioResult] = []
    for scenario in legacy.SCENARIOS:
        result = phase3_scenario_precise(scenario, p1)
        control_plane = " [CP-COMP]" if result.cp_compromised else (" [CP-DEG]" if result.cp_degraded else "")
        tag = f"risk={result.total_risk:.1f}{control_plane}" if result.satisfiable else "UNSAT"
        print(f"  {scenario['name']:<35} {tag}")
        results.append(result)
    print("[Phase 3 precise] Done.")
    return results


def _scenario_rows(scenarios: Iterable[legacy.ScenarioResult]) -> list[str]:
    rows = [
        f"  {'Scenario':<30} {'Total Risk':>10} {'Control Plane':>14}",
        f"  {'-' * 30} {'-' * 10} {'-' * 14}",
    ]
    for scenario in scenarios:
        control_plane = "COMP" if scenario.cp_compromised else ("DEG" if scenario.cp_degraded else "OK")
        rows.append(f"  {scenario.name:<30} {scenario.total_risk:>10.1f} {control_plane:>14}")
    return rows


def generate_precise_report(
    selection: PrecisePhase1Selection,
    p2: legacy.Phase2Result,
    scenarios: list[legacy.ScenarioResult],
) -> str:
    p1 = selection.phase1
    math = selection.precise_math
    lines: list[str] = []
    separator = "=" * 78

    lines.append(separator)
    lines.append("  testCase9 Precise Risk Report")
    lines.append(separator)
    lines.append("")
    lines.append("  This run uses Clingo to enumerate the approximate-optimal frontier and")
    lines.append("  Python Fraction arithmetic to compute redundancy-adjusted Phase 1 risk.")
    lines.append("")
    lines.append("  Phase 1 precise selection")
    lines.append(f"    Approx-optimal frontier size : {selection.approx_frontier_size}")
    lines.append(f"    Approximate objective cost   : {selection.approx_opt_cost}")
    lines.append(f"    Rounded exact total risk     : {math.total_risk}")
    lines.append("")
    for group_id, combined in sorted(math.combined_prob_norm.items()):
        lines.append(f"    Group {group_id} combined normalized prob : {_format_fraction(combined)}")
    for component, value in sorted(math.new_prob_denormalized.items()):
        lines.append(f"    {component} denormalized group probability  : {_format_fraction(value)}")
    lines.append("")
    lines.append(f"  {'Comp':<6} {'Security':<14} {'Logging':<14} {'Read':>8} {'Write':>8} {'Max':>8}")
    lines.append(f"  {'-' * 6} {'-' * 14} {'-' * 14} {'-' * 8} {'-' * 8} {'-' * 8}")
    facts = load_tc9_math_facts(legacy.BASE_DIR)
    for asset, component in sorted(facts.asset_to_component.items()):
        read_risk = math.rounded_risk[asset]["read"]
        write_risk = math.rounded_risk[asset]["write"]
        lines.append(
            f"  {component:<6} {p1.security[component]:<14} {p1.logging[component]:<14} "
            f"{read_risk:>8} {write_risk:>8} {max(read_risk, write_risk):>8}"
        )
    lines.append("")
    lines.append("  Resource totals for selected candidate")
    lines.append(f"    LUTs   : {p1.total_luts}")
    lines.append(f"    FFs    : {p1.total_ffs}")
    lines.append(f"    DSPs   : {p1.total_dsps}")
    lines.append(f"    LUTRAM : {p1.total_lutram}")
    lines.append(f"    BRAM   : {p1.total_bram}")
    lines.append(f"    Power  : {p1.total_power}")
    lines.append("")
    lines.append("  Phase 2 optimal placement")
    lines.append(f"    Firewalls     : {', '.join(sorted(p2.placed_fws))}")
    lines.append(f"    Policy servers: {', '.join(sorted(p2.placed_ps))}")
    lines.append(f"    Total cost    : {p2.total_cost}")
    lines.append("")
    lines.append("  Phase 3 scenario totals")
    lines.extend(_scenario_rows(scenarios))
    lines.append("")
    lines.append("  Notes")
    lines.append("    - Phase 1 risk is recomputed in Python to avoid Clingo-side integer")
    lines.append("      overflow and repeated truncation in the redundancy product.")
    lines.append("    - Phase 2 is solved with proven minimum-cost mode in this runner.")
    return "\n".join(lines)


def main() -> None:
    selection = phase1_precise()
    p2 = phase2_optimal(selection.phase1)
    scenarios = phase3_all_precise(selection.phase1)
    report = generate_precise_report(selection, p2, scenarios)

    print("\n" + report)
    output_path = Path(legacy.BASE_DIR) / "resilience_summary_tc9_precise.txt"
    output_path.write_text(report, encoding="utf-8")
    print(f"\nReport written to: {output_path}")


if __name__ == "__main__":
    main()
