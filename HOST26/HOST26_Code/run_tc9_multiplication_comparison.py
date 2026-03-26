from __future__ import annotations

from fractions import Fraction
from pathlib import Path

import clingo

import runClingo_tc9 as legacy
from runClingo_tc9_precise import phase1_precise
from tc9_lut_phase1 import phase1_lut
from tc9_precise_math import compute_precise_phase1_math, load_tc9_math_facts


BASE_DIR = Path(__file__).resolve().parent
REPORT_PATH = BASE_DIR / "tc9_multiplication_comparison_report.txt"
GROUP_COMPONENTS = ("c1", "c2", "c3", "c4", "c5")


def _fmt_fraction(value: Fraction) -> str:
    return f"{float(value):.6f} ({value.numerator}/{value.denominator})"


def _fmt_prob_thousand(value: Fraction) -> str:
    return f"{float(value):.3f}"


def _collect_original_phase1_raw() -> tuple[dict[str, str], dict[str, str], dict[str, int], dict[str, int], dict[str, int], dict[str, dict[str, int]], tuple[int, ...]]:
    ctl = clingo.Control(["-n", "0"])
    for file_path in legacy.PHASE1_FILES:
        ctl.load(file_path)
    ctl.ground([("base", [])])

    last_model: list[clingo.Symbol] = []
    cost: tuple[int, ...] = ()

    def on_model(model: clingo.Model) -> None:
        nonlocal last_model, cost
        last_model = list(model.symbols(shown=True))
        cost = tuple(model.cost)

    solve_result = ctl.solve(on_model=on_model)
    if solve_result.unsatisfiable or not last_model:
        raise RuntimeError("Original tc9 Phase 1 solve returned no model")

    security: dict[str, str] = {}
    logging: dict[str, str] = {}
    normalized: dict[str, int] = {}
    combined: dict[str, int] = {}
    denorm: dict[str, int] = {}
    new_risk: dict[str, dict[str, int]] = {}

    for symbol in last_model:
        name = symbol.name
        args = symbol.arguments
        if name == "selected_security" and len(args) == 2 and str(args[0]) in legacy.COMPONENTS:
            security[str(args[0])] = str(args[1])
        elif name == "selected_logging" and len(args) == 2 and str(args[0]) in legacy.COMPONENTS:
            logging[str(args[0])] = str(args[1])
        elif name == "original_prob_normalized" and len(args) == 2 and str(args[0]) in legacy.COMPONENTS:
            normalized[str(args[0])] = args[1].number
        elif name == "combined_prob_norm" and len(args) == 2:
            combined[str(args[0])] = args[1].number
        elif name == "new_prob_denormalized" and len(args) == 2 and str(args[0]) in legacy.COMPONENTS:
            denorm[str(args[0])] = args[1].number
        elif name == "new_risk" and len(args) == 4 and str(args[0]) in legacy.COMPONENTS:
            new_risk.setdefault(str(args[1]), {})[str(args[2])] = args[3].number

    return security, logging, normalized, combined, denorm, new_risk, cost


def _architecture_rows(title: str, security: dict[str, str], logging: dict[str, str]) -> list[str]:
    rows = [title]
    for component in sorted(security):
        rows.append(f"  {component}: security={security[component]} logging={logging[component]}")
    return rows


def main() -> None:
    facts = load_tc9_math_facts(BASE_DIR)
    original_security, original_logging, original_norm, original_combined, original_denorm, original_new_risk, original_cost = _collect_original_phase1_raw()
    original_exact = compute_precise_phase1_math(facts, original_security, original_logging)
    helper = phase1_precise()
    lut = phase1_lut(BASE_DIR)

    group_product_from_original_ints = (
        original_norm["c1"]
        * original_norm["c2"]
        * original_norm["c3"]
        * original_norm["c4"]
        * original_norm["c5"]
    )

    lines: list[str] = []
    lines.append("=" * 92)
    lines.append("tc9 Multiplication Comparison")
    lines.append("=" * 92)
    lines.append("")
    lines.extend(_architecture_rows("Original ASP selected design", original_security, original_logging))
    lines.append(f"  Approximate cost tuple: {original_cost}")
    lines.append("")
    lines.extend(_architecture_rows("Python exact helper selected design", helper.phase1.security, helper.phase1.logging))
    lines.append(f"  Approximate frontier size: {helper.approx_frontier_size}")
    lines.append("")
    lines.extend(_architecture_rows("LUT/log-sum selected design", lut.phase1.security, lut.phase1.logging))
    lines.append(f"  Approximate cost tuple: {lut.approx_opt_cost}")
    lines.append("")

    lines.append("M1. original_prob = vulnerability * logging")
    lines.append(f"  {'Comp':<6} {'Original ASP':>12} {'Python exact':>12} {'LUT design':>12}")
    lines.append(f"  {'-' * 6} {'-' * 12} {'-' * 12} {'-' * 12}")
    for component in sorted(original_security):
        lines.append(
            f"  {component:<6} "
            f"{original_exact.original_prob[component]:>12} "
            f"{helper.precise_math.original_prob[component]:>12} "
            f"{lut.precise_math.original_prob[component]:>12}"
        )
    lines.append("")

    lines.append("M2. original_register_risk = impact * vulnerability * logging / 10")
    lines.append(f"  {'Asset':<8} {'Original ASP':>18} {'Python exact':>18} {'LUT design':>18}")
    lines.append(f"  {'-' * 8} {'-' * 18} {'-' * 18} {'-' * 18}")
    for asset in sorted(facts.asset_to_component):
        orig_read = original_exact.exact_risk[asset]["read"] if facts.asset_to_component[asset] not in GROUP_COMPONENTS else Fraction(
            facts.impacts[asset]["read"] * original_exact.original_prob[facts.asset_to_component[asset]], 10
        )
        orig_write = original_exact.exact_risk[asset]["write"] if facts.asset_to_component[asset] not in GROUP_COMPONENTS else Fraction(
            facts.impacts[asset]["write"] * original_exact.original_prob[facts.asset_to_component[asset]], 10
        )
        helper_read = Fraction(facts.impacts[asset]["read"] * helper.precise_math.original_prob[facts.asset_to_component[asset]], 10)
        helper_write = Fraction(facts.impacts[asset]["write"] * helper.precise_math.original_prob[facts.asset_to_component[asset]], 10)
        lut_read = Fraction(facts.impacts[asset]["read"] * lut.precise_math.original_prob[facts.asset_to_component[asset]], 10)
        lut_write = Fraction(facts.impacts[asset]["write"] * lut.precise_math.original_prob[facts.asset_to_component[asset]], 10)
        lines.append(
            f"  {asset:<8} "
            f"{_fmt_fraction(orig_read):>18} / {_fmt_fraction(orig_write):<18} "
            f"{_fmt_fraction(helper_read):>18} / {_fmt_fraction(helper_write):<18} "
            f"{_fmt_fraction(lut_read):>18} / {_fmt_fraction(lut_write):<18}"
        )
    lines.append("")

    lines.append("M3. original_prob_normalized = (original_prob - mu) * 1000 / (omega - mu)")
    lines.append("    Group components only, because they feed the risky chained product.")
    lines.append(f"  {'Comp':<6} {'Original ASP int':>16} {'Python exact':>24} {'LUT prob/1000':>16}")
    lines.append(f"  {'-' * 6} {'-' * 16} {'-' * 24} {'-' * 16}")
    for component in GROUP_COMPONENTS:
        lut_scaled = lut.member_prob_scaled[component]
        lines.append(
            f"  {component:<6} "
            f"{original_norm[component]:>16} "
            f"{_fmt_fraction(original_exact.original_prob_normalized[component]):>24} "
            f"{(lut_scaled / 1000):>16.3f}"
        )
    lines.append("")

    lines.append("M4. Chained redundancy multiplication")
    lines.append("  Original ASP formula:")
    lines.append(
        "    combined_prob_norm = P1 * P2 * P3 * P4 * P5 / 100000000"
    )
    lines.append(f"    Integer factors used by ASP: {[original_norm[c] for c in GROUP_COMPONENTS]}")
    lines.append(f"    Raw integer numerator from ASP factors: {group_product_from_original_ints}")
    lines.append(f"    Original ASP emitted combined_prob_norm(1,{original_combined['1']})")
    lines.append("  Python exact on the same original ASP design:")
    lines.append(f"    combined_prob_norm = {_fmt_fraction(original_exact.combined_prob_norm[1])}")
    lines.append("  Python exact helper selected design:")
    lines.append(f"    combined_prob_norm = {_fmt_fraction(helper.precise_math.combined_prob_norm[1])}")
    lines.append("  LUT/log-sum selected design:")
    lines.append(f"    member_log_weight = {lut.member_log_weight}")
    lines.append(f"    group_ln_sum      = {lut.group_ln_sum[1]}")
    lines.append("    exact product after Python finish:")
    lines.append(f"    combined_prob_norm = {_fmt_fraction(lut.precise_math.combined_prob_norm[1])}")
    lines.append("")

    lines.append("M5. Denormalization")
    lines.append("  new_prob_denormalized = combined_prob_norm * 975 / 1000 + 250")
    lines.append(f"  Original ASP emitted: {original_denorm['c1']}")
    lines.append(f"  Python exact on original ASP design: {_fmt_fraction(original_exact.new_prob_denormalized['c1'])}")
    lines.append(f"  Python exact helper selected design: {_fmt_fraction(helper.precise_math.new_prob_denormalized['c1'])}")
    lines.append(f"  LUT/log-sum selected design: {_fmt_fraction(lut.precise_math.new_prob_denormalized['c1'])}")
    lines.append("")

    lines.append("M6. Group new_risk = impact * denormalized_prob / 100")
    lines.append(f"  {'Asset':<8} {'Original ASP':>18} {'Python exact on ASP design':>28} {'Helper exact design':>22} {'LUT design':>18}")
    lines.append(f"  {'-' * 8} {'-' * 18} {'-' * 28} {'-' * 22} {'-' * 18}")
    for asset in ("c1r1", "c2r1", "c3r1", "c4r1", "c5r1"):
        orig_pair = f"{original_new_risk[asset]['read']}/{original_new_risk[asset]['write']}"
        asp_exact_pair = f"{original_exact.rounded_risk[asset]['read']}/{original_exact.rounded_risk[asset]['write']}"
        helper_pair = f"{helper.precise_math.rounded_risk[asset]['read']}/{helper.precise_math.rounded_risk[asset]['write']}"
        lut_pair = f"{lut.precise_math.rounded_risk[asset]['read']}/{lut.precise_math.rounded_risk[asset]['write']}"
        lines.append(
            f"  {asset:<8} {orig_pair:>18} {asp_exact_pair:>28} {helper_pair:>22} {lut_pair:>18}"
        )
    lines.append("")

    lines.append("Totals")
    lines.append(f"  Original ASP selected design total risk (raw ASP): {sum(max(v.values()) for v in original_new_risk.values())}")
    lines.append(f"  Python exact on original ASP design: {original_exact.total_risk}")
    lines.append(f"  Python exact helper selected design: {helper.precise_math.total_risk}")
    lines.append(f"  LUT/log-sum selected design: {lut.precise_math.total_risk}")

    report = "\n".join(lines)
    print(report)
    REPORT_PATH.write_text(report, encoding="utf-8")
    print(f"\nWrote {REPORT_PATH}")


if __name__ == "__main__":
    main()
