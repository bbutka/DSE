from __future__ import annotations

from pathlib import Path

from tc9_lut_phase1 import benchmark_against_existing


BASE_DIR = Path(__file__).resolve().parent
REPORT_PATH = BASE_DIR / "tc9_lut_benchmark_report.txt"


def _format_architecture(security: dict[str, str], logging: dict[str, str]) -> list[str]:
    return [f"  {component}: security={security[component]} logging={logging[component]}" for component in sorted(security)]


def main() -> None:
    benchmark = benchmark_against_existing(BASE_DIR)
    precise = benchmark.precise_selection
    lut = benchmark.lut_selection
    cpsat = benchmark.cpsat_selection

    lines: list[str] = []
    lines.append("=" * 80)
    lines.append("tc9 LUT Phase 1 Benchmark")
    lines.append("=" * 80)
    lines.append("")
    lines.append("Reference model")
    lines.append("  Exact Python helper over Clingo's approximate-optimal Phase 1 frontier")
    lines.append(f"  Runtime (s): {benchmark.precise_runtime_seconds:.3f}")
    lines.append(f"  Frontier quality: approximate-optimal frontier size = {precise.approx_frontier_size}")
    lines.append(f"  Exact total risk: {precise.precise_math.total_risk}")
    lines.append(
        "  Resources: "
        f"LUTs={precise.phase1.total_luts}, FFs={precise.phase1.total_ffs}, "
        f"DSPs={precise.phase1.total_dsps}, LUTRAM={precise.phase1.total_lutram}, "
        f"BRAM={precise.phase1.total_bram}, Power={precise.phase1.total_power}"
    )
    lines.append("")
    lines.extend(_format_architecture(precise.phase1.security, precise.phase1.logging))
    lines.append("")
    lines.append("LUT/log-sum Phase 1")
    lines.append(f"  Runtime (s): {benchmark.lut_runtime_seconds:.3f}")
    lines.append(f"  Frontier quality: approximate-optimal frontier size = {lut.approx_frontier_size}")
    lines.append(f"  Approximate optimal cost tuple: {lut.approx_opt_cost}")
    lines.append(f"  Exact total risk after Python finish: {lut.precise_math.total_risk}")
    lines.append(
        "  Resources: "
        f"LUTs={lut.phase1.total_luts}, FFs={lut.phase1.total_ffs}, "
        f"DSPs={lut.phase1.total_dsps}, LUTRAM={lut.phase1.total_lutram}, "
        f"BRAM={lut.phase1.total_bram}, Power={lut.phase1.total_power}"
    )
    if lut.group_ln_sum:
        lines.append(f"  Group log-sums: {lut.group_ln_sum}")
    if lut.member_prob_scaled:
        lines.append(f"  Member probabilities (scaled): {lut.member_prob_scaled}")
    lines.append("")
    lines.extend(_format_architecture(lut.phase1.security, lut.phase1.logging))
    lines.append("")
    lines.append("CP-SAT exact Phase 1")
    lines.append(f"  Runtime (s): {benchmark.cpsat_runtime_seconds:.3f}")
    frontier_quality = (
        f"{cpsat.exact_frontier_size}+ (truncated at {cpsat.exact_frontier_limit})"
        if cpsat.exact_frontier_truncated
        else str(cpsat.exact_frontier_size)
    )
    lines.append(f"  Frontier quality: exact-optimal frontier size = {frontier_quality}")
    lines.append(f"  Exact total risk: {cpsat.precise_math.total_risk}")
    lines.append(
        "  Resources: "
        f"LUTs={cpsat.resources['luts']}, FFs={cpsat.resources['ffs']}, "
        f"DSPs={cpsat.resources['dsps']}, LUTRAM={cpsat.resources['lutram']}, "
        f"BRAM={cpsat.resources['bram']}, Power={cpsat.resources['power']}"
    )
    lines.append("")
    lines.extend(_format_architecture(cpsat.security, cpsat.logging))
    lines.append("")
    lines.append("Comparison")
    lines.append(
        f"  Same architecture as precise-helper: "
        f"{precise.phase1.security == lut.phase1.security and precise.phase1.logging == lut.phase1.logging}"
    )
    lines.append(
        f"  Same architecture as CP-SAT: "
        f"{cpsat.security == lut.phase1.security and cpsat.logging == lut.phase1.logging}"
    )
    lines.append(
        f"  Exact risk delta vs precise-helper: "
        f"{lut.precise_math.total_risk - precise.precise_math.total_risk}"
    )
    lines.append(
        f"  Exact risk delta vs CP-SAT: "
        f"{lut.precise_math.total_risk - cpsat.precise_math.total_risk}"
    )
    lines.append("")
    lines.append("Per-asset exact max-risk comparison")
    lines.append(f"  {'Asset':<8} {'Helper':>8} {'LUT':>8} {'CP-SAT':>8}")
    lines.append(f"  {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8}")
    for asset in sorted(precise.precise_math.rounded_max_risk):
        lines.append(
            f"  {asset:<8} "
            f"{precise.precise_math.rounded_max_risk[asset]:>8} "
            f"{lut.precise_math.rounded_max_risk[asset]:>8} "
            f"{cpsat.precise_math.rounded_max_risk[asset]:>8}"
        )

    report = "\n".join(lines)
    print(report)
    REPORT_PATH.write_text(report, encoding="utf-8")
    print(f"\nWrote {REPORT_PATH}")


if __name__ == "__main__":
    main()
