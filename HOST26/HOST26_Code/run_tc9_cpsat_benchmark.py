from __future__ import annotations

from pathlib import Path

from tc9_cpsat_phase1 import benchmark_against_precise_helper


BASE_DIR = Path(__file__).resolve().parent
REPORT_PATH = BASE_DIR / "tc9_cpsat_benchmark_report.txt"


def _format_architecture(security: dict[str, str], logging: dict[str, str]) -> list[str]:
    rows = []
    for component in sorted(security):
        rows.append(f"  {component}: security={security[component]} logging={logging[component]}")
    return rows


def main() -> None:
    benchmark = benchmark_against_precise_helper(BASE_DIR)
    precise = benchmark.precise_selection
    cpsat = benchmark.cpsat_selection

    lines: list[str] = []
    lines.append("=" * 80)
    lines.append("tc9 CP-SAT Phase 1 Benchmark")
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
        f"  Same selected architecture: "
        f"{precise.phase1.security == cpsat.security and precise.phase1.logging == cpsat.logging}"
    )
    lines.append(
        f"  Exact risk improvement: {precise.precise_math.total_risk} -> {cpsat.precise_math.total_risk} "
        f"(delta {cpsat.precise_math.total_risk - precise.precise_math.total_risk})"
    )
    lines.append("")
    lines.append("Known-flow normalized path products")
    lines.append("  Non-component path nodes are held at normalized probability 1.0 in this benchmark.")
    lines.append(f"  {'Source':<16} {'Flow':<18} {'Path':<36} {'Product':>18}")
    lines.append(f"  {'-' * 16} {'-' * 18} {'-' * 36} {'-' * 18}")
    for source, flow_id, path, product in benchmark.path_rows:
        lines.append(f"  {source:<16} {flow_id:<18} {path:<36} {product:>18}")

    report = "\n".join(lines)
    print(report)
    REPORT_PATH.write_text(report, encoding="utf-8")
    print(f"\nWrote {REPORT_PATH}")


if __name__ == "__main__":
    main()
