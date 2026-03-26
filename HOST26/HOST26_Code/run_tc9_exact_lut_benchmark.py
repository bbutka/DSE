from __future__ import annotations

from pathlib import Path

import clingo

from runClingo_tc9_precise import phase1_precise
from tc9_cpsat_phase1 import solve_cpsat_phase1


BASE_DIR = Path(__file__).resolve().parent
REPORT_PATH = BASE_DIR / "tc9_exact_lut_benchmark_report.txt"

ORIGINAL_FILES = [
    "testCases/testCase9_inst.lp",
    "Clingo/security_features_inst.lp",
    "Clingo/tgt_system_tc9_inst.lp",
    "Clingo/init_enc.lp",
    "Clingo/opt_redundancy_enc.lp",
    "Clingo/opt_latency_enc.lp",
    "Clingo/opt_power_enc.lp",
    "Clingo/opt_resource_enc.lp",
    "Clingo/bridge_enc.lp",
]

EXACT_LUT_FILES = [
    "testCases/testCase9_inst.lp",
    "Clingo/security_features_inst.lp",
    "Clingo/tgt_system_tc9_inst.lp",
    "Clingo/init_enc.lp",
    "Clingo/opt_redundancy_generic_enc.lp",
    "Clingo/opt_latency_enc.lp",
    "Clingo/opt_power_enc.lp",
    "Clingo/opt_resource_enc.lp",
    "Clingo/bridge_enc.lp",
]


def _solve(files: list[str], args: list[str]) -> tuple[list[clingo.Symbol], tuple[int, ...]]:
    ctl = clingo.Control(args)
    for rel in files:
        ctl.load(str(BASE_DIR / rel))
    ctl.ground([("base", [])])
    last_model: list[clingo.Symbol] = []
    last_cost: tuple[int, ...] = ()

    def on_model(model: clingo.Model) -> None:
        nonlocal last_model, last_cost
        last_model = list(model.symbols(shown=True))
        last_cost = tuple(model.cost)

    result = ctl.solve(on_model=on_model)
    if result.unsatisfiable or not last_model:
        raise RuntimeError("Solve returned no model")
    return last_model, last_cost


def _parse(symbols: list[clingo.Symbol]) -> dict[str, object]:
    parsed: dict[str, object] = {
        "security": {},
        "logging": {},
        "new_risk": {},
        "combined_prob_norm": {},
        "new_prob_denorm": {},
        "resources": {},
    }
    for sym in symbols:
        name = sym.name
        args = sym.arguments
        if name == "selected_security" and len(args) == 2 and str(args[0]).startswith("c") and "r" not in str(args[0]):
            parsed["security"][str(args[0])] = str(args[1])
        elif name == "selected_logging" and len(args) == 2 and str(args[0]).startswith("c") and "r" not in str(args[0]):
            parsed["logging"][str(args[0])] = str(args[1])
        elif name == "combined_prob_norm" and len(args) == 2:
            parsed["combined_prob_norm"][str(args[0])] = args[1].number
        elif name == "new_prob_denormalized" and len(args) == 2:
            parsed["new_prob_denorm"][str(args[0])] = args[1].number
        elif name == "new_risk" and len(args) == 4:
            parsed["new_risk"].setdefault(str(args[1]), {})[str(args[2])] = args[3].number
        elif name.startswith("total_") and len(args) == 1:
            parsed["resources"][name] = args[0].number
    return parsed


def _format_architecture(parsed: dict[str, object]) -> list[str]:
    security = parsed["security"]
    logging = parsed["logging"]
    rows: list[str] = []
    for component in sorted(security):
        rows.append(f"  {component}: security={security[component]} logging={logging[component]}")
    return rows


def _max_total(parsed: dict[str, object]) -> int:
    return sum(max(actions.values()) for actions in parsed["new_risk"].values())


def main() -> None:
    original_symbols, original_cost = _solve(ORIGINAL_FILES, ["-n", "0"])
    exact_symbols, exact_cost = _solve(EXACT_LUT_FILES, ["-n", "0", "--opt-mode=optN", "--warn=none"])
    original = _parse(original_symbols)
    exact_lut = _parse(exact_symbols)
    helper = phase1_precise()
    cpsat = solve_cpsat_phase1(BASE_DIR)

    lines: list[str] = []
    lines.append("=" * 84)
    lines.append("tc9 Exact LUT Replacement Benchmark")
    lines.append("=" * 84)
    lines.append("")
    lines.append("Equation replacement check")
    lines.append("  Original size-5 integer inputs from ASP's selected tc9 model:")
    lines.append("    P1=589, P2=589, P3=384, P4=589, P5=589")
    lines.append("  Original ASP output:")
    lines.append(f"    combined_prob_norm(1,{original['combined_prob_norm']['1']})")
    lines.append("  Exact LUT output for the same inputs:")
    lines.append("    combined_prob_norm_size5_lut(589,589,384,589,589,462160)")
    lines.append("")
    lines.append("Original ASP Phase 1")
    lines.append(f"  Cost tuple: {original_cost}")
    lines.append(f"  combined_prob_norm(1): {original['combined_prob_norm']['1']}")
    lines.append(f"  new_prob_denormalized(c1): {original['new_prob_denorm']['c1']}")
    lines.append(f"  Total max-risk sum: {_max_total(original)}")
    lines.append("")
    lines.extend(_format_architecture(original))
    lines.append("")
    lines.append("Exact-LUT Phase 1")
    lines.append(f"  Cost tuple: {exact_cost}")
    lines.append(f"  combined_prob_norm(1): {exact_lut['combined_prob_norm']['1']}")
    lines.append(f"  new_prob_denormalized(c1): {exact_lut['new_prob_denorm']['c1']}")
    lines.append(f"  Total max-risk sum: {_max_total(exact_lut)}")
    lines.append(
        "  Resources: "
        f"LUTs={exact_lut['resources'].get('total_luts_used', 0)}, "
        f"FFs={exact_lut['resources'].get('total_ffs_used', 0)}, "
        f"DSPs={exact_lut['resources'].get('total_dsps_used', 0)}, "
        f"LUTRAM={exact_lut['resources'].get('total_lutram_used', 0)}, "
        f"BRAM={exact_lut['resources'].get('total_bram_used', 0)}, "
        f"Power={exact_lut['resources'].get('total_power_used', 0)}"
    )
    lines.append("")
    lines.extend(_format_architecture(exact_lut))
    lines.append("")
    lines.append("Comparison to existing benchmarks")
    lines.append(f"  Exact-LUT total max-risk sum: {_max_total(exact_lut)}")
    lines.append(f"  Python helper exact total risk: {helper.precise_math.total_risk}")
    lines.append(f"  CP-SAT exact total risk: {cpsat.precise_math.total_risk}")

    report = "\n".join(lines)
    print(report)
    REPORT_PATH.write_text(report, encoding="utf-8")
    print(f"\nWrote {REPORT_PATH}")


if __name__ == "__main__":
    main()
