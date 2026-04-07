"""Run and document baseline-vs-revised Pixhawk 6X architecture comparisons."""

from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dse_tool.agents.phase1_mathopt_agent import Phase1MathOptAgent  # noqa: E402
from dse_tool.agents.phase2_agent import Phase2Agent  # noqa: E402
from dse_tool.agents.phase3_agent import Phase3Agent, generate_scenarios  # noqa: E402
from dse_tool.core.architecture_delta import compare_network_models  # noqa: E402
from dse_tool.core.architecture_comparison_report import (  # noqa: E402
    build_architecture_comparison_summary,
    format_architecture_comparison,
)
from dse_tool.core.asp_generator import (  # noqa: E402
    ASPGenerator,
    make_pixhawk6x_dual_ps_network,
    make_pixhawk6x_uav_network,
)
from dse_tool.core.solution_parser import SolutionResult  # noqa: E402
from dse_tool.core.solution_ranker import SolutionRanker  # noqa: E402


CLINGO_DIR = PROJECT_ROOT / "Clingo"
OUTPUT_PATH = PROJECT_ROOT / "PIXHAWK6X_ARCHITECTURE_COMPARISON.md"
STRATEGIES = ("max_security", "balanced", "min_resources")
OBJECTIVE_MODES = ("cost_only", "control_plane")
DETERMINISTIC_CLINGO = {"clingo_threads": 1}
DETERMINISTIC_MATHOPT = {
    "phase1_backend": "cpsat",
    "ilp_solver": "cpsat",
    "cpsat_threads": 1,
}


def _phase2_solver_config(objective_mode: str) -> dict:
    cfg = dict(DETERMINISTIC_CLINGO)
    if objective_mode == "control_plane":
        cfg["phase2_objective"] = "control_plane"
    return cfg


def _analyze(model, strategy: str, objective_mode: str, timeout: int = 300):
    facts = ASPGenerator(model).generate()
    scenarios = generate_scenarios(model, full=True)

    p1 = Phase1MathOptAgent(
        network_model=model,
        strategy=strategy,
        timeout=timeout,
        solver_config=DETERMINISTIC_MATHOPT,
    ).run()
    p2 = Phase2Agent(
        clingo_dir=str(CLINGO_DIR),
        testcase_lp="",
        phase1_result=p1,
        strategy=strategy,
        extra_instance_facts=facts,
        timeout=timeout,
        solver_config=_phase2_solver_config(objective_mode),
    ).run()
    p3 = Phase3Agent(
        clingo_dir=str(CLINGO_DIR),
        testcase_lp="",
        phase1_result=p1,
        phase2_result=p2,
        strategy=strategy,
        timeout=timeout,
        full_scenarios=True,
        extra_instance_facts=facts,
        solver_config=DETERMINISTIC_CLINGO,
    ).run(model_scenarios=scenarios)

    sol = SolutionResult(strategy=strategy, label=f"{model.name} {strategy}", phase1=p1, phase2=p2, scenarios=p3)
    SolutionRanker([sol]).rank()
    baseline = next((s for s in p3 if s.name == "baseline" and s.satisfiable), None)
    worst = sol.worst_scenario()
    return {
        "solution": sol,
        "phase1_total_risk": p1.total_risk(),
        "phase1_luts": p1.total_luts,
        "phase1_power": p1.total_power,
        "placed_fws": sorted(set(p2.placed_fws)),
        "placed_ps": sorted(set(p2.placed_ps)),
        "phase2_penalty": p2.resilience_objective_penalty(),
        "scenario_count": len(p3),
        "baseline_risk": baseline.total_risk if baseline else None,
        "worst_name": worst.name if worst else "",
        "worst_risk": worst.total_risk if worst else None,
    }


def _fmt(value):
    if value is None:
        return "N/A"
    if isinstance(value, float):
        return f"{value:.1f}"
    return str(value)


def main() -> None:
    baseline_model = make_pixhawk6x_uav_network()
    revised_model = make_pixhawk6x_dual_ps_network()
    delta = compare_network_models(baseline_model, revised_model)

    results = {mode: {"baseline": {}, "revised": {}} for mode in OBJECTIVE_MODES}
    for mode in OBJECTIVE_MODES:
        for strategy in STRATEGIES:
            results[mode]["baseline"][strategy] = _analyze(baseline_model, strategy, mode)
            results[mode]["revised"][strategy] = _analyze(revised_model, strategy, mode)

    summary = build_architecture_comparison_summary(
        baseline_model,
        revised_model,
        baseline_solution=results["control_plane"]["baseline"]["max_security"]["solution"],
        candidate_solution=results["control_plane"]["revised"]["max_security"]["solution"],
    )

    fw_governance_delta = sorted(set(revised_model.fw_governs) - set(baseline_model.fw_governs))
    removed_fw_governance = sorted(set(baseline_model.fw_governs) - set(revised_model.fw_governs))

    lines = [
        "# Pixhawk 6X Baseline vs Revised Architecture Comparison",
        "",
        "Date: April 7, 2026",
        "",
        "## Compared Architectures",
        "",
        f"- baseline: `{baseline_model.name}`",
        f"- revised: `{revised_model.name}`",
        "",
        "## What Was Added",
        "",
        f"- added component(s): {', '.join(delta.added_components) or 'none'}",
        f"- added candidate policy server(s): {', '.join(delta.added_ps_candidates) or 'none'}",
        f"- added link(s): {', '.join(f'{a}->{b}' for a, b in delta.added_links) or 'none'}",
        "",
        "## Why It Was Added",
        "",
        "- The baseline Pixhawk UAV model has a single control-plane candidate, `ps_fmu`, governing every candidate PEP.",
        "- The revised variant adds `ps_io` so the I/O and actuator protection paths can be governed separately from the FMU-side perimeter.",
        "- This is intended to test whether splitting control-plane authority reduces the single-policy-server concentration identified in the baseline analysis.",
        "",
        "## Governance Change",
        "",
        f"- governance edges added: {', '.join(f'{ps}->{fw}' for ps, fw in fw_governance_delta) or 'none'}",
        f"- governance edges removed: {', '.join(f'{ps}->{fw}' for ps, fw in removed_fw_governance) or 'none'}",
        "",
        "## Per-Strategy Results",
        "",
        "| Objective | Strategy | Architecture | P1 Risk | P1 LUTs | P1 Power (mW) | Placed FWs | Placed PS | P2 Penalty | Baseline Risk | Worst Scenario | Worst Risk |",
        "| --- | --- | --- | ---: | ---: | ---: | --- | --- | ---: | ---: | --- | ---: |",
    ]

    for mode in OBJECTIVE_MODES:
        for strategy in STRATEGIES:
            for label in ("baseline", "revised"):
                row = results[mode][label][strategy]
                lines.append(
                    f"| `{mode}` | `{strategy}` | `{label}` | "
                    f"{_fmt(row['phase1_total_risk'])} | "
                    f"{_fmt(row['phase1_luts'])} | "
                    f"{_fmt(row['phase1_power'])} | "
                    f"{', '.join(row['placed_fws']) or 'none'} | "
                    f"{', '.join(row['placed_ps']) or 'none'} | "
                    f"{_fmt(row['phase2_penalty'])} | "
                    f"{_fmt(row['baseline_risk'])} | "
                    f"{row['worst_name'] or 'N/A'} | "
                    f"{_fmt(row['worst_risk'])} |"
                )

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `cost_only` reproduces the original behavior: all three strategies still place only `pep_telem1` and `ps_fmu`.",
            "- `control_plane` adds a resilience-aware Phase 2 penalty for leaving safety-critical PEPs unplaced and for concentrating critical PEP governance under one PS.",
            "- Under `control_plane`, the baseline single-PS architecture still places only `pep_telem1`, but it pays a non-zero Phase 2 penalty because safety-critical paths remain unprotected.",
            "- Under `control_plane`, the revised dual-PS architecture places `pep_px4io`, `pep_can1`, `pep_can2`, and `pep_telem1`, and it activates both `ps_fmu` and `ps_io` with zero Phase 2 penalty.",
            "- This is the desired solver-discovered outcome: the resilience-aware objective makes the dual-PS architecture preferable without hard-forcing the second policy server.",
            "- In the targeted `ps_fmu_compromise` Phase 3 scenario, the revised design keeps one policy server active and leaves only `pep_telem1` ungoverned; `pep_px4io`, `pep_can1`, and `pep_can2` remain governed by `ps_io`.",
            "- The top-level worst-case risk metric does not yet improve, so the current benefit is localized control-plane containment rather than a broad reduction in global scenario risk.",
            "",
            "## Control-Plane Objective Detailed Comparison",
            "",
            "```text",
            format_architecture_comparison(summary),
            "```",
        ]
    )

    OUTPUT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(OUTPUT_PATH)


if __name__ == "__main__":
    main()
