"""Generate a current DASC 2026 paper data snapshot from the integrated DSE_Core flow."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CLINGO_DIR = PROJECT_ROOT / "Clingo"
OUTPUT_JSON = PROJECT_ROOT / "tools" / "dasc_2026_snapshot.json"
OUTPUT_MD = PROJECT_ROOT / "tools" / "dasc_2026_snapshot.md"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from dse_tool.agents.phase1_mathopt_agent import Phase1MathOptAgent  # noqa: E402
from dse_tool.agents.phase2_agent import Phase2Agent  # noqa: E402
from dse_tool.agents.phase3_agent import Phase3Agent, generate_scenarios  # noqa: E402
from dse_tool.agents.runtime_agent import RuntimeAgent, RUNTIME_SCENARIOS  # noqa: E402
from dse_tool.core.asp_generator import (  # noqa: E402
    ASPGenerator,
    make_darpa_uav_network,
    make_pixhawk6x_dual_ps_network,
    make_pixhawk6x_uav_network,
    make_tc9_network,
)


STRATEGIES = ("max_security", "min_resources", "balanced")
DETERMINISTIC_MATHOPT = {
    "phase1_backend": "cpsat",
    "ilp_solver": "cpsat",
    "cpsat_threads": 1,
}
DETERMINISTIC_CLINGO = {
    "clingo_threads": 1,
}
PIXHAWK_SAFETY_WEIGHTS = (100, 250, 500, 1000)
PIXHAWK_CONCENTRATION_WEIGHTS = (100, 250, 400, 1000)


def _scenario_summary(results) -> dict:
    worst = max((r for r in results if r.satisfiable), key=lambda r: r.total_risk_scaled, default=None)
    baseline = next((r for r in results if r.name == "baseline" and r.satisfiable), None)
    return {
        "count": len(results),
        "baseline_name": baseline.name if baseline else "",
        "baseline_risk": baseline.total_risk if baseline else None,
        "worst_name": worst.name if worst else "",
        "worst_risk": worst.total_risk if worst else None,
        "worst_scaled": worst.total_risk_scaled if worst else 0,
        "selected": {
            r.name: {
                "risk": r.total_risk,
                "risk_scaled": r.total_risk_scaled,
                "active_ps_count": r.active_ps_count,
                "services_ok": len(r.services_ok),
                "services_degraded": len(r.services_degraded),
                "services_unavail": len(r.services_unavail),
                "capabilities_lost": sorted(r.capabilities_lost),
            }
            for r in results
        },
    }


def _phase2_summary(result) -> dict:
    return {
        "satisfiable": result.satisfiable,
        "placed_fws": sorted(set(result.placed_fws)),
        "placed_ps": sorted(set(result.placed_ps)),
        "zta_cost": result.total_cost,
        "avg_policy_tightness": result.avg_policy_tightness(),
        "excess_privileges": len(result.excess_privileges),
        "missing_privileges": len(result.missing_privileges),
        "trust_gap_rot": len(result.trust_gap_rot),
        "trust_gap_sboot": len(result.trust_gap_sboot),
        "trust_gap_attest": len(result.trust_gap_attest),
        "trust_gap_keys": len(result.trust_gap_keys),
        "unattested_access": len(result.unattested_access),
        "unsigned_ps": len(result.unsigned_ps),
        "policy_tightness": result.policy_tightness,
        "resilience_penalty": result.resilience_objective_penalty(),
    }


def _phase1_summary(result) -> dict:
    return {
        "satisfiable": result.satisfiable,
        "optimal": result.optimal,
        "total_risk": result.total_risk(),
        "total_luts": result.total_luts,
        "total_power": result.total_power,
        "security": result.security,
        "realtime": result.realtime,
        "risk_by_component": result.risk_by_component(),
    }


def _run_case(model, strategy: str, timeout: int = 300, phase2_solver_config: dict | None = None) -> dict:
    facts = ASPGenerator(model).generate()
    scenarios = list(getattr(model, "scenarios", None) or []) or generate_scenarios(model, full=True)

    t0 = time.perf_counter()
    p1 = Phase1MathOptAgent(
        network_model=model,
        strategy=strategy,
        timeout=timeout,
        solver_config=DETERMINISTIC_MATHOPT,
    ).run()
    t1 = time.perf_counter()

    p2 = Phase2Agent(
        clingo_dir=str(CLINGO_DIR),
        testcase_lp="",
        phase1_result=p1,
        strategy=strategy,
        extra_instance_facts=facts,
        timeout=timeout,
        solver_config=phase2_solver_config or DETERMINISTIC_CLINGO,
    ).run()
    t2 = time.perf_counter()

    p3 = Phase3Agent(
        clingo_dir=str(CLINGO_DIR),
        testcase_lp="",
        phase1_result=p1,
        phase2_result=p2,
        strategy=strategy,
        timeout=timeout,
        extra_instance_facts=facts,
        full_scenarios=True,
        solver_config=DETERMINISTIC_CLINGO,
    ).run(model_scenarios=scenarios)
    t3 = time.perf_counter()

    return {
        "timing_s": {
            "phase1": round(t1 - t0, 3),
            "phase2": round(t2 - t1, 3),
            "phase3": round(t3 - t2, 3),
            "total": round(t3 - t0, 3),
        },
        "phase1": _phase1_summary(p1),
        "phase2": _phase2_summary(p2),
        "phase3": _scenario_summary(p3),
    }


def _run_tc9_runtime(timeout: int = 300) -> dict:
    model = make_tc9_network()
    facts = ASPGenerator(model).generate()

    p1 = Phase1MathOptAgent(
        network_model=model,
        strategy="max_security",
        timeout=timeout,
        solver_config=DETERMINISTIC_MATHOPT,
    ).run()
    p2 = Phase2Agent(
        clingo_dir=str(CLINGO_DIR),
        testcase_lp="",
        phase1_result=p1,
        strategy="max_security",
        extra_instance_facts=facts,
        timeout=timeout,
        solver_config=DETERMINISTIC_CLINGO,
    ).run()
    rt = RuntimeAgent(
        clingo_dir=str(CLINGO_DIR),
        testcase_lp="",
        timeout=timeout,
        extra_instance_facts=facts,
        solver_config=DETERMINISTIC_CLINGO,
    )

    adaptive = rt.solve_adaptive(p1, p2, scenarios=list(RUNTIME_SCENARIOS))
    joint = rt.solve_joint(p1)
    joint_adaptive = rt.solve_adaptive(
        p1,
        joint.to_phase2_result(),
        scenarios=list(RUNTIME_SCENARIOS),
        extra_runtime_facts=joint.as_runtime_facts(),
    )

    return {
        "adaptive": {
            r.scenario.name: {
                "mode": r.current_mode,
                "monitors": sorted(r.placed_monitors),
                "monitor_total_cost": r.monitor_total_cost,
                "responses": sorted(r.response_actions),
                "effective_allows": len(r.effective_allows),
            }
            for r in adaptive
        },
        "joint": {
            "satisfiable": joint.satisfiable,
            "optimal": joint.optimal,
            "placed_fws": sorted(joint.placed_fws),
            "placed_ps": sorted(joint.placed_ps),
            "placed_monitors": sorted(joint.placed_monitors),
            "total_zta_cost": joint.total_zta_cost,
            "monitor_total_cost": joint.monitor_total_cost,
            "total_joint_runtime_cost": joint.total_joint_runtime_cost,
            "response_readiness_score": joint.response_readiness_score,
            "detection_strength_score": joint.detection_strength_score,
            "weighted_detection_latency": joint.weighted_detection_latency,
            "false_positive_cost": joint.false_positive_cost,
        },
        "joint_adaptive": {
            r.scenario.name: {
                "mode": r.current_mode,
                "monitors": sorted(r.placed_monitors),
                "monitor_total_cost": r.monitor_total_cost,
                "responses": sorted(r.response_actions),
                "effective_allows": len(r.effective_allows),
            }
            for r in joint_adaptive
        },
    }


def _placement_signature(placed_fws: list[str], placed_ps: list[str]) -> str:
    fw_set = tuple(sorted(set(placed_fws)))
    ps_set = tuple(sorted(set(placed_ps)))
    if fw_set == ("pep_telem1",) and ps_set == ("ps_fmu",):
        return "single_ps_telem_only"
    if fw_set == ("pep_can1", "pep_can2", "pep_px4io", "pep_telem1") and ps_set == ("ps_fmu", "ps_io"):
        return "dual_ps_split"
    return f"fw={','.join(fw_set) or 'none'};ps={','.join(ps_set) or 'none'}"


def _pixhawk_phase2_solver_config(safety_weight: int, concentration_weight: int) -> dict:
    return {
        "clingo_threads": 1,
        "phase2_objective": "control_plane",
        "phase2_safety_fw_penalty_weight": safety_weight,
        "phase2_concentration_penalty_weight": concentration_weight,
    }


def _run_pixhawk_sensitivity(timeout: int = 300) -> dict:
    baseline_model = make_pixhawk6x_uav_network()
    revised_model = make_pixhawk6x_dual_ps_network()
    cache = {}
    for label, model in (("baseline", baseline_model), ("revised", revised_model)):
        for strategy in STRATEGIES:
            cache[(label, strategy)] = Phase1MathOptAgent(
                network_model=model,
                strategy=strategy,
                timeout=timeout,
                solver_config=DETERMINISTIC_MATHOPT,
            ).run()

    rows = []
    for strategy in STRATEGIES:
        for safety in PIXHAWK_SAFETY_WEIGHTS:
            for concentration in PIXHAWK_CONCENTRATION_WEIGHTS:
                for label, model in (("baseline", baseline_model), ("revised", revised_model)):
                    facts = ASPGenerator(model).generate()
                    p2 = Phase2Agent(
                        clingo_dir=str(CLINGO_DIR),
                        testcase_lp="",
                        phase1_result=cache[(label, strategy)],
                        strategy=strategy,
                        extra_instance_facts=facts,
                        timeout=timeout,
                        solver_config=_pixhawk_phase2_solver_config(safety, concentration),
                    ).run()
                    rows.append(
                        {
                            "strategy": strategy,
                            "architecture": label,
                            "safety_weight": safety,
                            "concentration_weight": concentration,
                            "signature": _placement_signature(p2.placed_fws, p2.placed_ps),
                            "zta_cost": p2.total_cost,
                            "penalty": p2.resilience_objective_penalty(),
                        }
                    )
    thresholds = {}
    for strategy in STRATEGIES:
        thresholds[strategy] = {}
        for concentration in PIXHAWK_CONCENTRATION_WEIGHTS:
            threshold = None
            for safety in PIXHAWK_SAFETY_WEIGHTS:
                hit = next(
                    (
                        row for row in rows
                        if row["strategy"] == strategy
                        and row["architecture"] == "revised"
                        and row["concentration_weight"] == concentration
                        and row["safety_weight"] == safety
                        and row["signature"] == "dual_ps_split"
                    ),
                    None,
                )
                if hit:
                    threshold = safety
                    break
            thresholds[strategy][str(concentration)] = threshold
    return {"rows": rows, "thresholds": thresholds}


def _write_markdown(snapshot: dict) -> None:
    lines = [
        "# DASC 2026 Snapshot",
        "",
        "Generated from the current integrated DSE_Core flow.",
        "",
    ]
    for case_name in ("tc9", "darpa"):
        lines.append(f"## {case_name.upper()}")
        lines.append("")
        for strategy in STRATEGIES:
            result = snapshot[case_name][strategy]
            p1 = result["phase1"]
            p2 = result["phase2"]
            p3 = result["phase3"]
            lines.extend(
                [
                    f"### {strategy}",
                    "",
                    f"- Phase 1: risk `{p1['total_risk']}`, LUTs `{p1['total_luts']}`, power `{p1['total_power']} mW`",
                    f"- Phase 2: FWs `{', '.join(p2['placed_fws']) or 'none'}`, PS `{', '.join(p2['placed_ps']) or 'none'}`, excess privileges `{p2['excess_privileges']}`",
                    f"- Phase 3: scenarios `{p3['count']}`, baseline `{p3['baseline_risk']}`, worst `{p3['worst_name']}` = `{p3['worst_risk']}`",
                    "",
                ]
            )
    OUTPUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    snapshot = {
        "tc9": {
            strategy: _run_case(make_tc9_network(), strategy)
            for strategy in STRATEGIES
        },
        "darpa": {
            strategy: _run_case(make_darpa_uav_network(), strategy)
            for strategy in STRATEGIES
        },
        "runtime_tc9": _run_tc9_runtime(),
        "pixhawk_baseline": {
            strategy: _run_case(make_pixhawk6x_uav_network(), strategy)
            for strategy in STRATEGIES
        },
        "pixhawk_control_plane_comparison": {
            "baseline_max_security": _run_case(
                make_pixhawk6x_uav_network(),
                "max_security",
                phase2_solver_config=_pixhawk_phase2_solver_config(250, 250),
            ),
            "revised_max_security": _run_case(
                make_pixhawk6x_dual_ps_network(),
                "max_security",
                phase2_solver_config=_pixhawk_phase2_solver_config(250, 250),
            ),
        },
        "pixhawk_sensitivity": _run_pixhawk_sensitivity(),
    }
    OUTPUT_JSON.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    _write_markdown(snapshot)
    print(OUTPUT_JSON)
    print(OUTPUT_MD)


if __name__ == "__main__":
    main()

