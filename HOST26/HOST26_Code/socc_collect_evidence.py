import json
import sys
import time
from pathlib import Path


TOOL_ROOT = Path(r"D:\DSE\DSE_ADD")
OUT_ROOT = Path(r"D:\DSE\DesignSpaceExplorationforSecurity-main\DesignSpaceExplorationforSecurity-main\HOST26\HOST26_Code")
sys.path.insert(0, str(TOOL_ROOT))

from dse_tool.core.asp_generator import ASPGenerator, make_tc9_network, make_reference_soc
from dse_tool.agents.phase1_agent import Phase1Agent
from dse_tool.agents.phase2_agent import Phase2Agent
from dse_tool.agents.phase3_agent import Phase3Agent, generate_scenarios


CLINGO_DIR = TOOL_ROOT / "Clingo"
STRATEGIES = ["max_security", "min_resources", "balanced"]


def collect_case(case_name, model_factory, full_scenarios=True):
    model = model_factory()
    facts = ASPGenerator(model).generate()
    scenarios = generate_scenarios(model, full=full_scenarios)
    results = []

    for strategy in STRATEGIES:
        row = {"case": case_name, "strategy": strategy, "scenario_count": len(scenarios)}

        t0 = time.perf_counter()
        p1 = Phase1Agent(
            clingo_dir=str(CLINGO_DIR),
            testcase_lp="",
            strategy=strategy,
            extra_instance_facts=facts,
            timeout=120,
        ).run()
        row["phase1_secs"] = round(time.perf_counter() - t0, 3)
        row["p1_sat"] = p1.satisfiable
        row["p1_optimal"] = p1.optimal
        row["risk"] = p1.total_risk() if p1.satisfiable else None
        row["luts"] = p1.total_luts if p1.satisfiable else None
        row["ffs"] = p1.total_ffs if p1.satisfiable else None
        row["lutram"] = p1.total_lutram if p1.satisfiable else None
        row["bram"] = p1.total_bram if p1.satisfiable else None
        row["power_mw"] = p1.total_power if p1.satisfiable else None

        if p1.satisfiable:
            t1 = time.perf_counter()
            p2 = Phase2Agent(
                clingo_dir=str(CLINGO_DIR),
                testcase_lp="",
                phase1_result=p1,
                strategy=strategy,
                timeout=120,
                extra_instance_facts=facts,
            ).run()
            row["phase2_secs"] = round(time.perf_counter() - t1, 3)
            row["p2_sat"] = p2.satisfiable
            row["p2_optimal"] = p2.optimal
            row["firewalls"] = sorted(set(p2.placed_fws)) if p2.satisfiable else []
            row["policy_servers"] = sorted(set(p2.placed_ps)) if p2.satisfiable else []
            row["fw_count"] = len(set(p2.placed_fws)) if p2.satisfiable else 0
            row["ps_count"] = len(set(p2.placed_ps)) if p2.satisfiable else 0
            row["excess_privs"] = len(p2.excess_privileges) if p2.satisfiable else None
            row["trust_gaps_rot"] = len(p2.trust_gap_rot) if p2.satisfiable else None
            row["trust_gaps_sboot"] = len(p2.trust_gap_sboot) if p2.satisfiable else None
            row["trust_gaps_attest"] = len(p2.trust_gap_attest) if p2.satisfiable else None

            if p2.satisfiable:
                t2 = time.perf_counter()
                p3 = Phase3Agent(
                    clingo_dir=str(CLINGO_DIR),
                    testcase_lp="",
                    phase1_result=p1,
                    phase2_result=p2,
                    strategy=strategy,
                    full_scenarios=full_scenarios,
                    timeout=120,
                    extra_instance_facts=facts,
                ).run(model_scenarios=scenarios)
                row["phase3_secs"] = round(time.perf_counter() - t2, 3)
                sat_scenarios = [s for s in p3 if s.satisfiable]
                if sat_scenarios:
                    worst = max(sat_scenarios, key=lambda s: s.total_risk)
                    baseline = next((s for s in sat_scenarios if s.name == "baseline"), None)
                    row["worst_scenario"] = worst.name
                    row["worst_risk"] = round(worst.total_risk, 3)
                    if baseline and baseline.total_risk:
                        row["worst_ratio"] = round(worst.total_risk / baseline.total_risk, 3)
                    else:
                        row["worst_ratio"] = None
                else:
                    row["worst_scenario"] = None
                    row["worst_risk"] = None
                    row["worst_ratio"] = None
            else:
                row["phase3_secs"] = None
        else:
            row["phase2_secs"] = None
            row["phase3_secs"] = None
            row["p2_sat"] = False

        row["total_secs"] = round(sum(v for v in [row.get("phase1_secs"), row.get("phase2_secs"), row.get("phase3_secs")] if isinstance(v, (int, float))), 3)
        results.append(row)

    return results


def render_markdown(results):
    lines = ["# SOCC 2026 Evidence Snapshot", ""]

    for case_name in sorted({r["case"] for r in results}):
        case_rows = [r for r in results if r["case"] == case_name]
        lines.append(f"## {case_name}")
        lines.append("")
        lines.append("| Strategy | Risk | LUTs | FFs | Power (mW) | FWs | PSs | Excess Privs | No-RoT | P1 (s) | P2 (s) | P3 (s) | Total (s) | Worst Scenario | Worst Ratio |")
        lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|")
        for r in case_rows:
            lines.append(
                f"| {r['strategy']} | {r.get('risk','')} | {r.get('luts','')} | {r.get('ffs','')} | "
                f"{r.get('power_mw','')} | {r.get('fw_count','')} | {r.get('ps_count','')} | "
                f"{r.get('excess_privs','')} | {r.get('trust_gaps_rot','')} | "
                f"{r.get('phase1_secs','')} | {r.get('phase2_secs','')} | {r.get('phase3_secs','')} | "
                f"{r.get('total_secs','')} | {r.get('worst_scenario','')} | {r.get('worst_ratio','')} |"
            )
        lines.append("")

    return "\n".join(lines)


def render_method_seed():
    return """# SOCC 2026 Method Table Seed

## Strategy Objectives

| Strategy | Objective Behavior | Source |
|---|---|---|
| `max_security` | uses the default risk-minimizing objective from the ASP encodings | `dse_tool/agents/phase1_agent.py` |
| `min_resources` | adds a secondary LUT minimization objective | `dse_tool/agents/phase1_agent.py` |
| `balanced` | minimizes total risk and then LUTs with explicit strategy-specific objective atoms | `dse_tool/agents/phase1_agent.py` |

## Hard Constraints

| Constraint Type | Enforced In |
|---|---|
| one security feature per component | `init_enc.lp` / phase 1 |
| one logging feature per component | `init_enc.lp` / phase 1 |
| LUT budget | `opt_resource_enc.lp` |
| FF / DSP / LUTRAM / BRAM budget | `opt_resource_enc.lp` |
| power budget | `opt_power_enc.lp` |
| latency cap | `opt_latency_enc.lp` + `bridge_enc.lp` |
| protection mediation / reachability constraints | `zta_policy_enc.lp` |

## Paper Action

Convert this seed into one compact table in the manuscript so the optimization problem is explicit instead of implied.
"""


def main():
    tc9 = collect_case("TC9", make_tc9_network, full_scenarios=True)
    refsoc = collect_case("RefSoC-16", make_reference_soc, full_scenarios=False)
    all_results = tc9 + refsoc

    out_dir = OUT_ROOT
    (out_dir / "SOCC_2026_Evidence_Snapshot.json").write_text(json.dumps(all_results, indent=2), encoding="utf-8")
    (out_dir / "SOCC_2026_Evidence_Snapshot.md").write_text(render_markdown(all_results), encoding="utf-8")
    (out_dir / "SOCC_2026_Method_Table_Seed.md").write_text(render_method_seed(), encoding="utf-8")

    print("Wrote:")
    print(out_dir / "SOCC_2026_Evidence_Snapshot.json")
    print(out_dir / "SOCC_2026_Evidence_Snapshot.md")
    print(out_dir / "SOCC_2026_Method_Table_Seed.md")


if __name__ == "__main__":
    main()
