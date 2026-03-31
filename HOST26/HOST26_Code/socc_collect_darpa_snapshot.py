import json
import sys
import time
from pathlib import Path


TOOL_ROOT = Path(r"D:\DSE\DSE_ADD")
OUT_ROOT = Path(r"D:\DSE\DesignSpaceExplorationforSecurity-main\DesignSpaceExplorationforSecurity-main\HOST26\HOST26_Code")
sys.path.insert(0, str(TOOL_ROOT))

import runClingo_darpa_uav as darpa


STRATEGIES = ["max_security", "min_resources", "balanced"]


def collect():
    rows = []
    for strategy in STRATEGIES:
        row = {"case": "DARPA_UAV", "strategy": strategy, "scenario_count": len(darpa.SCENARIOS)}

        t0 = time.perf_counter()
        p1 = darpa.phase1_optimise(strategy)
        row["phase1_secs"] = round(time.perf_counter() - t0, 3)
        row["p1_sat"] = True
        row["p1_optimal"] = p1.optimal
        row["risk"] = p1.total_risk()
        row["luts"] = p1.total_luts
        row["ffs"] = p1.total_ffs
        row["lutram"] = p1.total_lutram
        row["bram"] = p1.total_bram
        row["power_mw"] = p1.total_power

        t1 = time.perf_counter()
        p2 = darpa.phase2_zta(p1)
        row["phase2_secs"] = round(time.perf_counter() - t1, 3)
        row["p2_sat"] = p2.satisfiable
        row["p2_optimal"] = p2.optimal
        row["firewalls"] = sorted(set(p2.placed_fws))
        row["policy_servers"] = sorted(set(p2.placed_ps))
        row["fw_count"] = len(set(p2.placed_fws))
        row["ps_count"] = len(set(p2.placed_ps))
        row["excess_privs"] = len(p2.excess_privileges)
        row["trust_gaps_rot"] = len(p2.trust_gap_rot)
        row["trust_gaps_sboot"] = len(p2.trust_gap_sboot)
        row["trust_gaps_attest"] = len(p2.trust_gap_attest)

        t2 = time.perf_counter()
        scenarios = darpa.phase3_all(p1, p2)
        row["phase3_secs"] = round(time.perf_counter() - t2, 3)
        sat_scenarios = [s for s in scenarios if s.satisfiable]
        worst = max(sat_scenarios, key=lambda s: s.total_risk)
        baseline = next((s for s in sat_scenarios if s.name == "baseline"), None)
        row["worst_scenario"] = worst.name
        row["worst_risk"] = round(worst.total_risk, 3)
        row["worst_ratio"] = round(worst.total_risk / baseline.total_risk, 3) if baseline and baseline.total_risk else None

        row["total_secs"] = round(row["phase1_secs"] + row["phase2_secs"] + row["phase3_secs"], 3)
        rows.append(row)
    return rows


def to_markdown(rows):
    lines = ["# SOCC 2026 DARPA UAV Evidence Snapshot", ""]
    lines.append("| Strategy | Risk | LUTs | FFs | Power (mW) | FWs | PSs | Excess Privs | No-RoT | P1 (s) | P2 (s) | P3 (s) | Total (s) | Worst Scenario | Worst Ratio |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|")
    for r in rows:
        lines.append(
            f"| {r['strategy']} | {r['risk']} | {r['luts']} | {r['ffs']} | {r['power_mw']} | "
            f"{r['fw_count']} | {r['ps_count']} | {r['excess_privs']} | {r['trust_gaps_rot']} | "
            f"{r['phase1_secs']} | {r['phase2_secs']} | {r['phase3_secs']} | {r['total_secs']} | "
            f"{r['worst_scenario']} | {r['worst_ratio']} |"
        )
    lines.append("")
    return "\n".join(lines)


def main():
    rows = collect()
    (OUT_ROOT / "SOCC_2026_DARPA_UAV_Evidence_Snapshot.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    (OUT_ROOT / "SOCC_2026_DARPA_UAV_Evidence_Snapshot.md").write_text(to_markdown(rows), encoding="utf-8")
    print(OUT_ROOT / "SOCC_2026_DARPA_UAV_Evidence_Snapshot.json")
    print(OUT_ROOT / "SOCC_2026_DARPA_UAV_Evidence_Snapshot.md")


if __name__ == "__main__":
    main()
