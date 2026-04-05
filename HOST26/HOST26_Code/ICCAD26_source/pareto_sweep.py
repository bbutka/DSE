"""Pareto sweep: vary LUT cap on OT case, plot risk vs LUTs."""
import json, sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from iccad_cpsat_benchmark import (
    parse_catalog, parse_testcase, parse_profile, solve_cpsat,
    CLINGO_DIR, TESTCASE_DIR,
)
from pathlib import Path

CATALOG = CLINGO_DIR / "security_features_inst.lp"
TC_PATH = TESTCASE_DIR / "testCaseOT_inst.lp"
BASE_PROFILE = CLINGO_DIR / "tgt_system_inst_ot1.lp"

catalog = parse_catalog(CATALOG)
tc = parse_testcase(TC_PATH)
base_profile = parse_profile(BASE_PROFILE)

# Sweep LUT cap from 10,000 to 80,000 in steps of 2,500
results = []
for lut_cap in range(10000, 80001, 2500):
    profile = type(base_profile)(
        name=f"sweep_{lut_cap}",
        capabilities={**base_profile.capabilities, "max_luts": lut_cap},
    )
    t0 = time.perf_counter()
    r = solve_cpsat(tc, profile, catalog)
    t1 = time.perf_counter()
    if r.satisfiable:
        # Count feature types
        sec_counts = {}
        for v in r.security.values():
            sec_counts[v] = sec_counts.get(v, 0) + 1
        log_counts = {}
        for v in r.logging.values():
            log_counts[v] = log_counts.get(v, 0) + 1
        entry = {
            "lut_cap": lut_cap, "objective": r.objective,
            "luts_used": r.luts, "power_used": r.power,
            "time_s": round(t1 - t0, 4),
            "security": sec_counts, "logging": log_counts,
        }
        results.append(entry)
        print(f"LUT cap={lut_cap:>6}: obj={r.objective:>4}, LUTs={r.luts:>6}, t={t1-t0:.3f}s  sec={sec_counts}  log={log_counts}")
    else:
        print(f"LUT cap={lut_cap:>6}: UNSAT")

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pareto_sweep.json")
with open(out, "w") as f:
    json.dump(results, f, indent=2)
print(f"\nSaved {len(results)} points to {out}")

# Generate plot
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

caps = [r["lut_cap"] for r in results]
objs = [r["objective"] for r in results]
luts = [r["luts_used"] for r in results]

fig, ax1 = plt.subplots(figsize=(5, 3.2))
ax1.plot(caps, objs, "o-", color="#d62728", linewidth=2, markersize=5, label="Optimal Risk")
ax1.set_xlabel("LUT Budget Cap", fontsize=10)
ax1.set_ylabel("Optimal Total Risk", fontsize=10, color="#d62728")
ax1.tick_params(axis="y", labelcolor="#d62728")

ax2 = ax1.twinx()
ax2.plot(caps, luts, "s--", color="#1f77b4", linewidth=1.5, markersize=4, label="LUTs Used", alpha=0.7)
ax2.set_ylabel("LUTs Used", fontsize=10, color="#1f77b4")
ax2.tick_params(axis="y", labelcolor="#1f77b4")

# Add diagonal line where cap = used
ax1.axvline(x=min(r["lut_cap"] for r in results if r["luts_used"] < r["lut_cap"]),
            color="gray", linestyle=":", alpha=0.5, label="Constraint no longer binding")

fig.tight_layout()
img_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Images")
fig.savefig(os.path.join(img_dir, "pareto_sweep.pdf"), bbox_inches="tight", dpi=300)
fig.savefig(os.path.join(img_dir, "pareto_sweep.png"), bbox_inches="tight", dpi=300)
print("Saved pareto_sweep.pdf/png")
