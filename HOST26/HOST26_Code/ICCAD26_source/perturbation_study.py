"""Impact score perturbation study: +/-1 random noise, 100 trials on OT case."""
import json, sys, os, time, random, copy
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from iccad_cpsat_benchmark import (
    parse_catalog, parse_testcase, parse_profile, solve_cpsat,
    CLINGO_DIR, TESTCASE_DIR,
)
from pathlib import Path

CATALOG = CLINGO_DIR / "security_features_inst.lp"
TC_PATH = TESTCASE_DIR / "testCaseOT_inst.lp"
PROFILE_PATH = CLINGO_DIR / "tgt_system_inst_ot1.lp"

catalog = parse_catalog(CATALOG)
base_tc = parse_testcase(TC_PATH)
profile = parse_profile(PROFILE_PATH)

# Get baseline
baseline = solve_cpsat(base_tc, profile, catalog)
print(f"Baseline: obj={baseline.objective}")

random.seed(42)
N_TRIALS = 100
results = []

for trial in range(N_TRIALS):
    # Perturb impacts by +/-1, clamped to [1, 10]
    tc = copy.deepcopy(base_tc)
    for key in list(tc.impact.keys()):
        delta = random.choice([-1, 0, 1])
        tc.impact[key] = max(1, min(10, tc.impact[key] + delta))

    r = solve_cpsat(tc, profile, catalog)
    if r.satisfiable:
        sec_counts = {}
        for v in r.security.values():
            sec_counts[v] = sec_counts.get(v, 0) + 1
        results.append({
            "trial": trial, "objective": r.objective,
            "security": sec_counts,
        })
    if (trial + 1) % 20 == 0:
        print(f"  Trial {trial+1}/{N_TRIALS} done")

objectives = [r["objective"] for r in results]
print(f"\nResults over {len(results)} trials:")
print(f"  Baseline obj: {baseline.objective}")
print(f"  Mean obj:     {sum(objectives)/len(objectives):.1f}")
print(f"  Min obj:      {min(objectives)}")
print(f"  Max obj:      {max(objectives)}")
print(f"  Std dev:      {(sum((o - sum(objectives)/len(objectives))**2 for o in objectives)/len(objectives))**0.5:.1f}")

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "perturbation_study.json")
with open(out, "w") as f:
    json.dump({"baseline": baseline.objective, "trials": results,
               "mean": sum(objectives)/len(objectives),
               "std": (sum((o - sum(objectives)/len(objectives))**2 for o in objectives)/len(objectives))**0.5,
               "min": min(objectives), "max": max(objectives)}, f, indent=2)
print(f"Saved to {out}")

# Histogram
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

fig, ax = plt.subplots(figsize=(4.5, 3))
ax.hist(objectives, bins=20, color="#1f77b4", edgecolor="white", alpha=0.8)
ax.axvline(baseline.objective, color="#d62728", linewidth=2, linestyle="--", label=f"Baseline ({baseline.objective})")
ax.set_xlabel("Optimal Total Risk", fontsize=10)
ax.set_ylabel("Count (of 100 trials)", fontsize=10)
ax.legend(fontsize=9)
fig.tight_layout()
img_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Images")
fig.savefig(os.path.join(img_dir, "perturbation_hist.pdf"), bbox_inches="tight", dpi=300)
fig.savefig(os.path.join(img_dir, "perturbation_hist.png"), bbox_inches="tight", dpi=300)
print("Saved perturbation_hist.pdf/png")
