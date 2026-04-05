"""Generate ICCAD 2026 paper figures from benchmark data."""

import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(SCRIPT_DIR, "iccad_cpsat_comparison.json")
IMG_DIR = os.path.join(SCRIPT_DIR, "Images")
os.makedirs(IMG_DIR, exist_ok=True)

with open(DATA_FILE) as f:
    data = json.load(f)

# ── Figure 1: Runtime Scaling (log-scale) ──────────────────────────
# Aggregate by component count
from collections import defaultdict
asp_by_comp = defaultdict(list)
cpsat_by_comp = defaultdict(list)

comp_count_map = {
    "testCase1_inst": 3, "testCase2_inst": 8, "testCase3_inst": 1,
    "testCase5_inst": 8, "testCase6_inst": 3, "testCase7_inst": 8,
    "testCase8_inst": 8, "testCase9_inst": 8, "testCaseOT_inst": 20,
}

for entry in data:
    tc = entry["testcase"]
    n = comp_count_map.get(tc, 0)
    if not entry.get("asp_skipped", False):
        asp_by_comp[n].append(entry["asp_time_s"])
    cpsat_by_comp[n].append(entry["cpsat_time_s"])

comps = sorted(asp_by_comp.keys())
asp_means = [np.mean(asp_by_comp[c]) for c in comps]
cpsat_means = [np.mean(cpsat_by_comp[c]) for c in comps]

fig, ax = plt.subplots(figsize=(4.5, 3.2))
ax.semilogy(comps, asp_means, 'o-', color='#d62728', linewidth=2, markersize=7, label='ASP (clingo)')
ax.semilogy(comps, cpsat_means, 's-', color='#1f77b4', linewidth=2, markersize=7, label='CP-SAT (OR-Tools)')

# Annotate speedup at key points
for i, c in enumerate(comps):
    if c in (1, 8, 20):
        speedup = asp_means[i] / cpsat_means[i]
        if speedup >= 1:
            ax.annotate(f'{speedup:.0f}x', xy=(c, asp_means[i]),
                       xytext=(5, 5), textcoords='offset points',
                       fontsize=8, color='#d62728')

ax.set_xlabel('Number of Components', fontsize=10)
ax.set_ylabel('Solve Time (s, log scale)', fontsize=10)
ax.set_xticks(comps)
ax.legend(fontsize=9, loc='upper left')
ax.grid(True, alpha=0.3, which='both')
ax.set_xlim(0, 22)
fig.tight_layout()
fig.savefig(os.path.join(IMG_DIR, "runtime_scaling.pdf"), bbox_inches='tight', dpi=300)
fig.savefig(os.path.join(IMG_DIR, "runtime_scaling.png"), bbox_inches='tight', dpi=300)
print("Saved runtime_scaling.pdf/png")

# ── Figure 2: OpenTitan Feature Assignment Heatmap ─────────────────
# Build the heatmap from OT-A ASP data (the primary profile)
ot_a_list = [e for e in data if e["testcase"] == "testCaseOT_inst" and ("ot1" in e.get("profile","") or "OT-A" in e.get("profile",""))]
if not ot_a_list or ("cpsat_security" not in ot_a_list[0] and "asp_security" not in ot_a_list[0]):
    print("Skipping heatmap: OT-A data with feature assignments not available.")
    import sys; sys.exit(0)
ot_a = ot_a_list[0]

components_order = [
    "keymgr", "cpu", "otbn", "otp", "aes", "hmac", "kmac", "lc",
    "entropy", "dma", "flash", "alert", "sram", "rom", "spi", "i2c",
    "uart0", "uart1", "gpio", "timer"
]

sec_map = {"zero_trust": 3, "dynamic_mac": 2, "mac": 1}
log_map = {"zero_trust_logger": 3, "some_logging": 2, "no_logging": 1}
sec_labels = {3: "ZT", 2: "DM", 1: "MAC"}
log_labels = {3: "ZTL", 2: "SL", 1: "NL"}

sec_src = ot_a.get("cpsat_security", ot_a.get("asp_security", {}))
log_src = ot_a.get("cpsat_logging", ot_a.get("asp_logging", {}))
sec_data = [sec_map[sec_src[c]] for c in components_order]
log_data = [log_map[log_src[c]] for c in components_order]

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.5, 4.2), sharey=True)

# Security feature bar
colors_sec = {1: '#fee08b', 2: '#fdae61', 3: '#d73027'}
bars1 = ax1.barh(range(len(components_order)), [1]*len(components_order),
                 color=[colors_sec[v] for v in sec_data], edgecolor='white', linewidth=0.5)
for i, v in enumerate(sec_data):
    ax1.text(0.5, i, sec_labels[v], ha='center', va='center', fontsize=8, fontweight='bold')
ax1.set_yticks(range(len(components_order)))
ax1.set_yticklabels(components_order, fontsize=8)
ax1.set_xlim(0, 1)
ax1.set_xticks([])
ax1.set_title('Security Feature', fontsize=10)
ax1.invert_yaxis()

# Logging feature bar
colors_log = {1: '#e0e0e0', 2: '#74add1', 3: '#4575b4'}
bars2 = ax2.barh(range(len(components_order)), [1]*len(components_order),
                 color=[colors_log[v] for v in log_data], edgecolor='white', linewidth=0.5)
for i, v in enumerate(log_data):
    ax2.text(0.5, i, log_labels[v], ha='center', va='center', fontsize=8, fontweight='bold')
ax2.set_xlim(0, 1)
ax2.set_xticks([])
ax2.set_title('Logging Feature', fontsize=10)
ax2.invert_yaxis()

# Legends
from matplotlib.patches import Patch
sec_legend = [Patch(facecolor=colors_sec[3], label='Zero Trust (8)'),
              Patch(facecolor=colors_sec[2], label='Dynamic MAC (6)'),
              Patch(facecolor=colors_sec[1], label='MAC (4)')]
log_legend = [Patch(facecolor=colors_log[3], label='ZT Logger (3)'),
              Patch(facecolor=colors_log[2], label='Some Logging (1)'),
              Patch(facecolor=colors_log[1], label='No Logging (0)')]

ax1.legend(handles=sec_legend, loc='lower right', fontsize=7, framealpha=0.9)
ax2.legend(handles=log_legend, loc='lower right', fontsize=7, framealpha=0.9)

fig.suptitle('OpenTitan OT-A Feature Assignments (CP-SAT Optimal)', fontsize=11, y=1.01)
fig.tight_layout()
fig.savefig(os.path.join(IMG_DIR, "ot_feature_heatmap.pdf"), bbox_inches='tight', dpi=300)
fig.savefig(os.path.join(IMG_DIR, "ot_feature_heatmap.png"), bbox_inches='tight', dpi=300)
print("Saved ot_feature_heatmap.pdf/png")

print("Done.")
