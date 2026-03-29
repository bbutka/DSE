# DSE Security Analysis Tool — User Guide

**Version:** HOST26 GUI
**Date:** 2026-03-29
**Target FPGA:** PYNQ-Z2 (Xilinx xc7z020)

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Main Window Layout](#2-main-window-layout)
3. [Network Editor (Left Panel)](#3-network-editor-left-panel)
4. [Toolbar Buttons](#4-toolbar-buttons)
5. [Menu Bar](#5-menu-bar)
6. [Running an Analysis](#6-running-an-analysis)
7. [Understanding the Three Strategies](#7-understanding-the-three-strategies)
8. [Understanding the Three Phases](#8-understanding-the-three-phases)
9. [Results Panel (Right Panel)](#9-results-panel-right-panel)
10. [Phase 1 Detail Dialog](#10-phase-1-detail-dialog)
11. [Phase 2 Detail Dialog](#11-phase-2-detail-dialog)
12. [Phase 3 Detail Dialog](#12-phase-3-detail-dialog)
13. [Compare Strategies Dialog](#13-compare-strategies-dialog)
14. [Executive Summary](#14-executive-summary)
15. [Full Report](#15-full-report)
16. [Show ASP Facts Dialog](#16-show-asp-facts-dialog)
17. [Solver Config Dialog](#17-solver-config-dialog)
18. [Threat Model and Security Framework](#18-threat-model-and-security-framework)
19. [SecureSoC-16 Reference Architecture](#19-securesoc-16-reference-architecture)
20. [TC9 Reference Architecture](#20-tc9-reference-architecture)
21. [Interpreting Results — A Complete Walkthrough](#21-interpreting-results--a-complete-walkthrough)
22. [CSV Export](#22-csv-export)
23. [Regression Testing](#23-regression-testing)
24. [Keyboard Shortcuts](#24-keyboard-shortcuts)
25. [Glossary](#25-glossary)

---

## 1. Getting Started

### Launch the Tool

```
D:\DSE\DSE_ADD> launch.bat
```

This runs `python -m dse_tool` using the system Python 3.12 installation. The main window opens at 1400x800 pixels, centered on screen.

### Quick Start — Run Your First Analysis

1. Click **Load TC9** or **Load RefSoC-16** on the toolbar
2. The network topology appears on the canvas (left panel)
3. Click **Run Analysis**
4. Watch the progress log (upper-right) as all three phases execute
5. Results appear in the three strategy cards (lower-right)
6. Click **Details...** buttons, **Compare Strategies**, or **View Full Report** to explore

---

## 2. Main Window Layout

```
+-------------------------------------------------------------------+
| File  Edit  View  Help                                   (Menu Bar)|
+-------------------------------------------------------------------+
| [Run Analysis] [Stop] [Clear] [Load TC9] [Load RefSoC-16]        |
| [Solver Config] [Show ASP Facts]                    Ready (Toolbar)|
+-------------------------------------------------------------------+
|                          |  Phase Progress Panel                   |
|                          |  ┌─────────────────────────────┐       |
|   Network Editor         |  │ Phase 1: ● Phase 2: ● Phase3│       |
|   (Canvas)               |  │ [00:05] Running...          │       |
|                          |  │ Log messages appear here...  │       |
|                          |  └─────────────────────────────┘       |
|                          +----------------------------------------+
|                          |  Results Panel                          |
|                          |  ┌──────────┬──────────┬──────────┐    |
|                          |  │ Max Sec  │ Min Res  │ Balanced │    |
|                          |  │ SAT      │ SAT      │ SAT      │    |
|                          |  │ LUTs: .. │ LUTs: .. │ LUTs: .. │    |
|                          |  │ FFs:  .. │ FFs:  .. │ FFs:  .. │    |
|                          |  │ Power:.. │ Power:.. │ Power:.. │    |
|                          |  │ Risk: .. │ Risk: .. │ Risk: .. │    |
|                          |  │[Details] │[Details] │[Details] │    |
|                          |  │ Phase 2  │ Phase 2  │ Phase 2  │    |
|                          |  │[Details] │[Details] │[Details] │    |
|                          |  │ Phase 3  │ Phase 3  │ Phase 3  │    |
|                          |  │[Details] │[Details] │[Details] │    |
|                          |  └──────────┴──────────┴──────────┘    |
|                          | [Exec Summary][Compare][View Full Report]|
+-------------------------------------------------------------------+
| Ready                                                  (Status Bar)|
+-------------------------------------------------------------------+
```

The window is split into two resizable panes:
- **Left:** Network Editor canvas (drag the divider to resize)
- **Right:** Vertical split between Progress Panel (top) and Results Panel (bottom)

---

## 3. Network Editor (Left Panel)

The canvas displays your SoC topology as an interactive graph.

### Node Types and Visual Styles

| Type | Color | Shape | Description |
|------|-------|-------|-------------|
| Processor | Blue (#3a7dda) | Rounded rect | Bus masters (CPUs) |
| DMA | Green (#2db050) | Rectangle | DMA controllers |
| IP Core | Orange (#e07b00) | Oval | Peripheral IP blocks |
| Bus | Grey (#888888) | Rectangle (thin) | Interconnect segments |
| Policy Server | Purple (#9040cc) | Diamond | ZTA policy decision points |
| Firewall | Red (#cc3030) | Hexagon | ZTA policy enforcement points |

### Canvas Interactions

| Action | How |
|--------|-----|
| Move a node | Click and drag |
| Edit node properties | Double-click the node |
| Context menu | Right-click a node |
| Add a new node | Right-click empty canvas area and select "Add Node" |
| Delete a node | Right-click a node and select "Delete" |
| Add a link | Right-click a node and select "Add Link To..." then click target |
| Copy a node | Right-click and select "Copy" (or Ctrl+C) |
| Paste a node | Right-click empty area and select "Paste" (or Ctrl+V) |
| Zoom in/out | Ctrl+= / Ctrl+- |
| Undo/Redo | Ctrl+Z / Ctrl+Y |

### Node Properties (Double-Click Dialog)

When you double-click a node, you can edit:

- **Name**: Unique identifier used in ASP facts
- **Component Type**: processor, dma, ip_core, bus, policy_server, firewall
- **Trust Domain**: untrusted, low, normal, privileged, high, root
- **Impact Read/Write**: Confidentiality/integrity impact (1-5 scale)
- **Impact Availability**: Availability impact (0-5 scale)
- **Exploitability**: How easy to exploit (1=hard, 3=neutral, 5=trivial)
- **Latency Read/Write**: Allowable latency budget in cycles (must be >= 4)
- **Direction**: input, output, bidirectional
- **Hardware RoT**: Has hardware root of trust
- **Secure Boot**: Has secure boot capability
- **Attested**: Has platform attestation
- **Critical**: High-value target requiring firewall protection
- **Safety Critical**: Must be isolated under elevated threat modes
- **FW Cost / PS Cost**: Hardware deployment cost for firewalls/policy servers

### Analysis Results Overlay

After running analysis, the canvas displays:
- **Risk halos**: Colored rings around nodes proportional to their risk score
- **Placement badges**: Icons showing which security features were assigned
- **Feature labels**: Text showing the selected security and logging modes
- Strategy selector to switch between the three result overlays

---

## 4. Toolbar Buttons

| Button | Action |
|--------|--------|
| **Run Analysis** | Start the three-phase DSE analysis. Runs all three strategies sequentially. Disabled while running. |
| **Stop** | Request the orchestrator to stop after the current strategy completes. |
| **Clear** | Reset progress indicators, clear the log, and clear results. Does NOT clear the canvas topology. |
| **Load TC9** | Load the TC9 test case topology (8 IP cores, 2 masters, 2 buses, 2 firewalls, 2 policy servers). |
| **Load RefSoC-16** | Load the SecureSoC-16 reference architecture (10 IP cores, 3 masters, 3 buses, 2 firewalls, 2 policy servers). |
| **Solver Config** | Open the strategy override dialog to customize ASP objectives per strategy. |
| **Show ASP Facts** | Open a viewer showing the raw ASP facts generated from the current canvas topology. |

---

## 5. Menu Bar

### File Menu

| Item | Action |
|------|--------|
| Open Network... | Load a JSON topology file |
| Save Network... | Save current topology as JSON |
| Recent Files | Quick access to the 8 most recently opened files |
| Exit | Close the application |

### Edit Menu

| Item | Action |
|------|--------|
| Clear All | Same as toolbar Clear button |
| Solver Config... | Same as toolbar Solver Config button |

### View Menu

| Item | Action |
|------|--------|
| Show ASP Facts... | Same as toolbar Show ASP Facts button |
| Export Results as CSV... | Export the analysis results to a CSV file |

### Help Menu

| Item | Action |
|------|--------|
| About | Application info and version |

---

## 6. Running an Analysis

### What Happens When You Click "Run Analysis"

1. **Topology validation**: The tool checks for common issues (disconnected nodes, missing buses, etc.). Warnings are shown; you choose whether to continue.
2. **Network model extraction**: The canvas state is converted to a `NetworkModel` object.
3. **ASP fact generation**: The `ASPGenerator` converts the model into Clingo-compatible ASP facts.
4. **Security feature catalog export**: The IP catalog (`ip_catalog/xilinx_ip_catalog.py`) generates `security_features_inst.lp` with available security features, their resource costs, and latency impacts.
5. **Three-strategy execution**: The orchestrator runs all three strategies (max_security, min_resources, balanced) sequentially. Each strategy runs Phase 1, then Phase 2, then Phase 3.
6. **Scoring and ranking**: After all strategies complete, `SolutionRanker` normalizes metrics to 0-100 scores across six axes.
7. **Report generation**: The `ComparisonEngine` generates pros/cons and a full text report.

### Progress Panel

During analysis, the progress panel shows:
- **Phase indicators**: Colored dots showing which phase is running (grey=pending, yellow=running, green=done, red=failed)
- **Timer**: Elapsed time since analysis started
- **Log messages**: Real-time progress from each phase agent

### What If a Phase Returns UNSAT?

- **Phase 1 UNSAT**: No feasible security feature assignment exists under the given constraints. The strategy card shows "UNSAT" in red. Phases 2 and 3 are skipped.
- **Phase 2 UNSAT**: ZTA policy constraints cannot be satisfied. Phase 3 is skipped. Phase 1 results are still available.
- **Phase 3 scenario UNSAT**: A specific scenario has no feasible solution. Other scenarios still run.

Common causes of UNSAT:
- Latency budgets too tight (minimum achievable is 4 cycles)
- Risk caps too restrictive for the number of assets
- Missing firewall on-path facts for the ZTA topology
- Missing policy server governance relationships

---

## 7. Understanding the Three Strategies

The tool evaluates three optimization strategies simultaneously to explore the design space:

### Strategy 1: Maximum Security

- **Objective**: Minimize total risk (weighted sum of all residual security and availability risks)
- **Behavior**: Assigns the strongest security features (zero_trust) and most verbose logging (zero_trust_logger) wherever possible
- **Trade-off**: Highest FPGA resource usage and power consumption
- **Use case**: Safety-critical deployments where security is paramount

### Strategy 2: Minimum Footprint

- **Objective**: Minimize risk at primary level, then minimize LUT usage as secondary objective
- **Behavior**: Relaxes security where possible to reduce resource footprint; may assign MAC or dynamic_mac instead of zero_trust
- **Trade-off**: Higher residual risk but lower resource usage
- **Use case**: Resource-constrained FPGAs where area/power budget is tight

### Strategy 3: Balanced Trade-off

- **Objective**: Combined minimization of total risk and LUT usage (risk at priority 2, LUTs at priority 1)
- **Behavior**: Finds a middle ground between security and resources
- **Trade-off**: Moderate risk, moderate resource usage
- **Use case**: General-purpose deployments seeking a practical balance

---

## 8. Understanding the Three Phases

### Phase 1: Security Feature Selection

**What it does:** Selects the optimal security feature and logging mode for each IP core component, subject to:
- FPGA resource constraints (LUTs, FFs, DSPs, BRAMs, power)
- Latency constraints per component
- Risk budget constraints (max_security_risk for non-redundant, max_avail_risk for redundant groups)

**Security features available** (from most to least protective):

| Feature | Latency Cost | Protection Level |
|---------|-------------|-----------------|
| zero_trust | 3 cycles | Highest — cryptographic verification |
| dynamic_mac | 6 cycles | High — dynamic message authentication |
| mac | 4 cycles | Medium — static message authentication |

**Logging modes available:**

| Mode | Latency Cost | Detail Level |
|------|-------------|-------------|
| zero_trust_logger | 2 cycles | Full audit trail |
| some_logging | 1 cycle | Basic event logging |
| no_logging | 1 cycle | No logging overhead |

**Minimum achievable latency:** 4 cycles (= zero_trust latency of 3 + no_logging latency of 1). Any component with `allowable_latency < 4` makes the problem unsolvable.

**Risk model:**
- **Non-redundant components**: Additive security residual risk = Impact + DomainBonus + ExploitMod - Protection - LogProtect
- **Redundant group members**: Probabilistic availability risk = Impact x CombinedProbability / 100

**Outputs:** Selected security feature, logging mode, resource totals, and per-asset risk values for each component.

### Phase 2: Zero Trust Architecture Policy Synthesis

**What it does:** Given the Phase 1 security assignments, synthesizes a complete ZTA policy:

1. **Firewall placement**: Chooses which candidate firewalls (PEPs) to deploy
2. **Policy server placement**: Selects at least one policy server (PDP)
3. **Access control rules**: Derives allow/deny decisions per (master, IP, mode) triple
4. **Least-privilege analysis**: Identifies excess and missing privileges
5. **Trust gap analysis**: Finds components missing hardware roots of trust, secure boot, or attestation
6. **Mode-aware access control**: Three security modes:
   - **normal**: Explicit allow rules apply
   - **attack_suspected**: Only attested masters may access non-critical IPs
   - **attack_confirmed**: All access denied (full isolation)

**Hard constraints:**
- Low-trust masters (untrusted/low/normal domain) accessing critical IPs must pass through a deployed firewall
- Every deployed firewall must be governed by at least one deployed policy server
- Safety-critical components must be isolated in at least one elevated mode

**Outputs:** Placed firewalls, placed policy servers, allow/deny rules, policy tightness scores, trust gaps, excess/missing privileges, deployment cost.

### Phase 3: Resilience Scenario Analysis

**What it does:** Simulates compromise and failure scenarios against the topology with the Phase 1/2 security assignments:

**Core scenarios (6):**

| Scenario | Description |
|----------|-------------|
| baseline | No compromise, no failure |
| sys_cpu_compromise | Main CPU compromised |
| dma_compromise | DMA controller compromised |
| full_group_compromise | Entire redundant group compromised |
| noc0_failure | Primary bus fails |
| ps0_compromise | Policy server compromised |

**Full scenarios (18):** Adds individual component compromises, dual failures, PEP bypass, combined compromise+failure.

**Analysis per scenario:**
- **Blast radius**: How many other components a compromised node can reach
- **Service availability**: OK / degraded / unavailable based on quorum requirements
- **Control plane integrity**: Whether policy servers and PEPs remain functional
- **Cross-domain exposure**: Whether compromise in a lower trust domain reaches higher-trust assets
- **Asset risk under scenario**: Amplified risk values accounting for the compromise

**Outputs:** Per-scenario risk scores, blast radii, service status, control plane flags, exposure types.

---

## 9. Results Panel (Right Panel)

After analysis completes, three strategy cards appear side by side.

### Strategy Card Contents

Each card shows:

| Field | Description |
|-------|-------------|
| **Card title** | Strategy name (e.g., "Solution 1: Maximum Security") |
| **SAT/UNSAT** | Green "SAT" or red "UNSAT" — whether Phase 1 found a feasible solution |
| **LUTs** | Total LUT usage across all selected security features |
| **FFs** | Total flip-flop usage |
| **Power** | Total power consumption in milliwatts |
| **Risk** | Total risk score (sum of max risk per asset) |
| **Phase 1 [Details...]** | Opens Phase 1 detail dialog |
| **Phase 2** | Summary of placed FWs and PSs |
| **Phase 2 [Details...]** | Opens Phase 2 detail dialog |
| **Phase 3** | First 3 scenarios with risk scores |
| **Phase 3 [Details...]** | Opens Phase 3 scenario navigator |

### Bottom Buttons

| Button | Action |
|--------|--------|
| **Executive Summary** | Opens the one-page executive summary synthesizing all data across all strategies — identifies the primary security bottleneck ("long pole"), whether the architecture needs redesign, and the single most impactful improvement |
| **Compare Strategies** | Opens side-by-side comparison table with color-coded best/worst |
| **View Full Report** | Opens the complete text report with executive summary, per-solution details, pros/cons, and recommendations |

---

## 10. Phase 1 Detail Dialog

Opened by clicking **Details...** in a strategy card's main section.

### Resources Tab

Shows FPGA resource utilization with visual bar charts:
```
FPGA Resource Utilisation
=============================================
  LUTs          42,300  ████████████████
  FFs           84,600  ████████████████
  DSPs              12  █
  LUTRAMs        2,400  ██
  BRAMs             14  ██
  Power          9,200  ████████████
```

### Security Features Tab

Lists the security feature and logging mode assigned to each component:
```
Security features placed  (8 components):
──────────────────────────────────────────────────
  Component                 Security Feature
  ──────────────────────── ────────────────────
  c1                        zero_trust
  c2                        zero_trust
  c3                        zero_trust
  ...
  c8                        mac

Logging modes  (8 components):
──────────────────────────────────────────────────
  Component                 Logging Mode
  ──────────────────────── ────────────────────
  c1                        zero_trust_logger
  ...
  c8                        no_logging
```

### Risk Breakdown Tab

This is the most detailed view. It contains six sections:

**Section 1: Non-Redundant Components (Additive Security Residual Risk)**

Shows per-asset risk for components NOT in a redundancy group:
```
  Risk = Impact + DomainBonus(DB) + ExploitMod(EM) - Protect - LogProtect
  DB: untrusted=0, low=0, normal=1, privileged=2, high/root=3
  EM: exploitability-3  (hard=-2, neutral=0, trivial=+2)
  ──────────────────────────────────────────────────────────────────
  Component  Register   Op       Risk  DB  EM  Security         Logging
  c6         c6r1       read       5   3   0  dynamic_mac      some_logging
  c6         c6r1       write      3   3   0  dynamic_mac      some_logging
```

How to read: Each row shows the residual risk for one component-asset-operation triple. Lower risk is better. The DB (domain bonus) and EM (exploit modifier) columns help you understand *why* a component has higher risk — high-domain components get a domain bonus penalty, and easily exploitable components get an exploit modifier penalty.

**Section 2: Redundant Group Members (Probabilistic Availability Risk)**

Shows per-asset risk for components in redundancy groups, using the probabilistic model. The risk here reflects that redundant components collectively reduce availability impact.

**Section 3: Per-Component Risk Totals**

Aggregated risk contribution per component with visual bar chart. Use this to quickly identify which components contribute most to overall risk.

**Section 4: Max Risk Per Asset Register**

Shows the highest risk value for each asset register across read/write operations. This is what the "Total Risk" number on the strategy card sums.

**Section 5: CIA Dimension Summary**

Breaks down risk by Confidentiality (read), Integrity (write), and Availability:
```
  Dimension                      Raw Risk  Weight  Weighted
  ──────────────────────────────────────────────────────────
  C — Confidentiality                  24     1.0      24.0
  I — Integrity                        18     1.5      27.0
  A — Availability                     12     2.0      24.0
  ──────────────────────────────────────────────────────────
  WEIGHTED TOTAL                                       75.0
```

The CIA weights reflect that for embedded SoC systems, integrity (write attacks) and availability (DoS) have more immediate physical consequences than confidentiality (read attacks).

**Section 6: Topology Risk Weights**

Shows the amplification proxy weights assigned to each asset. Higher-weight assets are prioritized by the Phase 1 solver. Weights are based on:
- Base: 10
- Safety-critical: +20
- Is a master: +15
- High trust domain (privileged/high/root): +10
- +1 per reachable component (topology connectivity proxy)

---

## 11. Phase 2 Detail Dialog

Opened by clicking **Details...** in a strategy card's Phase 2 section.

### Allow / Deny Rules Tab

Lists all access control decisions organized by mode:
```
ALLOW rules (19)
──────────────────────────────────────────────────
  Master               IP Core              Op
  ─────────────────── ─────────────────── ─────
  arm_a53              crypto_eng           normal
  arm_a53              nvram                normal
  arm_m4               sensor_a             normal
  ...

DENY rules (42)
──────────────────────────────────────────────────
  Master               IP Core              Op
  ─────────────────── ─────────────────── ─────
  arm_a53              crypto_eng           attack_confirmed
  ...
```

**How to interpret:** In `normal` mode, allow rules govern access. In `attack_suspected`, only attested masters access non-critical IPs. In `attack_confirmed`, everything is denied for full lockdown.

### Policy Tightness Tab

Shows how closely each master's granted access matches its declared needs:
```
Average tightness: 72.3/100  (100=fully tight, 0=permissive)
──────────────────────────────────────────────────
  Master                    Score  Status
  ──────────────────────── ────── ───────────────
  dma0                         45  OVER-PRIVILEGED
  arm_a53                      85  tight
  arm_m4                       90  tight
```

**How to interpret:**
- **100** = perfect least-privilege (no excess grants)
- **>= 80** = "tight" — acceptable policy precision
- **< 50** = "OVER-PRIVILEGED" — master has access to far more than it needs; investigate excess privileges

### Trust Gaps Tab

Identifies hardware trust anchor deficiencies:
```
Components missing hardware trust anchors:
──────────────────────────────────────────────────
  Missing RoT:
    - sensor_c
    - gpio
    - debug_jtag
  Missing Secure Boot:
    - dma0
    - comm_eth
    - debug_jtag
  Missing Attestation:
    - arm_m4
    - dma0

Unattested privileged access pairs (2):
──────────────────────────────────────────────────
  dma0  →  crypto_eng
  arm_m4  →  nvram

Unsigned policy servers (1):
──────────────────────────────────────────────────
  ps_backup
```

**How to interpret:**
- **Missing RoT/Secure Boot**: Components without hardware-backed trust foundations. Higher risk of firmware tampering.
- **Unattested privileged access**: A master without attestation accessing a high-trust IP. An attacker could impersonate the master.
- **Unsigned PS**: Policy server without signed policy enforcement. Policy tampering risk.

These are security findings (not hard failures) — each is a recommendation for hardware improvement.

### Privileges Tab

Lists specific excess and missing privilege grants:
```
Excess privileges (5):
──────────────────────────────────────────────────
  arm_a53  gpio  read
  arm_a53  debug_jtag  read
  dma0  gpio  write
  ...

Missing privileges (0):
──────────────────────────────────────────────────
  (none)

Total FW+PS deployment cost: 570
```

**How to interpret:**
- **Excess privileges**: Master has topological access to a component but no declared `access_need`. This violates least-privilege — the access path should be blocked or the need documented.
- **Missing privileges**: Master has a declared need but no topological path. This is a connectivity gap that means the master cannot do its job.
- **Deployment cost**: Sum of hardware costs for all placed firewalls and policy servers.

---

## 12. Phase 3 Detail Dialog

Opened by clicking **Details...** in a strategy card's Phase 3 section.

### Layout

- **Left panel**: Scrollable list of scenarios with risk scores
- **Right panel**: Detailed analysis of the selected scenario

Click a scenario name on the left to view its full analysis on the right.

### Scenario Detail View

```
Scenario: dma_compromise
========================================================
Compromised  : dma0
Failed       : —
Total risk   : 23.00

Blast radii (per component):
────────────────────────────────────────
  axi_main                 12  ████████████
  arm_a53                  11  ███████████
  dma0                     11  ███████████
  apb_periph                9  █████████
  crypto_eng                4  ████
  ...

Asset risks under this scenario:
────────────────────────────────────────
  crypto_eng_r1              8
  nvram_r1                   6
  sensor_a_r1                4
  ...

Services OK        : sensor_svc, crypto_svc
Services degraded  : control_svc
Services unavail   : —

Unavailable assets : —
Cut-off nodes      : —

Control plane      : OK
```

### How to Interpret Each Field

| Field | Meaning |
|-------|---------|
| **Compromised** | Nodes assumed to be under attacker control |
| **Failed** | Nodes assumed to be non-functional (hardware failure) |
| **Total risk** | Amplified risk score for this scenario (higher = worse) |
| **Blast radii** | Per-component count of how many other nodes each can reach. Higher = more lateral movement potential |
| **Asset risks** | Per-asset risk values under this specific compromise scenario |
| **Services OK** | Services meeting their full membership requirement |
| **Services degraded** | Services below full membership but still meeting quorum (minimum viable) |
| **Services unavail** | Services that cannot meet quorum — **service outage** |
| **Cut-off nodes** | Nodes disconnected from the main topology due to bus failure |
| **Control plane** | OK / DEGRADED (some PS down) / STALE (no signed policy) / COMPROMISED (PS under attacker control) |
| **PEPs bypassed** | Firewalls that an attacker can circumvent due to compromised node position |
| **PSes compromised** | Policy servers under attacker control |

### Key Scenarios to Watch

- **baseline**: The "no attack" reference point. All risk should be at minimum levels.
- **sys_cpu / arm_a53 compromise**: Worst single-node attack — the main processor typically has the broadest access.
- **full_group_compromise**: Tests whether redundancy actually provides resilience when an entire group is lost.
- **noc0 / axi_main failure**: Tests architectural resilience to bus failure. This partitions the topology and can isolate entire subtrees.
- **ps0_compromise**: Tests whether a compromised policy server degrades the entire ZTA policy fabric.
- **pep_group_bypass**: Tests what happens when a firewall is circumvented — does the attacker gain unmediated access?

---

## 13. Compare Strategies Dialog

Opened by clicking **Compare Strategies** in the results panel.

Shows a color-coded comparison table:

```
  Metric               Max Security   Min Footprint  Balanced
  ─────────────────── ────────────── ────────────── ──────────
  SAT                  SAT            SAT            SAT
  LUTs                 42,300         28,100         35,400
  FFs                  84,600         56,200         70,800
  Power                9,200          5,800          7,500
  Total Risk           18             42             28
  P2 SAT               SAT            SAT            SAT
  FWs placed           2              2              2
  PSes placed          2              1              2
  Protected IPs        9              9              9
  P2 Cost              570            350            570
  Avg Tightness        72.3           72.3           72.3
  Scenarios            6              6              6
  Worst Risk           45.0           68.0           52.0
  Avg Blast Radius     8.5            8.5            8.5
```

**Color coding:**
- **Green background + green text**: Best value for that metric
- **Red background + red text**: Worst value for that metric
- Lower is better for: LUTs, FFs, Power, Total Risk, P2 Cost, Worst Risk, Avg Blast Radius
- Higher is better for: Avg Tightness, Protected IPs

**Note:** Avg Blast Radius is currently topology-only (not affected by firewall placement), so it will be identical across strategies. See the Checkpoint Status document for details on this design decision.

---

## 14. Executive Summary

Opened by clicking **Executive Summary** in the results panel. This is the most important analysis view — it synthesizes all Phase 1, 2, and 3 data across all three strategies into a single actionable summary.

### What It Answers

The Executive Summary answers three critical questions:

1. **What is the most important thing to fix?** (the "long pole in the tent")
2. **Can this architecture meet security goals with parameter tuning, or does it need structural redesign?**
3. **Which issues are structural (persist across ALL strategies) vs. parametric (strategy-dependent)?**

### Dialog Layout

The summary opens in a dark-themed window with color-coded text:

| Color | Meaning |
|-------|---------|
| Red | CRITICAL severity finding |
| Orange | HIGH severity finding |
| Yellow | MEDIUM severity finding |
| Green | LOW severity or positive finding |
| Blue | Section headers |
| Gold | Long pole (primary bottleneck) highlighting |
| Green banner | Architecture is ADEQUATE |
| Red banner | REDESIGN RECOMMENDED |

### Summary Sections

**VERDICT** — One paragraph stating whether the architecture is adequate, the recommended strategy, headline risk/LUT numbers, and the primary bottleneck.

**HEADLINE METRICS** — Best strategy name, total risk, resilience score (0-100), LUT usage with percentage of budget.

**KEY FINDINGS** — Ordered list of the most important discoveries:
- How many components use minimal MAC protection
- How many components have no logging
- Phase 2 UNSAT status across strategies
- Firewall deployment benefit (blast radius reduction)
- Control plane vulnerability under compromise scenarios

**STRUCTURAL ISSUES** — Issues that persist across ALL three strategies. These cannot be fixed by changing the optimization objective — they require topology changes. Examples:
- Assets that remain high-risk regardless of strategy
- Narrow risk spread across strategies (topology constrains the solution space)

**LONG POLE — Primary Bottleneck** — The single highest-priority item to fix, showing:
- Category: TOPOLOGY, CAPABILITY, TRUST, POLICY, or FEATURE
- Severity: CRITICAL, HIGH, MEDIUM, or LOW
- Component(s) affected
- What the issue is
- How to fix it
- What improves if fixed

**ALL BOTTLENECKS** — Complete ranked list of identified bottlenecks, sorted by severity then category.

**MISSION CAPABILITY ASSESSMENT** — Summary of functional resilience: how many scenarios cause the system to go non-functional, which essential capabilities are at risk.

**RECOMMENDATIONS** — Actionable steps, including whether architecture redesign is required and specific topology/trust/feature changes.

### Architecture Verdict Logic

The analyser evaluates five criteria to determine if the architecture is adequate:

| Check | Trigger for REDESIGN |
|-------|---------------------|
| Phase 2 feasibility | ZTA policy fails for ALL strategies |
| Essential capability loss | Essential capabilities lost under realistic scenarios |
| Topology bottlenecks | CRITICAL-severity topology-category bottleneck |
| Invariant high risk | 2+ cross-strategy invariant risks |
| Flat topology | Firewalls provide no containment benefit (blast radius unchanged) |

If the combined issue score reaches 4+, the verdict changes from ADEQUATE to **REDESIGN RECOMMENDED**.

### Bottleneck Categories (Priority Order)

| Category | Description | Example |
|----------|-------------|---------|
| **TOPOLOGY** | Bus architecture too flat, insufficient segmentation, no isolation zones | "Blast radius reaches 11/12 nodes even with firewalls" |
| **CAPABILITY** | Essential mission capabilities lost under compromise | "sensor_fusion lost in 3 scenarios" |
| **TRUST** | Missing hardware trust anchors | "8 trust anchor gaps — no RoT on high-domain receivers" |
| **POLICY** | ZTA policy infeasible or excess privileges | "Minimum 12 excess privileges across all strategies" |
| **FEATURE** | Latency-forced weak security features | "4 components forced to MAC due to tight latency" |

### Example Executive Summary Output

```
VERDICT
------------------------------------------------------------------------
  The current architecture is ADEQUATE for the security requirements.
  The recommended strategy (Solution 1: Maximum Security) achieves a
  total risk of 18 using 42,300 LUTs (79.5% of budget). The primary
  bottleneck is trust-level: 6 trust anchor gaps detected. Addressing
  this would have the highest impact on security. System remains
  functional across all 6 scenarios.

  Architecture Assessment: >>> ADEQUATE <<<

LONG POLE - Primary Bottleneck
------------------------------------------------------------------------
  Category    : TRUST
  Severity    : HIGH
  Component(s): c3, c4, c5, c6, c7
  Issue       : 6 trust anchor gaps — components lack RoT, secure
                boot, or attestation
  Fix         : Prioritize adding hardware RoT and secure boot to
                high-domain receivers; add attestation to all masters
  Impact      : Enables attested access in elevated security modes;
                reduces unattested privileged access warnings
```

### How to Use the Executive Summary

1. **Read the VERDICT first** — it tells you the overall picture in one paragraph
2. **Check the architecture assessment** — ADEQUATE means you can proceed to production; REDESIGN means stop and fix the topology
3. **Focus on the LONG POLE** — this is the single most impactful improvement you can make
4. **Review STRUCTURAL ISSUES** — these persist no matter which strategy you choose; they require topology changes, not parameter tuning
5. **Check MISSION CAPABILITIES** — if essential capabilities are at risk, add redundancy before anything else

---

## 15. Full Report

Opened by clicking **View Full Report** in the results panel.

The report is a comprehensive text document containing:

1. **Executive Summary**: Top recommendation and key finding (best strategy, total risk, LUT percentage)
2. **Per-Solution Details** (repeated for each of the 3 strategies):
   - Risk Profile: Total risk and per-asset risk breakdown
   - Resource Usage: LUTs, FFs, Power with percentage of FPGA capacity
   - Feature Assignments: Table showing security feature + logging mode + risk per component
   - Policy Analysis: FW/PS placement, excess/missing privileges, trust gaps
   - Resilience Analysis: All scenario results with risk, blast radius, control plane status, service impacts
   - Pros: Advantages of this strategy over the others
   - Cons: Disadvantages and security warnings
3. **Comparison Table**: Numeric side-by-side table of all key metrics plus normalized scores (security_score, resource_score, resilience_score, policy_score)
4. **Recommendations**: Actionable security improvement suggestions

The report opens in a scrollable text window. Use the scrollbar to navigate.

---

## 16. Show ASP Facts Dialog

Opened by clicking **Show ASP Facts** on the toolbar.

This shows the raw ASP (Answer Set Programming) facts generated from the current canvas topology. These are the exact facts sent to the Clingo solver.

### Facts Tab

Syntax-highlighted view of all generated facts:
- **Blue**: Predicate names (component, asset, link, etc.)
- **Green**: Comments (lines starting with %)
- **Orange**: String values
- **Light green**: Numeric values

### Search Feature

- Type in the search box to find specific facts (e.g., "crypto_eng" or "safety_critical")
- Press Enter to jump to the next match, Shift+Enter for previous match
- Match counter shows your position (e.g., "3 / 12")

### Summary Tab

Shows aggregated statistics:
- Total lines and non-blank/comment count
- Fact counts per predicate type (how many `component()`, `asset()`, `link()`, etc.)
- Warnings about missing critical facts (no components, no cand_fw, no on_path, etc.)
- Model overview: component/link/asset/service counts

### Export Options

- **Copy All**: Copies all facts to clipboard for pasting elsewhere
- **Save...**: Saves as a `.lp` file that can be run directly with Clingo for debugging

---

## 17. Solver Config Dialog

Opened by clicking **Solver Config** on the toolbar.

Lets you override the ASP objectives for each strategy. The dialog has three tabs (Max Security, Min Resources, Balanced) each with a text editor showing the extra ASP facts injected for that strategy.

### Default Strategy Objectives

**Max Security**: (empty — uses the default `#minimize` in the encoding unchanged)

**Min Resources**:
```
% min_resources strategy: add secondary LUT objective
#minimize { LUTs@2, total : total_luts_used(LUTs) }.
```

**Balanced**:
```
% balanced strategy: explicit total-risk objective plus LUT tie-break
total_risk_sum(R) :- R = #sum { Risk, C, Asset, Action : new_risk(C, Asset, Action, Risk) }.
#show total_risk_sum/1.
#minimize { R@2 : total_risk_sum(R) }.
#minimize { L@1 : total_luts_used(L) }.
```

### When to Modify

- To tighten risk bounds: Add `system_capability(max_security_risk, 2).`
- To relax resource constraints: Add `system_capability(max_luts, 80000).`
- To add custom ASP rules or constraints for specific components
- To experiment with different optimization priorities

Click **Reset Defaults** to restore the built-in objectives. Click **OK** to apply changes (they take effect on the next Run Analysis). Click **Cancel** to discard.

---

## 18. Threat Model and Security Framework

The tool implements a formal threat model documented in `docs/threat_model.md`. Understanding this model is essential for interpreting results correctly.

### System Abstraction

The SoC is modeled as a directed graph G = (V, E) where nodes are hardware components (masters, receivers, buses, firewalls, policy servers) and edges are physical bus connections. Each component is annotated with a trust domain, CIA impact scores, and exploitability rating.

### Adversary Model

The tool assumes a **network-capable adversary** who can:
- Inject or observe transactions on any bus segment reachable from a compromised master
- Fully compromise any single component (read/write/execute control)
- Attempt lateral movement through bus topology from compromised nodes
- Manipulate policies by compromising a policy server

The adversary **cannot**: physically probe the die at runtime, simultaneously compromise independent components without a topological path, or break correctly-implemented cryptographic primitives.

### Attack Scenarios

Phase 3 resilience analysis evaluates the system under parameterized scenarios:

| Scenario Class | Description | Example |
|---------------|-------------|---------|
| Single-master compromise | One bus master under adversary control | Compromised DMA via malicious firmware |
| Bus failure | A bus segment is non-functional | Manufacturing defect or targeted DoS |
| PS compromise | Policy server poisoned | Supply-chain attack on PS firmware |
| PEP bypass | Firewall component compromised | Hardware trojan in firewall IP |
| Redundancy group compromise | All redundant members compromised | Common-mode vulnerability |
| Combined | Simultaneous compromise + failure | Master compromised while bus is down |

### Trust Boundaries and Domains

```
Level 0: untrusted, low     - External interfaces, debug ports
Level 1: normal              - General-purpose processing
Level 2: privileged          - OS kernel, trusted peripherals
Level 3: high, root          - Crypto engines, safety-critical actuators
```

A **cross-trust boundary** access occurs when a lower-domain master accesses a higher-domain asset. These are the primary privilege escalation vector and are mediated by firewalls (PEPs).

### Security Properties Enforced

| Property | Definition | Enforcement |
|----------|-----------|-------------|
| **Confidentiality** | No unauthorized read access to assets | Deny rules + firewall mediation |
| **Integrity** | No unauthorized write access to assets | Deny rules + firewall mediation (1.5x weight) |
| **Availability** | Services meet quorum under failure | Redundancy groups + quorum thresholds (2.0x weight) |
| **Isolation** | Safety-critical components unreachable from low-trust masters in elevated modes | Hard constraint (UNSAT if violated) |
| **Least Privilege** | No master has access beyond declared needs | Soft property (reported as excess privilege) |
| **Functional Resilience** | Mission-capable under compromise/failure | Capability assessment (OK/degraded/lost) |

### Risk Quantification

**Base Risk** = Impact + DomainBonus + ExploitMod - SecurityProtection - LogProtection

**Scenario Risk** = BaseRisk x MaxAmplificationFactor

| Exposure Type | Amplification | Condition |
|--------------|--------------|-----------|
| Direct | 3.0x | Asset's owner is compromised |
| Cross-trust indirect | 2.0x | Reachable across trust boundary |
| Unmediated | 2.5x | PEP guarding asset is bypassed |
| Same-trust indirect | 1.5x | Lateral movement within same trust |
| PS conflict | 1.3x | Split-brain: one PS compromised, another alive |
| Stale policy | 1.2x | Governing PS failed; PEP on stale rules |

**Protection Discount** reduces indirect exposure factors: security_discount (zero_trust=5, dynamic_mac=3, mac=1) + logging_discount (zero_trust_logger=2, some_logging=1), capped at 7.

### CIA Weighting Justification

| Dimension | Weight | Rationale |
|-----------|--------|-----------|
| Confidentiality (read) | 1.0x | Data leakage is serious but not immediately safety-affecting |
| Integrity (write) | 1.5x | Corrupted sensor data or actuator commands cause physical harm |
| Availability (avail) | 2.0x | Denial of a safety-critical function has immediate physical consequences |

These weights are calibrated for **embedded/safety-critical SoC** systems. For data-centric SoCs (e.g., network processors), the weights should be adjusted (C > I >= A).

### Resilience Score Composition

**Resilience = 0.4 x BlastRadius + 0.4 x CapabilityRetention + 0.2 x ControlPlane**

| Sub-metric | Formula | Rationale |
|-----------|---------|-----------|
| BlastRadius | 100 - (avg_blast / total_nodes x 100) | Lower blast = better containment |
| CapabilityRetention | avg(OK + 0.5xDegraded) / TotalCaps x 100 | Penalizes lost capabilities; 0.25x if essential lost |
| ControlPlane | avg(100 if OK, 40 if degraded, 0 if compromised) | ZTA enforcement mechanism health |

### Standards Mapping

| Standard | How the Tool Maps to It |
|----------|------------------------|
| NIST SP 800-207 (ZTA) | Phase 2: PEP placement, PDP governance, least-privilege policy, trust evaluation |
| CVSS v3.1 | Exploitability scores map to CVSS base attack complexity; impact maps to CIA metrics |
| ISO 26262 (Functional Safety) | Safety-critical isolation, service quorum, system functional status |
| NIST SP 800-53 (AC, SI) | Access control policy synthesis (AC), integrity monitoring via logging (SI) |
| IEC 62443 | Domain hierarchy maps to zones/conduits; security levels map to protection features |

For the complete formal treatment including mathematical definitions and scope limitations, see `docs/threat_model.md`.

---

## 19. SecureSoC-16 Reference Architecture

The SecureSoC-16 (RefSoC-16) is a comprehensive reference SoC designed to exercise every feature of the DSE tool. Load it by clicking **Load RefSoC-16** on the toolbar.

### Topology Diagram

```
  arm_a53 (privileged) ──┐
  arm_m4  (normal)    ───┤── axi_main ──┬── axi_sec ──── crypto_eng (root, safety-critical)
  dma0    (normal)    ───┘              │                  nvram (privileged)
                                        │
                                        ├── apb_periph ── sensor_a (normal, redundant)
                                        │                  sensor_b (normal, redundant)
                                        │                  sensor_c (normal, redundant)
                                        │                  actuator (privileged, safety-critical)
                                        │                  watchdog (privileged, safety-critical)
                                        │                  gpio (low)
                                        │                  debug_jtag (untrusted)
                                        │
                                        └── comm_eth (untrusted)

  ZTA Infrastructure:
    fw_secure  ─── guards axi_sec segment (crypto_eng, nvram)
    fw_periph  ─── guards apb_periph (sensors, actuator, watchdog, gpio, debug_jtag)
    ps_main    ─── primary policy server (signed policy, key_storage)
    ps_backup  ─── backup policy server
```

### Components (16 total)

**Masters (3):**

| Name | Type | Domain | Exploit | Trust Anchors |
|------|------|--------|---------|---------------|
| arm_a53 | processor | privileged | 2 (hard) | RoT + sboot + attest + key_storage |
| arm_m4 | processor | normal | 3 (neutral) | sboot only |
| dma0 | dma | normal | 4 (easy) | none |

**Secure-Domain IP Cores (2):**

| Name | Domain | Safety | Exploit | Trust Anchors | Impact R/W/A |
|------|--------|--------|---------|---------------|------------|
| crypto_eng | root | Yes | 1 (very hard) | RoT + sboot + key_storage | 4/3/2 |
| nvram | privileged | No | 2 (hard) | RoT + key_storage | 5/5/3 |

**Sensor Array (3, Redundancy Group g1, quorum=2):**

| Name | Domain | Direction | Avail Impact | Trust |
|------|--------|-----------|--------------|-------|
| sensor_a | normal | input | 4 | sboot |
| sensor_b | normal | input | 4 | sboot |
| sensor_c | normal | input | 3 | none |

**Peripherals (4):**

| Name | Domain | Safety | Exploit | Direction | Impact R/W/A |
|------|--------|--------|---------|-----------|------------|
| actuator | privileged | Yes | 3 | output | 1/5/5 |
| comm_eth | untrusted | No | 5 (trivial) | bidirectional | 4/3/4 |
| watchdog | privileged | Yes | 2 | bidirectional | 1/2/5 |
| gpio | low | No | 3 | bidirectional | 1/2/1 |

**Debug:**

| Name | Domain | Exploit | Notes |
|------|--------|---------|-------|
| debug_jtag | untrusted | 5 (trivial) | Highest attack surface, high C/I impact |

### What Makes RefSoC-16 Special

This architecture was designed to exercise every DSE tool feature:

- **All 6 domain levels**: untrusted (comm_eth, debug_jtag), low (gpio), normal (arm_m4, dma0, sensors), privileged (arm_a53, actuator, watchdog, nvram), root (crypto_eng)
- **Full CIA triad**: Read-heavy (sensors), write-heavy (actuator, nvram), availability-critical (watchdog, sensors)
- **Exploitability range 1-5**: From crypto_eng(1) through debug_jtag(5)
- **Triple redundancy**: sensor_a, sensor_b, sensor_c in group g1
- **3 safety-critical components**: crypto_eng, actuator, watchdog — these must be isolated in elevated threat modes
- **5 trust anchor types**: RoT, secure boot, attestation, key_storage, signed_policy
- **3 bus segments** with distinct trust boundaries: axi_main (backbone), axi_sec (crypto/storage), apb_periph (sensors/actuators)
- **4 services**: sensor_svc (quorum=2), control_svc (quorum=2), comms_svc (quorum=1), crypto_svc (quorum=1)
- **Policy exceptions**: Debug access in maintenance mode, DMA GPIO during firmware update, emergency actuator override

### System Capabilities (PYNQ-Z2 xc7z020)

| Capability | Value |
|------------|-------|
| max_power | 15,000 mW |
| max_luts | 53,200 |
| max_ffs | 106,400 |
| max_dsps | 220 |
| max_bram | 140 |
| max_security_risk | 4 |
| max_avail_risk | 25 |

---

## 20. TC9 Reference Architecture

TC9 is the original test case topology used during development. Load it by clicking **Load TC9** on the toolbar.

### Topology Diagram

```
  sys_cpu (privileged) ──┐
  dma     (normal)    ───┤── noc0 ──┬── c1 (redundant group, high)
                         │          ├── c2 (redundant group, high)
                         │          ├── c3 (redundant group, high)
                         │          ├── c4 (redundant group, high)
                         │          ├── c5 (redundant group, high)
                         │          ├── noc1 ──── c6 (high)
                         │          │             c7 (high)
                         │          └── c8 (high)
                         │
                         └── ps0, ps1 (policy servers)
                             pep_group (FW, guards c1-c5)
                             pep_standalone (FW, guards c6-c8)
```

**Key characteristics:**
- **2 masters**: sys_cpu (privileged), dma (normal)
- **8 IP cores**: c1-c5 (redundant group g1, quorum-based), c6-c8 (standalone)
- **2 buses**: noc0 (main), noc1 (secondary, connects c6/c7)
- **2 firewalls**: pep_group (guards c1-c5), pep_standalone (guards c6-c8)
- **2 policy servers**: ps0, ps1
- **Tight latency on c8**: Forces the solver to use a weaker security feature (mac instead of zero_trust)

---

## 21. Interpreting Results — A Complete Walkthrough

This section walks through interpreting a complete TC9 analysis run from start to finish.

### Step 1: Load and Run

1. Click **Load TC9** on the toolbar
2. Observe the topology on the canvas — nodes are color-coded by type
3. Click **Run Analysis**
4. Watch the progress log: you should see Phase 1/2/3 completing for all three strategies
5. Wait for "=== DSE Analysis Complete ===" in the log

### Step 2: Read the Strategy Cards

Look at the three cards side by side. Key things to compare:

| What to Look For | What It Tells You |
|---|---|
| All three show SAT (green) | The topology and constraints are well-formed |
| Risk values differ significantly | The strategies are exploring meaningfully different trade-offs |
| LUT values increase with security | More security = more hardware — this is the fundamental trade-off |

### Step 3: Dig into Phase 1 Details

Click **Details...** on the Max Security card.

1. **Resources tab**: Check LUT percentage. Above 80% means you're tight on the PYNQ-Z2.
2. **Security Features tab**: Verify critical components got zero_trust. If c8 got mac instead, that's the latency constraint at work — c8's tight budget cannot accommodate zero_trust's higher latency.
3. **Risk Breakdown tab**:
   - Section 1: Which non-redundant components contribute the most risk? High-domain, high-exploitability components will dominate.
   - Section 3: Per-component totals help you quickly spot the riskiest components.
   - Section 5: CIA summary — integrity risk is typically weighted 1.5x and availability 2.0x, reflecting the physical consequences of write/DoS attacks on embedded systems.

### Step 4: Check Phase 2 Policy

Click **Details...** on the Phase 2 section.

1. **Allow/Deny Rules tab**: Verify deny rules exist for all master-receiver pairs in attack_confirmed mode. This confirms full isolation capability.
2. **Policy Tightness tab**: Any master below 50% is over-privileged. DMA controllers often score low here because they have broad bus access but limited declared needs.
3. **Trust Gaps tab**: Count the total gaps. Each is a hardening recommendation. Prioritize:
   - Unattested privileged access (highest risk — identity spoofing)
   - Missing RoT on high-domain components
   - Unsigned policy servers
4. **Privileges tab**: Excess privileges are the most actionable Phase 2 finding. Each represents an attack surface that should be reduced.

### Step 5: Examine Phase 3 Scenarios

Click **Details...** on the Phase 3 section.

1. Select **baseline** first. Note the total risk — this is your reference.
2. Select **sys_cpu_compromise**. Compare total risk vs baseline — the amplification factor tells you how damaging a CPU compromise is.
3. Check **Services** across scenarios. If any service goes "unavail", that scenario causes a service outage. The quorum requirement determines resilience.
4. Check **Control plane** on ps0_compromise. If it shows "COMPROMISED", the entire ZTA fabric is at risk.
5. Look at **Blast radii** — buses (noc0, axi_main) typically have the highest values because they connect to everything.

### Step 6: Compare Strategies

Click **Compare Strategies** for the color-coded table.

Key trade-offs to evaluate:
- **Risk vs LUTs**: Is reducing risk from 42 to 18 worth 14,200 extra LUTs?
- **Worst Risk**: For safety-critical systems, worst-case scenario risk matters more than average risk
- **P2 Cost**: Does deploying 2 policy servers vs 1 justify the extra hardware?

### Step 7: Export and Report

- Click **View Full Report** for the comprehensive document including recommendations
- Use **View > Export Results as CSV** to get data into a spreadsheet for presentations or further analysis

---

## 22. CSV Export

**Menu:** View > Export Results as CSV...

Exports one row per strategy with the following columns:

| Column | Description |
|--------|-------------|
| Strategy | max_security, min_resources, balanced |
| Label | Human-readable strategy name |
| P1 SAT | SAT or UNSAT |
| P1 Optimal | Whether the Phase 1 solution is proven optimal |
| LUTs, FFs, DSPs, BRAMs, Power | FPGA resource metrics |
| Total Risk | Sum of max risk per asset |
| P2 SAT | Phase 2 satisfiability |
| FWs Placed | Names of deployed firewalls |
| PSes Placed | Names of deployed policy servers |
| Protected IPs | Count of IPs behind a firewall |
| P2 Cost | Total FW+PS deployment cost |
| Avg Tightness | Average policy tightness score (0-100) |
| Num Scenarios | Number of Phase 3 scenarios run |
| Worst Risk | Highest single-scenario risk value |
| Avg Blast Radius | Average maximum blast radius across scenarios |

---

## 23. Regression Testing

The tool includes a comprehensive regression test suite with 127 tests covering all modules.

### Running the Suite

```bash
cd D:\DSE\DSE_ADD
py -3.12 -m unittest tests.test_regression -v
```

### What the Tests Cover

| Category | Tests | What It Validates |
|----------|-------|-------------------|
| Data model | 5 | Component, Asset, NetworkModel creation and defaults |
| TC9 factory | 14 | All TC9 model fields: components, buses, links, services, capabilities, trust anchors |
| RefSoC-16 factory | 12 | All RefSoC fields: domain coverage, exploitability range, direction types |
| ASP generator | 22 | Fact generation correctness: components, assets, links, domains, direction filtering |
| Topology validation | 6 | Structural UNSAT detection: missing FW coverage, ungoverned FW, bad ip_loc |
| Solution parser | 13 | Phase1/2/3Result methods: risk computation, serialization, properties |
| Solution ranker | 11 | Scoring, CIA weighting, capability penalties, resource ordering |
| Comparison engine | 3 | Pros/cons generation, custom caps, report text |
| Executive summary | 5 | Analysis output, architecture verdict, bottleneck sorting |
| Scenario generation | 8 | Auto-scenarios from topology, name validation, deduplication |
| Clingo integration | 2 | Basic SAT/UNSAT with real solver |
| Phase 1 integration | 4 | TC9 all 3 strategies + RefSoC max_security (real Clingo) |
| Phase 2 integration | 1 | TC9 ZTA policy synthesis (real Clingo) |
| Phase 3 integration | 3 | Baseline, auto-scenarios, capability assessment (real Clingo) |
| Full pipeline | 3 | TC9 orchestrator end-to-end, executive summary, RefSoC Phase 1 |
| Edge cases | 12 | Empty inputs, no solutions, single-solution comparison, constants |

### Test Duration

The full suite takes approximately 2.5 minutes due to Clingo solver integration tests. Unit-only tests (categories 1-10) complete in under 1 second.

### Adding New Tests

Tests are in `tests/test_regression.py` using Python's `unittest` framework. To add a test:

1. Add a method to the appropriate `Test*` class (or create a new class)
2. Use `self.skipTest()` for tests requiring clingo when it's unavailable
3. Run the suite to verify your test passes

---

## 24. Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+Z | Undo (canvas edit) |
| Ctrl+Y | Redo (canvas edit) |
| Ctrl+C | Copy selected node |
| Ctrl+V | Paste node |
| Ctrl+= | Zoom in |
| Ctrl+- | Zoom out |
| Enter (in search) | Next search match |
| Shift+Enter (in search) | Previous search match |

---

## 25. Glossary

| Term | Definition |
|------|-----------|
| **ASP** | Answer Set Programming — the constraint logic programming paradigm used by the Clingo solver to find optimal solutions |
| **Blast Radius** | Number of components reachable from a given node via topology links. Measures lateral movement potential. |
| **CIA Triad** | Confidentiality, Integrity, Availability — the three pillars of information security |
| **Clingo** | The ASP solver engine that finds optimal solutions under constraints |
| **Domain** | Trust level assigned to a component: untrusted, low, normal, privileged, high, root |
| **DSE** | Design Space Exploration — systematic evaluation of design alternatives |
| **Exploitability** | How easy a component is to attack: 1=very hard, 3=neutral, 5=trivial |
| **FPGA** | Field-Programmable Gate Array — the reconfigurable hardware target platform |
| **LUT** | Look-Up Table — basic FPGA logic element; proxy for silicon area usage |
| **PDP** | Policy Decision Point — the policy server that makes access control decisions |
| **PEP** | Policy Enforcement Point — the firewall that enforces access control decisions |
| **PYNQ-Z2** | Xilinx xc7z020 development board used as the reference FPGA target |
| **Quorum** | Minimum number of service members that must be functional for the service to remain operational |
| **Redundancy Group** | Set of interchangeable components that provide fault tolerance through replication |
| **RoT** | Root of Trust — hardware-backed trust anchor for secure boot chain verification |
| **SAT** | Satisfiable — the solver found at least one valid solution meeting all constraints |
| **SoC** | System on Chip — integrated circuit combining multiple functional components |
| **UNSAT** | Unsatisfiable — no valid solution exists under the given constraints |
| **Amplification Factor** | Multiplier applied to base risk under a specific compromise scenario — ranges from 1.0x (no exposure) to 3.0x (direct compromise) |
| **Attack Path** | Multi-hop sequence from a compromised node to a target through the bus topology. Maximum depth: 5 hops |
| **Bottleneck** | A specific issue limiting security or resilience, categorized as TOPOLOGY/CAPABILITY/TRUST/POLICY/FEATURE |
| **Capability Retention** | Percentage of mission capabilities that remain OK or degraded (not lost) across scenarios |
| **Effective Blast Radius** | Number of reachable nodes accounting for deployed firewalls (lower than structural blast radius) |
| **Escalation Path** | An attack path that crosses a trust boundary (lower domain → higher domain) |
| **Executive Summary** | One-page synthesis of all analysis data identifying the primary bottleneck and architecture verdict |
| **Long Pole** | The single highest-priority bottleneck — the issue that, if fixed, would have the greatest impact on security or resilience |
| **Mission Capability** | A high-level function the SoC must perform, composed of required services, components, and access paths |
| **Protection Discount** | Reduction in indirect exposure factors based on deployed security features (zero_trust=5, dynamic_mac=3, mac=1) and logging |
| **Structural Blast Radius** | Worst-case number of reachable nodes ignoring all firewalls (topology-only) |
| **ZTA** | Zero Trust Architecture — security model where no component is implicitly trusted; all access requires explicit verification |
