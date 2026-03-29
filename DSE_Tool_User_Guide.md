# DSE Security Analysis Tool — User Guide

**Version**: 1.0
**Date**: 2026-03-28
**Tool launch command**: `py -3.12 -m dse_tool` (run from the project root directory)

---

## Table of Contents

1. [Application Layout](#1-application-layout)
2. [The Network Canvas](#2-the-network-canvas)
3. [Toolbar Buttons](#3-toolbar-buttons)
4. [ZTA Layout Dialog](#4-zta-layout-dialog)
5. [Results Panel](#5-results-panel)
6. [File Menu](#6-file-menu)
7. [View Menu](#7-view-menu)
8. [Simple Worked Example](#8-simple-worked-example)
9. [Understanding What the Results Mean](#9-understanding-what-the-results-mean)
10. [Tips and Keyboard Shortcuts](#10-tips-and-keyboard-shortcuts)

---

## 1. Application Layout

When the tool opens, the window (default size 1400 × 800 px) is divided into five regions.

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Menu bar:  File  |  Edit  |  View  |  Help                             │
├─────────────────────────────────────────────────────────────────────────┤
│  Toolbar:  [Run Analysis] [Stop] [Clear] [Load TC9] [Solver Config]      │
│            [Show ASP Facts]                          Status: Ready       │
├───────────────────────────────────────┬─────────────────────────────────┤
│                                       │  Progress Panel (top-right)     │
│  Network Canvas + Sidebar (left 60%)  │  — real-time solver log output  │
│                                       ├─────────────────────────────────┤
│                                       │  Results Panel (bottom-right)   │
│                                       │  — three strategy cards         │
├───────────────────────────────────────┴─────────────────────────────────┤
│  Status bar:  Ready / Running Phase 1 … / Analysis complete             │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.1 Menu Bar

| Menu | Contents |
|------|----------|
| **File** | Open Network, Save Network, Recent Files (last 8), Exit |
| **Edit** | Clear All, Solver Config |
| **View** | Show ASP Facts, Export Results as CSV |
| **Help** | About |

### 1.2 Toolbar

The toolbar contains six action buttons and a status label. Each button is described in detail in Section 3.

### 1.3 Left Panel — Network Canvas and Sidebar

The left pane occupies approximately 60% of the window width. It contains:
- A **sidebar** on the left edge with all topology editing buttons.
- A **dark canvas** (background colour `#1a1a2e`) with a subtle grid where nodes are drawn.

The canvas is the primary workspace. Every node, link, and group is drawn here and can be manipulated with the mouse.

### 1.4 Right Panel

The right pane is split vertically:
- **Top half — Progress Panel**: shows timestamped log messages produced by the solver as it runs. Phase indicators (Phase 1, Phase 2, Phase 3) illuminate in sequence as each phase completes.
- **Bottom half — Results Panel**: shows three side-by-side strategy cards (Max Security, Min Resources, Balanced), each populated with metrics after analysis completes.

### 1.5 Status Bar

The bottom edge of the window shows the current state of the tool. Typical messages:
- `Ready` — idle, waiting for user input.
- `Running Phase 1 (strategy: Max Security)…` — solver active.
- `Analysis complete (3 solutions found)` — all phases done.
- `Analysis stopped by user` — user pressed Stop.

---

## 2. The Network Canvas

### 2.1 Sidebar Buttons

The sidebar runs along the left edge of the network canvas area. Each button is described below.

---

#### 2.1.1 Add Component

Opens a property dialog to define a new node. Click **OK** to place the node on the canvas at a default position; drag it to reposition.

**Property fields:**

| Field | Description |
|-------|-------------|
| **Name** | A unique identifier string (no spaces recommended). Used as the ASP atom name, e.g., `arm_m4`. Must be unique across the topology. |
| **Type** | `processor` — a master that initiates bus transactions. Drawn as a rectangle. `dma` — a DMA controller, also a master. Drawn as a rectangle. `ip_core` — a peripheral or memory-mapped resource being protected. Drawn as an oval. `bus` — an interconnect fabric (AHB, AXI, etc.). Drawn as a wide rectangle. `firewall` — a policy enforcement point (PEP) that can gate access between masters and IP cores. Drawn as a hexagon. `policy_server` — a centralised policy decision point (PDP) that governs one or more firewalls. Drawn as a diamond. |
| **Domain** | `low` — normal/unprivileged domain (blue tint on canvas). `high` — sensitive or privileged domain (orange/red tint). Domain affects trust relationships and risk scoring in the ASP model. |
| **Direction** | `bidirectional` — the component supports both read and write transactions. `input` — sensor or read-only source; generates only read-side ASP facts. `output` — actuator or write-only sink; generates only write-side ASP facts. |
| **Impact Read** | Integer 1–5. The security impact if this asset is read without authorisation (1 = negligible, 5 = catastrophic). Used in Phase 1 risk scoring. |
| **Impact Write** | Integer 1–5. The security impact if this asset is written without authorisation. |
| **Latency Read** | Expected read latency in clock cycles. Set to 1000 to mark as unconstrained. |
| **Latency Write** | Expected write latency in clock cycles. Set to 1000 to mark as unconstrained. |
| **Has Hardware RoT** | Checkbox. Enables a `has_rot(component)` ASP fact, indicating a hardware Root of Trust is present (e.g., a secure element or eFuse chain). |
| **Has Secure Boot** | Checkbox. Enables a `has_secure_boot(component)` ASP fact. |
| **Has Attestation** | Checkbox. Enables a `has_attestation(component)` ASP fact, indicating the component can produce signed evidence of its state. |
| **Is Critical IP** | Checkbox. Marks the component as a critical intellectual property asset. Shown with a red dashed border on the canvas. Increases risk weighting in Phase 1. |
| **Is Safety-Critical** | Checkbox. Marks the component as safety-critical. Affects risk weighting and Phase 3 exposure classification. |
| **FW Cost** | Only active when Type is `firewall`. Integer. The resource cost the solver uses when deciding whether to place this firewall. Lower cost makes placement more likely under Min Resources strategy. |
| **PS Cost** | Only active when Type is `policy_server`. Integer. The resource cost used when deciding whether to place this policy server. |
| **Extra Assets [Edit...]** | Opens a sub-dialog to add additional named assets to this component beyond the default one. For example, a processor might host a cryptographic key asset and a boot configuration asset in addition to its default asset. Each additional asset can have its own impact values. |

---

#### 2.1.2 Add Link

Click this button to enter **link mode**. The button stays highlighted while link mode is active. Then:
1. Click the **source node**.
2. Click the **destination node**.

A directed link (arrow) is drawn from source to destination. Links represent physical bus connections or point-to-point connections. Direction matters: the ASP generator uses link topology to discover bus-fanout paths (BFS path discovery) between masters and IP cores. If the path does not exist in the link graph, the solver cannot route protection through a firewall on that path.

To exit link mode without adding a link, press **Escape** or click the "Add Link" button again.

---

#### 2.1.3 Add Redundancy Group

Opens a multi-select dialog listing all current nodes. Select two or more nodes to form a named redundancy group. Redundancy groups are used in Phase 3 resilience analysis: if one member fails, the solver checks whether the remaining members can sustain the associated services. A node can belong to more than one redundancy group.

---

#### 2.1.4 Clear All

Removes all nodes, links, redundancy groups, access needs, services, mission phases, policy exceptions, and Phase 3 scenarios from the canvas. **This action cannot be undone.** A confirmation dialog appears before clearing.

---

#### 2.1.5 Access Needs

Opens the Access Needs dialog, which lists the declared least-privilege access policy. Each entry specifies:
- **Master**: the processor or DMA node that initiates the access.
- **Component**: the IP core being accessed.
- **Operation**: `read` or `write`.

These entries become `allow_rule` ASP facts and are the primary input to Phase 2 policy synthesis. If you do not declare an access need for a master/component/operation pair, Phase 2 will not generate an allow rule for it. Conversely, if you declare an access need but there is no firewall candidate on the path between that master and that component, Phase 2 will flag the pair as unprotected. Use "Add" to add a new row, "Remove" to delete the selected row, and "OK" to save.

---

#### 2.1.6 Services

Opens the Services dialog. A service is a named functional capability (e.g., `navigation`, `comms`, `thermal_control`) that is implemented by a set of IP cores with a minimum quorum. Fields:
- **Service name**: a unique string identifier.
- **Member IP cores**: the IP cores that implement this service. Use the multi-select list.
- **Quorum**: the minimum number of member IP cores that must be operational for the service to be considered `ok`. If fewer than quorum are available but at least one is, the service is `degraded`. If none are available, the service is `unavailable`.

Phase 3 reports service status for each scenario.

---

#### 2.1.7 FPGA Config

Opens the FPGA Resource Budget dialog. These values set the upper bounds the ASP solver must satisfy in Phase 1. If the solver cannot find a security feature assignment that stays within all budgets, Phase 1 returns UNSAT.

| Budget Parameter | Description |
|-----------------|-------------|
| `max_luts` | Maximum LUT count available on the device. Default: 53200 (PYNQ-Z2). |
| `max_ffs` | Maximum flip-flop count. Default: 106400. |
| `max_dsps` | Maximum DSP blocks. Default: 220. |
| `max_lutram` | Maximum LUT RAM capacity. Default: 17400. |
| `max_bram` | Maximum BRAM blocks. Default: 140. |
| `max_power` | Maximum total power in milliwatts. Default: 15000. |
| `max_asset_risk` | Maximum acceptable total residual risk score across all assets. Default: 500. |

Adjust these values to match your target device. Lowering `max_asset_risk` forces the solver to place more security features.

---

#### 2.1.8 Mission Phases

Opens the Mission Phases dialog. Mission phases define named operational modes such as `operational`, `maintenance`, `emergency`, `commissioning`. Each phase is a simple string label. Mission phases are referenced by policy exceptions (see 2.1.9) to allow temporary deviations from the standard ZTA policy.

---

#### 2.1.9 Policy Exceptions

Opens the Policy Exceptions dialog. An exception grants a specific master/component/operation combination permission to operate under a named mission phase, with a documented reason. This is used to model time-limited or context-specific access rights that would be denied under normal ZTA policy.

Each exception has:
- **Master**: the component requesting the exception.
- **Component**: the target IP core.
- **Operation**: `read` or `write`.
- **Mission Phase**: the phase under which the exception applies.
- **Reason**: free-text justification for the exception.

---

#### 2.1.10 Phase 3 Scenarios

Opens the Scenario Editor. Each scenario represents a threat event to test resilience. Fields:
- **Name**: a unique identifier (e.g., `bus_compromise`, `dma_failure`).
- **Compromised components**: a list of component names that are assumed to be under adversary control.
- **Failed components**: a list of component names that have stopped functioning.

If no scenarios are defined, Phase 3 uses built-in default scenarios (single-component compromise for each node). Defining custom scenarios allows testing multi-component failure conditions and realistic attack chains.

---

#### 2.1.11 Undo / Redo

- **Undo** (also **Ctrl+Z**): reverses the most recent canvas operation. Covered operations include: add node, delete node, move node, add link, delete link.
- **Redo** (also **Ctrl+Y**): reapplies the last undone operation.

The undo history is maintained in memory for the current session only. It is cleared when "Clear All" is used.

---

#### 2.1.12 Zoom In / Zoom Out

- **Zoom In** (also **Ctrl+=**): increases the canvas scale. Maximum zoom level is 3.0× (300%).
- **Zoom Out** (also **Ctrl+-**): decreases the canvas scale. Minimum zoom level is 0.2× (20%).

The zoom is centred on the canvas viewport. Use zoom to inspect tightly packed topologies or to get an overview of a large design.

---

#### 2.1.13 Find Component...

Also **Ctrl+F**. Opens a live-filter search dialog with a text entry box and a list of all components. As you type, the list filters by name or type. To navigate to a component:
- Double-click the entry in the list, or
- Select it and press **Enter**.

The canvas pans to centre the found node and highlights it briefly with a bright outline.

---

#### 2.1.14 Auto Layout

Arranges all nodes into a hierarchical left-to-right layout automatically. The columns are:
1. **Processors and DMA controllers** (leftmost)
2. **Buses**
3. **Firewalls and policy servers**
4. **IP cores** (rightmost)

Within each column, nodes are distributed vertically in the order they were added. Relative vertical ordering within a column is preserved. This layout is useful after importing a JSON file, after loading TC9, or whenever nodes have been placed manually and have begun to overlap.

---

#### 2.1.15 Load TC9 Example

Loads the TC9 reference test case directly onto the canvas, replacing any existing topology. TC9 is a representative SoC topology with:
- 8 IP cores on a shared bus
- 2 master nodes (processor and DMA)
- 2 candidate PEP (firewall) groups
- A pre-declared set of access needs and services

TC9 is used for regression testing and as a starting point for exploring the tool's capabilities. It is safe to load and modify TC9 without affecting any saved files.

---

#### 2.1.16 Save JSON / Load JSON

- **Save JSON**: saves the complete topology state — nodes, links, redundancy groups, access needs, services, mission phases, policy exceptions, and Phase 3 scenarios — as a `.json` file. You choose the file path via a save dialog.
- **Load JSON**: opens a file browser to select a previously saved `.json` file and loads it onto the canvas, replacing the current topology.

These operations correspond to File > Save Network and File > Open Network in the menu bar.

---

#### 2.1.17 Show Overlay (checkbox)

When checked and analysis has been run, the canvas draws additional visual annotations on top of the topology:

- **Risk halos around nodes**: a circular glow behind each node coloured by risk level. Green = low risk (score below threshold), yellow = medium risk, red = high risk (score near or above budget limit).
- **Placement badges on firewalls and policy servers**: `PLACED` (green badge) if Phase 2 chose to deploy this component, `NOT PLACED` (grey badge) if it was a candidate but was not selected.
- **Security feature abbreviations** next to components: `mac` = MAC-layer encryption placed, `dmt` = DMT logging placed, `zt` = zero-trust feature placed.
- **Link colours** (see Section 2.2 for a full description).

Uncheck this box to return the canvas to its undecorated view.

---

#### 2.1.18 Blast Radius (checkbox)

When checked and Phase 3 analysis has been run, each node on the canvas is surrounded by a coloured ring:
- **Red / thick ring**: high blast radius — this node can reach many other components if compromised.
- **Green / thin ring**: low blast radius — this node can reach few other components if compromised.

Blast radius is defined as the number of other components physically reachable through the link graph from this node if it is compromised (i.e., under adversary control).

**Note**: in flat bus topologies (all nodes connected to a single bus), all nodes have equal blast radius because the bus provides a path to every attached node. The visual rings will all be similar. Blast radius becomes informative only in segmented topologies where firewalls or distinct bus segments limit reachability. This overlay is therefore off by default.

---

#### 2.1.19 View ZTA Layout

Opens the ZTA Layout dialog. See Section 4 for a full description.

---

### 2.2 Canvas Node Shapes and Colours

| Component Type | Shape | Base Colour |
|---------------|-------|-------------|
| processor | Rounded rectangle | Blue (`#3a7dda`) |
| dma | Rectangle | Green (`#2db050`) |
| ip_core | Oval | Orange (`#e07b00`) |
| bus | Wide rectangle | Grey (`#888888`) |
| policy_server | Diamond | Purple (`#9040cc`) |
| firewall | Hexagon | Red (`#cc3030`) |

**Domain tint**: a semi-transparent overlay is applied on top of the base colour:
- `low` domain: blue tint
- `high` domain: orange/red tint

**Critical IP indicator**: IP cores marked as critical are surrounded by a red dashed border.

---

### 2.3 Link Colours (when Show Overlay is enabled after analysis)

| Colour | Meaning |
|--------|---------|
| Green solid | This link leads to an IP core that is protected by a placed firewall on the path from some master. |
| Orange dashed | This link leads to an IP core for which an access need is declared, but no firewall protection was placed on the path. The access need exists but is unguarded. |
| Grey | No access need is declared for any master reaching this IP core via this link. |

---

### 2.4 Canvas Mouse Interactions

| Gesture | Effect |
|---------|--------|
| Left-click + drag on node | Moves the node. Position snaps to the 20 px grid. |
| Double-click on node | Opens the property editor dialog for that node. |
| Right-click on node | Opens a context menu with: Edit, Add Link From Here, Copy, Delete. |
| Ctrl+click on node | Toggles the node in the multi-select set. A cyan dashed halo appears around selected nodes. |
| Drag on empty canvas | Rubber-band multi-select: a selection rectangle is drawn; all nodes inside are added to the selection set. |
| Delete key | Deletes all currently selected nodes and all links that connect to them. |
| Ctrl+C | Copies the selected node(s). |
| Ctrl+V | Pastes the copied node(s) at a small offset from the original position. |

---

## 3. Toolbar Buttons

### 3.1 Run Analysis

Starts the three-phase DSE analysis pipeline in a background thread, leaving the GUI responsive.

**What happens when you click Run Analysis:**

1. The tool calls `validate_topology()` on the current canvas state. If any warnings are found (e.g., isolated nodes, missing links), a dialog lists them and asks whether to continue.
2. The Progress Panel is reset and a timer starts.
3. The DSEOrchestrator is launched in a background daemon thread.
4. **Phase 1** runs for each of the three strategies (Max Security, Min Resources, Balanced). The Clingo ASP solver selects security features (RoT, encryption modes, logging modes) and computes the resulting LUT, FF, DSP, LUTRAM, BRAM, and power resource costs plus the total residual risk score. The solver enforces the FPGA budget caps from FPGA Config.
5. **Phase 2** runs for each strategy that found a SAT result in Phase 1. It synthesises a Zero Trust Architecture policy: selecting which firewall and policy server candidates to deploy, then generating `allow` and `deny` rules consistent with the declared access needs.
6. **Phase 3** runs resilience scenario analysis for each Phase 2 result. It tests the defined (or built-in) scenarios, computing blast radii, asset risk under compromise, service status, and control plane integrity.
7. Results are sent back to the GUI via a queue and displayed in the Results Panel cards.

The Run Analysis button is disabled while analysis is running. The Stop button becomes active.

---

### 3.2 Stop

Requests the solver to halt early. The current Clingo invocation is interrupted. Any results already computed are preserved and displayed; incomplete phases are marked as aborted. The status bar changes to `Analysis stopped by user`.

Use Stop if a large topology is taking too long or if you need to change the topology mid-analysis.

---

### 3.3 Clear

Clears the Progress Panel log output and resets all Results Panel cards to their empty `—` state. Does **not** clear the canvas topology or any declared topology data. Use this to reset the display before re-running analysis after a topology change.

---

### 3.4 Load TC9

Equivalent to the sidebar button. Loads the TC9 reference topology (8-IP-core SoC) directly, replacing the current canvas. A confirmation dialog appears if the canvas is not empty.

---

### 3.5 Solver Config

Opens a tabbed dialog with one tab for each of the three strategies:
- **Max Security** tab
- **Min Resources** tab
- **Balanced** tab

Each tab contains a text area for entering additional ASP facts or objective clauses that will be appended to the default strategy encoding before the solver runs. Leave the text area blank to use the built-in defaults.

**Example custom clause** (Max Security tab):
```prolog
#maximize { 1,C : has_rot(C) }.
```
This forces the Max Security strategy to maximise the number of components with hardware RoT placement.

**Example forcing a specific firewall:**
```prolog
:- not place_fw(pep1).
```
This adds a constraint that `pep1` must always be placed.

Custom clauses persist for the session. They are not saved as part of the JSON topology.

---

### 3.6 Show ASP Facts

Generates the Answer Set Programming (ASP) LP text from the current canvas topology and displays it in a two-tab dialog.

**Facts tab:**
Shows the full LP text with syntax highlighting:
- Comments (lines starting with `%`): green
- Fact predicate names (the part before the `(`): blue
- Numeric arguments: light green

A search bar at the top of the dialog allows text search within the facts. Press **Enter** to advance to the next match; press **Shift+Enter** to go to the previous match. Match count is displayed next to the search bar.

Buttons: **Copy All** copies the entire LP text to the clipboard. **Save...** opens a file browser to save the text as a `.lp` file for use outside the tool.

**Summary tab:**
Shows:
- A count of each fact type (e.g., `component: 9`, `allow_rule: 14`, `cand_fw: 2`).
- Automatic warnings for facts that are missing and would likely cause UNSAT. For example: `WARNING: no cand_fw facts — Phase 2 will be UNSAT`.
- Model statistics: total number of components, links, assets, access needs, and services.

**Why use Show ASP Facts before running analysis:**
The Summary tab is the fastest way to catch configuration errors that will cause solver failures:
- If `cand_fw` count = 0, Phase 2 has no firewall candidates and will always be UNSAT.
- If `on_path` count = 0, no ZTA protection paths are discoverable and ZTA placement is meaningless.
- If `allow_rule` count = 0 but you have declared access needs, check that your master and IP core names exactly match the names in the Access Needs dialog.
- If `asset` count = 0, Phase 1 has no assets to protect and will produce a trivial solution.

---

## 4. ZTA Layout Dialog

Opened via the **View ZTA Layout** sidebar button. This dialog provides a conceptual four-column architectural diagram of the Zero Trust Architecture, independent of the spatial layout of nodes on the canvas.

### 4.1 Column Layout

| Column | Contents | Visual |
|--------|----------|--------|
| **Masters** (leftmost) | All processor and DMA nodes | White/grey boxes |
| **Firewalls** (centre-left) | All firewall candidates. Placed FWs shown in red with `PLC` badge; candidates not selected shown dim with `---` badge. | Hexagonal outlines |
| **Policy Servers** (centre-right) | All policy server candidates. Placed PS shown in purple with `PLC` badge; not placed shown dim. | Diamond outlines |
| **IP Cores** (rightmost) | All IP core nodes. Green circle = protected by at least one placed firewall on the path from a master with a declared access need. Orange circle = unprotected (access need declared but no placed FW on path). | Circles |

### 4.2 Arrow Types

| Arrow | Meaning |
|-------|---------|
| Green solid | A protected master → IP core path passes through a placed firewall. |
| Red dashed | An access need is declared (master needs to reach IP core) but no placed firewall guards the path — this is an unprotected access need and a ZTA gap. |
| Purple dashed | A placed policy server governs a firewall or has a policy relationship with an IP core. |

### 4.3 Summary Bar

A one-line summary at the bottom of the dialog reports:
`Placed FWs: X | Placed PSes: Y | Protected IPs: N / Total`

Where:
- `X` = number of firewall candidates that were placed by Phase 2.
- `Y` = number of policy server candidates that were placed.
- `N` = number of IP cores that have at least one protected access path.
- `Total` = total number of IP cores in the topology.

A high `N / Total` ratio is desirable. Any IP core with an `allow_rule` that is not in `N` is a ZTA gap.

### 4.4 Cross-Check vs Canvas Button

This button runs a consistency verification between the ZTA Layout and the declared topology:

1. For every declared access need (master, IP core, operation), it checks whether that pair appears in the protected set (firewall placed on path) or is flagged as unprotected (no FW on path).
2. It checks for **spurious protections**: cases where a firewall is placed on the path between a master and an IP core, but no access need was declared for that pair. This may indicate an over-broad firewall placement.
3. It reports either a **pass** (all access needs are explicitly categorised as protected or unprotected, no spurious protections) or a **warning list** of issues.

The cross-check result is shown in a popup dialog. Review all warnings before proceeding with a design decision based on Phase 2 results.

---

## 5. Results Panel

After analysis completes, the three strategy cards in the Results Panel are populated with summary data. The cards are labelled **Strategy 1** (Max Security), **Strategy 2** (Min Resources), and **Strategy 3** (Balanced).

### 5.1 Strategy Card Structure

Each card displays:

**SAT/UNSAT indicator:**
A bold label at the top of the card. Green `SAT` means Phase 1 found a valid solution that satisfies all FPGA budget constraints. Red `UNSAT` means no valid solution exists — typically because the budget caps are too tight for the required security features, or because the topology has no assets to protect.

**Resource metrics (Phase 1):**

| Label | Meaning |
|-------|---------|
| `LUTs:` | Total LUT count used by the selected security features. |
| `FFs:` | Total flip-flop count. |
| `Power:` | Total power consumption in milliwatts. |
| `Risk:` | Total residual risk score across all assets after security features are applied. Lower is better. |

**Phase 1 Details... button:**
Opens a three-tab dialog:
- **Resources tab**: a bar-chart style table showing all six resource metrics (LUTs, FFs, DSPs, LUTRAM, BRAM, Power) as actual values versus budget caps. Resources close to the cap are highlighted in amber.
- **Security Features tab**: lists which security feature was placed on which component (e.g., `arm_m4 ← MAC encryption`), and which logging mode was selected.
- **Risk Breakdown tab**: a per-asset risk table sorted by risk value (descending). Shows the maximum risk per asset, the residual risk after feature placement, and the total risk. Assets near or at the maximum allowed risk are highlighted.

**Phase 2 section:**
A small section within the card showing the names of the placed firewalls and policy servers (e.g., `FWs: pep1, pep2 | PSes: ps0`). If Phase 2 was UNSAT, this section shows `UNSAT — see Details`.

**Phase 2 Details... button:**
Opens a four-tab dialog:
- **Allow/Deny Rules tab**: a full table of all generated `allow` rules (master, IP core, operation) and `deny` rules. Allow rules correspond to declared access needs with a placed FW on the path. Deny rules cover all other master/IP core pairs.
- **Policy Tightness tab**: a per-master tightness score from 0 to 100. A score of 100 means every allow rule for that master has an exact matching declared access need and there are no excess allow rules. A score of 0 means the master has unrestricted access (blanket rules). Masters with scores below 80 are flagged as over-privileged. See Section 9 for a full explanation.
- **Trust Gaps tab**: lists components that participate in the security policy but are missing hardware trust anchors. Specific gaps reported include: no RoT, no Secure Boot, no Attestation, no Key Storage. Also lists unattested privileged access pairs (a master with high-impact access needs but no attestation) and unsigned policy servers (a PS without Secure Boot cannot guarantee policy integrity).
- **Privileges tab**: shows the excess privilege list (allow rules with no matching access need), the missing privilege list (access needs with no matching allow rule), the total deployment cost (sum of FW Cost + PS Cost for all placed components), and the UNSAT reason if Phase 2 could not find a valid policy.

**Phase 3 section:**
Shows the first three scenario names with their associated total risk score (e.g., `bus_compromise: risk=42`). If Phase 3 was not run (because Phase 2 was UNSAT), this section shows `—`.

**Phase 3 Details... button:**
Opens a two-pane dialog:
- **Left pane**: all scenarios listed by name with risk scores. Click a scenario to select it.
- **Right pane**: for the selected scenario, shows:
  - A blast radii bar chart: one bar per component showing `BR:N` (blast radius N). Higher bars indicate components that expose more of the system if compromised.
  - An asset risk table: per-asset residual risk scores under the scenario's compromise/failure conditions.
  - Service status: each declared service listed as `ok`, `degraded`, or `unavailable`.
  - Control plane flags: whether the scenario compromises the policy decision plane (i.e., a PS is compromised).
  - PEPs bypassed: list of firewalls that are bypassed under this scenario.
  - PSes compromised: list of policy servers that are compromised.
  - Exposure type breakdown: counts of components exposed by physical access, logical access, or trust chain compromise.

### 5.2 Compare Strategies Button

Located at the bottom right of the Results Panel. Enabled only after analysis has completed with at least one SAT result.

Opens a colour-coded comparison grid with one column per strategy and one row per metric. Cell colouring:
- **Green**: best value for this metric among all three strategies.
- **Red**: worst value for this metric among all three strategies.
- **White**: intermediate value.

Metrics covered include all Phase 1 resource metrics, Phase 2 policy tightness averages, total deployment cost, and Phase 3 aggregate risk.

Use this dialog as the primary decision-making tool for choosing which strategy to implement. Look for the strategy that wins the most green cells for your priority metrics. If you prioritise minimising risk, Max Security is expected to win the Risk row. If you prioritise minimal resource footprint, Min Resources is expected to win most resource rows.

### 5.3 View Full Report Button

Opens a text window containing the full formatted comparison report. The report covers all three strategies with complete Phase 1, Phase 2, and Phase 3 data in a readable columnar format. Use the **Copy** button in the report window to copy the text to the clipboard for pasting into a design document.

---

## 6. File Menu

| Item | Action |
|------|--------|
| **Open Network...** | Opens a file browser dialog. Select a `.json` file previously saved by this tool. The topology (nodes, links, access needs, services, scenarios) is loaded onto the canvas, replacing the current state. |
| **Save Network...** | Opens a save dialog. Saves the complete current topology as a `.json` file. The JSON format is human-readable and version-controllable. |
| **Recent Files** | A submenu listing the last 8 files that were opened or saved. Click any entry to open that file immediately. Recent file paths are stored in `~/.dse_tool_prefs.json` (where `~` is your Windows user home directory). |
| **Exit** | Closes the application. If analysis is running, it is stopped first. No save prompt is shown — save your topology before exiting if you want to preserve it. |

---

## 7. View Menu

| Item | Action |
|------|--------|
| **Show ASP Facts...** | Same as the toolbar button. Generates and displays the ASP LP text for the current canvas topology. See Section 3.6 for full details. |
| **Export Results as CSV...** | Opens a save dialog. Saves a 19-column CSV file containing all Phase 1, Phase 2, and Phase 3 metrics for all three strategies. Each strategy occupies one row. Requires that analysis has been run at least once in the current session; if not, a warning dialog appears. |

**CSV column set** (all three strategies × all metrics):

| Columns | Content |
|---------|---------|
| strategy | Strategy name (Max Security / Min Resources / Balanced) |
| phase1_sat | SAT or UNSAT |
| luts, ffs, dsps, lutram, bram, power | Phase 1 resource values |
| risk | Phase 1 total residual risk |
| phase2_sat | SAT or UNSAT |
| placed_fws | Comma-separated list of placed FW names |
| placed_pses | Comma-separated list of placed PS names |
| policy_tightness_avg | Average tightness score across all masters |
| deployment_cost | Total FW + PS deployment cost |
| phase3_scenario_count | Number of Phase 3 scenarios evaluated |
| phase3_max_risk | Maximum risk score across all scenarios |
| phase3_services_unavailable | Count of services that became unavailable in worst-case scenario |

---

## 8. Simple Worked Example

This section walks through building a complete analysis from scratch. The scenario is a small embedded SoC with:
- An **ARM Cortex-M4 processor** (`arm_m4`) that needs read access to a temperature sensor and write access to a PWM output.
- A **DMA controller** (`dma_ctrl`) that needs write access to a data logger.
- Three **IP cores**: `temp_sensor` (input/read-only), `pwm_out` (output/write-only), `data_logger` (output).
- A **shared AHB bus** (`ahb_bus`) connecting all components.

### Step 1: Launch the Tool

Open a terminal, navigate to the project root directory, and run:

```
py -3.12 -m dse_tool
```

The main window opens. The canvas is empty. The status bar reads `Ready`.

### Step 2: Add the Processor

1. Click **Add Component** in the sidebar.
2. Fill in the dialog:
   - **Name**: `arm_m4`
   - **Type**: `processor`
   - **Domain**: `low`
   - **Direction**: `bidirectional`
   - **Impact Read**: `3`
   - **Impact Write**: `4`
   - Leave all other fields at their defaults.
3. Click **OK**.

A blue rounded rectangle labelled `arm_m4` appears on the canvas.

### Step 3: Add the DMA Controller

1. Click **Add Component**.
2. Fill in the dialog:
   - **Name**: `dma_ctrl`
   - **Type**: `dma`
   - **Domain**: `low`
   - **Direction**: `bidirectional`
   - **Impact Read**: `2`
   - **Impact Write**: `3`
3. Click **OK**.

A green rectangle labelled `dma_ctrl` appears.

### Step 4: Add the Bus

1. Click **Add Component**.
2. Fill in the dialog:
   - **Name**: `ahb_bus`
   - **Type**: `bus`
   - **Domain**: `low`
3. Click **OK**.

A grey wide rectangle labelled `ahb_bus` appears.

### Step 5: Add the Temperature Sensor

1. Click **Add Component**.
2. Fill in the dialog:
   - **Name**: `temp_sensor`
   - **Type**: `ip_core`
   - **Domain**: `high`
   - **Direction**: `input`
   - **Impact Read**: `4`
   - **Impact Write**: `1`
   - **Is Critical IP**: checked
3. Click **OK**.

An orange oval with a red dashed border appears for `temp_sensor`.

### Step 6: Add the PWM Output

1. Click **Add Component**.
2. Fill in the dialog:
   - **Name**: `pwm_out`
   - **Type**: `ip_core`
   - **Domain**: `high`
   - **Direction**: `output`
   - **Impact Read**: `1`
   - **Impact Write**: `5`
3. Click **OK**.

### Step 7: Add the Data Logger

1. Click **Add Component**.
2. Fill in the dialog:
   - **Name**: `data_logger`
   - **Type**: `ip_core`
   - **Domain**: `low`
   - **Direction**: `output`
   - **Impact Read**: `2`
   - **Impact Write**: `3`
3. Click **OK**.

### Step 8: Add Links

You should now have 6 nodes on the canvas. Connect them by clicking **Add Link** and then clicking source and destination in sequence:

1. Click **Add Link** → click `arm_m4` → click `ahb_bus`. A directed arrow from `arm_m4` to `ahb_bus` appears.
2. Click **Add Link** → click `ahb_bus` → click `temp_sensor`.
3. Click **Add Link** → click `ahb_bus` → click `pwm_out`.
4. Click **Add Link** → click `ahb_bus` → click `data_logger`.
5. Click **Add Link** → click `dma_ctrl` → click `ahb_bus`.

Press **Escape** to exit link mode.

### Step 9: Arrange Nodes (Optional)

Click **Auto Layout**. The nodes rearrange into a clean left-to-right hierarchy: `arm_m4` and `dma_ctrl` on the left, `ahb_bus` in the centre, and `temp_sensor`, `pwm_out`, `data_logger` on the right.

### Step 10: Declare Access Needs

1. Click **Access Needs** in the sidebar.
2. In the dialog, click **Add** and set: Master = `arm_m4`, Component = `temp_sensor`, Operation = `read`. Click OK on the row.
3. Click **Add** and set: Master = `arm_m4`, Component = `pwm_out`, Operation = `write`. Click OK.
4. Click **Add** and set: Master = `dma_ctrl`, Component = `data_logger`, Operation = `write`. Click OK.
5. Click **OK** to close the Access Needs dialog.

### Step 11: Verify ASP Facts

1. Click **Show ASP Facts** in the toolbar.
2. Select the **Summary** tab.
3. Verify the following counts are correct:
   - `component: 6`
   - `allow_rule: 3`
   - `asset: 3` (one per IP core)
   - `link: 5`

4. You will see warnings about `cand_fw: 0` and `on_path: 0`. These are **expected at this stage** — this topology has no firewall or policy server candidates, so Phase 2 will be UNSAT. Phase 1 and Phase 3 will still run.
5. Close the dialog.

### Step 12: Run Analysis

Click **Run Analysis** in the toolbar. The Progress Panel begins showing log output. Watch the phase indicators light up in sequence:
- Phase 1 completes: resource metrics appear in the Results Panel cards.
- Phase 2: the progress log will report `UNSAT — no candidate firewalls exist`. The Phase 2 sections of the cards will show `UNSAT`.
- Phase 3: built-in single-component scenarios run against the Phase 1 results.

After a few seconds, analysis completes and the status bar reads `Analysis complete`.

### Step 13: Inspect Overlays

1. Check the **Show Overlay** checkbox in the sidebar.
2. The IP core nodes (`temp_sensor`, `pwm_out`, `data_logger`) now show coloured risk halos. `temp_sensor` (Impact Read = 4, Is Critical) will likely show a yellow or red halo. `data_logger` will show a lower-risk colour.
3. The links to the IP cores will be coloured orange dashed (declared access need but no FW protection), which confirms the Phase 2 UNSAT status visually.

4. Check the **Blast Radius** checkbox. All nodes show similar ring sizes — this is expected in a flat bus topology where every node is one hop from the bus and thus from all other nodes.

### Step 14: Review Phase 1 Results

1. In the **Strategy 1** card, click **Details...** (the Phase 1 details button).
2. Select the **Security Features** tab. This shows which security features the solver placed on each component under the Max Security strategy (e.g., `arm_m4 ← MAC encryption`, `temp_sensor ← DMT logging`).
3. Select the **Risk Breakdown** tab. Verify that `temp_sensor` has the highest residual risk of the three IP cores (because Impact Read = 4 and it is marked critical).
4. Close the dialog.

### Step 15: Add Firewall Support

To enable Phase 2 and get a full ZTA result, add a firewall and policy server:

1. Click **Add Component** → Name = `pep1`, Type = `firewall`, FW Cost = `150`. Click OK.
2. Click **Add Component** → Name = `ps0`, Type = `policy_server`, PS Cost = `100`. Click OK.
3. Click **Add Link** → click `arm_m4` → click `pep1`.
4. Click **Add Link** → click `pep1` → click `temp_sensor`.
5. Click **Add Link** → click `ps0` → click `pep1`.

This creates a guarded path: `arm_m4 → pep1 → temp_sensor`. The path for `pwm_out` and `data_logger` via `ahb_bus` remains unguarded (for comparison).

6. Click **Run Analysis** again. This time Phase 2 will find a solution that places `pep1` and `ps0`, generating an allow rule for `arm_m4 / temp_sensor / read`.

7. Click **View ZTA Layout** to see the architectural view with `pep1` marked as `PLC` and `temp_sensor` shown as a green (protected) IP core.

---

## 9. Understanding What the Results Mean

### 9.1 Phase 2 UNSAT

A Phase 2 UNSAT result means the solver could not find a valid Zero Trust Architecture policy for the current topology and access needs. The most common causes are:

- **No candidate firewalls** (`cand_fw = 0`): the topology contains no nodes of type `firewall`. Phase 2 requires at least one firewall candidate to generate a policy. Add a firewall node and link it on the path between a master and an IP core.
- **No on-path facts** (`on_path = 0`): firewall candidates exist, but none of them lie on a bus-routed path between any master and any IP core with a declared access need. Check that links form a connected path through the firewall.
- **Contradictory access needs**: two access needs require opposite policies on the same component (rare; usually caused by mis-entered data).

The Phase 2 Details dialog (Privileges tab) states the UNSAT reason when one is detected.

### 9.2 Policy Tightness Score

The policy tightness score for a master ranges from 0 to 100 and measures how precisely the generated policy matches the declared access needs.

- **100 (fully tight)**: every allow rule in the generated policy corresponds exactly to a declared access need. No master has been granted access to anything it did not explicitly declare it needs.
- **0 (fully permissive)**: the master has blanket access — allow rules exist for operations and IP cores that were never declared as needed.
- **Intermediate values** reflect partial over-provisioning. A score below 80 is flagged as over-privileged in the Policy Tightness tab.

A lower score does not necessarily mean the policy is insecure in isolation, but it means the principle of least privilege is being violated. An attacker who compromises a master with a low tightness score gains more capability than the declared needs would suggest.

### 9.3 Blast Radius: Flat Bus vs Segmented Topology

**Flat bus**: when all components are connected to a single shared bus (like the worked example in Section 8), every node can physically reach every other node via the bus. All blast radii are therefore equal and equal to `(total nodes - 1)`. The Blast Radius overlay is uninformative in this case — all rings are the same colour.

**Segmented topology**: when firewalls or separate bus segments partition the network, a compromised node can only reach nodes in the same segment or segments accessible through the firewall. Blast radii differ significantly between segments. The Blast Radius overlay becomes meaningful: nodes in large or central segments (such as the bus or a policy server) will have high blast radii (red rings), while nodes in isolated segments will have low blast radii (green rings). Segmentation is one of the key benefits of ZTA: it limits blast radius by design.

### 9.4 Over-Privileged Masters

A master is over-privileged when the policy has granted it allow rules for operations or IP cores that it did not declare a need for in the Access Needs dialog. This can happen when:
- A firewall's placement rule is broader than required (it guards an IP core for a master that has no access need for that IP core).
- A policy server's scope is too wide.
- The access needs were not fully declared.

The **Privileges tab** in the Phase 2 Details dialog lists the exact excess allow rules. To fix over-privilege, either remove the excess allow rules by adjusting the firewall placement or scope, or add the missing access needs if the access is genuinely required (in which case it should be explicitly declared).

### 9.5 Trust Gaps

A trust gap is reported when a component participates in the ZTA security policy — meaning it either enforces a policy rule (firewall), decides policy (policy server), or is subject to a high-impact rule — but lacks the hardware trust anchors that would make verification possible.

Examples:
- A **policy server without Secure Boot**: this PS generates and distributes allow/deny rules. If it lacks Secure Boot, an attacker who compromises its boot process can substitute a different policy without detection. The PS claims to enforce the declared policy, but there is no hardware-rooted way to verify that claim.
- A **firewall without RoT**: the FW enforces allow/deny rules at the bus level. Without a hardware Root of Trust, its configuration can be tampered with after deployment.
- An **IP core with high impact read/write but no attestation**: the asset is valuable, but there is no way to remotely verify that the component accessing it is the one the policy intended.

Trust gaps do not cause UNSAT — the solver can still find a valid policy. They are advisory findings that a security reviewer should address before deploying the design.

---

## 10. Tips and Keyboard Shortcuts

### 10.1 Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Z` | Undo last canvas operation |
| `Ctrl+Y` | Redo last undone operation |
| `Ctrl+=` | Zoom in |
| `Ctrl+-` | Zoom out |
| `Ctrl+F` | Open Find Component dialog |
| `Ctrl+C` | Copy selected node(s) |
| `Ctrl+V` | Paste copied node(s) at an offset |
| `Delete` | Delete all selected nodes and their links |
| `Double-click` on node | Open property editor for that node |
| `Enter` (in search/dialog) | Confirm selection / advance to next search match |
| `Shift+Enter` (in search) | Go to previous search match |
| `Escape` | Cancel current link mode or close a dialog |

### 10.2 Workflow Tips

1. **Always check the ASP Facts Summary tab before running analysis.** It catches missing facts (zero `cand_fw`, zero `on_path`, zero `allow_rule`) that would cause UNSAT and save you time waiting for the solver. Ten seconds of checking the summary tab can avoid a confusing UNSAT result.

2. **The ZTA Cross-check button is the fastest way to verify Phase 2 consistency.** After analysis, open the ZTA Layout dialog and click Cross-check. A clean pass means every declared access need is accounted for (either protected or explicitly unprotected). Any warning points directly at a topology or access needs configuration issue.

3. **Use Auto Layout after importing a large topology.** JSON files imported from another designer or from a script may have all nodes stacked at the default position. Click Auto Layout immediately after loading to spread the nodes into a readable hierarchy.

4. **Save your topology as JSON before running analysis.** Analysis does not auto-save. If you modify the topology while reading results and want to go back, the saved JSON is your restore point. Use File > Save Network or the sidebar Save JSON button.

5. **The Compare Strategies dialog is the best starting point for choosing a strategy.** After a successful analysis, click Compare Strategies and look at the colour-coded grid. Count the green cells for your priority dimension (security, resources, or balance). The strategy with the most green cells in your priority columns is the recommended choice.

6. **Declare all access needs explicitly, even obvious ones.** Phase 2 only generates allow rules for declared access needs. If you assume a processor can read from a bus implicitly without declaring a need, Phase 2 will not protect that access — and the Trust Gaps report will not flag it because there is no policy for it at all.

7. **Use custom Phase 3 scenarios to test realistic attack chains.** The built-in scenarios test single-component compromise. Real attacks often involve a chain: an attacker compromises a DMA controller, then uses it to overwrite a policy server's configuration, then disables a firewall. Model this as a multi-component scenario (DMA + PS compromised simultaneously) to see the combined blast radius and service impact.

8. **Solver Config text areas are session-only.** Any extra ASP clauses you enter in the Solver Config dialog are not saved in the JSON topology file. If you rely on custom strategy clauses, note them separately and re-enter them after loading the topology in a new session.

9. **If Phase 1 is UNSAT, first try relaxing the FPGA budget.** Open FPGA Config and increase `max_asset_risk` or `max_luts`. Phase 1 UNSAT most often means the current budget is too tight for the number of security features required by the topology. Increasing the risk budget by 10–20% often reveals whether the topology is fundamentally unacceptable (always UNSAT) or just budget-constrained.

10. **Use the Blast Radius overlay only in segmented topologies.** In flat bus designs, all nodes have equal blast radius and the overlay provides no differentiation. Add firewalls and separate bus segments, re-run analysis, and then enable Blast Radius to see meaningful differentiation between high-risk central nodes and low-risk leaf nodes.

---

*End of DSE Security Analysis Tool User Guide.*
