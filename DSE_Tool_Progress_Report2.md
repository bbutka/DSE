# DSE Tool Progress Report 2

**Date:** 2026-03-28
**Tool:** Design Space Exploration (DSE) GUI for SoC/FPGA Security
**Stack:** Python / Tkinter / Clingo ASP Solver

---

## Executive Summary

This report covers the second development session on the DSE Tool, a Python/Tkinter GUI for design space exploration of SoC/FPGA security using a three-phase Clingo ASP pipeline (Phase 1: security/power, Phase 2: ZTA policy, Phase 3: resilience scenarios). The session resolved several critical bugs affecting the ZTA Layout dialog and access-need iteration, and delivered 16 new features spanning verification tools, canvas interaction improvements, and results panel enhancements. The tool now provides a substantially more complete analysis and review workflow, with remaining work focused on advanced editing capabilities, richer visualisation, and report export.

---

## System Overview

| Aspect | Detail |
|--------|--------|
| Language | Python 3 |
| GUI Framework | Tkinter |
| Solver | Clingo ASP |
| Pipeline Phases | Phase 1 (security/power), Phase 2 (ZTA policy), Phase 3 (resilience) |
| Target Hardware | SoC / FPGA |
| Platform Tested | Windows only |

---

## Bug Fixes

### 1. ZTA Layout Dialog — Empty Canvas for TC9

**Root cause:** `model.cand_fws` was empty for TC9 because PEPs (`pep_group`, `pep_standalone`) are ASP-only solver names and are never placed as canvas nodes. This caused the ZTA Layout dialog to render column headers with no node content.

**Fix:**
- FW and PS node lists now take the union of `p2.placed_fws` / `p2.placed_ps` with canvas nodes, so ASP-only placements are included.
- Connection drawing now has two branches:
  - Detailed `on_paths` routing when path data is available.
  - Synthesised direct master → IP arrows derived from `p2.protected` when `on_paths` is empty (the TC9 case).

### 2. TypeError in ZTA Layout Access-Needs Loop

**Root cause:** The access-needs iteration attempted tuple unpacking on `AccessNeed` objects directly, producing `TypeError: cannot unpack non-iterable AccessNeed object`.

**Fix:** Access-needs loop updated to iterate over `AccessNeed` object attributes rather than attempting implicit tuple unpacking.

### 3. Blast Radius Overlay — Overlapping Halos

**Root cause:** Blast radius halos were rendered as large filled circles that overlapped other nodes and obscured the diagram.

**Fix:** Halos replaced with tight coloured rings drawn on node borders. The overlay is now gated behind a dedicated "Blast Radius" checkbox (off by default) so it does not interfere with the default canvas view.

---

## New Features

### Verification Tools

#### 1. Show ASP Facts Dialog

Accessible via toolbar button and **View** menu. Displays the raw ASP LP text generated from the current canvas topology.

**Tabs:**
- **Facts:** Scrollable text with syntax highlighting for comments, fact names, numbers, and strings.
- **Summary:** Fact-type count table; 7 automatic warnings for missing critical facts (e.g., no `cand_fw`, no `on_path`); model statistics.

**Additional capabilities:**
- Live search with Enter / Shift+Enter to cycle through matches.
- Copy All, Save .lp, and line/character count.

#### 2. Canvas Validation Overlay

After topology validation, nodes with warnings receive a red **warning badge** rendered directly on the canvas. Badges are automatically cleared when analysis completes successfully. Warning text is parsed to extract node names and map them back to their canvas representations.

#### 3. Phase 2 Details Dialog

A **"Details..."** button on each Phase 2 strategy card opens a four-tab dialog:

| Tab | Content |
|-----|---------|
| Allow/Deny Rules | Full allow and deny rule tables (master, IP core, operation) |
| Policy Tightness | Per-master tightness score (0–100), over-privileged flag, average |
| Trust Gaps | Missing RoT / Secure Boot / Attestation / Key Storage per component; unattested access pairs; unsigned policy servers |
| Privileges | Excess privilege list, missing privilege list, total FW+PS cost, UNSAT reason |

#### 4. Phase 3 Scenario Navigator

A **"Details..."** button on the Phase 3 card opens a split-pane dialog listing all scenarios (not just the first three). Selecting a scenario shows:

- Blast radii bar chart per component.
- Asset risk table.
- Service status breakdown: ok / degraded / unavailable.
- Control plane status flags: degraded / stale / compromised.
- PEPs bypassed, PSes compromised.
- Exposure types: direct / cross / unmediated.

#### 5. ZTA Cross-Check Button

Located inside the ZTA Layout dialog. Compares `p2.protected` pairs against `model.access_needs` and reports:

- **UNPROTECTED access needs:** A declared access need is not in the protected set.
- **SPURIOUS protection:** An entry in the protected set has no corresponding declared access need.

Shows a pass summary with counts when no issues are found.

---

### Canvas Improvements

#### 6. Auto Layout

A sidebar **"Auto Layout"** button arranges all canvas nodes into hierarchical columns based on node type:

| Column X | Node Types |
|----------|-----------|
| 120 | Processors, DMA controllers |
| 320 | Buses |
| 480 | Firewalls, Policy Servers |
| 680 | IP Cores |

Relative vertical order within each column is preserved.

#### 7. Rubber-Band Multi-Select

Dragging on an empty canvas area draws a selection rectangle. All nodes whose bounding boxes intersect the rectangle are added to the selection set. Ctrl+click toggles individual nodes. Selected nodes are shown with dashed cyan oval halos. The Delete key removes all currently selected nodes.

#### 8. Hover Tooltips

Hovering over any canvas node for 600 ms displays a floating tooltip showing:

- Name and type
- Domain
- Impact (R/W) and Latency (R/W)
- Security flags: RoT, Secure Boot, Attestation

#### 9. Blast Radius Overlay

After Phase 3 analysis, a separate **"Blast Radius"** checkbox (off by default) draws a tight coloured ring around each node scaled by relative blast radius:

- Red / thick ring: high blast radius.
- Green / thin ring: low blast radius.
- A `BR:N` label is shown only for the top 30% severity nodes to reduce clutter.

#### 10. Component Search

Accessible via the sidebar **"Find Component..."** button or **Ctrl+F**. Provides a live-filter listbox of all canvas nodes. Double-clicking or pressing Enter pans the canvas to the selected node and selects it.

---

### Results Panel Improvements

#### 11. Phase 1 Details Dialog

A **"Details..."** button on each Phase 1 strategy card's metrics section opens a three-tab dialog:

| Tab | Content |
|-----|---------|
| Resources | Bar chart of LUTs / FFs / DSPs / LUTRAMs / BRAMs / Power |
| Security Features | Per-component security and logging placements |
| Risk Breakdown | Per-asset risk table with flexible 3/4-tuple unpacking, total risk, max-risk-per-asset bars |

#### 12. Strategy Comparison Dialog

A **"Compare Strategies"** button (enabled after analysis completes) opens a side-by-side colour-coded grid for all three strategies:

- Green cell = best value for that metric.
- Red cell = worst value for that metric.

**Metrics covered:**

| Category | Metrics |
|----------|---------|
| General | SAT status, all 5 resource metrics, total risk |
| Phase 2 | FWs/PSes placed, protected IPs, cost, average tightness |
| Phase 3 | Scenario count, worst risk, average blast radius |

---

### Main Window Improvements

#### 13. Recent Files Menu

**File → Recent Files** stores the last 8 opened or saved files in `~/.dse_tool_prefs.json`. The list is updated on every open and save operation. Clicking an entry loads the file; a missing file shows an error dialog.

#### 14. CSV Export

**View → Export Results as CSV...** generates a 19-column CSV covering all Phase 1, Phase 2, and Phase 3 metrics per strategy. Falls back to `results_panel` solutions if the orchestrator is no longer active.

#### 15. Resource Budget Warnings

Automatically triggered after analysis completes. Compares Phase 1 resource totals against FPGA Config limits (`max_luts`, `max_ffs`, `max_dsps`, `max_bram`, `max_power`) and shows a warning dialog listing all overruns.

#### 16. View Menu

A **View** menu has been added to the menu bar with entries:

- Show ASP Facts
- *(separator)*
- Export Results as CSV

---

## Summary of Completed Work

| Category | Items Completed |
|----------|----------------|
| Bug fixes | 3 |
| Verification tools | 5 |
| Canvas improvements | 5 |
| Results panel improvements | 2 |
| Main window improvements | 4 |
| **Total** | **19** |

---

## Remaining Work

### High Priority

| Item | Description |
|------|-------------|
| On-path constraint editor | GUI to specify which firewall candidate must sit on which master → IP path. BFS auto-derives these currently but provides no manual override. Critical for custom topologies. |
| Per-component resource breakdown | Phase 1 returns aggregate LUT/FF totals but not per-component allocations. Requires changes to ASP encoding and the solution parser. |
| PDF / DOCX report export | Currently only full-text report and CSV are available. A formatted PDF with embedded diagrams would be submission-ready. |
| Interactive FW/PS placement | Allow the designer to lock a FW/PS placement before solving ("must place pep_group"). Currently fully solver-driven. |

### Medium Priority

| Item | Description |
|------|-------------|
| Attack path visualisation | Show the specific path an attacker would take from a compromised node to each reachable asset, not just the blast radius count. |
| Visual strategy diff | Overlay two strategies on the same canvas to show which components gain or lose security features. |
| Fault tree view | Tree diagram showing how failures propagate through the topology. |
| Full trust anchor editor | Current UI has binary checkboxes only (has_rot, has_sboot, has_attest). Full trust anchor types (signed policies, key storage, trusted telemetry) are not exposed. |
| Drag-and-drop file loading | Drop a `.json` file onto the canvas to load it. Requires `tkinterdnd2`, which is not currently installed. |
| Minimap | Overview panel for large topologies (20+ nodes). |

### Lower Priority

| Item | Description |
|------|-------------|
| Undo/redo for modal dialogs | Undo/redo currently covers canvas operations only. Edits made inside dialogs (access needs, services, etc.) are not undoable. |
| Keyboard shortcuts for dialogs | Tab navigation, Enter to confirm, Escape to cancel. Dialogs currently rely on mouse interaction. |
| Batch property edit | Select multiple nodes and edit domain/impact for all simultaneously. |
| Sensitivity analysis | "If I increase power budget by 20%, how does the security score change?" Requires re-running the solver with varied caps. |
| Collaborative editing | Multi-user JSON merge. The tool is single-user only. |
| Version control integration | Track topology changes with git commit messages. |

---

## Known Limitations

1. **Blast radius is physical topology only.** It does not account for ZTA policy enforcement. In a flat bus topology such as TC9, all nodes have equal blast radius (fully connected). This is correct behaviour: blast radius shows what happens if an attacker bypasses policy entirely.

2. **TC9 has no canvas firewall nodes.** `pep_group` and `pep_standalone` are ASP-only solver names and are never placed on the canvas. This is why `model.on_paths` is always empty for TC9 and the ZTA Layout dialog uses the synthesised path mode.

3. **Phase 2 UNSAT on empty topologies.** If no `cand_fw` or `cand_ps` facts are generated, Phase 2 will always be UNSAT. The Show ASP Facts → Summary tab now warns about this condition.

4. **Windows-only tested.** The tool uses Tkinter with some Windows-specific geometry assumptions. Behaviour on Linux or macOS has not been verified.
