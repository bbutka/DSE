# DSE Tool Checkpoint Status Report

**Date:** 2026-03-29
**Branch:** feat/dual-risk-budget (2 commits ahead of origin + extensive uncommitted changes)
**Tool Version:** HOST26_Code (GUI-based DSE Security Analysis Tool)

---

## 1. Current State Summary

The DSE Security Analysis Tool is a three-phase design space exploration framework for security-enabled SoC topologies. It uses Answer Set Programming (Clingo) to solve constrained optimization problems across security feature selection, Zero Trust Architecture policy synthesis, and resilience scenario analysis.

### Working Status

| Test Case | Phase 1 | Phase 2 | Phase 3 | Exec Summary | Status |
|-----------|---------|---------|---------|--------------|--------|
| TC9 (max_security) | SAT | SAT | SAT (7+ scenarios) | PASS | **PASS** |
| TC9 (min_resources) | SAT | SAT | SAT (7+ scenarios) | PASS | **PASS** |
| TC9 (balanced) | SAT | SAT | SAT (7+ scenarios) | PASS | **PASS** |
| RefSoC-16 (max_security) | SAT | UNSAT | Blocked | N/A | **PHASE 2 BLOCKED** |
| RefSoC-16 (min_resources) | SAT | UNSAT | Blocked | N/A | **PHASE 2 BLOCKED** |
| RefSoC-16 (balanced) | SAT | UNSAT | Blocked | N/A | **PHASE 2 BLOCKED** |

### Regression Test Suite

**127 tests, 127 passing** (`py -3.12 -m unittest tests.test_regression -v`)

| Category | Count | Status |
|----------|-------|--------|
| Data model (Component, Asset, NetworkModel) | 5 | PASS |
| TC9 factory validation | 14 | PASS |
| RefSoC-16 factory validation | 12 | PASS |
| ASP fact generation | 22 | PASS |
| Topology validation | 6 | PASS |
| Solution parser (Phase 1/2/3 results) | 13 | PASS |
| Solution ranker (scoring, CIA, capabilities) | 11 | PASS |
| Comparison engine and report | 3 | PASS |
| Executive summary analyser | 5 | PASS |
| Scenario generation | 8 | PASS |
| Clingo integration (basic SAT/UNSAT) | 2 | PASS |
| Phase 1 integration (TC9 × 3, RefSoC × 1) | 4 | PASS |
| Phase 2 integration (TC9) | 1 | PASS |
| Phase 3 integration (TC9 baseline + auto + caps) | 3 | PASS |
| Full pipeline (orchestrator + executive summary) | 3 | PASS |
| Edge cases and regression guards | 12 | PASS |

---

## 2. What Works (Complete Feature List)

### Core Pipeline
- **Full TC9 pipeline**: All three strategies pass all three phases end-to-end
- **Phase 1**: Security feature selection with CIA-weighted risk, amplification-aware objective, dual risk budgets (security + availability)
- **Phase 2**: ZTA policy synthesis — firewall/PS placement, allow/deny rules, three security modes (normal/suspected/confirmed), policy tightness scoring, trust gap analysis, excess/missing privilege detection
- **Phase 3**: Resilience scenario analysis — blast radius (structural + effective), attack path enumeration, service availability, control plane health, capability functional assessment, protection-aware exposure model
- **Auto-scenario generation**: Scenarios generated dynamically from topology (master compromises, bus failures, PS compromises, redundancy group failures, PEP bypasses, combined scenarios)
- **Topology validation**: Pre-solve structural checks for UNSAT risk (FW coverage, governance, ip_loc consistency, safety-critical typing)
- **UNSAT diagnosis**: Phase 2 performs 3 independent constraint relaxation probes to identify root cause

### Analysis & Reporting
- **Solution ranker**: 0-100 normalized scores across 6 axes (Security, Resources, Power, Latency, Resilience, Policy)
- **CIA-weighted scoring**: Read=1.0x, Write=1.5x, Availability=2.0x for embedded/safety-critical context
- **Resilience scoring**: 40% blast radius + 40% capability retention + 20% control plane health
- **Comparison engine**: Topology-agnostic pros/cons with parameterized resource budgets
- **Full report**: Executive summary, per-strategy details, risk profiles, feature assignments, policy analysis, resilience scenarios, mission capability summary, recommendations
- **Executive Summary**: Cross-strategy invariant analysis, bottleneck ranking (TOPOLOGY > CAPABILITY > TRUST > POLICY > FEATURE), architecture adequacy verdict, long pole identification
- **CSV export**: Per-strategy metrics to spreadsheet

### GUI
- **Network editor canvas**: Drag-to-move, right-click menus, double-click edit, zoom, undo/redo, copy/paste, grid snap
- **Preset topologies**: "Load TC9" and "Load RefSoC-16" with full model fidelity
- **Analysis results overlay**: Risk halos, placement badges, feature labels on canvas
- **Phase detail dialogs**: Resources, security features, risk breakdown (Phase 1); allow/deny, tightness, trust gaps, privileges (Phase 2); scenario navigator with blast radius, services, capabilities, attack paths (Phase 3)
- **Compare Strategies dialog**: Color-coded comparison table with capability retention and non-functional scenario counts
- **Executive Summary button**: One-click synthesis of all data with architecture verdict
- **Solver Config dialog**: Per-strategy ASP objective overrides
- **Show ASP Facts dialog**: Searchable, syntax-highlighted viewer with summary tab
- **JSON save/load**: Network topology persistence
- **Resource budget warnings**: Post-analysis FPGA cap check

### Documentation
- **Formal threat model** (`docs/threat_model.md`): System abstraction, adversary model, attack scenarios, trust boundaries, security properties (C/I/A/Isolation/Least-Privilege/Functional-Resilience), risk quantification model, CIA weighting justification, standards mapping
- **User guide** (`DSE_Tool_User_Guide.md`): Complete walkthrough of all features
- **Project rules** (`CLAUDE.md`): Architecture notes, conventions, known issues for AI assistants

---

## 3. Changes Since Last Checkpoint

### New Files
| File | Description |
|------|-------------|
| `dse_tool/core/executive_summary.py` | Executive summary analysis engine — bottleneck identification, long pole analysis, architecture verdict |
| `Clingo/resilience_enc.lp` | Generalized resilience encoding with FW-aware blast radius, attack paths, protection discounts, capability assessment |
| `Clingo/tgt_system_refsoc_inst.lp` | Standalone RefSoC-16 instance facts for direct Clingo testing |
| `docs/threat_model.md` | Formal threat model document for conference submission |
| `CLAUDE.md` | Project rules and conventions |
| `tests/test_regression.py` | 127-test regression suite |

### Major Code Changes
| Area | Changes |
|------|---------|
| **Resilience encoding** | Generalized PS rules (no hardcoded ps0/ps1), FW-aware blast radius (`effective_blast_radius`), attack path enumeration (`attack_step`/`min_attack_distance`/`escalation_path`), protection-aware exposure discounts, functional capability assessment (`capability_ok`/`capability_degraded`/`capability_lost`/`system_functional`) |
| **Scenario generation** | `generate_scenarios()` in `phase3_agent.py` auto-creates scenarios from topology; `_valid_asp_components()` validates names against ASP-emittable set |
| **Executive summary** | `ExecutiveSummaryAnalyser` with cross-strategy invariant detection, risk hotspot analysis, policy effectiveness, resilience patterns, capability impact, trust gap assessment, bottleneck ranking, architecture verdict |
| **Results panel** | "Executive Summary" button wired through `set_system_caps` → `_ExecutiveSummaryDialog` with color-coded text, architecture verdict banner, long pole highlighting |
| **Comparison engine** | Topology-agnostic resource caps (`max_luts`/`max_power`/`max_ffs` parameters), mission capability summary in report, capability retention and non-functional scenario rows in comparison table |
| **Solution ranker** | CIA-weighted security score, composite resilience score with capability retention, policy score heuristic fallback |
| **Topology validation** | `ASPGenerator.validate_topology()` with 4 structural checks; orchestrator runs validation pre-solve |
| **UNSAT diagnosis** | `Phase2Agent._diagnose_unsat()` with 3 independent constraint relaxation probes |
| **Solution parser** | `same_exp` field for same-trust exposure, `ScenarioResult` fields for effective blast radius, attack paths, escalation paths, structural paths, capability status |

### Bug Fixes (W1-W10 Weaknesses)
| # | Fix | File |
|---|-----|------|
| W1 | Parameterized resource caps (no hardcoded PYNQ-Z2 constants) | comparison.py, orchestrator.py |
| W2 | `system_caps` flows through entire pipeline | comparison.py, solution_ranker.py |
| W3 | Documented attack_step cycle handling | resilience_enc.lp |
| W4 | Fixed circular `scenario_asset_risk` with `has_action_risk` guard | resilience_enc.lp |
| W5 | Policy score composite heuristic fallback | solution_ranker.py |
| W6 | Scenario component name validation | phase3_agent.py |
| W7 | Documented effective_reachable fixpoint semantics | resilience_enc.lp |
| W8 | Same-trust exposure parsing and display | solution_parser.py, results_panel.py |
| W9 | Documented asset-level vs component-level selection | init_enc.lp |
| W10 | Topology validation + UNSAT diagnosis | asp_generator.py, phase2_agent.py |

---

## 4. Known Issues — Future Work

### 4a. RefSoC-16 Phase 2 UNSAT (HIGH PRIORITY)

**Status:** Phase 1 passes for all 3 strategies. Phase 2 returns UNSAT, blocking Phase 3.

**Diagnosis:** Topology validation passes (no structural UNSAT risks detected). UNSAT diagnosis probes need runtime verification. Most likely cause is constraint interaction between critical-IP firewall coverage and ZTA policy rules when the topology has 3 masters, 3 bus segments, and 10+ receivers with mixed trust domains.

**Recommended fix path:**
1. Dump RefSoC Phase 2 facts and run Clingo manually to get UNSAT core
2. Run the 3 diagnostic probes and identify which constraint(s) conflict
3. Fix the specific constraint interaction

### 4b. Remaining Plan Work Packages

| WP | Description | Status | Depends On |
|----|-------------|--------|------------|
| WP1 | Fix RefSoC Phase 2 UNSAT | IN PROGRESS | Nothing |
| WP2 | Generalize resilience encoding (rename tc9 files) | DONE | — |
| WP3 | Auto-generate scenarios from topology | DONE | WP2 |
| WP4 | Firewall-aware blast radius | DONE | WP2 |
| WP5 | Attack path enumeration | DONE | WP2, WP4 |
| WP6 | Protection-aware exposure model | DONE | WP2 |

### 4c. Minor Issues

| Issue | Severity | Description |
|-------|----------|-------------|
| Debug dump files | LOW | `_debug_p1_*.lp` files still generated by Phase 1 agent |
| JSON ZTA persistence | LOW | Save/load doesn't persist ZTA state (cand_fws, on_paths, etc.) |
| Node dialog trust anchors | LOW | Can't edit key_storage/signed_policy/trusted_telemetry via canvas dialog |
| Legacy tc9 files | LOW | `resilience_tc9_enc.lp`, `runtime_adaptive_tc9_enc.lp` still present but unused |

---

## 5. Architecture Overview

```
dse_tool/
├── __main__.py              # Entry point (python -m dse_tool)
├── gui/
│   ├── main_window.py       # Root Tk window, toolbar, menus, orchestrator wiring
│   ├── network_editor.py    # Canvas topology editor with model round-trip
│   ├── progress_panel.py    # Phase progress indicators + log
│   └── results_panel.py     # Strategy cards, detail dialogs, comparison, exec summary
├── agents/
│   ├── orchestrator.py      # Coordinates 3 strategies × 3 phases + scoring + reporting
│   ├── phase1_agent.py      # Security feature selection (Clingo)
│   ├── phase2_agent.py      # ZTA policy synthesis + UNSAT diagnosis (Clingo)
│   └── phase3_agent.py      # Resilience scenario analysis + auto-scenario gen (Clingo)
├── core/
│   ├── asp_generator.py     # NetworkModel → ASP facts; TC9/RefSoC factories; topology validation
│   ├── clingo_runner.py     # Clingo API wrapper with timeout
│   ├── solution_parser.py   # Atom list → Phase1/2/3 Result dataclasses
│   ├── solution_ranker.py   # 0-100 scores: Security, Resources, Power, Latency, Resilience, Policy
│   ├── comparison.py        # Pros/cons generation, full report text, comparison table
│   └── executive_summary.py # Cross-strategy analysis, bottleneck ranking, architecture verdict
Clingo/
├── init_enc.lp              # Base component/asset initialization + feature selection
├── bridge_enc.lp            # Component-to-asset bridging + latency constraints
├── opt_power_enc.lp         # Power optimization encoding
├── opt_resource_enc.lp      # FPGA resource encoding
├── opt_redundancy_generic_enc.lp  # Dual-risk (security + availability) encoding
├── security_features_inst.lp      # Auto-generated from IP catalog
├── zta_policy_enc.lp              # Phase 2: ZTA policy synthesis
├── resilience_enc.lp              # Phase 3: Generalized resilience + capabilities
└── resilience_tc9_enc.lp          # Phase 3: Legacy TC9-specific (unused)
docs/
└── threat_model.md          # Formal threat model for conference submission
tests/
└── test_regression.py       # 127-test regression suite
ip_catalog/
└── xilinx_ip_catalog.py     # FPGA IP resource cost database
```

---

## 6. Key Technical Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| Minimum achievable latency | 4 cycles | zero_trust(3) + no_logging(1) |
| FPGA target | PYNQ-Z2 (xc7z020) | system_caps |
| Max LUTs | 53,200 | system_capability |
| Max FFs | 106,400 | system_capability |
| Max Power | 15,000 mW | system_capability |
| CIA weights | C=1.0, I=1.5, A=2.0 | solution_ranker.py |
| Risk amplification scale | ×10 | AMP_DENOM in solution_parser.py |
| Domain levels | untrusted(0), low(0), normal(1), privileged(2), high(3), root(3) | domain_level/2 |
| Security modes | normal, attack_suspected, attack_confirmed | mode/1 in zta_policy_enc.lp |
| Resilience score weights | 40% blast + 40% capability + 20% control plane | solution_ranker.py |
| Protection discount cap | 7 (security + logging combined) | resilience_enc.lp |
| Attack path depth bound | 5 hops | resilience_enc.lp |
| Bottleneck priority | CRITICAL > HIGH > MEDIUM > LOW; TOPOLOGY > CAPABILITY > TRUST > POLICY > FEATURE | executive_summary.py |
| Architecture redesign threshold | 4+ arch_issues triggers REDESIGN verdict | executive_summary.py |

---

## 7. How to Pick Up From Here

### Quick Start
```bash
cd D:\DSE\DSE_ADD
py -3.12 -m dse_tool              # Launch GUI
py -3.12 -m unittest tests.test_regression -v   # Run regression suite
```

### Priority Tasks
1. **Commit all changes to GitHub** — 21 modified files + 8 new files at risk
2. **Fix RefSoC-16 Phase 2 UNSAT** — the only major blocking issue
3. **Remove debug dump files** — `_debug_p1_*.lp` generation in Phase 1 agent
4. **Test executive summary with real TC9 data** — verify GUI button end-to-end

### Key Files to Read First
1. `CLAUDE.md` — project rules, architecture, conventions, known issues
2. `docs/threat_model.md` — formal threat model (security properties, risk quantification)
3. `dse_tool/core/executive_summary.py` — newest analysis engine
4. `Clingo/resilience_enc.lp` — generalized resilience encoding with all WP4/5/6 features
5. `tests/test_regression.py` — regression suite covering all modules
