# DASC 2026 Paper Plan

## Target
- **Conference**: IEEE/AIAA 44th Digital Avionics Systems Conference (DASC 2026)
- **Theme**: "Safe and Secure Digital Avionics in the Age of AI"
- **Format**: 8 pages, IEEE two-column, double-blind review
- **Deadline**: May 30, 2026 (full paper)

## Title (working)
"Assurance-Aware Design Space Exploration for Zero-Trust Avionics SoC Security"

## Abstract Claims → Evidence Map

| # | Abstract Claim | Evidence in Codebase | Status |
|---|---------------|---------------------|--------|
| 1 | Pareto-optimal security architectures | ASP solver with `#minimize` in `opt_redundancy_generic_enc.lp` explores full solution space | READY |
| 2 | Access control policies | `zta_policy_enc.lp` §1-§6: ACL synthesis, RBAC, mission-context, 3-mode policies | READY |
| 3 | Redundancy/fail-safe checklists | `opt_redundancy_generic_enc.lp` + resilience scenarios verify bus independence | READY |
| 4 | Graphical comparison views | GUI `results_panel.py` + `comparison.py` text report + CSV export | READY |
| 5 | Risk calculated per component/asset | Additive dual-risk model: `Risk = Impact + DB + EM - SP - LP` | READY |
| 6 | ZTA hardware security | FW/PS placement, trust anchor gaps, attestation in `zta_policy_enc.lp` §5-§7 | READY |
| 7 | Anomaly detection | `runtime_adaptive_tc9_enc.lp`: monitor placement, observability, threat scoring | READY |

## Paper Structure (8 pages, IEEE two-column)

### I. Introduction (1 page)
- Problem: SoC security in avionics — hardware consolidation trend
- Gap: No automated tool for multi-objective ZTA synthesis on SoCs
- Contribution: 4 deliverables from single model
- Paper organization

### II. Related Work (1 page)
- SoC hardware security (prior isolation/interconnect work)
- Avionics security frameworks (DO-326A, NIST 800-207, ARINC 653)
- Collins Aerospace ZT patterns (Hasan et al. 2023, 2024)
- DARPA CASE / BriefCASE toolchain
- ASP for systems design
- Positioning paragraph: first automated ZTA synthesis at SoC level

### III. System Model and Threat Model (1 page)
- Graph model G=(V,E) with typed vertices
- 6-level trust domains
- CIA impact model
- Exploitability modifier
- Threat classes (from docs/threat_model.md)

### IV. Workflow and ASP Formulation (2 pages)
- Phase 1: Security feature DSE
  - Additive risk formula (Equation 1)
  - Dual-risk budget (Equation 2-3)
  - Resource/power/latency constraints
  - Key ASP rules (Listing 1: ~12 rules)
- Phase 2: ZTA policy synthesis
  - FW/PS placement with cost minimization
  - Least-privilege analysis
  - Mode-aware access control (normal/suspected/confirmed)
  - Trust anchor gap detection
- Phase 3: Resilience analysis
  - Scenario generation (auto from topology)
  - Blast radius (structural + firewall-aware)
  - Service availability (quorum model)
  - Capability assessment

### V. Implementation (0.5 page)
- Tool architecture: Python + Clingo ASP solver
- Xilinx IP catalog (PYNQ-Z2 resource estimates)
- GUI with network editor + results panel

### VI. Case Studies and Results (2 pages)
- **Case Study 1: SoCDrone (TC9)**
  - 8 components, 2 buses, 5-member redundancy group
  - Phase 1: optimal assignments, 17% LUT utilization
  - Phase 2: 2 FWs, 1 PS, 9 excess privileges detected
  - Phase 3: 18 scenarios, worst=3.0x baseline
  - Key finding: c8 latency constraint dominates residual risk

- **Case Study 2: DARPA CASE UAV**
  - 11 components, 4 buses, 4 safety-critical, 0 redundancy
  - Translation from AADL software architecture to SoC model
  - Phase 1-3 results (pending run)
  - Key findings: single-string architecture, radio_drv bridge risk

- **Comparative Table**: TC9 vs UAV metrics

### VII. Conclusion (0.5 page)
- Summary of contributions
- Limitations: single-chip scope, no timing verification
- Future work: multi-chip, formal verification integration

## Figures and Tables

| # | Type | Content | Source |
|---|------|---------|--------|
| Fig 1 | Diagram | Workflow architecture (4 deliverables) | Manual |
| Fig 2 | Diagram | SoCDrone topology block diagram | Manual |
| Fig 3 | Diagram | DARPA UAV topology block diagram | Manual |
| Fig 4 | Chart | Resilience heatmap (scenario × strategy) | From results |
| Table I | Data | Risk model parameters and protection values | `xilinx_ip_catalog.py` |
| Table II | Data | TC9 Phase 1 results (per-component assignment) | `runClingo_tc9.py` output |
| Table III | Data | TC9 Phase 3 scenario results | `runClingo_tc9.py` output |
| Table IV | Data | Comparative: TC9 vs DARPA UAV | Both runs |
| Table V | Data | Trust anchor gap findings | Phase 2 output |
| Listing 1 | Code | Key ASP rules (~12 lines) | LP files |

## Key Numbers from TC9 Run

- Phase 1: Total risk = 51, LUTs = 9,340/53,200 (17%), Power = 184mW
- Phase 2: 2 FWs placed, 1 PS deployed, cost = 450, 9 excess privileges
- Phase 3: 18 scenarios, baseline=51.0, worst=153.0 (3.0x), ZTA reduction=3.0x
- Trust gaps: 6 components lack HW RoT, 3 lack secure boot, 1 master unattested
- Control plane: ps0 compromise = 2.5x amplification (highest CP scenario)
