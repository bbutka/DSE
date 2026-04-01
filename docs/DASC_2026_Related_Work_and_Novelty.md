# DASC 2026 — Related Work and Novelty Positioning

## What's New vs. Prior Art

| Capability | Closest Prior Work | What Prior Work Covers | What This Tool Adds | Evidence File |
|---|---|---|---|---|
| ZTA for avionics | Hasan et al. (Collins, 2023-24) | AADL ZT pattern library, manual application | Automated synthesis + optimization via ASP | `zta_policy_enc.lp` |
| SoC interconnect security | ARM TrustZone, Xilinx isolation | Static hardware partitioning | Dynamic multi-objective placement under resource constraints | `opt_redundancy_generic_enc.lp` |
| Risk quantification | CVSS, NIST 800-30, OWASP | Multiplicative likelihood×impact | Additive CIA-disaggregated model with exploitability + domain bonus | `opt_redundancy_generic_enc.lp` L128-146 |
| Redundancy verification | DO-178C, IEC 61508 | Manual review of bus independence | Formal ASP proof: `service_quorum` + `node_cut_off` + common-mode detection | `resilience_enc.lp` §8 |
| Access control synthesis | BriefCASE model transformations | Insert ZT components via AADL transforms | Constraint-solving produces provably minimal ACLs under resource caps | `zta_policy_enc.lp` §1-§6 |
| Lifecycle mode policies | ARINC 653 partitioning | Static partition schedules | 3-mode (normal/suspected/confirmed) + 3-phase (op/maint/emergency) co-synthesis | `zta_policy_enc.lp` §4, §6 |
| Resilience analysis | Fault tree analysis (FTA) | Manual scenario enumeration | Auto-generated scenarios from topology + quantitative amplification factors | `resilience_enc.lp`, `phase3_agent.py` |
| Attack path analysis | Network attack graphs | IT network vulnerability chains | SoC-level multi-hop paths with firewall-aware + structural variants | `resilience_enc.lp` §10 |
| Resource-constrained DSE | NSGA-II, genetic algorithms | Heuristic Pareto front exploration | Exact optimal via ASP with Vivado post-implementation costs | `xilinx_ip_catalog.py` |
| Trust anchor gap detection | Manual security review | Expert judgment on missing attestation/RoT | Automatic formal gap detection with quantified risk impact | `zta_policy_enc.lp` §7 |

## Five Strongest Novelty Differentiators

### 1. Risk Model Measures Something Prior Metrics Don't
The additive residual-risk formula `R = Impact + DomainBonus + ExploitMod - EffectiveProtect - LogProtect` avoids the multiplicative artefact that CVSS-style scoring produces on ordinal scales. Under the old multiplicative model, improving logging from `no_logging` to `some_logging` cuts risk by 50% regardless of impact; under the additive model, the reduction is a fixed amount — the correct ordinal-scale behaviour. The dual-risk budget separates security risk (additive, controlled by feature selection) from availability risk (probabilistic, controlled by redundancy architecture).

**File**: `opt_redundancy_generic_enc.lp` lines 124-146

### 2. ASP Formulation Guarantees Optimality
The solver proves there is no assignment with lower total risk that also satisfies all resource/power/latency/partitioning constraints. This is stronger than heuristic DSE (NSGA-II), which can't prove optimality. Integrity constraints like `:- master(M), domain(M,low), critical(IP), reachable(M,IP), not protected(M,IP)` make infeasible topologies UNSAT.

**File**: `zta_policy_enc.lp` line 165

### 3. Checklists Are Ground Atoms, Not Prose
`service_ok(compute_svc)` is either in the answer set or it isn't. The 18-scenario sweep produces a complete fault/compromise coverage matrix. Each `trust_gap_rot(c3)` finding is a formally derived conclusion from the model, not an engineer's judgment call. Reproducible, versionable, machine-checkable.

**File**: `resilience_enc.lp` §8-§11

### 4. Mode-Aware Policy Is Co-Synthesised with Firewall Topology
A manually designed three-mode policy might be inconsistent with firewall placement. The ASP formulation makes this impossible — if the chosen firewalls can't enforce all three modes, the solver returns UNSAT with a diagnostic.

**File**: `zta_policy_enc.lp` §6

### 5. No Existing Tool Produces All Four Deliverables from a Single Input
Prior work addresses individual aspects. This workflow takes one architectural model and outputs: (1) Pareto candidates, (2) ACLs, (3) checklists, (4) comparisons.

**File**: `orchestrator.py`

## Risk to Novelty Story — Counters

| Reviewer Challenge | Counter-Argument | Code Evidence |
|---|---|---|
| "Just a composition of known pieces" | The integration is the contribution — no existing tool produces all 4 deliverables. Collins' stated future work is what this tool does today. | `orchestrator.py` |
| "Risk model is ad-hoc" | Additive model is NIST 800-30 aligned; dual budget cleanly separates security vs availability risk; exploitability modifier follows CVSS structure | `opt_redundancy_generic_enc.lp` header comments |
| "ASP doesn't scale" | TC9 (8 components) solves in <5s; DARPA UAV (11 components) solves in <30s; RefSoC-16 (15 components) solves in <60s | Test suite timing |
| "Only one test case" | Two case studies: SoCDrone (designed as SoC) + DARPA CASE UAV (translated from AADL) | `tgt_system_tc9_inst.lp`, `tgt_system_darpa_uav_inst.lp` |
| "No formal verification" | ASP provides exact optimality proofs and integrity constraints; the solver PROVES no better solution exists | Clingo optN mode |

## Related Work Section Draft (~1 page, IEEE two-column)

### A. SoC Hardware Security
Hardware-enforced isolation on SoCs is well-established through ARM TrustZone [1], Xilinx isolation design flow [2], and secure interconnect architectures [3]. These provide static partitioning but do not automatically select or optimize security feature placement under resource constraints. Our work adds multi-objective optimization over the security feature space.

### B. Avionics Security and Partitioning
Avionics security is governed by DO-326A/ED-202A [4] for airborne systems and ARINC 653 [5] for temporal/spatial partitioning. NIST SP 800-207 [6] defines zero-trust architecture principles. The FAA has mandated ZTA transition for its infrastructure [7]. Hasan et al. at Collins Aerospace [8,9] defined AADL-based ZT architecture patterns for cyber-physical systems, including PEP, attestation, and runtime integrity monitors, and demonstrated manual application to a UAV surveillance system. Their stated future work is to "build a tool that provides the ability to leverage ZT architecture patterns and build ZT compliant CPS systems while providing design-time assurance" — the objective this paper addresses through a different formalism.

The DARPA Cyber Assured Systems Engineering (CASE) program [10] produced the BriefCASE toolchain for applying security model transformations to AADL architectures, with CakeML-verified components deployed on seL4. Our second case study translates the DARPA CASE UAV architecture into our SoC model to enable direct comparison with the manual hardening approach.

A 2023 DASC paper on Zero Trust Avionics Systems (ZTAS) [11] argued that ZTA for aircraft systems is inevitable and called for well-defined approaches for simultaneously designing functionality and ZT cybersecurity — precisely the automated workflow this paper presents.

### C. Risk Quantification
CVSS [12] and NIST SP 800-30 [13] provide risk assessment frameworks. Aven [14] identified pathological artefacts in multiplicative risk matrices applied to ordinal scales. Our additive model avoids these artefacts while preserving NIST-aligned structure. The dual-risk budget cleanly separates security risk (controlled by feature selection) from availability risk (controlled by redundancy).

### D. ASP for Systems Design
Answer Set Programming has been applied to network security analysis [15] and configuration synthesis. Our use of ASP for hardware security DSE is novel in its combination of optimization objectives (#minimize), hard constraints (integrity constraints), and diagnostic capabilities (UNSAT analysis with targeted constraint relaxation).

### Positioning
This work addresses Collins' stated future work objective through automated constraint solving rather than manual pattern application. Unlike BriefCASE's model-transformation approach, our ASP formulation explores the full design space and proves optimality. The tool produces four deliverables from a single input model — Pareto-optimal architectures, access control policies, resilience checklists, and strategy comparisons — capabilities not available in any single existing tool.

## References (to verify/complete)

[1] ARM, "ARM TrustZone Technology," ARM Ltd., 2023.
[2] Xilinx, "Isolation Design Flow," UG1085, 2022.
[3] S. Drzevitzky et al., "Secure interconnect for SoCs," DATE, 2019.
[4] RTCA, "DO-326A: Airworthiness Security Process Specification," 2014.
[5] ARINC, "ARINC 653: Avionics Application Software Standard Interface," 2015.
[6] S. Rose et al., "Zero Trust Architecture," NIST SP 800-207, 2020.
[7] MITRE, "FAA Zero Trust Architecture Implementation," 2023.
[8] M. Hasan et al., "Zero Trust Architecture Design Patterns for CPS," SAE AeroTech, 2023.
[9] M. Hasan et al., "Assurance of ZT mechanisms for CPS," J. Systems Architecture, 2024.
[10] D. Hardin et al., "BriefCASE: Cyber Assured Systems Engineering," DARPA, 2021.
[11] "Zero Trust Avionics Systems (ZTAS)," IEEE/AIAA 42nd DASC, 2023.
[12] FIRST, "Common Vulnerability Scoring System v3.1," 2019.
[13] NIST, "Guide for Conducting Risk Assessments," SP 800-30 Rev.1, 2012.
[14] T. Aven, "On the meaning of a risk matrix," Reliability Eng. & System Safety, 2012.
[15] J. Oetsch et al., "ASP for security analysis," LPNMR, 2015.
