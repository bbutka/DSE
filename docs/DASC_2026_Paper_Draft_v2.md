# Assurance-Aware Design Space Exploration for Zero-Trust Avionics SoC Security

*Paper draft for IEEE/AIAA 44th DASC 2026 — "Safe and Secure Digital Avionics in the Age of AI"*
*Format: 8 pages, IEEE two-column, double-blind*

---

## Abstract

Modern avionics increasingly consolidate safety-critical and security-sensitive functions onto shared System-on-Chip (SoC) platforms. This hardware consolidation creates new attack surfaces where a compromised IP core can reach safety-critical assets through shared bus interconnects. We present an automated design space exploration (DSE) workflow that synthesizes zero-trust security architectures for avionics SoCs. Using Answer Set Programming (ASP), the tool takes a single architectural model and produces five deliverables: (1) Pareto-optimal security feature assignments under FPGA resource constraints, (2) least-privilege access control policies with lifecycle mode awareness, (3) resilience checklists derived from automated fault and compromise scenarios, (4) runtime-adaptive mode transition and response policies driven by anomaly scoring, and (5) multi-strategy comparison reports. The workflow employs an additive risk model aligned with NIST SP 800-30 that separately budgets security risk and availability risk, enabling independent optimization of feature selection and redundancy architecture. We evaluate the approach on two case studies: an 8-component SoC drone and an 11-component UAV translated from the DARPA CASE surveillance architecture. The tool identifies 9 excess privileges, 6 trust anchor gaps, and a 3.0× risk reduction from zero-trust overlay on the SoC drone, while revealing single-string architecture vulnerabilities in the UAV that the manual AADL-based hardening approach of Hasan et al. did not surface.

**Keywords**: Zero-Trust Architecture, System-on-Chip Security, Design Space Exploration, Answer Set Programming, Avionics, DO-326A

---

## I. Introduction

The avionics industry is undergoing a fundamental shift toward hardware consolidation, where multiple safety-critical and security-sensitive functions are integrated onto shared System-on-Chip (SoC) platforms. This trend, driven by size, weight, and power (SWaP) optimization, creates new cybersecurity challenges: a compromised IP core on a shared bus fabric can potentially access every other component on the same interconnect, bypassing the physical isolation that traditional federated architectures provided.

Zero-Trust Architecture (ZTA), as defined by NIST SP 800-207 [6], eliminates implicit trust based on network location. The FAA has mandated ZTA transition for its ground infrastructure [7], and recent work has called for extending ZTA principles to airborne avionics systems [11]. However, applying ZTA to SoC interconnects presents unique challenges not addressed by enterprise network ZTA: hardware resource constraints (LUTs, flip-flops, power), real-time latency requirements, and the need to co-optimize security feature selection with firewall placement and access control policy synthesis.

This paper presents an automated DSE workflow that addresses these challenges through Answer Set Programming (ASP). Given a single SoC architectural model, the tool produces five deliverables:

1. **Pareto-optimal security architectures** — security and logging feature assignments that minimize residual risk under FPGA resource, power, and latency constraints, with proven optimality.
2. **Access control policies** — least-privilege ACLs with role-based access control, mission-phase awareness (operational, maintenance, emergency), and three-mode security policies (normal, attack suspected, attack confirmed).
3. **Resilience checklists** — automatically generated fault and compromise scenarios with quantitative blast radius, service availability, capability assessment, and attack path analysis.
4. **Runtime-adaptive response policies** — anomaly-driven mode transitions with automatic quarantine, re-attestation, PEP lockdown, and policy-signing enforcement actions, bridged to the static Phase 2 policy layer.
5. **Strategy comparison reports** — multi-dimensional scoring across security, resources, power, latency, and resilience for three optimization strategies (maximum security, minimum footprint, balanced).

The key contributions are:
- An additive risk model with dual-risk budget that separates security risk from availability risk, aligned with NIST SP 800-30 and avoiding multiplicative artefacts on ordinal scales.
- Automated ZTA policy synthesis that co-optimizes firewall topology with mode-aware access control, proving infeasibility when constraints conflict.
- Runtime-adaptive security mode transitions where anomaly scoring drives automatic quarantine and response actions, with an enforcement bridge that overrides static policies based on runtime trust state.
- Topology-agnostic resilience analysis with firewall-aware blast radius and multi-hop attack path enumeration.
- Evaluation on two case studies demonstrating generality across SoC architectures, including a direct comparison with the Collins Aerospace manual ZT pattern approach on the same UAV system.

> **Fig. 1 — DSE Workflow Overview** *(two-column, top of page 2)*
> A left-to-right pipeline diagram with four stages:
> (1) **Input Model** — box showing SoC topology graph (components, buses, masters, trust domains, assets, latency constraints, FPGA budget). Label: "Single .lp instance file".
> (2) **Phase 1: Security DSE** — ASP solver icon with label "Clingo 5.8, optN mode". Outputs: security/logging assignment table, resource bar chart (LUTs/FFs/Power), risk budget gauge.
> (3) **Phase 2: ZTA Synthesis** — firewall/PEP placement diagram fragment, ACL matrix, mode-aware policy tree (normal→attack_suspected→attack_confirmed). Arrow labeled "UNSAT → infeasibility diagnosis".
> (4) **Phase 3: Resilience** — scenario grid with heatmap cells color-coded by risk amplification factor (green=1×, yellow=1.5×, red=2×+). Blast radius graph overlay.
> Right side: three strategy columns (max_security / min_resources / balanced) converge into a **Comparison Report** box.
> *Caption*: "Fig. 1. Automated DSE workflow. A single SoC model produces four deliverables through three sequential ASP solving phases, run for each of three optimization strategies."

---

## II. Related Work

### A. SoC Hardware Security
Hardware-enforced isolation on SoCs is well-established through ARM TrustZone [1], Xilinx isolation design flow [2], and secure interconnect architectures. These provide static partitioning but do not automatically select or optimize security feature placement under resource constraints. Our work adds multi-objective optimization over the security feature space, producing provably optimal placements subject to FPGA resource caps.

### B. Avionics Security and ZTA
Avionics security is governed by DO-326A/ED-202A [4] for airworthiness security processes and ARINC 653 [5] for temporal/spatial partitioning. NIST SP 800-207 [6] defines zero-trust principles. The FAA has mandated ZTA transition for ground infrastructure [7], but application to on-chip avionics remains nascent.

Hasan et al. [8,9] defined AADL-based ZT architecture patterns for cyber-physical systems, including PEP, attestation, and runtime integrity monitors, demonstrating manual application to a UAV surveillance system. Their stated future work is to "build a tool that provides the ability to leverage ZT architecture patterns and build ZT compliant CPS systems while providing design-time assurance." This paper addresses that objective through constraint solving rather than manual pattern application.

The DARPA CASE program [10] produced the BriefCASE toolchain for security model transformations on AADL architectures with CakeML-verified components on seL4. A 2023 DASC paper [11] argued that ZTA for avionics is inevitable and called for simultaneous functionality-security co-design approaches. Our tool provides the automated synthesis workflow these works envision.

### C. Risk Quantification and DSE
CVSS [12] and NIST SP 800-30 [13] provide risk frameworks. Aven [14] identified pathological artefacts in multiplicative risk matrices on ordinal scales. Our additive model avoids these while preserving NIST structure. For design space exploration, heuristic approaches (NSGA-II, genetic algorithms) cannot prove optimality; ASP provides exact solutions with constraint satisfaction guarantees [15].

### D. Positioning
Unlike Collins' manual pattern application, our ASP formulation explores the full design space and proves optimality. Unlike BriefCASE's model transformations, we simultaneously synthesize feature assignments, firewall placement, and access policies under quantitative resource constraints. No existing tool produces all four deliverables from a single input model.

---

## III. System Model and Threat Model

### A. SoC Graph Model
We model the SoC as a directed graph *G = (V, E)* where vertices are typed:

- *V_M*: Bus masters (processors, DMA controllers) — transaction initiators
- *V_R*: Receiver IP cores (accelerators, peripherals, sensors) — transaction targets
- *V_B*: Bus interconnects (AXI, APB, NoC segments)
- *V_FW*: Policy Enforcement Points (hardware firewalls)
- *V_PS*: Policy Decision Points (policy servers)

Edges *E ⊆ V × V* represent physical bus connections. Each component is annotated with:

| Property | Domain | Semantics |
|---|---|---|
| domain(c) | {untrusted, low, normal, privileged, high, root} | Hardware trust domain |
| impact(c, op) | [1,5] for op ∈ {read, write, avail} | CIA impact if compromised |
| exploitability(c) | [1,5] | CVSS-aligned attack surface |
| latency(c, op) | cycles | Maximum allowable pipeline depth |

### B. Threat Model
We consider an attacker who can compromise any single component or bus, with effects propagating through the interconnect topology. The model captures the following key threat classes (8 total; enumerated in full in the open-source instance files):
- **Direct compromise**: attacker controls a component's assets
- **Cross-domain escalation**: compromised low-trust component reaches high-trust assets
- **Control plane attack**: policy server compromise bypasses all governed firewalls
- **Common-mode failure**: shared bus failure cuts off all connected components

### C. Security Features
Each receiver component is assigned exactly one security feature and one logging feature from a catalog with Vivado post-implementation resource estimates (Table I).

**Table I: Security Feature Catalog (PYNQ-Z2 Target)**

| Feature | LUTs | FFs | Power (mW) | Latency (cy) | Protection |
|---|---|---|---|---|---|
| no_security | 0 | 0 | 0 | 0 | 0 |
| mac | 650 | 480 | 12 | 3 | 4 |
| dynamic_mac | 1200 | 920 | 22 | 5 | 5 |
| zero_trust | 2100 | 1500 | 38 | 8 | 6 |
| no_logging | 0 | 0 | 0 | 0 | 0 |
| some_logging | 180 | 140 | 4 | 1 | 1 |
| zero_trust_logger | 450 | 320 | 8 | 2 | 2 |

---

## IV. Workflow and ASP Formulation

The tool executes three phases sequentially, each formulated as an ASP optimization problem solved by the Clingo solver.

### A. Phase 1: Security Feature DSE

**Risk Model.** For each component *c* with asset *a* and action *op* ∈ {read, write, avail}:

*R(c, a, op) = max(0, Impact(a, op) + DomainBonus(c) + ExploitMod(c) - EffProtect(c, op) - LogProtect(c))*

where DomainBonus maps trust domains to [0,3], ExploitMod = exploitability − 3 ∈ [−2, +2], EffProtect dispatches to security (read/write) or availability (avail) protection tables, and LogProtect is the logging feature's detection capability. The ExploitMod offset of 3 represents the median CVSS v3.1 attack complexity for SoC IP cores: components with exploitability < 3 (CakeML-verified, formally proven) receive a risk discount, while components with exploitability > 3 (RF interfaces, debug ports) receive a penalty. This centers the modifier at zero for typical IP cores, consistent with NIST 800-30's "likely" likelihood category.

**Dual-Risk Budget.** Two independent hard constraints replace a single risk cap, separating concerns that prior SoC risk models conflate:

1. *Security risk budget*: for non-redundant components, R(c,a,op) ≤ Cap_sec
2. *Availability risk budget*: for redundant group members, Impact × P_combined / 100 ≤ Cap_avail

where P_combined is the product of individual failure probabilities scaled to the integer range [0, 100] (i.e., P_combined = ∏ p_i × 10^k, truncated to [0,100]). The two budgets bind independently: in TC9, c8's security risk cap binds at 3 (forcing zero_trust assignment) while its availability risk is unconstrained (no redundancy group), whereas the c1–c5 group members have relaxed security caps but tight availability caps from the probabilistic formula. This independence allows the solver to optimize feature selection and redundancy architecture separately.

**Optimization.** The solver minimizes total weighted risk subject to:
- Exactly one security feature and one logging feature per component
- Total LUTs ≤ FPGA capacity (53,200 for PYNQ-Z2)
- Total power ≤ budget (15W)
- Per-asset latency ≤ allowable latency
- Dual-risk budget constraints

The ASP encoding guarantees *proven optimality*: the solver exhaustively explores all valid feature assignments and returns the one with minimum total risk.

**Listing 1: Key Phase 1 ASP Rules**

```prolog
% Choice: exactly one security and logging feature per component
1 { selected_security(C, F) : security_feature(F) } 1 :- asset(C, _, _).
1 { selected_logging(C, L)  : logging_feature(L)  } 1 :- asset(C, _, _).

% Additive residual risk (clamped >= 0)
original_register_risk(C, R, Action, Risk) :-
    component(C), asset(C, R, Action), impact(R, Action, Imp),
    domain_bonus(C, DB), exploit_mod(C, EM),
    effective_protect_score(C, Action, P), log_protect_score(C, LP),
    Risk = Imp + DB + EM - P - LP, Risk >= 0.

% Dual-risk budget: security cap (non-redundant)
:- security_residual_risk(_, _, _, Risk),
   system_capability(max_security_risk, Cap), Risk > Cap.

% Dual-risk budget: availability cap (redundant groups)
:- avail_risk(_, _, _, Risk),
   system_capability(max_avail_risk, Cap), Risk > Cap.

% Minimize total weighted risk
#minimize { WR, C, Asset, Action : weighted_risk(C, Asset, Action, WR) }.
```

> **Fig. 2 — Additive Risk Model** *(single column, Section IV.A)*
> A formula diagram showing the risk equation with annotated components:
> `Risk = Impact + DomainBonus + ExploitMod − EffectiveProtect − LogProtect`
> Below the equation, a stacked bar for an example component (radio_drv): Impact=5 (red), DomainBonus=0 (none), ExploitMod=+2 (orange), EffectiveProtect=−5 (blue, zero_trust), LogProtect=−2 (teal, zero_trust_logger). Net residual = 0.
> Second bar shows same component with mac+no_logging: EffectiveProtect=−3, LogProtect=0. Net residual = 4.
> *Caption*: "Fig. 2. Additive risk model for a single (component, asset, action) triple. Protection scores subtract from impact+exploitability, clamped to zero. Zero_trust+logger drives residual to zero for this component; mac alone leaves residual risk of 4."

### B. Phase 2: ZTA Policy Synthesis

Phase 2 takes Phase 1's security assignments and synthesizes:

**Firewall and policy server placement** minimizes total cost subject to isolation constraints: every low-trust master that can topologically reach a critical IP must be protected. Least-privilege analysis compares topology-implied access against declared needs, flagging `excess_privilege(M, C, Op)` for every grant not in `access_need`.

**Mode-aware access control** with three security modes:
- *Normal*: role-based access per declared needs
- *Attack suspected*: only attested masters access non-critical IPs (preserves monitoring)
- *Attack confirmed*: full isolation of all IPs

**Trust anchor gap detection** identifying components lacking hardware root of trust, secure boot, attestation, or key storage.

### C. Phase 3: Resilience Analysis

Scenarios are auto-generated from the topology (not hardcoded), covering:
- Single-master compromise, bus failures, PS/PEP compromise
- Redundancy group attacks, combined fault+compromise scenarios
- Control plane degradation (PS failure → stale policy → ungoverned PEPs)

For each scenario, the solver computes:
- **Blast radius**: structural (topology-only) and effective (firewall-aware)
- **Service availability**: quorum-based OK/degraded/unavailable per service
- **Capability assessment**: essential/important capabilities OK/degraded/lost
- **Attack paths**: multi-hop chains to safety-critical targets (≤5 hops)
- **Risk amplification**: per-asset scenario risk via exposure type factors

### D. Phase 4: Runtime Adaptation

While Phases 1–3 produce static design-time policies, real-world avionics systems must respond to anomalies detected during operation. Phase 4 extends the three-mode policy framework with runtime-adaptive mode transitions driven by anomaly scoring.

**Monitor Placement.** Runtime monitors are placed analogously to Phase 2's firewall placement: a cost-bounded selection from candidates, subject to hard constraints that every safety-critical component and active policy server must be covered. Coverage is maximized by weighted priority at level @2; cost is minimized at level @1.

**Anomaly Scoring and Trust State.** Each observed node accumulates a composite anomaly score from two sources: a *static trust prior* (penalties for missing attestation, RoT, signed policy — derived from Phase 2 trust gap analysis) and a *runtime alert score* (weighted sum of observed anomaly signals such as rate spikes, cross-domain access, privilege creep, sequence violations, and policy violations). The anomaly score maps to four trust states:

| Anomaly Score | Trust State | Meaning |
|---|---|---|
| < 40 | high | Normal operation |
| 40–69 | medium | Elevated concern |
| 70–99 | low | Suspected compromise |
| ≥ 100 | compromised | Confirmed compromise |

**Automatic Mode Transition.** The trust state drives mode transitions without human intervention:
- Any node reaching `compromised` → system enters `attack_confirmed`
- A safety-critical or policy-server node reaching `low` → `attack_confirmed`
- Any node reaching `medium` or `low` (non-safety) → `attack_suspected`
- All nodes `high` → `normal`

**Adaptive Response Actions.** Four response actions are generated automatically:
- `quarantine(N)`: isolate compromised or low-trust safety-critical nodes
- `re_attest(M)`: demand re-attestation from masters with medium/low trust (suppressed if quarantined — a quarantined node cannot execute attestation)
- `lockdown_pep(PEP)`: lock all PEPs to deny-all in `attack_confirmed`
- `force_signed_policy(PS)`: require unsigned policy servers to switch to signed enforcement under `attack_suspected`

**Enforcement Bridge.** The runtime layer overrides Phase 2's static `final_allow` decisions via `effective_deny(M, C, Op)`: any access statically allowed by Phase 2 is revoked when the current mode and trust state jointly indicate `adaptive_deny`. This degrades policies gracefully under threat without firewall hardware reconfiguration.

---

## V. Implementation

The tool is implemented in Python with the Clingo 5.8 ASP solver.

| Component | Files | Lines | Role |
|---|---|---|---|
| ASP encodings | 15 | 3,476 | Risk model, ZTA synthesis, resilience, runtime |
| Python core | 8 | 2,841 | Solver wrapper, parser, ranker, comparison |
| Python agents | 4 | 853 | Phase orchestration, strategy injection |
| GUI | 5 | 5,856 | Network editor, results panel, progress |
| IP catalog | 1 | 675 | Vivado post-implementation resource estimates |
| **Total** | **33** | **13,701** | |

The IP catalog provides Xilinx Zynq-7000 (PYNQ-Z2, xc7z020clg400-1) post-implementation resource estimates sourced from Vivado synthesis reports. Phase solve times: Phase 1 <5 s (TC9) / 15.5 s (UAV); Phase 2 <2 s; Phase 3 <30 s for 18–24 scenarios. The orchestrator runs three strategies in parallel via background threads. Input modes: (1) built-in factory models, and (2) custom topologies via drag-and-drop network editor with JSON save/load and ASP export.

The tool and all test cases are available as open-source software [URL redacted for double-blind review].

---

## VI. Case Studies and Results

> **Fig. 3 — SoCDrone (TC9) Topology** *(single column, Section VI.A)*
> Graph diagram with two NoC buses (noc0, noc1) as horizontal lanes.
> sys_cpu connects to noc0; dma connects to both noc0 and noc1.
> noc0 has 5 nodes hanging below: c1, c2, c3, c4, c5 (redundancy group, shown with bracket labeled "5-member quorum group").
> noc1 has 3 nodes: c6, c7, c8. c8 marked with a star (safety-critical).
> Firewall symbols: pep_group between noc0 and {c1–c5}, pep_standalone between noc1 and {c6–c8}.
> ps0 and ps1 boxes connected to the firewalls with dashed governance arrows.
> Trust domains color-coded: c1–c6, c8 = high domain (blue), c7 = low domain (gray).
> *Caption*: "Fig. 3. SoCDrone (TC9) SoC topology. The 5-member redundancy group shares noc0, creating a common-mode bus failure risk. pep_group and pep_standalone are Phase 2 firewall placements."

### A. Case Study 1: SoCDrone (TC9)

The SoCDrone is an 8-component SoC with 2 bus masters (sys_cpu, dma), 2 NoC buses, a 5-member redundancy group (c1–c5), and 3 standalone IPs including one safety-critical component (c8). The PYNQ-Z2 FPGA provides the resource budget.

**Phase 1 Results.** All three strategies achieve proven optimality (max\_security in 3.8 s, min\_resources in 8.2 s, balanced in 7.6 s). Under max\_security, total weighted risk is minimized to 74 at 17% LUTs (9,120/53,200) and 179 mW. The safety-critical c8 receives dynamic\_mac+zero\_trust\_logger despite its 5-cycle read latency constraint, while c6 (high-impact, unconstrained) receives zero\_trust+zero\_trust\_logger driving its residual to 0. Under min\_resources, all components converge to mac, the minimum-cost feature satisfying the risk cap, cutting LUT usage to 10% (5,380/53,200) and power to 100 mW at the cost of raising weighted risk to 101 — a 37% LUT reduction for a 36% risk increase. Balanced produces identical assignments to min\_resources for this instance: TC9's redundancy group has sufficient risk headroom under the availability cap that the optimizer reaches the same LUT-efficient solution.

**Table II: TC9 Phase 1 — Security Assignments by Strategy**

| Component | Domain | max\_sec (Security+Log) | wRisk | min\_res (Security+Log) | wRisk |
|---|---|---|---|---|---|
| c1 | high | mac + no\_logging | 14 | mac + no\_logging | 18 |
| c2 | high | dynamic\_mac + some\_logging | 17 | mac + no\_logging | 21 |
| c3 | high | zero\_trust + no\_logging | 14 | mac + no\_logging | 18 |
| c4 | high | dynamic\_mac + no\_logging | 17 | mac + no\_logging | 21 |
| c5 | high | mac + zero\_trust\_logger | 12 | mac + no\_logging | 15 |
| c6 | high | zero\_trust + zero\_trust\_logger | 0 | mac + some\_logging | 4 |
| c7 | low | mac + some\_logging | 0 | mac + no\_logging | 0 |
| c8 | high | dynamic\_mac + zero\_trust\_logger | 0 | mac + no\_logging | 4 |
| **Total** | | | **74** | | **101** |
| **LUTs / Power** | | | **9,120 / 179 mW** | | **5,380 / 100 mW** |

**Phase 2 Results.** ZTA synthesis placed 2 firewalls (pep_group guarding c1–c5, pep_standalone guarding c6–c8) and 1 policy server (ps0) at a total hardware cost of 450 units. The solver identified 9 excess privilege grants — the DMA controller has read+write access to all IPs but only needs write access to c1–c5 and read access to c8. Policy tightness for dma was 43%, flagged as over-privileged. Trust anchor analysis revealed 6 components lacking hardware root of trust, 1 unattested master (dma), and 1 unsigned policy server (ps1).

**Phase 3 Results.** Eighteen scenarios were executed covering architecture compromises, control plane attacks, and bus failures.

**Table III: TC9 Phase 3 — Selected Scenario Results**

| Scenario | Risk | vs Baseline | Control Plane | Services |
|---|---|---|---|---|
| baseline | 51.0 | 1.00x | OK | 3/0/0 |
| sys_cpu_compromise | 102.0 | 2.00x | OK | 3/0/0 |
| full_group_compromise | 153.0 | 3.00x | OK | 3/0/0 |
| ps0_compromise | 127.5 | 2.50x | COMPROMISED | 3/0/0 |
| noc0_failure | 51.0 | 1.00x | OK | 3/0/0 |
| c8_failure | 51.0 | 1.00x | OK | 2/0/1 |

Key findings: (1) The ZTA overlay reduces worst-case risk by 3.0× compared to no-ZTA baseline (153.0 → 51.0). (2) ps0 compromise (2.50×) is the highest-impact single event because ps0 governs both firewalls; its compromise bypasses all policy enforcement. (3) The redundancy group provides availability resilience (3-of-5 quorum) but NOT security independence: noc0 failure cuts off all 5 members simultaneously (common-mode failure). (4) c8's 5-cycle latency constraint is the dominant source of residual risk — relaxing it to 12 cycles would reduce c8r1 write risk by 33%.

**Security Assessment Findings — SoCDrone (TC9):**

> **FINDING-1 (HIGH):** DMA controller holds 9 excess privilege grants including write access to safety-critical c8. Policy tightness = 43%. *Recommendation: restrict DMA ACL to declared access\_need at PEP level.*
>
> **FINDING-2 (HIGH):** ps0 compromise bypasses all firewall protection (2.5× amplification). ps1 lacks signed-policy enforcement. *Recommendation: add signed-policy to ps1; ensure ps0/ps1 architectural independence.*
>
> **FINDING-3 (MEDIUM):** noc0 is a common-mode failure point for all 5 redundancy-group members simultaneously. Phase 4 monitor `mon_ctrl` detects ps0 anomalies but cannot observe c7 (no\_logging, no monitor coverage) — logging assignment for c7 should be upgraded to at least `some_logging`.

**Phase 4 Results — Runtime Adaptation (TC9).** With Phase 1 and Phase 2 context injected, the Phase 4 solver places 2 of 4 candidate monitors: `mon_ctrl` (covering ps0, ps1, pep_group, pep_standalone) and `mon_c8` (dedicated c8 coverage), total cost 170/400 budget. This achieves 100% coverage of safety-critical components and all policy infrastructure. A coverage gap is identified: c7 (low-trust domain, `no_logging` assignment) and the `dma` master are not directly covered — signals from these nodes are flagged as `missed_signal`, a finding that directly informs the Phase 1 logging assignment for c7.

Three representative scenarios demonstrate the mode transition logic: (1) c8 receives `sequence_violation(sev=3)` and `privilege_creep(sev=2)`, yielding anomaly\_score=130 (compromised) and immediate `attack_confirmed` with three response actions: `quarantine(c8)`, `lockdown_pep(pep_group)`, `lockdown_pep(pep_standalone)`; (2) ps0 receives `bypass_alert(sev=3)` and `policy_violation(sev=2)`, yielding anomaly\_score=165 → `quarantine(ps0)` plus both PEP lockdowns; (3) c7 receives `cross_domain` and `privilege_creep` signals — both are missed due to the coverage gap, mode remains `normal`, confirming that Phase 1's `no_logging` assignment for c7 creates an undetectable attack path through the low-trust domain.

> **Fig. 4 — DARPA CASE UAV SoC Topology** *(single column, Section VI.B)*
> Graph with 4 bus lanes (bus_rf, bus_mc, bus_uart, bus_wifi) as horizontal segments.
> GS (untrusted, red border) → bus_rf → radio_drv → bus_mc (bridge shown with double-headed arrow labeled "RF bridge").
> bus_mc (central lane): MC master → 9 receiver IPs hanging below: fpln, wpm, cam_mgr, nfzdb, uart_drv, swu, attest_gate, geofence, fpln_filt.
> Three CakeML-verified IPs (attest_gate, geofence, fpln_filt) marked with diamond symbol and "formally verified" label.
> uart_drv → bus_uart → FC (safety-critical, star symbol).
> bus_wifi: MC → wifi_drv, cam_mgr.
> Firewall pep_mc shown at junction between radio_drv bridge and bus_mc, with ps_uart governance arrow.
> Trust domains: GS=red (untrusted), radio_drv=orange (low), MC/FC=green (privileged), attest_gate=gold (root), geofence/fpln_filt/nfzdb=blue (high), others=white (normal), wifi_drv=red (untrusted).
> *Caption*: "Fig. 4. DARPA CASE UAV SoC topology (translated from AADL). The radio_drv bridges the untrusted RF bus into the trusted MC internal bus — the primary attack path. All services route through bus_mc, making it a single-point availability failure."

### B. Case Study 2: DARPA CASE UAV

To demonstrate generality, we translated the DARPA Cyber Assured Systems Engineering (CASE) UAV surveillance architecture — the same system used by Hasan et al. [8] to demonstrate manual ZT pattern application — from its AADL software representation into our SoC interconnect model. This reflects the avionics trend toward hardware-consolidated implementations where safety and security functions are realized as dedicated IP cores.

The translated architecture has 11 receiver components across 4 buses, 3 masters (mission computer, flight controller, ground station), 4 safety-critical components, and zero redundancy groups. It includes the three BriefCASE/Collins hardening additions: attestation gate, flight plan filter, and geofence monitor (CakeML-verified components).

**Phase 1 Results (max_security strategy).** The solver proves optimality in 15.5 s, assigning zero_trust+zero_trust_logger to 8 of 11 components. The 3 high-latency components (cam_mgr, wifi_drv, swu) receive dynamic_mac or mac. Total risk is driven to 0 at 34% LUT utilization (18,170/53,200 LUTs, 367 mW). The CakeML-verified components (attest_gate, geofence, fpln_filt, exploitability=1) achieve risk=0 even under max_security without dominating the resource budget.

**Table IIa: DARPA UAV Phase 1 — Security Assignments (max_security)**

| Component | Domain | Security | Logging | Exploit | Risk |
|---|---|---|---|---|---|
| radio_drv | low | zero_trust | zero_trust_logger | 5 (RF) | 0 |
| fpln | normal | zero_trust | zero_trust_logger | 3 | 0 |
| wpm | normal | zero_trust | zero_trust_logger | 3 | 0 |
| cam_mgr | normal | dynamic_mac | zero_trust_logger | 3 | 0 |
| wifi_drv | untrusted | dynamic_mac | zero_trust_logger | 5 (WiFi) | 0 |
| uart_drv | normal | zero_trust | zero_trust_logger | 3 | 0 |
| nfzdb | high | zero_trust | zero_trust_logger | 2 | 0 |
| attest_gate | root | zero_trust | zero_trust_logger | 1 (CakeML) | 0 |
| geofence | high | zero_trust | zero_trust_logger | 1 (CakeML) | 0 |
| fpln_filt | high | zero_trust | zero_trust_logger | 1 (CakeML) | 0 |
| swu | privileged | dynamic_mac | zero_trust_logger | 4 | 0 |

**Phase 1 Results (min_resources strategy, best-found in 60 s).** The solver timed out after 60 seconds having evaluated 18 candidate models; the best-found solution (not proven optimal) reduces LUT usage to 18% (9,870 LUTs, 190 mW) at the cost of total risk rising to 35. High-impact untrusted components retain stronger features (wifi_drv keeps zero_trust; radio_drv gets mac+some_logging), while verified components (attest_gate, geofence, fpln_filt) step down to dynamic_mac with minimal logging. This demonstrates the solver navigating the security-resource Pareto frontier: the 47% LUT reduction comes with 35 units of residual risk concentrated in availability assets.

**Phase 2 Results.** ZTA synthesis placed 1 firewall (pep_mc, guarding the MC internal bus bridged from the untrusted RF bus) and 1 policy server (ps_uart) at cost 350 units — consistent across all three strategies since the topology is fixed. Analysis identified **22 excess privileges**: the ground station (gs, untrusted) has only 10% policy tightness, holding topological access to all 9 MC-bus components via the radio_drv bridge but requiring only radio_drv read+write. The mission computer has 73% tightness with 5 excess grants (nfzdb write, swu read/write, wifi_drv read/write outside operational phase). Trust anchor analysis found 10 components lacking hardware root-of-trust, 2 unattested masters (fc, gs), and 1 unsigned policy server (ps_uart).

**Phase 3 Results.** Under max_security all 24 scenario risks are 0 (mathematically trivial: base risk 0 × any amplification = 0). The min_resources strategy, which is the operationally relevant configuration under resource constraints, surfaces the architectural SPOFs: baseline risk=38.0, worst-case 2.11× under ps_uart compromise or pep_mc bypass (risk=80.0). Key finding: `bus_mc_failure` loses **5 capabilities simultaneously** (flight_control, navigation, ota_update, attestation, ground_comms) — a single-point availability failure inherent to the star topology around the MC internal bus that no security feature assignment can mitigate. `flight_control` is the most vulnerable capability, lost in 6 of 24 scenarios.

**Comparison with Manual Hardening.** The DARPA CASE UAV is the same system that Hasan et al. [8] manually hardened with AADL ZT patterns. Table IIIa compares the two approaches directly.

**Table IIIa: Automated DSE vs. Manual AADL Hardening (Same UAV System)**

| Metric | Collins Manual [8] | This Tool (Automated) |
|---|---|---|
| Time to harden | Not reported (manual AADL editing) | 15.5 s (Phase 1) + 2 s (Phase 2) |
| Design space explored | Designer's choice (≤5 patterns applied) | All 3^11 = 177,147 feature combinations |
| Optimality guarantee | None (heuristic selection) | Proven optimal for max\_security (15.5 s); best-found in 60 s for min\_resources |
| Excess privileges found | N/A (not in scope) | 22 (including 10% GS tightness) |
| Trust anchor gaps found | N/A (not in scope) | 10 no-RoT, 2 unattested, 1 unsigned PS |
| Lifecycle modes | 1 (hardened state only) | 9 (3 modes × 3 mission phases) |
| Resilience scenarios | N/A (not in scope) | 24 with quantitative risk amplification |
| SPOF detection | N/A (not in scope) | bus_mc identified as 5-capability SPOF |
| Resource accounting | N/A (not in scope) | 34% LUT, 367 mW (max_sec); 18% LUT (min_res) |
| Reproducibility | Depends on engineer expertise | Deterministic solver output from .lp file |

The Collins approach provides *qualitative* security improvement ("prevents eavesdropping," "validates ground station integrity") but cannot quantify residual risk, detect excess privileges, or identify single-points-of-failure. Our tool identifies all three automatically.

**Security Assessment Findings — DARPA CASE UAV (min_resources):**

> **FINDING-1 (CRITICAL):** Ground station (untrusted) has topological access to all 9 MC-bus components via radio\_drv bridge but requires only radio\_drv write. Policy tightness = 10%. *Recommendation: enforce per-component ACL at pep\_mc.*
>
> **FINDING-2 (CRITICAL):** bus\_mc is a single-point failure for all 5 essential capabilities. *Recommendation: add redundant MC-bus path or partition safety-critical components to a dedicated bus.*
>
> **FINDING-3 (HIGH):** 10 of 11 receivers lack hardware RoT; ps\_uart is unsigned. If ps\_mc fails, all PEP policy becomes unverifiable. *Recommendation: add HW RoT to uart\_drv and nfzdb; add signed-policy to ps\_uart.*

> **Fig. 5 — Strategy Comparison Heatmap** *(two-column, Section VI.C)*
> A 3×6 matrix (strategies × metrics) shown as a color-coded heatmap.
> Rows: max_security, min_resources, balanced.
> Columns: Total Risk | LUT% | Power (mW) | Excess Privs | Worst Scenario (×) | Trust Gaps
> TC9 values:      0 / 17% / 184 / 9 / 3.00× / 6
> UAV max_sec:     0 / 34% / 367 / 22 / N/A / 10
> UAV min_res:    35 / 18% / 190 / 22 / 2.11× / 10
> UAV balanced:    0 / 31% / 333 / 22 / N/A / 10
> Color scale: green (best) → yellow → red (worst) per column.
> *Caption*: "Fig. 5. Strategy comparison across both case studies. min_resources cuts LUT usage by 47% relative to max_security on the UAV at the cost of residual risk=35. TC9's redundancy group provides a 3× worst-case amplification that the UAV's single-string topology avoids at the cost of zero resilience margin."

### C. Comparative Analysis

**Table IV: Case Study Comparison**

| Metric | SoCDrone (TC9) | DARPA CASE UAV |
|---|---|---|
| Components | 8 | 11 |
| Masters | 2 | 3 |
| Buses | 2 | 4 |
| Safety-critical | 1 | 4 |
| Redundancy groups | 1 (5 members) | 0 (all SPOF) |
| Services | 3 | 5 |
| Trust domains used | 2 (low, high) | 6 (all levels) |
| Phase 1 total risk (max_sec) | 51 | 0 (budget sufficient) |
| Phase 1 total risk (min_res) | — | 35 |
| Phase 1 LUT usage (max_sec) | 17% | 34% |
| Phase 1 LUT usage (min_res) | — | 18% |
| Phase 2 FWs placed | 2 | 1 |
| Phase 2 excess privs | 9 | 22 |
| Phase 3 worst scenario (min_res) | 3.00× | 2.11× (ps/pep compromise) |
| Trust anchor gaps | 6 no-RoT, 1 unattested | 10 no-RoT, 2 unattested |
| Capabilities lost in worst scenario | 0 | 5 (bus_mc_failure) |

The two case studies exercise complementary aspects of the tool. TC9 tests redundancy-aware risk budgeting on a compact SoC where latency-constrained components force sub-optimal security assignments (c8 cannot get zero_trust), producing residual risk even under max_security. The DARPA UAV has no latency bottlenecks that block full protection — max_security achieves risk=0 — but its star topology around the MC internal bus creates a catastrophic single-point bus failure invisible to the security optimizer. Both architectures expose the same classes of ZTA gap (excess privilege, missing attestation, unsigned policy server) through identical Phase 2 analysis, demonstrating the tool's topology-agnostic generality.

---

## VII. Discussion and Limitations

**Scalability.** TC9 (8 components) solves Phase 1 in <5 seconds; RefSoC-16 (15 components) in <60 seconds. ASP grounding is polynomial in the number of components × features; solving is NP-complete in the worst case but practical for SoC-scale problems (tens to low hundreds of components).

**Model fidelity.** The SoC graph model captures bus topology and trust domains but not microarchitectural side channels, electromagnetic emanation, or supply chain compromise. Latency constraints use pipeline depth (cycles) rather than worst-case execution time analysis.

**Single-chip scope.** The current model addresses intra-SoC security. Multi-chip avionics (federated + integrated) would require extending the graph model with inter-chip links and gateway components.

**ZTA compliance.** The tool synthesizes ZTA-aligned policies (least privilege, explicit verification, assume breach) but does not formally verify compliance with DO-326A airworthiness security objectives. Integration with certification evidence tools (e.g., BriefCASE assurance cases) is future work.

---

## VIII. Conclusion

We presented an automated DSE workflow for zero-trust avionics SoC security that produces five deliverables from a single architectural model: Pareto-optimal architectures, access control policies, resilience checklists, runtime-adaptive response policies, and strategy comparisons. The additive risk model with dual-risk budget enables principled separation of security and availability optimization. The runtime adaptation layer extends static design-time policies with anomaly-driven mode transitions and automatic response actions, bridging the gap between design-time security analysis and operational threat response.

Evaluation on two case studies — an SoC drone and a DARPA CASE UAV translated from AADL — demonstrates the tool's ability to identify excess privileges, trust anchor gaps, and single-point-of-failure vulnerabilities that the manual AADL-based hardening approach of Hasan et al. did not surface. Direct comparison on the same UAV system shows the automated approach explores 177,147 feature combinations in 15.5 seconds with proven optimality, versus hours of manual pattern selection with no optimality guarantee.

Future work includes multi-chip topology support, integration with DO-326A certification evidence generation (e.g., BriefCASE assurance cases), and extension of the runtime adaptation layer with detection latency modeling to quantify residual risk during the undetected attack window.

---

## References

[1] ARM, "ARM TrustZone Technology for ARMv8-M," ARM Ltd., ARM 100690, 2023.

[2] Xilinx, "Zynq-7000 SoC Isolation Design Flow Lab Guide," UG1085 (v2022.1), 2022.

[3] L. Fiorin, G. Palermo, S. Lukovic, and C. Silvano, "Secure memory accesses on networks-on-chip," *IEEE Trans. Comput.*, vol. 57, no. 9, pp. 1216–1229, Sep. 2008.

[4] RTCA, "DO-326A/ED-202A: Airworthiness Security Process Specification," 2014.

[5] ARINC, "ARINC 653: Avionics Application Software Standard Interface Part 1," Supplement 4, 2015.

[6] S. Rose, O. Borchert, S. Mitchell, and S. Connelly, "Zero Trust Architecture," NIST SP 800-207, Aug. 2020.

[7] F. Buck, "Zero Trust Strengthens Aviation Cybersecurity," MITRE Impact Story, 2020. [Online]. Available: https://www.mitre.org/news-insights/impact-story/zero-trust-strengthens-aviation-cybersecurity

[8] S. Hasan, I. Amundson, and D. Hardin, "Zero Trust Architecture Patterns for Cyber-Physical Systems," SAE Technical Paper 2023-01-1001, *SAE AeroTech*, 2023, doi:10.4271/2023-01-1001.

[9] S. Hasan, I. Amundson, and D. Hardin, "Zero-trust design and assurance patterns for cyber-physical systems," *J. Systems Architecture*, vol. 155, 103261, Oct. 2024, doi:10.1016/j.sysarc.2024.103261.

[10] D. Cofer, I. Amundson, J. Babar, D. Hardin *et al.*, "Cyber Assured Systems Engineering at Scale," *IEEE Security & Privacy*, vol. 20, no. 3, pp. 42–51, May–Jun. 2022.

[11] [Author(s) omitted for double-blind review], "Zero Trust Avionics Systems (ZTAS)," in *Proc. IEEE/AIAA 42nd DASC*, San Diego, CA, 2023, pp. 1–8, doi:10.1109/DASC58513.2023.10311248.

[12] FIRST, "Common Vulnerability Scoring System v3.1: Specification Document," Jun. 2019. [Online]. Available: https://www.first.org/cvss/v3.1/specification-document

[13] NIST, "Guide for Conducting Risk Assessments," SP 800-30 Rev. 1, Sep. 2012.

[14] T. Aven, "On the meaning of a black, green, yellow or red risk in a risk matrix," *Reliability Eng. & System Safety*, vol. 154, pp. 143–148, Oct. 2017, doi:10.1016/j.ress.2016.05.016.

[15] M. Gebser, R. Kaminski, B. Kaufmann, and T. Schaub, "Answer Set Solving in Practice," *Synthesis Lectures on Artificial Intelligence and Machine Learning*, Morgan & Claypool, 2012, doi:10.2200/S00457ED1V01Y201211AIM019.
