# Assurance-Aware Design Space Exploration for Zero-Trust Avionics SoC Security

*Reduced draft targeting an 8-page IEEE/AIAA DASC submission*

## Abstract

Modern avionics platforms increasingly consolidate safety-critical and security-sensitive functions onto shared System-on-Chip (SoC) platforms. This consolidation improves size, weight, and power characteristics, but it also creates new attack surfaces because a compromised IP core or bus master can reach other assets through shared interconnects. This paper presents an assurance-aware design space exploration (DSE) workflow for avionics SoCs that jointly synthesizes security feature assignments and zero-trust enforcement policies under hardware constraints. The workflow uses Answer Set Programming (ASP) to assign per-component security and logging features subject to resource, power, and latency limits, then synthesizes firewall and policy-server placement together with least-privilege access control. The method exposes excess privileges, trust-anchor gaps, and topology-driven resilience weaknesses early in design. Evaluation on a primary 8-component SoC drone case and a secondary 11-component UAV translation shows that the workflow identifies actionable architectural findings while quantifying tradeoffs across security and implementation cost. On the primary case, the zero-trust overlay reduces baseline risk to 51 with 2 firewalls and 1 policy server, while exposing 9 excess privileges and 6 no-root-of-trust gaps. On the UAV case, the tool reveals a single-string internal-bus weakness and 22 excess privileges that persist across all strategies.

**Keywords**: Zero-Trust Architecture, Avionics, System-on-Chip Security, Design Space Exploration, Answer Set Programming

## I. Introduction

Avionics architectures are moving toward deeper hardware consolidation. Processors, accelerators, DMA engines, sensors, and mission functions that were once separated across boards are increasingly realized on shared System-on-Chip (SoC) platforms. That transition improves SWaP characteristics, but it also changes the cybersecurity problem. A compromise on one bus-connected component can create architectural reachability to many other assets, including safety-critical ones, through the shared interconnect fabric.

This creates a design-time problem rather than a purely operational one. Avionics architects must choose which hardware security features to deploy, where to place enforcement, and how to preserve latency and resource constraints. Manual hardening patterns help, but they do not explore the full design space and do not prove whether a selected architecture is resource-feasible or close to optimal.

This paper presents an assurance-aware DSE workflow for zero-trust avionics SoC security. The workflow takes a single architectural model and produces three practical outputs:

1. Security and logging feature assignments under resource, power, and latency constraints.
2. Zero-trust enforcement placement and least-privilege policy synthesis.
3. Resilience-oriented architectural findings derived from compromise and failure scenarios.

The paper focuses on the design-time core: feature assignment and policy synthesis. Runtime adaptation and certification-evidence generation remain important, but they are outside the scope of this reduced DASC paper.

The main contributions are:

1. An ASP-based formulation for avionics SoC security feature selection under hardware constraints.
2. Automated zero-trust policy synthesis that places firewalls and policy servers while exposing excess privilege and trust gaps.
3. Evaluation on two avionics-relevant SoC topologies showing how the workflow surfaces topology-driven weaknesses that manual review can miss.

## II. Related Work

SoC hardware isolation is well established through TrustZone-style partitioning [1], FPGA isolation flows [2], and secure interconnect mechanisms [3]. These mechanisms provide important building blocks, but they do not solve the synthesis problem of deciding which protections to deploy and where to place them under implementation constraints.

In avionics, security engineering is shaped by DO-326A process concerns [4] and partitioning assumptions such as those in ARINC 653 [5]. Zero-trust principles have been defined at the enterprise level in NIST SP 800-207 [6], and recent avionics-oriented work has argued for adapting zero-trust ideas to aerospace systems. Hasan et al. applied zero-trust design patterns manually to cyber-physical architectures and highlighted the need for tool support at design time [7], [8].

This work addresses that gap at the SoC architecture level. It does not introduce a new isolation primitive or a new certification framework. Instead, it contributes an exact constraint-based workflow that jointly reasons about feature assignment, zero-trust enforcement placement, and hardware budgets.

## III. System Model and DSE Workflow

We model the SoC as a directed graph `G = (V, E)` whose vertices represent bus masters, receiver IPs, buses, firewalls, and policy servers. Edges represent interconnect links. Each receiver component carries:

- asset impact values for read and write operations
- candidate security and logging features
- per-feature cost in LUTs, FFs, BRAM, and power
- allowable read and write latency
- trust-domain and trust-anchor information

The workflow has two synthesis phases and one analysis phase.

**Figure 1.** Workflow overview: architectural model -> Phase 1 feature assignment -> Phase 2 zero-trust synthesis -> Phase 3 resilience analysis.

### A. Phase 1: Security Feature Assignment

Each component receives exactly one security feature and one logging feature. The feature catalog is derived from the implementation library used by the tool. Table I summarizes the features used in the experiments.

**Table I. Feature summary used in Phase 1**

| Feature | Type | Latency | LUTs | FFs | BRAM | Power (mW) | Modeling role |
|---|---|---:|---:|---:|---:|---:|---|
| `zero_trust` | security | 3 | 1200 | 850 | 0 | 24 | strongest protection |
| `dynamic_mac` | security | 6 | 950 | 680 | 0 | 18 | medium protection |
| `mac` | security | 4 | 650 | 420 | 0 | 12 | lowest-cost security |
| `zero_trust_logger` | logging | 2 | 520 | 480 | 2 | 11 | strongest logging |
| `some_logging` | logging | 1 | 180 | 220 | 1 | 4 | lightweight logging |
| `no_logging` | logging | 1 | 0 | 0 | 0 | 0 | no audit support |

For standalone components, the residual-risk model is additive:

```text
r = max(0, impact + domain_bonus - security_protect - log_protect)
```

For redundant groups, the encoding uses a normalized group-compromise model so that common-mode dependence is still visible even when individual members appear well protected. The phase-1 solver minimizes total residual risk subject to:

- one security feature and one logging feature per component
- LUT, FF, DSP, LUTRAM, BRAM, and power budgets
- per-asset latency limits
- effective per-asset risk caps

The tool supports three strategy modes:

- `max_security`: minimize risk
- `min_resources`: minimize footprint after satisfying the model constraints
- `balanced`: minimize risk, then footprint

### B. Phase 2: Zero-Trust Policy Synthesis

Phase 2 injects the phase-1 design as background facts and synthesizes:

- firewall placement
- policy-server placement
- least-privilege access policies
- trust-anchor gap findings

The key constraint is architectural mediation: if a lower-trust master can topologically reach a protected target, the path must be mediated by an enforcement point. The solver also compares topology-implied access against declared `access_need` facts, flagging excess privileges and missing privileges.

### C. Phase 3: Resilience Analysis

Phase 3 is used here only for compact architectural assessment. It executes compromise and failure scenarios against the synthesized design and reports:

- total scenario risk
- worst-case amplification relative to baseline
- service degradation or loss
- control-plane concentration effects

This phase is included in the DASC version only to support design-time findings. Runtime adaptation is left to future work.

## IV. Primary Case Study: SoCDrone (TC9)

The primary case is an 8-component avionics-style SoC with:

- 2 masters (`sys_cpu`, `dma`)
- 2 buses
- a 5-member redundancy group (`c1-c5`)
- 3 standalone IPs (`c6-c8`)
- one latency-sensitive safety-critical component (`c8`)

The case is useful because it combines shared-bus exposure, redundancy, and hard latency limits in one compact instance.

**Figure 2.** TC9 topology with two buses, a 5-member redundancy group on `noc0`, standalone IPs on `noc1`, and synthesized firewalls guarding each domain.

### A. Security Feature Results

Table II summarizes the measured three-strategy results for TC9.

**Table II. TC9 strategy comparison**

| Metric | max_security | min_resources | balanced |
|---|---:|---:|---:|
| Total risk | 51 | 69 | 51 |
| LUTs used | 9,340 | 5,380 | 6,840 |
| FFs used | 7,100 | 3,580 | 4,880 |
| Power (mW) | 184 | 100 | 132 |
| Firewalls placed | 2 | 2 | 2 |
| Policy servers placed | 1 | 1 | 1 |
| Excess privileges | 9 | 9 | 9 |
| No-RoT trust gaps | 6 | 6 | 6 |
| Worst scenario | group compromise | group compromise | group compromise |
| Worst amplification | 3.0x | 2.839x | 3.0x |
| Total runtime (s) | 6.366 | 10.185 | 19.250 |

These results show a clean security-footprint tradeoff. `min_resources` reduces LUT use from 9,340 to 5,380, but raises total risk from 51 to 69. `balanced` recovers the same total risk as `max_security` while cutting LUT use to 6,840.

### B. Zero-Trust Synthesis Findings

Phase 2 produces stable structural findings across all strategies. The solver places 2 firewalls and 1 policy server, and it consistently identifies:

- 9 excess privileges
- 6 no-root-of-trust gaps
- a concentrated policy-control dependency

The most important result is that the DMA master is materially over-privileged relative to declared need. That finding is topological, not merely a consequence of weak local protection settings.

### C. Resilience Findings

The worst scenario for TC9 is compromise of the full redundancy group, which produces a 3.0x amplification over the secured baseline for `max_security` and `balanced`. This exposes a subtle but important avionics lesson: the 5-member group improves availability only if the interconnect itself remains healthy. Because the members share the same bus, the architecture still contains a common-mode weakness.

The case also shows why design-time co-optimization matters. The safety-critical `c8` path is latency constrained, which prevents arbitrarily strong protection choices from being assigned without violating timing. The tool therefore exposes where the architecture itself, not just the security policy, is constraining the security outcome.

## V. Secondary Portability Case: DARPA/UAV Translation

To show portability, the workflow was also applied to an 11-component UAV architecture translated from the DARPA CASE surveillance system used in prior manual hardening work. The translated SoC contains:

- 3 masters
- 4 buses
- no redundancy groups
- 4 safety-critical components
- one bridge from an untrusted ingress path into the trusted internal bus

Table III summarizes the compact cross-strategy results.

**Table III. DARPA/UAV portability summary**

| Metric | max_security | min_resources | balanced |
|---|---:|---:|---:|
| Total risk | 0 | 35 | 0 |
| LUTs used | 18,170 | 9,260 | 16,530 |
| Firewalls placed | 1 | 1 | 1 |
| Policy servers placed | 1 | 1 | 1 |
| Excess privileges | 22 | 22 | 22 |
| No-RoT trust gaps | 10 | 10 | 10 |
| Worst scenario | baseline | `ps_uart_compromise` | baseline |
| Worst amplification | N/A | 2.105x | N/A |
| Total runtime (s) | 12.228 | 71.054 | 12.482 |

This case complements TC9. Under `max_security`, the architecture is strong enough to drive total residual risk to zero, but the topology still reveals 22 excess privileges and a narrow internal-bus trust boundary. Under `min_resources`, the architecture exposes a 2.105x worst-case amplification under policy-server compromise. In other words, even when feature assignment looks strong, the bus organization can still dominate the security story.

The `min_resources` point on this case is the main runtime warning sign: it is the most expensive search and should be treated as the operational stress point for the current solver formulation.

## VI. Discussion and Limitations

Two results matter most for avionics architects.

First, zero-trust feature assignment alone is not enough. The workflow repeatedly exposes structural weaknesses such as over-privileged DMA access, policy-control concentration, and narrow trust boundaries at bus bridges. These are design-time architecture issues, not just misconfigured access-control lists.

Second, the tool provides a disciplined alternative to manual hardening trade studies. Instead of choosing protections qualitatively, the architect can ask whether a given protection mix is feasible under power, area, and latency constraints, and whether the resulting topology still contains avoidable privilege or trust gaps.

The present DASC paper has three main limits. It does not include a head-to-head baseline against CP-SAT or heuristic search. It models architecture-level timing through latency caps rather than cycle-accurate execution analysis. And it stops at design-time synthesis rather than full certification evidence or runtime adaptation. Those are important next steps, but they do not reduce the value of the current design-time workflow.

## VII. Conclusion

This paper presented an assurance-aware DSE workflow for zero-trust avionics SoC security. The workflow jointly synthesizes security feature assignments and enforcement placement under hardware constraints, then uses resilience scenarios to expose topology-driven weaknesses. The primary TC9 case showed a clear tradeoff between residual risk and FPGA footprint while revealing 9 excess privileges and 6 no-root-of-trust gaps. The secondary DARPA/UAV case showed that even when high-security assignments drive residual risk to zero, the architecture can still retain serious privilege and trust-boundary weaknesses.

The central conclusion is that avionics SoC security should be treated as a constrained architecture-synthesis problem, not a manual hardening exercise. Answer Set Programming provides a practical way to solve that problem while keeping resource budgets, timing limits, and zero-trust enforcement visible to the designer.

## References

[1] Arm, "TrustZone for Cortex-A," official technology overview.

[2] AMD, "Isolation Design Flow," official documentation hub.

[3] J. Lazaro, U. Bidarte, L. Muguira, A. Astarloa, and J. Jimenez, "Embedded firewall for on-chip bus transactions," *Computers & Electrical Engineering*, vol. 98, art. 107707, 2022.

[4] RTCA, "DO-326A/ED-202A: Airworthiness Security Process Specification," 2014.

[5] ARINC, "ARINC 653: Avionics Application Software Standard Interface Part 1," Supplement 4, 2015.

[6] S. Rose, O. Borchert, S. Mitchell, and S. Connelly, *Zero Trust Architecture*, NIST SP 800-207, 2020.

[7] S. Hasan, I. Amundson, and D. Hardin, "Zero Trust Architecture Patterns for Cyber-Physical Systems," SAE Technical Paper 2023-01-1001, 2023.

[8] S. Hasan, I. Amundson, and D. Hardin, "Zero-trust design and assurance patterns for cyber-physical systems," *Journal of Systems Architecture*, vol. 155, 103261, 2024.

[9] M. Gebser, R. Kaminski, B. Kaufmann, and T. Schaub, "Multi-shot ASP solving with clingo," *Theory and Practice of Logic Programming*, vol. 19, no. 1, pp. 27-82, 2019.
