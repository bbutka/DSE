# Exact Design Space Exploration for SoC Security Architecture Synthesis Using Answer Set Programming

*Draft 0 for IEEE SOCC 2026*

## Abstract

System-on-Chip (SoC) platforms integrate processors, accelerators, memories, and peripherals on shared interconnects, making security architecture design a constrained optimization problem rather than a simple add-on decision. Security features, logging mechanisms, and enforcement points improve protection, but they also consume area, power, and latency budget. We present an exact design space exploration workflow for SoC security architecture synthesis based on Answer Set Programming (ASP). Given an architectural model, the method jointly selects per-component security and logging features and synthesizes enforcement placement under hard hardware constraints. The formulation captures resource, power, and latency budgets together with reachability and access-enforcement constraints, enabling exact optimization rather than heuristic front approximation. We evaluate the method on representative SoC topologies and compare multiple optimization strategies, including maximum-security, minimum-resource, and balanced configurations. The results show that the solver identifies feasible high-security architectures within modest FPGA utilization, exposes topology-driven over-privilege and trust gaps, and makes tradeoffs among protection strength, implementation cost, and bottleneck constraints explicit. The workflow demonstrates that exact ASP-based DSE is a practical approach for hardware-aware SoC security architecture synthesis.

**Keywords:** System-on-Chip Security, Design Space Exploration, Answer Set Programming, Security Architecture Synthesis, Hardware-Aware Optimization

## I. Introduction

Modern SoCs consolidate processors, DMA engines, accelerators, memories, and peripheral interfaces onto shared interconnect fabrics. This consolidation improves performance and integration efficiency, but it also creates dense attack surfaces. A compromise on one bus-attached component can expose many other components through shared reachability, especially when the architecture lacks fine-grained enforcement points. Security design in this setting is not a simple feature-selection problem. Stronger controls such as message authentication, logging, firewalls, and policy servers consume lookup tables, flip-flops, power, and latency budget, and those costs interact with topology and application constraints.

The resulting design task is fundamentally a constrained synthesis problem: select security features, place enforcement elements, and satisfy implementation limits while still minimizing residual risk. Existing design-space exploration methods often rely on heuristic search or manual architecture refinement. Those approaches can surface candidate tradeoffs, but they generally do not prove that the returned design is optimal under the stated constraints, nor do they naturally diagnose infeasible combinations of protection and topology.

This paper presents an ASP-based workflow for exact SoC security architecture synthesis. The method accepts a graph-structured SoC model with assets, trust domains, reachability, and hardware budgets. It then performs two tightly coupled synthesis tasks: (1) exact assignment of security and logging features under resource, power, and latency constraints, and (2) topology-aware placement of policy enforcement and decision points subject to access-enforcement requirements. A third analysis stage evaluates compromise and failure scenarios on the synthesized architecture to expose structural weaknesses that feature assignment alone cannot remove.

The paper makes four contributions:

1. An exact ASP formulation for SoC security feature synthesis under resource, power, and latency constraints.
2. Joint optimization of per-component protection features and topology-aware enforcement placement.
3. Strategy-front comparison across maximum-security, minimum-resource, and balanced optimization goals.
4. Evaluation on representative SoC architectures showing practical solve times, modest FPGA footprint, and actionable architecture findings.

The paper is positioned as a SoC design-tools and architecture methods paper. The central result is not only automated scoring, but exact security architecture synthesis under implementation constraints.

## II. Related Work

### A. SoC Security Architecture

Hardware-enforced isolation for SoCs is well established through mechanisms such as TrustZone-style partitioning, secure interconnects, and bus firewalls. These approaches provide important building blocks, but they typically assume that the designer has already chosen where protection should be placed and what security strength each component should receive. They do not solve the synthesis problem of jointly selecting controls under implementation constraints.

### B. Design Space Exploration Under Hardware Constraints

DSE techniques are widely used for performance, power, and area tradeoffs, and analogous methods have been applied to hardware-security co-design. Heuristic techniques such as genetic algorithms and related front-search methods can recover useful tradeoff sets, but they generally do not provide exact optimality guarantees. For security architecture synthesis, where feasibility depends on interacting logical and numerical constraints, exact constraint solving has a clear advantage.

### C. Constraint Solving and ASP

ASP is well suited to design problems that combine discrete choices, recursive reachability, integrity constraints, and optimization. In the present context, ASP offers three properties that are especially useful: concise expression of topology and policy constraints, exact optimization through `#minimize`, and explicit failure when required protections cannot be realized within the architecture. These properties make ASP a strong fit for architecture-level security synthesis.

## III. Problem Formulation

We model an SoC as a directed graph `G = (V, E)` with typed vertices for masters, receiver IPs, buses, and enforcement elements. Bus masters initiate transactions, receiver IPs own assets, and edges encode architectural reachability. Each component is annotated with:

- trust-domain information
- asset impact values for read, write, and availability
- implementation costs for candidate security and logging features
- maximum allowable latency

The synthesis problem has two decision layers.

### A. Feature Assignment

Each component must receive exactly one security feature and one logging feature. These choices affect residual risk as well as implementation cost. The selected architecture must satisfy:

- LUT, FF, BRAM, and power budgets
- per-component latency limits
- any explicit risk-cap or availability constraints encoded in the instance

### B. Enforcement Placement

Given the synthesized feature configuration and the SoC topology, the workflow places firewalls and policy servers so that accesses from lower-trust or insufficiently verified masters to protected components are mediated. This stage also computes excess privilege by comparing topology-implied reachability against declared access needs.

### C. Optimization Goals

The workflow supports three strategy families:

- `max_security`: prioritize risk minimization
- `min_resources`: prioritize implementation footprint
- `balanced`: explicitly trade risk against resource cost

This makes the output a strategy front rather than a single opaque solution.

## IV. ASP Formulation

### A. Exact Feature Synthesis

The first phase uses ASP choice rules to assign one security feature and one logging feature per component. Constraints enforce implementation budgets and latency feasibility. The objective minimizes total residual risk over all assets. At a high level, the encoding takes the form:

```prolog
1 { selected_security(C, F) : security_feature(F) } 1 :- component(C).
1 { selected_logging(C, L)  : logging_feature(L) } 1 :- component(C).

:- total_luts(L), lut_budget(B), L > B.
:- total_power(P), power_budget(B), P > B.
:- path_latency(C, Op, T), latency_cap(C, Op, Cap), T > Cap.

#minimize { Risk, C, A, Op : weighted_risk(C, A, Op, Risk) }.
```

The importance of the formulation is not the syntax alone, but the fact that the solver searches the entire discrete feature space subject to all active constraints. The returned design is therefore an exact optimum for the chosen objective, not a heuristic approximation.

### B. Topology-Aware Enforcement Placement

The second phase reasons over master-to-target reachability and protection requirements. Candidate firewalls and policy servers are selected only when they are necessary to block or mediate disallowed accesses. A representative core rule pattern is:

```prolog
{ place_fw(FW) : cand_fw(FW) }.
1 { place_ps(PS) : cand_ps(PS) }.

:- master(M), protected_target(T),
   reachable(M, T), not mediated(M, T).

#minimize { Cost, X : placement_cost(X, Cost) }.
```

This phase computes both a synthesized enforcement architecture and architectural findings such as excess privilege, missing privilege, and trust-anchor gaps. The latter are useful as diagnostics, but the primary contribution remains the placement synthesis itself.

### C. Why ASP Fits This Problem

This problem combines:

- discrete feature choices
- graph reachability
- access-control structure
- numerical implementation constraints
- exact optimization

ASP handles this mix cleanly. The same model can express architectural feasibility, optimization objectives, and failure conditions. This is harder to do coherently with purely local rule systems or informal post-processing.

## V. Experimental Setup

The implementation is built in Python around Clingo-based ASP encodings. The feature and resource model targets a PYNQ-Z2 FPGA-class SoC platform, and the evaluation uses two representative architectural models.

### A. TC9 SoC

The primary case study is an 8-component SoC with:

- 2 bus masters
- 2 bus/interconnect domains
- a 5-member redundancy group
- 3 standalone IPs
- one latency-sensitive critical component

This model is useful because it exhibits three common SoC-security tensions simultaneously: shared-bus exposure, redundancy-vs-common-mode tradeoffs, and security-latency conflict on a critical path.

### B. DARPA CASE UAV Translation

The second case study is an 11-component translated architecture derived from a larger UAV system model. It contains:

- 3 masters
- 4 buses
- no redundancy groups
- 4 safety-critical components
- a clear bridge from an untrusted interface into a more trusted internal bus

This case is particularly useful for strategy-front comparison because all three optimization modes have already been exercised and produce clear footprint/security tradeoffs.

## VI. Results

### A. TC9: Detailed SoC Security Synthesis

For the TC9 SoC, the phase-1 solver produced an optimal feature assignment with total base risk 51 and practical implementation cost:

- LUTs: 9,340 / 53,200 (17%)
- FFs: 7,100 / 106,400 (6%)
- BRAM: 10 / 140
- Power: 184 mW / 15,000 mW
- Optimality proven: True

These numbers are important because they show that exact synthesis does not force unrealistic footprint. The design occupies a modest fraction of the target FPGA while still enforcing a strong protection architecture.

Phase 2 then placed:

- 2 firewalls
- 1 policy server

and identified 9 excess privileges. The dominant finding is that the DMA master is significantly over-privileged relative to declared access needs. Its measured policy tightness is 43%, and its excess access includes write exposure to the critical `c8` path and read exposure across the redundancy group. This is a topology-driven finding that a purely local per-component hardening method would miss.

The same case also highlights a useful architectural distinction: feature synthesis can reduce residual risk, but it cannot remove structural common-mode weaknesses. Without any ZTA overlay, the architecture's worst-case exposure is 153.0. With the synthesized ZTA placement active, the baseline risk is 51.0, a 3.00x reduction. However, the underlying bus structure still allows high amplification under the wrong compromise scenarios.

Representative scenario results on the synthesized TC9 architecture are:

| Scenario | Risk | Relative to baseline |
|---|---:|---:|
| baseline | 51.0 | 1.00x |
| `sys_cpu_compromise` | 102.0 | 2.00x |
| `dma_compromise` | 102.0 | 2.00x |
| `full_group_compromise` | 153.0 | 3.00x |
| `ps0_compromise` | 127.5 | 2.50x |
| `ps0_failure` | 61.2 | 1.20x |

These results show three distinct design lessons.

First, security architecture synthesis meaningfully reduces baseline exposure. Second, control-plane compromise can be as damaging as direct data-plane compromise; `ps0_compromise` reaches 2.50x baseline because it governs both deployed firewalls. Third, redundancy in the compute group improves some availability properties but does not eliminate common-mode dependence on the shared `noc0` fabric.

The TC9 case also reveals a recurring real-world issue for SoC security design: latency can dominate the feasible architecture. The critical `c8` path remains a bottleneck because its timing budget constrains which stronger features can be realized. This is exactly the type of tradeoff that must be solved jointly with the security problem rather than after the fact.

### B. DARPA/UAV: Strategy-Front Comparison

The translated UAV case provides the cleanest verified three-strategy comparison in the current codebase. The results are:

| Metric | max_security | min_resources | balanced |
|---|---:|---:|---:|
| Total risk | 0 | 39 | 0 |
| LUTs used | 18,170 | 8,410 | 16,530 |
| LUT utilization | 34% | 15% | 31% |
| FFs used | 14,120 | 6,160 | 12,640 |
| Power (mW) | 367 | 160 | 333 |
| Firewalls placed | 1 | 1 | 1 |
| Policy servers placed | 1 | 1 | 1 |
| Excess privileges | 22 | 22 | 22 |
| No-RoT trust gaps | 10 | 10 | 10 |
| Optimality proven | True | True | True |

Three points matter here.

First, the strategy front is real rather than cosmetic. Moving from `max_security` to `min_resources` reduces LUT use from 18,170 to 8,410, more than a 50% reduction, but raises residual risk from 0 to 39. The `balanced` strategy recovers zero risk while staying below the `max_security` footprint.

Second, architectural findings are stable across strategy choice. The number of excess privileges and the required enforcement placements do not disappear when the objective changes, because those findings are primarily topological rather than local-feature effects.

Third, exact solving makes the front easy to interpret. Each point is an exact result for its chosen objective, which means the designer is comparing principled alternatives rather than heuristically sampled candidates.

At the architectural level, this case also exposes a different kind of weakness from TC9. The critical issue is not a redundancy/common-mode interaction but a single-string internal bus structure. In the evaluated scenarios, `bus_mc_failure` causes simultaneous loss of multiple capabilities, and the untrusted ingress path through `radio_drv` creates a concentrated trust-boundary problem. This makes the case a useful complement to TC9.

## VII. Discussion

The experiments support three broader conclusions.

### A. Exact Synthesis Is Practical at This Scale

Both case studies are large enough to exhibit realistic architectural interactions, yet the solver still returns exact solutions with practical runtime and modest implementation cost. This is sufficient to justify exact solving as a design-tools method for moderate-size SoC security synthesis problems.

### B. Topology Matters as Much as Local Hardening

A purely feature-centric view of security would miss several of the strongest findings in the experiments:

- DMA over-privilege in TC9
- control-plane concentration at `ps0`
- single-string bus dependence in the UAV case
- stable excess-privilege structure across optimization strategies

These are architecture findings, not just component findings. That is why the joint formulation is more useful than local hardening guidance alone.

### C. Strategy Fronts Are More Useful Than a Single "Best" Design

Security architects often need to argue about whether an additional 5,000-10,000 LUTs are justified by a drop in risk, or whether a balanced design recovers most of the benefit of an aggressive one. A front of exact strategy points is therefore more actionable than a single optimum. The UAV case demonstrates this clearly, and the same workflow can be extended to richer front construction in future work.

### D. Limitations

The current formulation still abstracts several realities:

- communication timing is modeled at a coarse latency-budget level
- attack propagation is topology-aware but not cycle-accurate
- the strategy-front evaluation is currently cleaner on the UAV case than on TC9
- the current manuscript draft emphasizes feature and firewall placement more than monitor placement

These are limitations of scope, not contradictions in the method. They define the next steps for scaling and refinement.

## VIII. Conclusion

This paper presented an ASP-based workflow for exact SoC security architecture synthesis under hardware constraints. The method jointly selects protection features and synthesizes enforcement placement while respecting resource, power, and latency budgets. Evaluation on two representative SoC architectures showed that the approach is practical at useful scale, exposes topology-driven weaknesses that local hardening alone would miss, and produces interpretable strategy fronts across security and footprint objectives.

The strongest result is methodological: SoC security architecture design can be treated as an exact constrained synthesis problem rather than an informal or purely heuristic exploration problem. For SOCC, this is the right lens for the contribution.

## Submission Notes

Before final submission, this draft should be tightened into IEEE format with the following edits:

1. Compress the text to the conference page limit and move some prose into figures/tables.
2. Add final figure callouts using the existing workflow and topology SVGs.
3. Add a compact implementation paragraph with measured solve times from the current runners.
4. Replace generic related-work placeholders with final citations.
5. Decide whether monitor placement remains a small extension note or is removed entirely from the final paper.

## Candidate References

[1] ARM TrustZone and related SoC isolation references.

[2] Xilinx or AMD secure/interconnect isolation references.

[3] Representative secure interconnect or bus-firewall paper.

[4] Representative heuristic DSE or NSGA-II security co-design paper.

[5] ASP or constraint-programming reference for architecture synthesis.

[6] Clingo / Potassco system reference.
