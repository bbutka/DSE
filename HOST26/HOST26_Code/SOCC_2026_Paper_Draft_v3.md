# Exact Design Space Exploration for SoC Security Architecture Synthesis Using Answer Set Programming

*Draft v3 for IEEE SOCC 2026*

## Abstract

System-on-Chip (SoC) platforms integrate processors, accelerators, memories, and peripherals on shared interconnects, making security architecture design a constrained optimization problem rather than a simple add-on decision. Security features, logging mechanisms, and enforcement points improve protection, but they also consume area, power, and latency budget. We present a design space exploration workflow for SoC security architecture synthesis based on Answer Set Programming (ASP). Given an architectural model, the method jointly selects per-component security and logging features and synthesizes enforcement placement under hard hardware constraints. The formulation captures resource, power, and latency budgets together with reachability and access-enforcement constraints, enabling exact optimization when solving completes and best-found fallback under a time limit when it does not. We evaluate the method on two representative SoC topologies and compare multiple optimization strategies, including maximum-security, minimum-resource, and balanced configurations. The results show that the solver identifies feasible high-security architectures within modest FPGA utilization, exposes topology-driven over-privilege and trust gaps, and makes tradeoffs among protection strength, implementation cost, and bottleneck constraints explicit. The workflow demonstrates that ASP-based DSE is a practical approach for hardware-aware SoC security architecture synthesis.

**Keywords:** System-on-Chip Security, Design Space Exploration, Answer Set Programming, Security Architecture Synthesis, Hardware-Aware Optimization

## I. Introduction

Modern SoCs consolidate processors, DMA engines, accelerators, memories, and peripherals onto shared interconnect fabrics. This integration improves performance and cost efficiency, but it also creates broad attack surfaces: a compromise on one bus-attached component can expose many others through architectural reachability. Existing hardware-security building blocks such as TrustZone-style isolation [1], isolation-oriented FPGA design flows [2], and on-chip firewalls [3] help reduce exposure, but they do not by themselves solve the synthesis problem of deciding which protections to deploy, where to place them, and how to satisfy implementation constraints.

This is fundamentally a constrained optimization problem. Stronger protections consume lookup tables, flip-flops, power, and latency budget, and these costs interact with trust boundaries, topology, and access requirements. At the same time, security architecture design cannot be reduced to local per-IP hardening. Shared buses, over-privileged masters, and centralized control-plane elements create system-level risks that must be analyzed jointly with feature selection.

We address this problem with an ASP-based workflow for SoC security architecture synthesis. The formulation combines discrete feature choice, topology-aware enforcement placement, and implementation constraints in one optimization framework. In contrast to heuristic front-search methods such as NSGA-II [7], the method targets exact solutions for a stated objective whenever the solver completes, and otherwise returns the best found solution together with explicit optimality status. That distinction matters for an architecture paper: the reader needs to know which tradeoff points are proven and which are not.

The paper makes four contributions:

1. An ASP formulation for SoC security feature synthesis under resource, power, and latency constraints.
2. Joint optimization of per-component protection features and topology-aware enforcement placement.
3. Strategy-front comparison across maximum-security, minimum-resource, and balanced optimization goals.
4. Evaluation on two representative SoC architectures showing practical runtimes, modest FPGA footprint, and actionable architectural findings.

## II. Background and Positioning

### A. SoC Security Building Blocks

Arm TrustZone provides a system-wide hardware isolation model spanning processors, memory, peripherals, and bus transactions [1]. AMD's Isolation Design Flow similarly emphasizes separation and verification of protected FPGA regions, including Zynq 7000-class devices [2]. These are important building blocks, but they assume substantial manual design judgment about what to isolate and where to place enforcement.

Recent work on embedded AXI firewalls demonstrates that low-overhead on-chip enforcement can be realized directly in SoC fabrics [3]. That line of work validates the feasibility of hardware firewalls, but not the architecture-synthesis problem addressed here.

### B. Zero-Trust and Risk Framing

The paper borrows the "no implicit trust" principle from zero-trust thinking [4], but shifts the context from enterprise deployment to SoC architecture synthesis. The relevant design question is not enterprise identity management; it is whether bus-level accesses by masters to targets are explicitly mediated and justified.

The risk model is motivated by structured risk assessment practice [5], but the contribution here is not a new risk standard. It is the use of an implementation-aware residual-risk objective inside a constrained synthesis workflow.

### C. Why ASP Instead of Heuristic Search

Heuristic multi-objective search is useful when one wants broad approximate fronts [7]. However, this problem also requires recursive reachability reasoning, integrity constraints, and architectural diagnostics. ASP and clingo are well suited to this combination because they support exact optimization together with symbolic topology and policy reasoning [6]. The present paper does not claim a head-to-head baseline against a heuristic solver; instead, it positions ASP as an exact or best-found alternative with stronger logical expressiveness for the current model.

## III. Problem Formulation

We model an SoC as a directed graph `G = (V, E)` with typed vertices for masters, receiver IPs, buses, and enforcement elements. Bus masters initiate transactions, receiver IPs own assets, and edges encode architectural reachability. Each component carries:

- trust-domain information
- asset impact values for read, write, and availability
- candidate security and logging features
- feature costs in LUTs, FFs, BRAM, and power
- maximum allowable latency

The synthesis problem has two coupled decision layers.

### A. Feature Assignment

Each component must receive exactly one security feature and one logging feature. The resulting design must satisfy:

- LUT, FF, BRAM, and power budgets
- per-component latency limits
- any explicit risk-cap or availability constraints encoded in the instance

### B. Enforcement Placement

Given the synthesized feature configuration and the topology, the workflow places firewalls and policy servers so that accesses from lower-trust or insufficiently verified masters to protected targets are mediated. This stage also computes excess privilege by comparing topology-implied access against declared access need.

### C. Optimization Modes

The workflow supports three strategy modes:

- `max_security`
- `min_resources`
- `balanced`

The paper therefore evaluates a front of strategy points rather than one opaque optimum.

## IV. ASP-Based Architecture Synthesis

### A. Phase 1: Security Feature Selection

The first phase assigns one security feature and one logging feature per component. Constraints enforce implementation budgets and latency feasibility; the objective minimizes total residual risk over assets. At a high level:

```prolog
1 { selected_security(C, F) : security_feature(F) } 1 :- component(C).
1 { selected_logging(C, L)  : logging_feature(L) } 1 :- component(C).

:- total_luts(L), lut_budget(B), L > B.
:- total_power(P), power_budget(B), P > B.
:- path_latency(C, Op, T), latency_cap(C, Op, Cap), T > Cap.

#minimize { Risk, C, A, Op : weighted_risk(C, A, Op, Risk) }.
```

Strategy-specific objective modifiers are layered on top of the base encoding:

- `max_security`: use the default risk objective
- `min_resources`: add a secondary LUT minimization objective
- `balanced`: minimize total risk, then LUTs

### B. Phase 2: Topology-Aware Enforcement Placement

The second phase reasons over master-to-target reachability and protection requirements. Candidate firewalls and policy servers are activated only where they are needed to block or mediate disallowed accesses:

```prolog
{ place_fw(FW) : cand_fw(FW) }.
1 { place_ps(PS) : cand_ps(PS) }.

:- master(M), protected_target(T),
   reachable(M, T), not mediated(M, T).

#minimize { Cost, X : placement_cost(X, Cost) }.
```

This stage produces both placement decisions and architectural diagnostics:

- excess privilege
- missing privilege
- trust-anchor gaps
- concentrated control-plane dependencies

### C. Phase 3: Compromise and Failure Analysis

The final stage evaluates the synthesized architecture under compromise and failure scenarios. This phase is not the primary contribution, but it distinguishes between:

- residual risk reduced by better feature assignment
- structural weakness that remains because of topology

That distinction is useful in shared-interconnect SoCs.

## V. Experimental Setup

The implementation is built in Python around clingo-based encodings [6]. The feature-cost model targets a PYNQ-Z2 FPGA-class platform, and the experiments use two architectural models.

### A. TC9 SoC

TC9 is the primary detailed case study. It contains:

- 8 receiver components
- 2 masters
- 2 bus/interconnect domains
- a 5-member redundancy group
- 3 standalone IPs
- one latency-sensitive critical component

This model exhibits shared-bus exposure, redundancy-versus-common-mode dependence, and latency-driven limits on stronger protection.

### B. DARPA/UAV Translation

The second case study is an 11-component translated architecture derived from a larger UAV system model. It contains:

- 3 masters
- 4 buses
- no redundancy groups
- 4 safety-critical components
- one clear bridge from an untrusted ingress path into a more trusted internal bus

This case is useful because its three strategy runs expose a strong footprint-versus-risk tradeoff and a timeout-sensitive minimum-resource search.

## VI. Results

### A. TC9: Measured Three-Strategy Comparison

TC9 now has a complete measured three-strategy snapshot. The results are shown in Table I.

**Table I. TC9 strategy comparison**

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
| Phase 1 runtime (s) | 6.134 | 9.967 | 19.031 |
| Phase 2 runtime (s) | 0.007 | 0.007 | 0.007 |
| Phase 3 runtime (s) | 0.225 | 0.211 | 0.212 |
| Total runtime (s) | 6.366 | 10.185 | 19.250 |
| Optimality proven | True | True | True |

This table closes an earlier weakness in the paper: the primary SoC case now has a real strategy front rather than a single design point. Three findings stand out.

First, `min_resources` materially reduces implementation cost, cutting LUT use from 9,340 to 5,380, but raises residual risk from 51 to 69. Second, `balanced` recovers the same risk as `max_security` while lowering LUT use to 6,840. Third, all three strategies preserve the same enforcement architecture and privilege findings, which indicates that some issues are topological rather than local-feature effects.

The scenario story on TC9 remains structurally important. Without any ZTA overlay, the architecture's worst-case exposure is 153.0. With synthesized enforcement active, the baseline risk is 51.0, a 3.00x reduction. The worst measured scenario under both `max_security` and `balanced` remains full group compromise at 3.00x baseline, while `min_resources` reaches a larger absolute worst-case risk of 195.9 even though its relative worst-case ratio is 2.839 because the baseline is higher.

TC9 also preserves the earlier architectural findings:

- the DMA master remains materially over-privileged
- centralized policy control at `ps0` remains a concentration point
- redundancy does not remove common-mode dependence on the shared `noc0` fabric
- the latency-sensitive `c8` path still constrains stronger feature choices

### B. DARPA/UAV: Matching Measured Snapshot

The DARPA/UAV case now has a matching measured snapshot generated from the dedicated runner. The results are shown in Table II.

**Table II. DARPA/UAV strategy comparison**

| Metric | max_security | min_resources | balanced |
|---|---:|---:|---:|
| Total risk | 0 | 35 | 0 |
| LUTs used | 18,170 | 9,260 | 16,530 |
| FFs used | 14,120 | 6,850 | 12,640 |
| Power (mW) | 367 | 178 | 333 |
| Firewalls placed | 1 | 1 | 1 |
| Policy servers placed | 1 | 1 | 1 |
| Excess privileges | 22 | 22 | 22 |
| No-RoT trust gaps | 10 | 10 | 10 |
| Phase 1 runtime (s) | 12.015 | 70.834 | 12.271 |
| Phase 2 runtime (s) | 0.011 | 0.009 | 0.009 |
| Phase 3 runtime (s) | 0.202 | 0.211 | 0.202 |
| Total runtime (s) | 12.228 | 71.054 | 12.482 |
| Phase 1 optimality proven | True | False | True |

This table exposes a useful nuance that was missing in the earlier draft. The `min_resources` point is not a proven optimum in this run. It is a best-found solution returned after the phase-1 search hit the configured timeout. That does not invalidate the point, but it changes how the paper should describe it. The paper can still claim:

- exact strategy points for the runs that complete with proof
- best-found fallback for the run that times out

Substantively, the DARPA/UAV results still support the strategy-front argument. Moving from `max_security` to `min_resources` reduces LUT use from 18,170 to 9,260 but raises residual risk from 0 to 35. The `balanced` strategy recovers zero residual risk while staying below the `max_security` footprint.

The structural findings are stable across strategy modes:

- 1 firewall and 1 policy server are placed in all three runs
- 22 excess privileges remain
- 10 no-RoT gaps remain

This case therefore complements TC9 in a different way. Its key weakness is not redundancy/common-mode interaction, but a single-string internal-bus organization plus a narrow trust boundary at the ingress path. The worst measured `min_resources` scenario is `ps_uart_compromise` at 2.105x baseline.

### C. Runtime and Scaling View

To make the practical-runtime claim explicit, Table III summarizes the measured end-to-end times for the strongest strategy points.

**Table III. Runtime summary**

| Case | Strategy | Components | Scenarios | Total time (s) | Optimality status |
|---|---|---:|---:|---:|---|
| TC9 | max_security | 8 receivers | 29 | 6.366 | proven |
| TC9 | min_resources | 8 receivers | 29 | 10.185 | proven |
| TC9 | balanced | 8 receivers | 29 | 19.250 | proven |
| DARPA/UAV | max_security | 11 receivers | 24 | 12.228 | proven |
| DARPA/UAV | min_resources | 11 receivers | 24 | 71.054 | best-found after timeout |
| DARPA/UAV | balanced | 11 receivers | 24 | 12.482 | proven |

These measured runtimes support a narrower and more defensible claim than the previous draft: the method is practical at this problem scale, but some strategy/objective combinations can become significantly harder than others. In particular, the DARPA `min_resources` run is the main warning sign and should be described honestly rather than folded into a blanket "all exact" claim.

## VII. Discussion

### A. What Is Now Supported

The revised evidence supports the following claims directly:

- the method can produce exact strategy points on both case studies
- the primary TC9 case now has a full three-strategy comparison
- runtimes are practical for the reported instances
- topology-driven findings remain visible across strategy modes

### B. What Is Still Not Supported

The paper still does not contain a head-to-head heuristic baseline. It should therefore avoid claiming empirical superiority over heuristic methods. The correct positioning is:

- ASP provides exact optimization when the solver completes
- ASP provides best-found fallback with explicit optimality status under a time limit
- the model is especially attractive because it combines topology, reachability, and optimization in one formulation

### C. Topology Matters as Much as Local Hardening

Several of the strongest findings in the experiments are architectural:

- DMA over-privilege in TC9
- centralized control-plane dependence at `ps0`
- stable excess privilege across all DARPA/UAV strategies
- single-string bus weakness in the DARPA/UAV case

These findings would be easy to miss in a workflow focused only on per-component hardening. Joint synthesis is therefore the right abstraction.

### D. Limitations

The current formulation still abstracts several realities:

- communication timing is modeled at the latency-budget level rather than cycle-accurately
- attack propagation is topology-aware but not microarchitecturally detailed
- one strategy point in the DARPA/UAV study is best-found rather than proven optimal
- monitor placement exists in the wider tool flow but is not emphasized in this paper

These are scope limits, not inconsistencies in the method.

## VIII. Conclusion

We presented an ASP-based workflow for SoC security architecture synthesis under hardware constraints. The method jointly selects protection features and synthesizes enforcement placement while respecting resource, power, and latency budgets. Measured evaluation on TC9 and the DARPA/UAV translation showed that the approach is practical at useful scale, exposes topology-driven weaknesses that local hardening alone would miss, and produces interpretable strategy fronts across security and footprint objectives.

The revised evidence supports the paper's strongest claim: SoC security architecture design can be treated as a constrained synthesis problem with exact solutions when the search completes and explicit best-found fallbacks when it does not. That is a defensible and useful methods contribution for SOCC.

## Final Figures and Tables

The final paper should stay centered on:

- workflow overview figure
- TC9 topology figure
- Table I: TC9 strategy comparison
- Table II: DARPA/UAV strategy comparison
- Table III: runtime summary

If page pressure is severe, cut extended scenario prose before cutting the strategy tables.

## References

[1] Arm, "TrustZone for Cortex-A," official technology overview. [Online]. Available: https://www.arm.com/technologies/trustzone-for-cortex-a

[2] AMD, "Isolation Design Flow" and "Isolation Design Flow for AMD 7 Series FPGAs or Zynq 7000 SoCs (Vivado Tools), XAPP1222," official documentation hub. [Online]. Available: https://www.amd.com/en/products/adaptive-socs-and-fpgas/technologies/isolation-design-flow.html

[3] J. Lazaro, U. Bidarte, L. Muguira, A. Astarloa, and J. Jimenez, "Embedded firewall for on-chip bus transactions," *Computers & Electrical Engineering*, vol. 98, art. 107707, 2022, doi: 10.1016/j.compeleceng.2022.107707.

[4] S. Rose, O. Borchert, S. Mitchell, and S. Connelly, *Zero Trust Architecture*, NIST SP 800-207, Aug. 2020, doi: 10.6028/NIST.SP.800-207.

[5] Joint Task Force Transformation Initiative, *Guide for Conducting Risk Assessments*, NIST SP 800-30 Rev. 1, Sep. 2012, doi: 10.6028/NIST.SP.800-30r1.

[6] M. Gebser, R. Kaminski, B. Kaufmann, and T. Schaub, "Multi-shot ASP solving with clingo," *Theory and Practice of Logic Programming*, vol. 19, no. 1, pp. 27-82, 2019, doi: 10.1017/S1471068418000054.

[7] K. Deb, A. Pratap, S. Agarwal, and T. Meyarivan, "A fast and elitist multi-objective genetic algorithm: NSGA-II," *IEEE Transactions on Evolutionary Computation*, vol. 6, no. 2, pp. 182-197, 2002, doi: 10.1109/4235.996017.
