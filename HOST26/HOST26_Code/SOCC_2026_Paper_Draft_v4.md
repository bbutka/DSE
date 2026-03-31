# Exact Design Space Exploration for SoC Security Architecture Synthesis Using Answer Set Programming

*Draft v4, strengthened for journal submission*

## Abstract

System-on-Chip (SoC) platforms integrate processors, accelerators, memories, and peripherals on shared interconnects, making security architecture design a constrained optimization problem rather than a simple add-on decision. Security features, logging mechanisms, and enforcement points improve protection, but they also consume area, power, and latency budget. We present a design space exploration workflow for SoC security architecture synthesis based on Answer Set Programming (ASP). Given an architectural model, the method jointly selects per-component security and logging features and synthesizes enforcement placement under hard hardware constraints. The formulation uses an additive residual-risk model for standalone components, a closed-form normalized compromise model for redundant groups, and explicit resource, power, and latency constraints derived from the implementation catalog. It therefore supports exact optimization when solving completes and best-found fallback under a time limit when it does not. We evaluate the method on two representative SoC topologies and compare multiple optimization strategies, including maximum-security, minimum-resource, and balanced configurations. The results show that the solver identifies feasible high-security architectures within modest FPGA utilization, exposes topology-driven over-privilege and trust gaps, and makes tradeoffs among protection strength, implementation cost, and bottleneck constraints explicit. The workflow demonstrates that ASP-based DSE is a practical approach for hardware-aware SoC security architecture synthesis.

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

Heuristic multi-objective search is useful when one wants broad approximate fronts [7], and security-aware design-space exploration has already been argued for embedded systems more generally [8]. However, this problem also requires recursive reachability reasoning, integrity constraints, and architectural diagnostics. ASP and clingo are well suited to this combination because they support exact optimization together with symbolic topology and policy reasoning [6]. The present paper does not claim a head-to-head baseline against a heuristic solver; instead, it positions ASP as an exact or best-found alternative with stronger logical expressiveness for the current model.

### D. Position Relative to Adjacent Work

Three neighboring literature threads matter here. First, SoC and MPSoC communication-security work has shown that interconnect organization and mediation points are central to system security, especially in NoC-style platforms [9]. Second, policy-oriented SoC security work has treated specification and verification of security policy as a first-class design concern [10]. Third, classical DSE work motivates systematic exploration of architecture tradeoffs, including security-aware tradeoffs [7], [8].

The gap addressed here is narrower and more specific: exact joint synthesis of feature assignment and enforcement placement under explicit hardware budgets and topology-derived access constraints. The contribution is therefore not a new security primitive, not a new policy language, and not a claim that ASP dominates all alternative solvers. The contribution is a method for solving this integrated synthesis problem in a way that keeps logical structure, implementation budgets, and solver status visible to the designer.

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

### D. Explicit Cost and Risk Model

For standalone components, the phase-1 encoding uses an additive residual-risk model:

```text
r_standalone = max(0, impact + domain_bonus - security_protect - log_protect)
```

where `domain_bonus` is `3` for high-domain components and `0` otherwise. Security and logging features therefore reduce residual risk through explicit protection scores rather than through an implicit black-box weight.

For components inside a redundancy group, the encoding uses a normalized closed-form compromise model. Each component first receives a normalized compromise score based on its selected security and logging features:

```text
original_prob = vulnerability * logging
normalized_prob = (original_prob - mu) * 1000 / (omega - mu)
```

The group compromise probability is then computed recursively as the normalized product of all member probabilities, with division applied at each step to remain within Clingo's integer range. The resulting denormalized group probability replaces the standalone additive score for group members:

```text
r_group = impact * denormalized_group_prob / 100
```

This split model matters because the tool is simultaneously reasoning about standalone IPs and redundant clusters. A single additive model would miss common-mode effects in groups, while a single multiplicative model would distort ordinary standalone tradeoffs.

**Table I. Feature semantics used in phase 1**

| Feature | Type | Modeling score | Protection score | Latency | LUTs | FFs | BRAM | Power |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `zero_trust` | security | vulnerability = 10 | 8 | 3 | 1200 | 850 | 0 | 24 |
| `dynamic_mac` | security | vulnerability = 20 | 6 | 6 | 950 | 680 | 0 | 18 |
| `mac` | security | vulnerability = 30 | 4 | 4 | 650 | 420 | 0 | 12 |
| `zero_trust_logger` | logging | logging = 5 | 3 | 2 | 520 | 480 | 2 | 11 |
| `some_logging` | logging | logging = 10 | 1 | 1 | 180 | 220 | 1 | 4 |
| `no_logging` | logging | logging = 20 | 0 | 1 | 0 | 0 | 0 | 0 |

Security-feature resource costs are component-scoped; logging-feature costs are counted once per selected component through the exported base-cost facts. The implementation also enforces DSP, LUTRAM, and BUFG constraints, although LUTs, FFs, BRAM, and power are the dominant dimensions discussed in the results.

**Table II. Optimization structure**

| Layer | Decision variables | Hard constraints | Objective behavior |
|---|---|---|---|
| Phase 1 feature assignment | `selected_security(C,F)`, `selected_logging(C,L)` | one feature of each type per component; LUT/FF/DSP/LUTRAM/BRAM budgets; power budget; latency caps; effective risk cap | minimize total `new_risk` |
| `max_security` strategy | same as phase 1 | same as phase 1 | use default total-risk objective |
| `min_resources` strategy | same as phase 1 | same as phase 1 | add secondary LUT minimization objective |
| `balanced` strategy | same as phase 1 | same as phase 1 | minimize total risk, then LUTs |
| Phase 2 enforcement placement | candidate firewall and policy-server placements | protected targets must be mediated; reachability and policy consistency | minimize placement cost |
| Phase 3 resilience analysis | scenario compromise/failure facts | scenario semantics and control-plane consistency | evaluate residual exposure rather than optimize |

## IV. ASP-Based Architecture Synthesis

### A. Phase 1: Security Feature Selection

The first phase assigns one security feature and one logging feature per component. Constraints enforce implementation budgets and latency feasibility; the objective minimizes total residual risk over assets. For standalone components this risk comes from the additive model in Section III-D, while redundant groups use the normalized group-compromise model. At a high level:

```prolog
1 { selected_security(C, F) : security_feature(F) } 1 :- component(C).
1 { selected_logging(C, L)  : logging_feature(L) } 1 :- component(C).

:- total_luts(L), lut_budget(B), L > B.
:- total_power(P), power_budget(B), P > B.
:- path_latency(C, Op, T), latency_cap(C, Op, Cap), T > Cap.

#minimize { Risk, C, A, Op : new_risk(C, A, Op, Risk) }.
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

### D. Exactness and Solver Status

The workflow uses clingo in optimization mode and reports the status of each strategy point explicitly. A result is treated as exact only when the solver returns an optimal model with proof. If the search reaches the configured timeout first, the workflow records the returned design as best found and preserves that status in the reported tables. This operational definition is important because journal reviewers should be able to distinguish exact optima from timeout-limited tradeoff points rather than infer that distinction from runtime alone.

## V. Experimental Setup

The implementation is built in Python around clingo-based encodings [6]. The feature-cost model targets a PYNQ-Z2 FPGA-class platform, and the experiments use two architectural models. Phase 1 loads the instance facts together with `security_features_inst.lp`, `init_enc.lp`, `opt_redundancy_generic_enc.lp`, `opt_latency_enc.lp`, `opt_power_enc.lp`, `opt_resource_enc.lp`, and `bridge_enc.lp`. Phase 2 uses the synthesized design with `zta_policy_enc.lp`, and Phase 3 evaluates the resulting architecture with the resilience encoding. Reported feature costs come directly from the exported implementation catalog, not from hand-entered table values.

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

Table III reports the measured three-strategy TC9 results.

**Table III. TC9 strategy comparison**

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

Three findings stand out. First, `min_resources` materially reduces implementation cost, cutting LUT use from 9,340 to 5,380, but raises residual risk from 51 to 69. Second, `balanced` recovers the same risk as `max_security` while lowering LUT use to 6,840. Third, all three strategies preserve the same enforcement architecture and privilege findings, which indicates that some issues are topological rather than local-feature effects.

The scenario story on TC9 remains structurally important. Without any ZTA overlay, the architecture's worst-case exposure is 153.0. With synthesized enforcement active, the baseline risk is 51.0, a 3.00x reduction. The worst measured scenario under both `max_security` and `balanced` remains full group compromise at 3.00x baseline, while `min_resources` reaches a larger absolute worst-case risk of 195.9 even though its relative worst-case ratio is 2.839 because the baseline is higher.

TC9 also exhibits the following architectural findings:

- the DMA master remains materially over-privileged
- centralized policy control at `ps0` remains a concentration point
- redundancy does not remove common-mode dependence on the shared `noc0` fabric
- the latency-sensitive `c8` path still constrains stronger feature choices

### B. DARPA/UAV: Matching Measured Snapshot

Table IV reports the measured DARPA/UAV results from the dedicated runner.

**Table IV. DARPA/UAV strategy comparison**

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

The `min_resources` point is not a proven optimum in this run. It is a best-found solution returned after the phase-1 search hit the configured timeout. That does not invalidate the point, but it does change the status of that strategy point relative to the exact runs.

Substantively, the DARPA/UAV results still support the strategy-front argument. Moving from `max_security` to `min_resources` reduces LUT use from 18,170 to 9,260 but raises residual risk from 0 to 35. The `balanced` strategy recovers zero residual risk while staying below the `max_security` footprint.

The structural findings are stable across strategy modes:

- 1 firewall and 1 policy server are placed in all three runs
- 22 excess privileges remain
- 10 no-RoT gaps remain

This case therefore complements TC9 in a different way. Its key weakness is not redundancy/common-mode interaction, but a single-string internal-bus organization plus a narrow trust boundary at the ingress path. The worst measured `min_resources` scenario is `ps_uart_compromise` at 2.105x baseline.

### C. Runtime and Scaling View

To make the runtime claim explicit, Table V summarizes the measured end-to-end times for the strongest strategy points.

**Table V. Runtime summary**

| Case | Strategy | Components | Scenarios | Total time (s) | Optimality status |
|---|---|---:|---:|---:|---|
| TC9 | max_security | 8 receivers | 29 | 6.366 | proven |
| TC9 | min_resources | 8 receivers | 29 | 10.185 | proven |
| TC9 | balanced | 8 receivers | 29 | 19.250 | proven |
| DARPA/UAV | max_security | 11 receivers | 24 | 12.228 | proven |
| DARPA/UAV | min_resources | 11 receivers | 24 | 71.054 | best-found after timeout |
| DARPA/UAV | balanced | 11 receivers | 24 | 12.482 | proven |

These measured runtimes show that the method is practical at the reported problem scale, but that some strategy/objective combinations can become significantly harder than others. In particular, the DARPA `min_resources` run is the main warning sign and should be described honestly rather than folded into a blanket "all exact" claim.

## VII. Discussion

### A. Architectural Findings Versus Local Hardening

Several of the strongest findings in the experiments are architectural rather than component-local:

- DMA over-privilege in TC9
- centralized control-plane dependence at `ps0`
- stable excess privilege across all DARPA/UAV strategies
- single-string bus weakness in the DARPA/UAV case

These findings would be easy to miss in a workflow focused only on per-component hardening. Joint synthesis is therefore the right abstraction when the dominant risk comes from reachability, mediation, and control concentration instead of from the weakness of any one IP block.

### B. What the Current Evidence Supports

The current results support four concrete claims. First, the method can produce exact strategy points for both case studies when the solve completes with proof. Second, the primary TC9 case exhibits a true three-strategy tradeoff rather than a single nominal optimum. Third, the measured runtimes are practical at the reported problem scale. Fourth, topology-driven findings remain stable across strategy modes, which suggests that policy placement and privilege structure matter independently of feature tuning.

### C. What the Current Evidence Does Not Yet Support

The paper still does not contain a head-to-head baseline against CP-SAT, MILP, or a heuristic front-search method. It therefore should not claim empirical superiority over alternative solvers. The current evidence supports ASP as an exact-or-best-found formulation with strong logical expressiveness for topology and policy reasoning, not as a universally superior optimizer.

The evaluation is also still narrow for a full journal claim. Two manually constructed SoC instances demonstrate feasibility and reveal meaningful tradeoffs, but they do not yet establish broad scaling behavior across large families of architectures. A stronger journal submission should therefore add a synthetic scaling sweep or an additional automatically generated case family.

### D. Threats to Validity and Limits

The current formulation abstracts several realities:

- communication timing is modeled at the latency-budget level rather than cycle-accurately
- attack propagation is topology-aware but not microarchitecturally detailed
- one strategy point in the DARPA/UAV study is best-found rather than proven optimal
- monitor placement exists in the wider tool flow but is not emphasized in this paper

These are scope limits, not inconsistencies. They define the current boundary of the method: architecture-level synthesis with explicit implementation constraints, not cycle-accurate security-performance co-simulation.

## VIII. Conclusion

We presented an ASP-based workflow for SoC security architecture synthesis under hardware constraints. The method jointly selects protection features and synthesizes enforcement placement while respecting resource, power, and latency budgets. The paper states the risk model, feature semantics, and solver-status interpretation explicitly so that the synthesis problem is reproducible rather than merely conceptual.

Measured evaluation on TC9 and the DARPA/UAV translation showed that the approach is practical at useful scale, exposes topology-driven weaknesses that local hardening alone would miss, and produces interpretable strategy fronts across security and footprint objectives. The strongest defensible claim is therefore that SoC security architecture design can be treated as a constrained synthesis problem with exact solutions when the search completes and explicit best-found fallbacks when it does not. That is a useful methods contribution and a credible basis for journal submission.

## References

[1] Arm, "TrustZone for Cortex-A," official technology overview. [Online]. Available: https://www.arm.com/technologies/trustzone-for-cortex-a

[2] AMD, "Isolation Design Flow" and "Isolation Design Flow for AMD 7 Series FPGAs or Zynq 7000 SoCs (Vivado Tools), XAPP1222," official documentation hub. [Online]. Available: https://www.amd.com/en/products/adaptive-socs-and-fpgas/technologies/isolation-design-flow.html

[3] J. Lazaro, U. Bidarte, L. Muguira, A. Astarloa, and J. Jimenez, "Embedded firewall for on-chip bus transactions," *Computers & Electrical Engineering*, vol. 98, art. 107707, 2022, doi: 10.1016/j.compeleceng.2022.107707.

[4] S. Rose, O. Borchert, S. Mitchell, and S. Connelly, *Zero Trust Architecture*, NIST SP 800-207, Aug. 2020, doi: 10.6028/NIST.SP.800-207.

[5] Joint Task Force Transformation Initiative, *Guide for Conducting Risk Assessments*, NIST SP 800-30 Rev. 1, Sep. 2012, doi: 10.6028/NIST.SP.800-30r1.

[6] M. Gebser, R. Kaminski, B. Kaufmann, and T. Schaub, "Multi-shot ASP solving with clingo," *Theory and Practice of Logic Programming*, vol. 19, no. 1, pp. 27-82, 2019, doi: 10.1017/S1471068418000054.

[7] K. Deb, A. Pratap, S. Agarwal, and T. Meyarivan, "A fast and elitist multi-objective genetic algorithm: NSGA-II," *IEEE Transactions on Evolutionary Computation*, vol. 6, no. 2, pp. 182-197, 2002, doi: 10.1109/4235.996017.

[8] A. D. Pimentel, "A Case for Security-Aware Design-Space Exploration of Embedded Systems," *Journal of Low Power Electronics and Applications*, vol. 10, no. 3, art. 22, 2020, doi: 10.3390/jlpea10030022.

[9] G. Sharma, G. Bousdras, S. Ellinidou, O. Markowitch, and J.-M. Dricot, "Exploring the security landscape: NoC-based MPSoC to Cloud-of-Chips," *Microprocessors and Microsystems*, vol. 84, art. 103963, 2021, doi: 10.1016/j.micpro.2021.103963.

[10] S. Ray, A. Basak, and S. Bhunia, *Security Policy in System-on-Chip Designs: Specification, Implementation and Verification*. Springer, 2019, doi: 10.1007/978-3-319-93464-8.
