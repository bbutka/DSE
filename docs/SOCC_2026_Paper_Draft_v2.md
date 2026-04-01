# Exact Design Space Exploration for SoC Security Architecture Synthesis Using Answer Set Programming

*Draft v2 for IEEE SOCC 2026*

## Abstract

System-on-Chip (SoC) platforms integrate processors, accelerators, memories, and peripherals on shared interconnects, making security architecture design a constrained optimization problem rather than a simple add-on decision. Security features, logging mechanisms, and enforcement points improve protection, but they also consume area, power, and latency budget. We present an exact design space exploration workflow for SoC security architecture synthesis based on Answer Set Programming (ASP). Given an architectural model, the method jointly selects per-component security and logging features and synthesizes enforcement placement under hard hardware constraints. The formulation captures resource, power, and latency budgets together with reachability and access-enforcement constraints, enabling exact optimization rather than heuristic front approximation. We evaluate the method on representative SoC topologies and compare multiple optimization strategies, including maximum-security, minimum-resource, and balanced configurations. The results show that the solver identifies feasible high-security architectures within modest FPGA utilization, exposes topology-driven over-privilege and trust gaps, and makes tradeoffs among protection strength, implementation cost, and bottleneck constraints explicit. The workflow demonstrates that exact ASP-based DSE is a practical approach for hardware-aware SoC security architecture synthesis.

**Keywords:** System-on-Chip Security, Design Space Exploration, Answer Set Programming, Security Architecture Synthesis, Hardware-Aware Optimization

## I. Introduction

Modern SoCs consolidate processors, DMA engines, accelerators, memories, and peripherals onto shared interconnect fabrics. This integration improves performance and cost efficiency, but it also creates broad attack surfaces: a compromise on one bus-attached component can expose many others through architectural reachability. Existing hardware-security building blocks such as TrustZone-style isolation [1], isolation-oriented FPGA design flows [2], and on-chip firewalls [3] help reduce exposure, but they do not by themselves solve the synthesis problem of deciding which protections to deploy, where to place them, and how to satisfy implementation constraints.

This is fundamentally a constrained optimization problem. Stronger protections consume lookup tables, flip-flops, power, and latency budget, and these costs interact with trust boundaries, topology, and access requirements. At the same time, security architecture design cannot be reduced to local per-IP hardening. Shared buses, over-privileged masters, and centralized control-plane elements create system-level risks that must be analyzed jointly with feature selection.

We address this problem with an ASP-based workflow for exact SoC security architecture synthesis. The formulation combines discrete feature choice, topology-aware enforcement placement, and implementation constraints in one optimization framework. In contrast to heuristic front-search methods such as NSGA-II [7], the proposed method provides exact solutions for a stated objective and explicit infeasibility when the architecture cannot realize required protections.

The paper makes four contributions:

1. An exact ASP formulation for SoC security feature synthesis under resource, power, and latency constraints.
2. Joint optimization of per-component protection features and topology-aware enforcement placement.
3. Strategy-front comparison across maximum-security, minimum-resource, and balanced optimization goals.
4. Evaluation on representative SoC architectures showing practical solve times, modest FPGA footprint, and actionable architectural findings.

> **Fig. 1 placement note:** use [fig1_workflow_overview.svg](D:/DSE/DSE_ADD/docs/fig1_workflow_overview.svg) as the workflow figure, relabeled for SOCC as input topology -> feature synthesis -> enforcement placement -> strategy comparison.

## II. Background and Positioning

### A. SoC Security Building Blocks

Arm TrustZone provides a system-wide hardware isolation model spanning processors, memory, peripherals, and bus transactions [1]. AMD's Isolation Design Flow similarly emphasizes separation and verification of protected FPGA regions, including Zynq 7000-class devices [2]. These are important building blocks, but they assume substantial manual design judgment about what to isolate and where to place enforcement.

Recent work on embedded AXI firewalls demonstrates that low-overhead on-chip enforcement can be realized directly in SoC fabrics [3]. That line of work validates the feasibility of hardware firewalls, but not the exact architecture-synthesis problem addressed here.

### B. Zero-Trust and Risk Framing

The paper borrows the "no implicit trust" principle from zero-trust thinking [4], but shifts the context from enterprise deployment to SoC architecture synthesis. The relevant design question is not enterprise identity management; it is whether bus-level accesses by masters to targets are explicitly mediated and justified.

The risk model is motivated by structured risk assessment practice [5], but the contribution here is not a new general-purpose risk standard. It is the use of an implementation-aware residual-risk objective inside an exact architecture-synthesis workflow.

### C. Why ASP Instead of Heuristic Search

Heuristic multi-objective search is useful when one wants broad approximate fronts [7]. However, this problem also requires recursive reachability reasoning, integrity constraints, and architectural diagnostics. ASP and clingo are well suited to this combination because they support exact optimization together with symbolic topology and policy reasoning [6].

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

The current workflow supports three explicit strategy modes:

- `max_security`
- `min_resources`
- `balanced`

This design choice is deliberate. Rather than claiming one universal optimum, the tool exposes exact strategy points that architects can compare directly.

## IV. ASP-Based Architecture Synthesis

### A. Phase 1: Exact Security Feature Selection

The first phase assigns one security feature and one logging feature per component. Constraints enforce implementation budgets and latency feasibility; the objective minimizes total residual risk over assets. At a high level:

```prolog
1 { selected_security(C, F) : security_feature(F) } 1 :- component(C).
1 { selected_logging(C, L)  : logging_feature(L) } 1 :- component(C).

:- total_luts(L), lut_budget(B), L > B.
:- total_power(P), power_budget(B), P > B.
:- path_latency(C, Op, T), latency_cap(C, Op, Cap), T > Cap.

#minimize { Risk, C, A, Op : weighted_risk(C, A, Op, Risk) }.
```

The significance is that the solver searches the complete discrete design space defined by the model and active constraints. The returned solution is therefore exact for the selected objective.

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

These are not separate ad hoc analyses; they are direct consequences of the same architectural model.

### C. Phase 3: Compromise and Failure Analysis

The final stage evaluates the synthesized architecture under compromise and failure scenarios. This phase is not the main contribution of the paper, but it is valuable because it distinguishes between:

- residual risk reduced by better feature assignment
- structural weakness that remains because of topology

That distinction is important in shared-interconnect SoCs.

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

This model is useful because it exhibits three representative tensions at once:

- shared-bus exposure
- redundancy versus common-mode dependence
- latency-driven limits on stronger protection

> **Fig. 2 placement note:** use [fig3_tc9_topology.svg](D:/DSE/DSE_ADD/docs/fig3_tc9_topology.svg) as the TC9 topology figure.

### B. DARPA/UAV Translation

The second case study is an 11-component translated architecture derived from a larger UAV system model. It contains:

- 3 masters
- 4 buses
- no redundancy groups
- 4 safety-critical components
- one clear bridge from an untrusted ingress path into a more trusted internal bus

This case is the best current vehicle for strategy-front comparison because verified results already exist for all three optimization modes.

## VI. Results

### A. TC9: Exact Synthesis on a Constrained SoC

For TC9, the phase-1 solver produced an optimal feature assignment with total base risk 51 and modest implementation cost:

- LUTs: 9,340 / 53,200 (17%)
- FFs: 7,100 / 106,400 (6%)
- BRAM: 10 / 140
- Power: 184 mW / 15,000 mW
- Optimality proven: True

These numbers matter because they show that exact synthesis does not imply impractical overhead. The architecture remains comfortably within the target FPGA budget while supporting nontrivial protection choices.

Phase 2 then placed:

- 2 firewalls
- 1 policy server

and identified 9 excess privileges. The dominant finding is that the DMA master is materially over-privileged relative to declared access need: measured policy tightness is 43%, with excess write exposure to the critical `c8` path and excess read exposure across the redundancy group. This is a topology finding, not merely a local feature-selection issue.

The before/after contrast is strong. Without any ZTA overlay, the architecture's worst-case exposure is 153.0. With synthesized enforcement active, the baseline risk is 51.0, a 3.00x reduction. However, the shared-bus architecture still enables large amplification under the wrong scenarios. Representative results are shown in Table I.

**Table I. TC9 selected scenario results**

| Scenario | Risk | Relative to baseline |
|---|---:|---:|
| baseline | 51.0 | 1.00x |
| `sys_cpu_compromise` | 102.0 | 2.00x |
| `dma_compromise` | 102.0 | 2.00x |
| `full_group_compromise` | 153.0 | 3.00x |
| `ps0_compromise` | 127.5 | 2.50x |
| `ps0_failure` | 61.2 | 1.20x |

Three architecture lessons follow.

First, exact feature and enforcement synthesis materially lowers baseline exposure. Second, centralized control-plane compromise can be nearly as damaging as data-plane compromise; `ps0_compromise` reaches 2.50x baseline because one policy server governs both deployed firewalls. Third, redundancy in the compute group does not remove common-mode dependence on the shared `noc0` fabric.

The latency-sensitive `c8` path is also instructive. Its timing budget constrains which higher-security choices are feasible, showing why SoC security must be synthesized jointly with implementation constraints rather than bolted on afterward.

### B. DARPA/UAV: Exact Strategy-Front Comparison

The translated UAV case provides the cleanest verified three-strategy comparison currently available in the codebase. The exact results are summarized in Table II.

**Table II. Strategy comparison on the translated UAV SoC**

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

This table demonstrates that the strategy front is substantive, not cosmetic. Moving from `max_security` to `min_resources` reduces LUT use from 18,170 to 8,410, but raises residual risk from 0 to 39. The `balanced` strategy recovers zero residual risk while staying below the `max_security` footprint.

Equally important, the topology-driven findings remain stable across strategy modes. Excess privilege and required enforcement placement do not disappear when the objective changes, because they are caused primarily by architecture rather than local protection choice.

At the structural level, this case complements TC9. Its key weakness is not redundancy/common-mode interaction, but a single-string internal-bus organization. The internal bus failure scenario removes multiple capabilities simultaneously, while the untrusted ingress path through `radio_drv` creates a concentrated trust-boundary problem.

## VII. Discussion

### A. Exact Synthesis Is Practical at Useful Scale

The evaluated designs are not toy examples. They are large enough to exhibit realistic interactions among resource limits, trust boundaries, and architectural reachability. Yet the solver still returns exact results with practical footprints. That is sufficient to justify exact solving as a design-tools method for moderate-scale SoC security synthesis.

### B. Topology Matters as Much as Local Hardening

Several of the strongest findings in the experiments are architectural:

- DMA over-privilege in TC9
- centralized control-plane dependence at `ps0`
- stable excess privilege across all UAV strategies
- single-string bus weakness in the UAV case

These findings would be easy to miss in a workflow focused only on per-component hardening. Joint synthesis is therefore the right abstraction.

### C. Exact Strategy Points Are Actionable

Architects often need to decide whether a footprint increase is justified by a risk reduction. Exact strategy points are easier to reason about than heuristic samples because each point is a solver-certified result for a stated objective. This does not eliminate the usefulness of broader Pareto methods, but it gives a cleaner baseline for architecture decisions.

### D. Limitations

The current formulation still abstracts several realities:

- communication timing is modeled at the latency-budget level rather than cycle-accurately
- attack propagation is topology-aware but not microarchitecturally detailed
- the current strategy-front story is stronger on the UAV case than on TC9
- monitor placement is present in the wider tool flow but not emphasized in this paper

These are scope limits, not inconsistencies in the method. They define the next steps for scaling and refinement.

## VIII. Conclusion

We presented an ASP-based workflow for exact SoC security architecture synthesis under hardware constraints. The method jointly selects protection features and synthesizes enforcement placement while respecting resource, power, and latency budgets. Evaluation on two representative architectures showed that the approach is practical at useful scale, exposes topology-driven weaknesses that local hardening alone would miss, and produces interpretable strategy fronts across security and footprint objectives.

The main result is methodological: SoC security architecture design can be treated as an exact constrained synthesis problem rather than an informal or purely heuristic exploration problem. That framing fits SOCC well and is the strongest version of the paper.

## Final Figures and Tables

For the next revision, keep the paper centered on:

- Fig. 1: workflow overview
- Fig. 2: TC9 topology
- Table I: TC9 selected scenarios
- Table II: UAV strategy comparison

If page pressure is severe, cut the second topology figure before cutting Table II.

## References

[1] Arm, "TrustZone for Cortex-A," official technology overview. [Online]. Available: https://www.arm.com/technologies/trustzone-for-cortex-a

[2] AMD, "Isolation Design Flow" and "Isolation Design Flow for AMD 7 Series FPGAs or Zynq 7000 SoCs (Vivado Tools), XAPP1222," official documentation hub. [Online]. Available: https://www.amd.com/en/products/adaptive-socs-and-fpgas/technologies/isolation-design-flow.html

[3] J. Lazaro, U. Bidarte, L. Muguira, A. Astarloa, and J. Jimenez, "Embedded firewall for on-chip bus transactions," *Computers & Electrical Engineering*, vol. 98, art. 107707, 2022, doi: 10.1016/j.compeleceng.2022.107707.

[4] S. Rose, O. Borchert, S. Mitchell, and S. Connelly, *Zero Trust Architecture*, NIST SP 800-207, Aug. 2020, doi: 10.6028/NIST.SP.800-207.

[5] Joint Task Force Transformation Initiative, *Guide for Conducting Risk Assessments*, NIST SP 800-30 Rev. 1, Sep. 2012, doi: 10.6028/NIST.SP.800-30r1.

[6] M. Gebser, R. Kaminski, B. Kaufmann, and T. Schaub, "Multi-shot ASP solving with clingo," *Theory and Practice of Logic Programming*, vol. 19, no. 1, pp. 27-82, 2019, doi: 10.1017/S1471068418000054.

[7] K. Deb, A. Pratap, S. Agarwal, and T. Meyarivan, "A fast and elitist multi-objective genetic algorithm: NSGA-II," *IEEE Transactions on Evolutionary Computation*, vol. 6, no. 2, pp. 182-197, 2002, doi: 10.1109/4235.996017.
