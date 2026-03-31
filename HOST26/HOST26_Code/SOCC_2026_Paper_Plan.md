# SOCC 2026 Paper Plan

## Target
- Conference: IEEE International System-on-Chip Conference (SOCC 2026)
- Working deadline: April 22, 2026
- Venue fit: SoC architecture, systems, design tools, and application scenarios
- Target format: IEEE double-column paper

## Paper Identity

This paper should be positioned as a **SoC methods paper**, not an avionics paper.

The core contribution is an **exact design space exploration workflow for SoC security architecture synthesis** under hardware constraints. The paper should emphasize:

- security feature assignment on SoC components
- firewall / monitor / policy placement
- resource / power / latency-aware optimization
- exact solving with ASP rather than heuristic search
- comparison of strategy fronts rather than a single design point

The avionics/UAV material is still useful, but only as a case-study source and portability demonstration. It should not dominate the framing, title, abstract, or introduction.

## Recommended Title Direction

Preferred title family:

- Exact Design Space Exploration for SoC Security Architecture Synthesis Using Answer Set Programming
- Resource-Aware SoC Security Architecture Synthesis with Exact ASP Optimization
- Exact Placement and Optimization of SoC Security Features and Firewalls Under Hardware Constraints

Avoid title language such as:

- assurance-aware
- avionics
- DO-326A
- airworthiness
- zero-trust avionics

Those terms narrow the venue fit and obscure the stronger SoC-design contribution.

## One-Sentence Pitch

We present an ASP-based exact solver that synthesizes SoC security architectures by jointly selecting protection features and enforcement placements under LUT/FF/power/latency constraints, and we evaluate the resulting strategy front across representative architectures.

## Main Claims

The paper should make four claims and support each with concrete evidence already present in the codebase and reports.

### Claim 1: Exact SoC security synthesis under hardware constraints

The solver jointly assigns security and logging features to SoC components while enforcing hardware budgets and latency constraints.

Evidence:

- `opt_redundancy_enc.lp`, `opt_latency_enc.lp`, `opt_power_enc.lp`, `opt_resource_enc.lp`
- `runClingo_tc9.py`
- TC9 quantitative results in `resilience_summary_tc9.txt`

### Claim 2: Joint architectural placement, not just local hardening

The workflow does more than choose per-component features. It also places firewalls, policy servers, and monitors based on topology and reachability constraints.

Evidence:

- `zta_policy_enc.lp`
- runtime monitor placement logic where useful
- topology figures and control-plane results in TC9/UAV summaries

### Claim 3: Exact ASP search gives stronger guarantees than heuristic DSE

The contribution is not merely automation. The method gives exact optimality or exact constraint satisfaction, and can diagnose infeasibility via UNSAT-style constraints.

Evidence:

- `#minimize`-based encodings
- strategy comparison material in `tc9_dse_method_comparison.md`
- solver outputs showing optimality on TC9

### Claim 4: Strategy-front comparison reveals actionable architecture tradeoffs

The value of the method is not one "best" design but the structure of tradeoffs across security, footprint, power, latency, and resilience.

Evidence:

- `max_security`, `min_resources`, and `balanced` outputs
- comparative result tables already discussed in `DASC_2026_Paper_Draft_v2.md`
- summary reports in `resilience_summary_tc9.txt` and `resilience_summary_darpa_uav.txt`

## What To Exclude or Minimize

To fit SOCC well, the paper should cut aggressively:

- avionics certification/process language
- FAA/DO-326A-heavy motivation
- lifecycle/process assurance framing
- broad "five deliverables" storyline
- long discussion of runtime adaptation unless it is reduced to a small extension note
- detailed CPS/avionics policy-process discussion

Runtime adaptation can remain as one paragraph of extensibility or future work, but it should not be a co-equal contribution in the SOCC paper.

## Recommended Structure

### 1. Introduction

Purpose:

- motivate the problem as SoC security synthesis under implementation constraints
- explain why manual security feature selection and enforcement placement do not scale
- state that heuristic DSE cannot provide exact optimality guarantees

End with concise contributions:

- exact SoC security feature synthesis
- joint firewall/policy placement
- hardware-constrained optimization
- strategy-front evaluation on representative architectures

### 2. Problem Formulation

Define:

- SoC topology graph
- component/asset model
- security and logging feature catalog
- firewall / monitor / policy placement candidates
- resource, power, and latency budgets
- optimization objectives and hard constraints

This section should be mathematical and architecture-focused, not process-focused.

### 3. ASP Encoding

Show:

- one-of feature assignment
- resource and latency constraints
- reachability and enforcement constraints
- placement rules
- objective functions
- exact optimality / infeasibility properties

Keep code snippets short and high-signal.

### 4. Security Architecture Synthesis Flow

Describe the solving pipeline:

- Phase 1: feature selection
- Phase 2: firewall/policy placement and least-privilege analysis
- optional monitor placement if included
- strategy generation and comparison

This is the place to explain why the workflow is "architecture synthesis" rather than simple scoring.

### 5. Experimental Evaluation

Primary case:

- TC9 as the main SoC case study
- use it for quantitative tables and the main narrative

Secondary case:

- DARPA/UAV as a portability or translation case
- use it to show the method is not tied to a single topology

Key evaluation dimensions:

- total risk
- LUTs / FFs / BRAM / DSP / power
- latency-constrained components
- number of firewalls / policy servers / monitors placed
- excess privilege findings
- trust-anchor gaps if retained
- resilience amplification or structural weakness metrics
- solve time and optimality status

### 6. Discussion

Cover:

- why exact ASP is appropriate here
- comparison against heuristic fronts and where heuristics may scale better
- current scaling limits
- model assumptions, including abstraction of communication and attack reachability

### 7. Conclusion

Short and technical:

- summarize the exact synthesis contribution
- restate what the experiments show
- point to scaling and richer path-aware modeling as next steps

## Figure Plan

Prioritize a small set of architecture-oriented figures.

### Fig. 1: Workflow Overview

Use the existing workflow figure as a base, but relabel it for SOCC:

- input topology and hardware budgets
- Phase 1 feature synthesis
- Phase 2 enforcement placement
- strategy-front comparison

### Fig. 2: TC9 SoC Topology

Use the existing topology figure and keep it generic.

### Fig. 3: Strategy Comparison

Prefer a compact table or Pareto-style scatter comparing:

- max_security
- min_resources
- balanced

Axes/columns should include risk, LUTs, power, latency bottlenecks, and placed enforcement count.

Optional:

- a second topology figure for the UAV case only if space permits

## Table Plan

### Table I: Feature Catalog and Costs

Include:

- security feature
- logging feature
- LUTs
- FFs
- power
- latency
- protection effect

### Table II: Formal Constraints and Objectives

Compact mapping from engineering requirement to ASP formulation:

- one feature per component
- resource budget
- latency cap
- protection requirement
- minimize residual risk
- minimize placement cost

### Table III: TC9 Strategy Comparison

This is the most important table.

Columns should include at least:

- strategy
- total risk
- LUTs
- FFs
- power
- number of firewalls
- number of policy servers
- notable bottleneck / finding

### Table IV: Cross-Case Summary

Only if space allows:

- TC9
- UAV / translated case
- components
- interconnect complexity
- solve time
- top findings

## Recommended Results Emphasis

Lead with the strongest results already visible in the material:

- TC9 solves exactly with feasible hardware usage
- the best assignment uses a modest fraction of FPGA resources
- latency constraints materially change the selected architecture
- topology-aware placement exposes over-privilege and trust gaps
- strategy comparison shows security/footprint tradeoffs instead of a single opaque optimum

Do not overclaim with resilience unless the numbers are clean and directly relevant to the architecture story.

## Narrative Conversion Rules

When converting the existing DASC text into SOCC form:

- replace "avionics SoC" with "SoC" unless the sentence is explicitly about the UAV case study
- replace "zero-trust avionics" with "SoC security architecture" or "on-chip access enforcement"
- replace process/compliance motivation with implementation-constraint motivation
- reduce related work on avionics standards to one short paragraph or remove it
- increase emphasis on design tools, exact optimization, and hardware-aware placement

## Minimum Viable SOCC Draft

If time becomes tight, the minimum viable paper should include only:

- problem statement
- ASP formulation
- TC9 case study
- one strategy-comparison table
- one topology figure
- one workflow figure

The UAV case can then become a brief supporting paragraph rather than a full second case study.

## Drafting Order

1. Write a new introduction and contributions from scratch.
2. Reuse the generic system/problem language from `ARCHITECTURE.md`.
3. Pull only the reusable equations and results from the DASC draft.
4. Build the strategy comparison table early so the paper has a clear center.
5. Add the secondary case only after the TC9 story is tight.

## Source Files To Mine

- `D:\DSE\DesignSpaceExplorationforSecurity-main\DesignSpaceExplorationforSecurity-main\ARCHITECTURE.md`
- `D:\DSE\DSE_ADD\tc9_dse_method_comparison.md`
- `D:\DSE\DSE_ADD\resilience_summary_tc9.txt`
- `D:\DSE\DSE_ADD\resilience_summary_darpa_uav.txt`
- `D:\DSE\DSE_ADD\docs\fig1_workflow_overview.svg`
- `D:\DSE\DSE_ADD\docs\fig3_tc9_topology.svg`
- `D:\DSE\DSE_ADD\docs\fig4_darpa_uav_topology.svg`

## Final Recommendation

Proceed with a new SOCC paper, not a repackaged DASC paper. The best fit is a compact methods paper on **exact SoC security architecture synthesis with ASP**, centered on constrained optimization and strategy-front comparison.
