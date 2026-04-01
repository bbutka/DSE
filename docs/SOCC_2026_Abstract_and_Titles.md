# SOCC 2026 Abstract and Title Options

## Working Deadline

Use April 22, 2026 as the active submission deadline.

## Best Title Options

### Option 1

Exact Design Space Exploration for SoC Security Architecture Synthesis Using Answer Set Programming

Why this is strong:

- leads with exact DSE
- clearly states SoC focus
- names ASP as the technical method
- fits the conference's design-tools and architecture audience

### Option 2

Resource-Aware SoC Security Architecture Synthesis with Exact ASP Optimization

Why this is strong:

- emphasizes hardware constraints immediately
- highlights exact optimization rather than generic automation
- reads like a methods paper

### Option 3

Exact Placement and Optimization of SoC Security Features and Firewalls Under Hardware Constraints

Why this is strong:

- foregrounds joint placement
- communicates architectural synthesis value
- avoids domain-specific baggage

### Option 4

Joint Synthesis of SoC Security Features and Enforcement Points with Exact Constraint Solving

Why this is strong:

- good if the paper focuses heavily on joint feature and firewall placement
- keeps method language broad enough for readers outside ASP

## Recommended Title

Exact Design Space Exploration for SoC Security Architecture Synthesis Using Answer Set Programming

This is the cleanest and strongest default title.

## Abstract Option A

System-on-Chip (SoC) platforms integrate processors, accelerators, memories, and peripherals on shared interconnects, making security architecture design a constrained optimization problem rather than a simple add-on decision. Security features, logging mechanisms, and enforcement points improve protection, but they also consume area, power, and latency budget. We present an exact design space exploration workflow for SoC security architecture synthesis based on Answer Set Programming (ASP). Given an architectural model, the method jointly selects per-component security and logging features and synthesizes enforcement placement under hard hardware constraints. The formulation captures resource, power, and latency budgets together with reachability and access-enforcement constraints, enabling exact optimization rather than heuristic front approximation. We evaluate the method on representative SoC topologies and compare multiple optimization strategies, including maximum-security, minimum-resource, and balanced configurations. The results show that the solver identifies feasible high-security architectures within modest FPGA utilization, exposes topology-driven over-privilege and trust gaps, and makes tradeoffs among protection strength, implementation cost, and bottleneck constraints explicit. The workflow demonstrates that exact ASP-based DSE is a practical approach for hardware-aware SoC security architecture synthesis.

## Abstract Option B

Designing secure System-on-Chip (SoC) architectures requires coordinated choices across protection features, access-enforcement placement, and hardware implementation budgets. Existing design-space exploration approaches often rely on heuristic search, which can approximate tradeoff fronts but does not provide exact optimality guarantees. This paper presents an Answer Set Programming (ASP) formulation for exact SoC security architecture synthesis. The method assigns security and logging features to components, places firewalls and related enforcement elements, and enforces LUT, flip-flop, power, and latency constraints within a single optimization workflow. In addition to producing exact feasible designs, the solver supports architectural diagnostics such as over-privilege findings, trust-anchor gaps, and strategy comparisons across alternative optimization goals. Evaluation on representative SoC case studies shows how latency bottlenecks and topology structure materially affect the optimal security architecture and demonstrates that exact solving can recover actionable strategy fronts with practical solve times. These results position ASP as a strong design-tools method for constrained SoC security synthesis.

## Abstract Option C

Security architecture design for modern System-on-Chip (SoC) platforms must balance protection strength against implementation cost. Selecting stronger security features, adding logging, and inserting firewalls or monitors can reduce attack exposure, but these choices compete with limited hardware resources and timing budgets. We present a hardware-aware design space exploration method that uses Answer Set Programming (ASP) to synthesize SoC security architectures exactly. The formulation jointly captures feature assignment, enforcement placement, and implementation constraints, allowing the solver to optimize for alternative strategies such as maximum security, minimum footprint, and balanced tradeoffs. Using representative SoC topologies, we show that the method produces exact strategy fronts, identifies structural over-privilege in shared-interconnect designs, and quantifies the architectural impact of latency-constrained components. The work frames SoC security synthesis as an exact optimization problem and demonstrates the value of ASP as a practical engine for architecture-level security design.

## Recommended Abstract

Use Abstract Option A unless the final paper spends substantially more space on exact-vs-heuristic comparison, in which case Option B becomes stronger.

## Short Contribution List for the Introduction

Use a compact three- or four-point contribution list:

1. An exact ASP formulation for SoC security architecture synthesis under resource, power, and latency constraints.
2. Joint optimization of per-component protection features and topology-aware enforcement placement.
3. Strategy-front comparison across maximum-security, minimum-resource, and balanced optimization goals.
4. Evaluation on representative SoC architectures showing practical solve times and actionable architectural tradeoffs.

## Keywords

- System-on-Chip Security
- Design Space Exploration
- Answer Set Programming
- Security Architecture Synthesis
- Hardware-Aware Optimization
- Firewall Placement

## Phrases To Prefer

- SoC security architecture synthesis
- exact design space exploration
- hardware-aware optimization
- enforcement placement
- strategy-front comparison
- constrained architecture synthesis

## Phrases To Avoid

- assurance-aware avionics
- airworthiness security
- DO-326A-driven
- zero-trust avionics
- lifecycle assurance workflow

## Optional One-Line Summary for EDAS or Notes

An exact ASP-based method for synthesizing SoC security architectures under implementation constraints, with joint feature-placement and enforcement-placement optimization.
