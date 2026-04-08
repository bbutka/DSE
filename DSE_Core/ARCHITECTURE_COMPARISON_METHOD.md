# Architecture Comparison Method

Date: April 7, 2026

## Purpose

This note defines how `DSE_Core` comparisons should be interpreted when the
user wants to compare:

- the existing architecture
- one or more revised architectures
- the added security/ZTA overhead on top of each architecture

The key rule is that fixed platform hardware, architectural changes, and
security overhead must not be collapsed into one undifferentiated number.

## Three Separate Ledgers

### 1. Fixed architecture cost

This is the hardware already inherent to a design before any DSE-added
protection is selected.

Examples:

- existing Pixhawk 6X board components
- baseline buses and ports
- baseline vehicle-overlay hardware that is considered part of the design

This ledger is design-specific, but it is not the Phase 1 security-overhead
ledger.

### 2. Architecture delta cost

This is the hardware added or removed when one architecture is revised into
another.

Examples:

- adding a second CAN-connected actuator path
- adding a second telemetry ingress
- adding a companion isolation processor
- removing a companion path entirely

This should be compared against a baseline architecture using explicit
structural delta analysis.

### 3. Security overhead

This is the overhead added by DSE-selected protections and governance.

Current `DSE_Core` ledgers:

- Phase 1 resource totals:
  - `Phase1Result.total_luts`
  - `Phase1Result.total_ffs`
  - `Phase1Result.total_dsps`
  - `Phase1Result.total_lutram`
  - `Phase1Result.total_bram`
  - `Phase1Result.total_power`
- Phase 2 abstract placement cost:
  - `Phase2Result.total_cost`

Important:

- Phase 1 totals are security/realtime-detection overhead only
- Phase 2 `total_cost` is an abstract ZTA placement cost, not a LUT/FF total

## Current Implementation Status

The current code now supports:

- explicit `Phase1Result.security_overhead_summary()`
- explicit `Phase2Result.zta_overhead_cost()`
- structural baseline-vs-candidate comparison through
  `dse_tool.core.architecture_delta.compare_network_models()`
- report generation through
  `dse_tool.core.architecture_comparison_report`

The Phase 2 ZTA encoding also now allows `1..N` policy servers to be placed
when a model exposes multiple candidate PS nodes. This expands the search
space without forcing multi-PS placement; the optimizer may still choose a
single PS if that remains the best solution under the current cost and
resilience objectives.

## Recommended Comparison Workflow

For any revised architecture:

1. Compare the revised architecture to the baseline architecture structurally.
2. Record the architecture delta separately from security overhead.
3. Run baseline Phase 2/3 analysis on the raw architecture.
4. Run full Phase 1 -> Phase 2 -> Phase 3 analysis on the protected design.
5. Report:
   - architecture delta
   - Phase 1 security overhead
   - Phase 2 ZTA cost
   - resilience/security outcome delta

## Interpretation Rule

When comparing multiple strategies on the same architecture:

- use Phase 1 totals as the main resource-overhead comparison

When comparing different architectures:

- do not use Phase 1 totals alone
- report architecture delta and security overhead separately

## Pixhawk 6X Guidance

For Pixhawk 6X specifically:

- the board/platform model should be treated as fixed architecture
- the UAV overlay is a chosen system architecture
- any revised UAV architecture should be compared to that overlay using:
  - structural architecture delta
  - Phase 1 security overhead
  - Phase 2 ZTA cost
  - Phase 3 resilience results
