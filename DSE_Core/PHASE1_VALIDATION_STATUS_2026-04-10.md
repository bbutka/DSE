# Phase 1 Validation Status

Date: 2026-04-10

## Scope

This note records the Phase 1 model cleanup, backend changes, ASP comparison-path work, and current validation status in `DSE_Core`.

The work covered four areas:

1. Remove the legacy additive Phase 1 risk model from the active top-level ASP path.
2. Align reporting and runtime wording with the weighted Phase 1 objective actually optimized by the solver.
3. Make ASP an explicit comparison backend, not a hidden fallback behind CP-SAT.
4. Make redundant-group ASP comparisons practical by preprocessing the Phase 1 search space in Python before Clingo sees it.

## Risk Model Changes

The active Phase 1 formulation now uses the multiplicative model consistently:

`Risk = Impact * Exposure * Realtime * ExploitFactor / 100`

for non-redundant components, and the redundancy-specific probability chain for grouped components:

1. Build the per-component residual score from `Exposure * Realtime`.
2. Normalize to the `[0,1000]` working range.
3. Multiply normalized scores across the group.
4. Denormalize back to the residual-risk score range.
5. Apply optional common-cause beta correction.
6. Convert the corrected group score to availability risk with `Impact * Score * ExploitFactor / 1000`.

The additive model

`Risk = Impact + DomainBonus - SecurityProtection - LogProtection`

is no longer part of the active top-level Phase 1 flow.

## Backend Changes

### 1. CP-SAT remains the primary Phase 1 backend

`orchestrator.py` no longer performs automatic CP-SAT to ASP fallback. ASP is now an explicit backend choice for comparison work only.

### 2. Displayed Phase 1 risk now matches the optimized objective

`Phase1Result.total_risk()` now returns the weighted per-asset-per-action objective value that Phase 1 actually minimizes.

The previous max-per-asset display metric is still available as `summary_total_risk()` for diagnostics and backward-looking comparison.

### 3. Redundancy common-cause correction is supported

`redundancy_beta_pct` is now part of the generated/system caps path and the GUI defaults, and participates in the math backend and ASP model.

### 4. Max-security mathopt is now deterministic on equal-risk ties

`max_security` in the math backend now breaks ties on LUT usage after minimizing weighted risk. This prevents CP-SAT from drifting to a different equal-risk, higher-LUT optimum than the ASP comparison backend.

## ASP Comparison-Path Changes

### 1. Candidate-pair preprocessing

The ASP Phase 1 agent now precomputes feasible security/realtime pairs per component before solving. This mirrors the math backend's early filtering:

- per-action latency filtering
- non-redundant security-risk cap filtering
- pair dominance pruning

Instead of grounding the full feature cartesian product, `init_enc.lp` can now consume:

- `candidate_pair(Component, Pair)`
- `pair_security(Pair, Security)`
- `pair_realtime(Pair, Realtime)`

and derive `selected_security/2` and `selected_realtime/2` from `selected_pair/2`.

### 2. Redundant-group plan preprocessing

Candidate-pair filtering alone was not enough for `tc9`. The remaining bottleneck was the 5-member redundant-group optimization.

The ASP comparison path now precomputes redundant-group plans in Python and emits:

- `group_plan_candidate(Group, Plan)`
- `group_plan_member_pair(Group, Plan, Component, Pair)`
- `group_plan_final_risk(Group, Plan, Component, Asset, Action, Risk)`

ASP then chooses one whole redundant-group plan instead of rebuilding the group probability chain from raw feature choices during solve.

This was the change that made `tc9` practical again under the ASP comparison backend.

### 3. No relaxed-risk fallback inside the ASP agent

The old Phase 1 ASP agent retry path that silently relaxed risk caps after UNSAT was removed. ASP now reports infeasibility directly.

## Validation Coverage

### Backend smoke / parity suite

`tests/test_phase1_backends.py` now covers:

- backend selection behavior
- ASP timeout reuse behavior
- 8 small non-redundant parity cases
- 1 small redundant parity case with a 3-component redundancy group

Latest verified run:

```text
python -m unittest tests.test_phase1_backends -v
Ran 9 tests in 0.059s
OK
```

### Regression checks

`tests/test_regression.py` was updated so the reported Phase 1 objective and the legacy summary metric are both checked explicitly.

### Triple-validation suite

`tests/test_phase1_risk_parity.py` validates Phase 1 with three independent checks:

1. CP-SAT solve
2. CBC solve
3. Pure Python reference checker

The Python checker verifies:

- multiplicative risk arithmetic
- redundancy probability arithmetic
- feature-selection completeness
- resource accounting
- resource caps
- latency caps
- security-risk and availability-risk caps
- cross-solver objective parity

Covered topologies:

- 9 minimal cases
  - 8 non-redundant
  - 1 redundant group of 3
- `tc9`
- reference SoC
- DARPA UAV
- OpenTitan OT-A
- OpenTitan OT-B
- Pixhawk 6X Platform
- Pixhawk 6X UAV
- Pixhawk 6X UAV Dual PS
- Pixhawk 6X Dual PS

Across 3 strategies, this yields 54 parametrized parity tests.

Latest verified run:

```text
python -m pytest tests/test_phase1_risk_parity.py -n 6 -q
54 passed in 128.12s (0:02:08)
```

## Current tc9 Status

### What now matches

For `tc9`, CP-SAT and ASP now match on the key Phase 1 optimization outputs for `max_security`:

- satisfiable result
- weighted Phase 1 objective risk
- selected security features
- per-asset-per-action risk values

The latest direct comparison was:

```text
MATH True 4425 6740
ASP  True 4425 7060
```

### Remaining caveat

The selected realtime feature assignment can still differ inside the redundant group even when:

- total weighted risk is the same
- security selection is the same

In the current `tc9` comparison path, ASP can still pick a higher-LUT equal-risk plan under `max_security`. That means the current comparison backend is objective-parity correct, but not yet fully lexicographically aligned with the math backend on all equal-risk ties.

If exact assignment identity and equal-risk LUT parity become requirements, the next step is to add a final canonical tie-break that both backends share and that does not materially slow Clingo.

## Files Most Affected

- `Clingo/init_enc.lp`
- `Clingo/opt_redundancy_generic_enc.lp`
- `Clingo/security_features_inst.lp`
- `dse_tool/agents/orchestrator.py`
- `dse_tool/agents/phase1_agent.py`
- `dse_tool/agents/ilp_phase1_agent.py`
- `dse_tool/core/solution_parser.py`
- `dse_tool/core/asp_generator.py`
- `ip_catalog/xilinx_ip_catalog.py`
- `tests/test_phase1_backends.py`
- `tests/test_phase1_risk_parity.py`
- `tests/test_regression.py`

## Practical Conclusion

The Phase 1 mathematical model is now validated across independent solvers and a reference checker, the additive risk path has been removed from the active top-level Phase 1 flow, and ASP redundancy comparisons are fast enough to be useful again on `tc9`.

The recommended operational posture remains:

- use CP-SAT as the production Phase 1 backend
- use ASP as an explicit comparison/debug backend
- treat exact redundant-group assignment identity and equal-risk LUT tie alignment as a secondary refinement, not a blocker, because objective-risk parity is already in place
