# MiniZinc Mapping for HOST26 tc9

This folder contains a first MiniZinc port of the current `HOST26` tc9 **Phase 1** model.

## Scope

This mapping covers:

- security feature selection per component
- logging feature selection per component
- latency constraints
- resource and power budget constraints
- generic redundancy probability recursion from `opt_redundancy_generic_enc.lp`
- the current Phase 1 optimization objective

It does **not** yet cover:

- Phase 2 ZTA policy synthesis
- joint runtime monitor placement
- runtime anomaly scoring
- Phase 3 resilience scenario analysis

## Files

- `tc9_phase1.mzn`
  MiniZinc model for current tc9 Phase 1
- `../export_tc9_phase1_minizinc.py`
  Generates `tc9_phase1.dzn` from the LP facts already in this repository
- `../run_tc9_minizinc_phase1.py`
  Convenience runner that writes the `.dzn` and runs MiniZinc if the CLI is installed

## What is mapped faithfully

The model follows the **current** ASP behavior rather than an idealized cleanup.

That means it intentionally preserves:

- the current Phase 1 objective: minimize the sum of `new_risk(read) + new_risk(write)`
- the current recursive normalized redundancy product used in `opt_redundancy_generic_enc.lp`
- the current resource-base accounting quirks from `opt_resource_enc.lp`
- the current power-base accounting style from `opt_power_enc.lp`

This makes the MiniZinc model suitable for comparison against the current code path before changing the mathematics or the objective.

## How to run

Once MiniZinc is installed:

```powershell
py -3.12 ..\run_tc9_minizinc_phase1.py
```

or directly:

```powershell
py -3.12 ..\export_tc9_phase1_minizinc.py
minizinc tc9_phase1.mzn tc9_phase1.dzn
```

## Recommended next steps

1. Confirm that the MiniZinc Phase 1 result matches the current Clingo Phase 1 result.
2. Decide whether to preserve or fix the current objective mismatch between:
   - solver objective = sum of action risks
   - report total = sum of max read/write per asset
3. Add a second MiniZinc variant that uses:
   - exact Python-generated path or redundancy tables
   - or cleaner additive transformed costs
4. Only after Phase 1 is stable, map Phase 2 policy synthesis.
