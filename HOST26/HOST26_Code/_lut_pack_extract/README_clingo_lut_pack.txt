# Clingo LUT + Interpolation Pack

This ZIP contains the files needed to use the natural-log lookup table and
integer-only interpolation inside Clingo for values `x` in `[1, 10^9]`.

## Files

- `clingo_ln_lookup_table_1_to_1e9.lp`
  - Lookup table facts:
    - `ln_lut(Exp10, MantissaScaled, LnScaled).`
  - Uses:
    - `x = MantissaScaled * 10^Exp10 / 1000`
    - `LnScaled = round(ln(x) * 1_000_000)`

- `clingo_ln_interp_rules_1_to_1e9.lp`
  - Integer-only linear interpolation rules.
  - Input:
    - `ln_query(Id, X).`
  - Output:
    - `ln_interp(Id, LnScaled).`

- `tc9_lut_adapter_example.lp`
  - Example adapter showing how to connect dynamic scaled probabilities
    into the LUT/interpolation layer and aggregate with sum-of-logs.

- `tc9_python_finish_example.py`
  - Optional Python-side post-processing example for exact/high-precision
    reconstruction of products from emitted member probabilities.

## Basic usage

Include the LUT and interpolation rules:

```prolog
#include "clingo_ln_lookup_table_1_to_1e9.lp".
#include "clingo_ln_interp_rules_1_to_1e9.lp".
```

Ask for log values for dynamic integer inputs:

```prolog
ln_query(p1, 875000).
ln_query(p2, 920000).
```

Then use:

```prolog
ln_interp(p1, Ln1).
ln_interp(p2, Ln2).
```

## Important scaling note

For probability-like values in `(0, 1]`, use a fixed integer scale such as:

- `PROB_SCALE = 1_000_000`

Example:
- `0.875 -> 875000`
- `0.001 -> 1000`

Zero is not valid because `ln(0)` is undefined. Handle zero as a special case in
your encoding.

## Recommended TC9 pattern

For testCase9-style redundancy/group calculations:

1. Keep Clingo responsible for:
   - structure
   - membership
   - dynamic scaled probability values
   - log interpolation
   - sum-of-logs aggregation and ranking

2. Keep Python responsible for:
   - exact product reconstruction
   - final human-readable probabilities
   - report tables

This avoids:
- repeated truncation from repeated product/divide updates
- large intermediate integer products inside Clingo
