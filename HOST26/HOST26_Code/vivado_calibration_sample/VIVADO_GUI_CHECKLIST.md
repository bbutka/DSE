# Vivado GUI Calibration Checklist

This folder gives you a minimal calibration starter for the workflow:

- baseline shell only
- shell plus one feature block
- compare post-implementation reports

The sample files are:

- `feature_shell_baseline.v`
- `feature_mac_like.v`
- `feature_shell_with_mac_like.v`
- `sample_ooc.xdc`

The `feature_mac_like` block is only a placeholder so you can verify the
process. To calibrate a real item, replace `feature_mac_like` with the real
feature RTL and keep the same shell-vs-shell-plus-feature workflow.

## 1. Create a Vivado project

1. In Vivado GUI, create a new RTL project.
2. Set the target part to `xc7z020clg400-1` for PYNQ-Z2.
3. Add these files from this folder.
4. Add `sample_ooc.xdc` as a constraint file.

## 2. Run the baseline build

1. In **Sources**, set top to `feature_shell_baseline`.
2. Run **Synthesis**.
3. Open **Synthesized Design** and save:
   - Utilization report
   - Timing summary
4. Run **Implementation**.
5. Open **Implemented Design** and save:
   - Utilization report
   - Timing summary
   - Power report

Recommended report names:

- `baseline_util_post_route.rpt`
- `baseline_timing_post_route.rpt`
- `baseline_power_post_route.rpt`

## 3. Run the feature build

1. Change top to `feature_shell_with_mac_like`.
2. Re-run **Synthesis** and **Implementation**.
3. Save the same three reports.

Recommended report names:

- `mac_like_util_post_route.rpt`
- `mac_like_timing_post_route.rpt`
- `mac_like_power_post_route.rpt`

## 4. Compute the calibrated cost

Use post-route values and subtract baseline:

```text
feature_cost = (shell + feature) - shell
```

Record:

- LUT
- FF
- DSP
- BRAM
- WNS / timing
- estimated power

## 5. Map the result into the ASP model

If the feature is instantiated once per protected item, update:

- `byAsset`

If the feature is instantiated once per component, update:

- `byComponent`

If the feature is shared globally, update:

- `base`

The target file in this repo is:

- `Clingo/security_features_inst.lp`

## 6. Recommended first real measurements

Measure these separately:

- `mac`
- `dynamic_mac`
- `zero_trust`
- `some_logging`
- `zero_trust_logger`

For each one, keep:

- report filenames
- Vivado version
- part
- clock period
- whether the number is measured or estimated

## 7. Important note

This sample is for process validation only. The `feature_mac_like` module is
not your production MAC implementation. Once the GUI flow works, replace it
with the real RTL block you want to calibrate.
