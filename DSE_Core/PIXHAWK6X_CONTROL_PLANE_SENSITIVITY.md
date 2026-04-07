# Pixhawk 6X Control-Plane Objective Sensitivity

Date: April 7, 2026

This report sweeps the optional Phase 2 `control_plane` objective weights
for both the baseline `Pixhawk 6X UAV` architecture and the revised
`Pixhawk 6X UAV (Dual-PS)` architecture.

Weight grid:

- safety-critical PEP penalty weights: 100, 250, 500, 1000
- governance concentration penalty weights: 100, 250, 400, 1000

Signatures:

- `single_ps_telem_only`: `pep_telem1` + `ps_fmu` only
- `dual_ps_split`: `pep_telem1`, `pep_can1`, `pep_can2`, `pep_px4io` with `ps_fmu` + `ps_io`

## Strategy: `max_security`

### Summary

- baseline signatures: {'fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu': 6, 'single_ps_telem_only': 10}
- revised signatures: {'dual_ps_split': 12, 'single_ps_telem_only': 4}
- lowest safety-critical penalty weight that yields `dual_ps_split`
  in the revised architecture for each concentration weight:
  - concentration `100`: 250
  - concentration `250`: 250
  - concentration `400`: 250
  - concentration `1000`: 250

| Safety Penalty | Concentration Penalty | Baseline Signature | Revised Signature | Baseline Cost | Baseline Penalty | Revised Cost | Revised Penalty |
| ---: | ---: | --- | --- | ---: | ---: | ---: | ---: |
| 100 | 100 | `single_ps_telem_only` | `single_ps_telem_only` | 340 | 300 | 340 | 300 |
| 100 | 250 | `single_ps_telem_only` | `single_ps_telem_only` | 340 | 300 | 340 | 300 |
| 100 | 400 | `single_ps_telem_only` | `single_ps_telem_only` | 340 | 300 | 340 | 300 |
| 100 | 1000 | `single_ps_telem_only` | `single_ps_telem_only` | 340 | 300 | 340 | 300 |
| 250 | 100 | `fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu` | `dual_ps_split` | 740 | 300 | 900 | 0 |
| 250 | 250 | `single_ps_telem_only` | `dual_ps_split` | 340 | 750 | 900 | 0 |
| 250 | 400 | `single_ps_telem_only` | `dual_ps_split` | 340 | 750 | 900 | 0 |
| 250 | 1000 | `single_ps_telem_only` | `dual_ps_split` | 340 | 750 | 900 | 0 |
| 500 | 100 | `fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu` | `dual_ps_split` | 740 | 300 | 900 | 0 |
| 500 | 250 | `fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu` | `dual_ps_split` | 740 | 750 | 900 | 0 |
| 500 | 400 | `single_ps_telem_only` | `dual_ps_split` | 340 | 1500 | 900 | 0 |
| 500 | 1000 | `single_ps_telem_only` | `dual_ps_split` | 340 | 1500 | 900 | 0 |
| 1000 | 100 | `fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu` | `dual_ps_split` | 740 | 300 | 900 | 0 |
| 1000 | 250 | `fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu` | `dual_ps_split` | 740 | 750 | 900 | 0 |
| 1000 | 400 | `fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu` | `dual_ps_split` | 740 | 1200 | 900 | 0 |
| 1000 | 1000 | `single_ps_telem_only` | `dual_ps_split` | 340 | 3000 | 900 | 0 |

## Strategy: `balanced`

### Summary

- baseline signatures: {'fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu': 6, 'single_ps_telem_only': 10}
- revised signatures: {'dual_ps_split': 12, 'single_ps_telem_only': 4}
- lowest safety-critical penalty weight that yields `dual_ps_split`
  in the revised architecture for each concentration weight:
  - concentration `100`: 250
  - concentration `250`: 250
  - concentration `400`: 250
  - concentration `1000`: 250

| Safety Penalty | Concentration Penalty | Baseline Signature | Revised Signature | Baseline Cost | Baseline Penalty | Revised Cost | Revised Penalty |
| ---: | ---: | --- | --- | ---: | ---: | ---: | ---: |
| 100 | 100 | `single_ps_telem_only` | `single_ps_telem_only` | 340 | 300 | 340 | 300 |
| 100 | 250 | `single_ps_telem_only` | `single_ps_telem_only` | 340 | 300 | 340 | 300 |
| 100 | 400 | `single_ps_telem_only` | `single_ps_telem_only` | 340 | 300 | 340 | 300 |
| 100 | 1000 | `single_ps_telem_only` | `single_ps_telem_only` | 340 | 300 | 340 | 300 |
| 250 | 100 | `fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu` | `dual_ps_split` | 740 | 300 | 900 | 0 |
| 250 | 250 | `single_ps_telem_only` | `dual_ps_split` | 340 | 750 | 900 | 0 |
| 250 | 400 | `single_ps_telem_only` | `dual_ps_split` | 340 | 750 | 900 | 0 |
| 250 | 1000 | `single_ps_telem_only` | `dual_ps_split` | 340 | 750 | 900 | 0 |
| 500 | 100 | `fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu` | `dual_ps_split` | 740 | 300 | 900 | 0 |
| 500 | 250 | `fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu` | `dual_ps_split` | 740 | 750 | 900 | 0 |
| 500 | 400 | `single_ps_telem_only` | `dual_ps_split` | 340 | 1500 | 900 | 0 |
| 500 | 1000 | `single_ps_telem_only` | `dual_ps_split` | 340 | 1500 | 900 | 0 |
| 1000 | 100 | `fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu` | `dual_ps_split` | 740 | 300 | 900 | 0 |
| 1000 | 250 | `fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu` | `dual_ps_split` | 740 | 750 | 900 | 0 |
| 1000 | 400 | `fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu` | `dual_ps_split` | 740 | 1200 | 900 | 0 |
| 1000 | 1000 | `single_ps_telem_only` | `dual_ps_split` | 340 | 3000 | 900 | 0 |

## Strategy: `min_resources`

### Summary

- baseline signatures: {'fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu': 6, 'single_ps_telem_only': 10}
- revised signatures: {'dual_ps_split': 12, 'single_ps_telem_only': 4}
- lowest safety-critical penalty weight that yields `dual_ps_split`
  in the revised architecture for each concentration weight:
  - concentration `100`: 250
  - concentration `250`: 250
  - concentration `400`: 250
  - concentration `1000`: 250

| Safety Penalty | Concentration Penalty | Baseline Signature | Revised Signature | Baseline Cost | Baseline Penalty | Revised Cost | Revised Penalty |
| ---: | ---: | --- | --- | ---: | ---: | ---: | ---: |
| 100 | 100 | `single_ps_telem_only` | `single_ps_telem_only` | 340 | 300 | 340 | 300 |
| 100 | 250 | `single_ps_telem_only` | `single_ps_telem_only` | 340 | 300 | 340 | 300 |
| 100 | 400 | `single_ps_telem_only` | `single_ps_telem_only` | 340 | 300 | 340 | 300 |
| 100 | 1000 | `single_ps_telem_only` | `single_ps_telem_only` | 340 | 300 | 340 | 300 |
| 250 | 100 | `fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu` | `dual_ps_split` | 740 | 300 | 900 | 0 |
| 250 | 250 | `single_ps_telem_only` | `dual_ps_split` | 340 | 750 | 900 | 0 |
| 250 | 400 | `single_ps_telem_only` | `dual_ps_split` | 340 | 750 | 900 | 0 |
| 250 | 1000 | `single_ps_telem_only` | `dual_ps_split` | 340 | 750 | 900 | 0 |
| 500 | 100 | `fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu` | `dual_ps_split` | 740 | 300 | 900 | 0 |
| 500 | 250 | `fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu` | `dual_ps_split` | 740 | 750 | 900 | 0 |
| 500 | 400 | `single_ps_telem_only` | `dual_ps_split` | 340 | 1500 | 900 | 0 |
| 500 | 1000 | `single_ps_telem_only` | `dual_ps_split` | 340 | 1500 | 900 | 0 |
| 1000 | 100 | `fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu` | `dual_ps_split` | 740 | 300 | 900 | 0 |
| 1000 | 250 | `fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu` | `dual_ps_split` | 740 | 750 | 900 | 0 |
| 1000 | 400 | `fw=pep_can1,pep_can2,pep_px4io,pep_telem1; ps=ps_fmu` | `dual_ps_split` | 740 | 1200 | 900 | 0 |
| 1000 | 1000 | `single_ps_telem_only` | `dual_ps_split` | 340 | 3000 | 900 | 0 |

## Takeaway

- The qualitative behavior is identical across all three Phase 1
  strategies in this sweep.
- In the sampled grid, the revised architecture selects
  `dual_ps_split` in 12 of 16 weight pairs for every strategy.
- The revised architecture first switches to `dual_ps_split` when the
  safety-critical PEP penalty reaches `250`, and that threshold is
  unchanged across all sampled concentration weights.
- The baseline architecture never produces a split-governance result.
  It either stays at `single_ps_telem_only` or escalates to a
  monolithic single-PS placement with additional safety PEPs.
- This supports the claim that the resilience-aware objective is
  architecture-sensitive rather than hard-forced: once the safety
  penalty is high enough to value those protections, only the revised
  architecture can realize them without governance concentration.
