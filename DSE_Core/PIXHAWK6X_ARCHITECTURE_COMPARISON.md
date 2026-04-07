# Pixhawk 6X Baseline vs Revised Architecture Comparison

Date: April 7, 2026

## Compared Architectures

- baseline: `Pixhawk 6X UAV`
- revised: `Pixhawk 6X UAV (Dual-PS)`

## What Was Added

- added component(s): ps_io
- added candidate policy server(s): ps_io
- added link(s): io_mcu->ps_io

## Why It Was Added

- The baseline Pixhawk UAV model has a single control-plane candidate, `ps_fmu`, governing every candidate PEP.
- The revised variant adds `ps_io` so the I/O and actuator protection paths can be governed separately from the FMU-side perimeter.
- This is intended to test whether splitting control-plane authority reduces the single-policy-server concentration identified in the baseline analysis.

## Governance Change

- governance edges added: ps_io->pep_can1, ps_io->pep_can2, ps_io->pep_px4io
- governance edges removed: ps_fmu->pep_can1, ps_fmu->pep_can2, ps_fmu->pep_px4io

## Per-Strategy Results

| Objective | Strategy | Architecture | P1 Risk | P1 LUTs | P1 Power (mW) | Placed FWs | Placed PS | P2 Penalty | Baseline Risk | Worst Scenario | Worst Risk |
| --- | --- | --- | ---: | ---: | ---: | --- | --- | ---: | ---: | --- | ---: |
| `cost_only` | `max_security` | `baseline` | 243 | 25180 | 507 | pep_telem1 | ps_fmu | 0 | 243.0 | rc_receiver_compromise | 346.9 |
| `cost_only` | `max_security` | `revised` | 243 | 25180 | 507 | pep_telem1 | ps_fmu | 0 | 243.0 | rc_receiver_compromise | 346.9 |
| `cost_only` | `balanced` | `baseline` | 243 | 24460 | 493 | pep_telem1 | ps_fmu | 0 | 243.0 | rc_receiver_compromise | 352.0 |
| `cost_only` | `balanced` | `revised` | 243 | 24460 | 493 | pep_telem1 | ps_fmu | 0 | 243.0 | rc_receiver_compromise | 352.0 |
| `cost_only` | `min_resources` | `baseline` | 600 | 17250 | 338 | pep_telem1 | ps_fmu | 0 | 600.0 | telem_radio_compromise | 938.0 |
| `cost_only` | `min_resources` | `revised` | 600 | 17250 | 338 | pep_telem1 | ps_fmu | 0 | 600.0 | telem_radio_compromise | 938.0 |
| `control_plane` | `max_security` | `baseline` | 243 | 25180 | 507 | pep_telem1 | ps_fmu | 750 | 243.0 | rc_receiver_compromise | 346.9 |
| `control_plane` | `max_security` | `revised` | 243 | 25180 | 507 | pep_can1, pep_can2, pep_px4io, pep_telem1 | ps_fmu, ps_io | 0 | 243.0 | rc_receiver_compromise | 346.9 |
| `control_plane` | `balanced` | `baseline` | 243 | 24460 | 493 | pep_telem1 | ps_fmu | 750 | 243.0 | rc_receiver_compromise | 352.0 |
| `control_plane` | `balanced` | `revised` | 243 | 24460 | 493 | pep_can1, pep_can2, pep_px4io, pep_telem1 | ps_fmu, ps_io | 0 | 243.0 | rc_receiver_compromise | 352.0 |
| `control_plane` | `min_resources` | `baseline` | 600 | 17250 | 338 | pep_telem1 | ps_fmu | 750 | 600.0 | telem_radio_compromise | 938.0 |
| `control_plane` | `min_resources` | `revised` | 600 | 17250 | 338 | pep_can1, pep_can2, pep_px4io, pep_telem1 | ps_fmu, ps_io | 0 | 600.0 | telem_radio_compromise | 938.0 |

## Interpretation

- `cost_only` reproduces the original behavior: all three strategies still place only `pep_telem1` and `ps_fmu`.
- `control_plane` adds a resilience-aware Phase 2 penalty for leaving safety-critical PEPs unplaced and for concentrating critical PEP governance under one PS.
- Under `control_plane`, the baseline single-PS architecture still places only `pep_telem1`, but it pays a non-zero Phase 2 penalty because safety-critical paths remain unprotected.
- Under `control_plane`, the revised dual-PS architecture places `pep_px4io`, `pep_can1`, `pep_can2`, and `pep_telem1`, and it activates both `ps_fmu` and `ps_io` with zero Phase 2 penalty.
- This is the desired solver-discovered outcome: the resilience-aware objective makes the dual-PS architecture preferable without hard-forcing the second policy server.
- In the targeted `ps_fmu_compromise` Phase 3 scenario, the revised design keeps one policy server active and leaves only `pep_telem1` ungoverned; `pep_px4io`, `pep_can1`, and `pep_can2` remain governed by `ps_io`.
- The top-level worst-case risk metric does not yet improve, so the current benefit is localized control-plane containment rather than a broad reduction in global scenario risk.

## Control-Plane Objective Detailed Comparison

```text
ARCHITECTURE COMPARISON
Baseline:  Pixhawk 6X UAV
Candidate: Pixhawk 6X UAV (Dual-PS)

Structural Delta
  Added components: ps_io

Baseline Ledgers
  Strategy: max_security
  Phase 1 security overhead: LUTs=25,180, FFs=19,230, Power=507 mW
  Phase 2 ZTA cost: 340
  Scores: security=73.1, resources=52.7, power=96.6, resilience=43.3
  Baseline Phase 3 total risk: 243.0
  Worst scenario: rc_receiver_compromise (risk=346.9)

Candidate Ledgers
  Strategy: max_security
  Phase 1 security overhead: LUTs=25,180, FFs=19,230, Power=507 mW
  Phase 2 ZTA cost: 900
  Scores: security=73.1, resources=52.7, power=96.6, resilience=42.8
  Baseline Phase 3 total risk: 243.0
  Worst scenario: rc_receiver_compromise (risk=346.9)
```
