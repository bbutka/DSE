# TC9 Phase 1 ASP vs CP-SAT Parity Summary

Generated from:
- `tools/local_tc9_asp_artifacts/*.json`
- current `Phase1MathOptAgent` TC9 `max_security` result

## Conclusion

The saved ASP checkpoint sequence reaches the same TC9 Phase 1 risk optimum as CP-SAT:

- Same `total_risk = 106`
- Same per-asset/action risk distribution
- Same max-risk-per-asset distribution

The remaining difference is implementation choice among equal-risk optima:

- ASP did not match CP-SAT on exact security-feature assignment
- ASP did not match CP-SAT on exact realtime-detection assignment
- ASP stayed more resource-expensive than CP-SAT even after improving among equal-risk solutions

So the strongest defensible parity statement is:

`ASP and CP-SAT agree on the TC9 Phase 1 risk optimum, but not on the exact equal-risk implementation selected under the current search/objective behavior.`

Under the completion criterion for this effort, that is sufficient: risk parity
is established, and exact equal-risk implementation parity is out of scope.

## CP-SAT Reference

Strategy: `max_security`

- Total risk: `106`
- Total LUTs: `7260`
- Total power: `148`

Security assignment:

```text
c1 no_security
c2 no_security
c3 no_security
c4 no_security
c5 zero_trust
c6 zero_trust
c7 zero_trust
c8 zero_trust
```

Realtime assignment:

```text
c1 no_realtime
c2 no_realtime
c3 no_realtime
c4 bus_monitor
c5 runtime_attestation
c6 runtime_attestation
c7 runtime_attestation
c8 runtime_attestation
```

## ASP Checkpoint Progression

| Model | Elapsed (s) | Total Risk | LUTs | Power |
|---|---:|---:|---:|---:|
| 1 | 409 | 173 | 8100 | 160 |
| 2 | 415 | 149 | 12980 | 262 |
| 3 | 432 | 143 | 12520 | 253 |
| 4 | 436 | 137 | 12520 | 253 |
| 7 | 437 | 112 | 12620 | 255 |
| 8 | 440 | 111 | 12610 | 254 |
| 9 | 443 | 106 | 12760 | 258 |
| 10 | 1154 | 106 | 10660 | 215 |

## Risk-Matching ASP Checkpoints

Two saved ASP checkpoints matched the CP-SAT risk outcome exactly:

| Checkpoint | Model | Elapsed (s) | Total Risk | LUTs | Power | Same Security | Same Realtime |
|---|---:|---:|---:|---:|---:|---|---|
| `asp_checkpoint_t000443_m0009.json` | 9 | 443 | 106 | 12760 | 258 | no | no |
| `asp_checkpoint_t001154_m0010.json` | 10 | 1154 | 106 | 10660 | 215 | no | no |

## Best Equal-Risk ASP Checkpoint

Best saved ASP equal-risk checkpoint:

- File: `asp_checkpoint_t001154_m0010.json`
- Model index: `10`
- Elapsed: `1154 s`
- Total risk: `106`
- Total LUTs: `10660`
- Total power: `215`

Gap vs CP-SAT:

- LUT gap: `+3400`
- Power gap: `+67`
- Same security assignment: `no`
- Same realtime assignment: `no`

## Interpretation

What the saved checkpoints show:

1. ASP reached the CP-SAT risk optimum by model `9`.
2. ASP later improved LUTs among equal-risk solutions by model `10`.
3. Even its best saved equal-risk checkpoint remained substantially more expensive than the CP-SAT optimum.

This supports the conclusion that the current remaining parity gap is:

- not a disagreement in the Phase 1 risk model
- but a difference in which equal-risk optimum the solver reaches and proves first
