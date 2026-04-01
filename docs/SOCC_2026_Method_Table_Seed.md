# SOCC 2026 Method Table Seed

## Strategy Objectives

| Strategy | Objective Behavior | Source |
|---|---|---|
| `max_security` | uses the default risk-minimizing objective from the ASP encodings | `dse_tool/agents/phase1_agent.py` |
| `min_resources` | adds a secondary LUT minimization objective | `dse_tool/agents/phase1_agent.py` |
| `balanced` | minimizes total risk and then LUTs with explicit strategy-specific objective atoms | `dse_tool/agents/phase1_agent.py` |

## Hard Constraints

| Constraint Type | Enforced In |
|---|---|
| one security feature per component | `init_enc.lp` / phase 1 |
| one logging feature per component | `init_enc.lp` / phase 1 |
| LUT budget | `opt_resource_enc.lp` |
| FF / DSP / LUTRAM / BRAM budget | `opt_resource_enc.lp` |
| power budget | `opt_power_enc.lp` |
| latency cap | `opt_latency_enc.lp` + `bridge_enc.lp` |
| protection mediation / reachability constraints | `zta_policy_enc.lp` |

## Paper Action

Convert this seed into one compact table in the manuscript so the optimization problem is explicit instead of implied.
