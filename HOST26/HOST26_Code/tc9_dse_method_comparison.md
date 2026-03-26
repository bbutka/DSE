# tc9 Design Space Exploration Method Comparison

This note maps the current `testCase9` exploration pipeline onto three candidate methods for future path-aware exploration:

1. Clingo + Python hybrid
2. CP-SAT
3. MILP

The goal is to optimize both:

- architecture/security-feature choices
- known communication paths such as:
  - `c1 -> bus -> c2 -> peripheral`
  - `c1 -> bus1 -> inter_bus_security -> bus2 -> c2`

while keeping path-risk math numerically stable.

## 1. Current tc9 Pipeline

The current implementation is in [runClingo_tc9.py](D:/DSE/DesignSpaceExplorationforSecurity-main/DesignSpaceExplorationforSecurity-main/HOST26/HOST26_Code/runClingo_tc9.py).

### Phase 1

Files:

- [testCase9_inst.lp](D:/DSE/DesignSpaceExplorationforSecurity-main/DesignSpaceExplorationforSecurity-main/HOST26/HOST26_Code/testCases/testCase9_inst.lp)
- [security_features_inst.lp](D:/DSE/DesignSpaceExplorationforSecurity-main/DesignSpaceExplorationforSecurity-main/HOST26/HOST26_Code/Clingo/security_features_inst.lp)
- [tgt_system_tc9_inst.lp](D:/DSE/DesignSpaceExplorationforSecurity-main/DesignSpaceExplorationforSecurity-main/HOST26/HOST26_Code/Clingo/tgt_system_tc9_inst.lp)
- [opt_redundancy_enc.lp](D:/DSE/DesignSpaceExplorationforSecurity-main/DesignSpaceExplorationforSecurity-main/HOST26/HOST26_Code/Clingo/opt_redundancy_enc.lp)
- [opt_latency_enc.lp](D:/DSE/DesignSpaceExplorationforSecurity-main/DesignSpaceExplorationforSecurity-main/HOST26/HOST26_Code/Clingo/opt_latency_enc.lp)
- [opt_power_enc.lp](D:/DSE/DesignSpaceExplorationforSecurity-main/DesignSpaceExplorationforSecurity-main/HOST26/HOST26_Code/Clingo/opt_power_enc.lp)
- [opt_resource_enc.lp](D:/DSE/DesignSpaceExplorationforSecurity-main/DesignSpaceExplorationforSecurity-main/HOST26/HOST26_Code/Clingo/opt_resource_enc.lp)
- [bridge_enc.lp](D:/DSE/DesignSpaceExplorationforSecurity-main/DesignSpaceExplorationforSecurity-main/HOST26/HOST26_Code/Clingo/bridge_enc.lp)

Current role:

- choose `selected_security(C, F)`
- choose `selected_logging(C, L)`
- compute per-asset risk
- enforce resource/power limits
- minimize total risk

### Phase 2

Files:

- [zta_policy_enc.lp](D:/DSE/DesignSpaceExplorationforSecurity-main/DesignSpaceExplorationforSecurity-main/HOST26/HOST26_Code/Clingo/zta_policy_enc.lp)

Current role:

- infer reachability
- place firewalls and policy servers
- compute excess privilege and policy tightness
- minimize ZTA cost

### Phase 3

Files:

- [resilience_tc9_enc.lp](D:/DSE/DesignSpaceExplorationforSecurity-main/DesignSpaceExplorationforSecurity-main/HOST26/HOST26_Code/Clingo/resilience_tc9_enc.lp)

Current role:

- scenario analysis after architecture/policy selection

## 2. New Requirement: Known Communication Paths

You want exploration to account for specific communication paths, not only node-local asset risk.

Example path facts:

```text
flow(f1).
path_hop(f1,1,c1).
path_hop(f1,2,bus1).
path_hop(f1,3,c2).
path_hop(f1,4,peripheral0).

flow(f2).
path_hop(f2,1,c1).
path_hop(f2,2,bus1).
path_hop(f2,3,ib_sec0).
path_hop(f2,4,bus2).
path_hop(f2,5,c2).
```

Desired path scoring:

```text
path_score_norm(flow) = Π norm_prob(node)
```

with `norm_prob(node)` depending on the explored architecture and security-feature choices.

That means path scores are dynamic, not fixed constants.

## 3. Method 1: Clingo + Python Hybrid

### Mapping

Keep Clingo responsible for:

- architecture/topology feasibility
- feature selection
- path activation and path membership
- resource/power/cost constraints
- coarse optimization objective

Move Python to:

- exact path-risk computation
- exact normalized-product evaluation
- tie-breaking among equal-cost or equal-risk Clingo solutions
- final report generation

### How it would work

Clingo emits candidate designs with facts such as:

```text
selected_security(c1, mac).
selected_logging(c1, some_logging).
active_path(f1).
path_hop(f1,1,c1).
path_hop(f1,2,bus1).
path_hop(f1,3,c2).
```

Python then computes:

```text
norm_prob(c1)
norm_prob(bus1)
norm_prob(c2)
path_score_norm(f1) = norm_prob(c1) * norm_prob(bus1) * norm_prob(c2)
```

### Strengths

- minimal disruption to the current codebase
- keeps the strong logical/topological modeling already present in Clingo
- avoids overflow-prone long products inside ASP
- easiest migration path from the current tc9 pipeline

### Weaknesses

- exact path-product optimization is not happening fully inside one solver pass
- usually requires frontier enumeration or iterative re-solving
- can become slow if many candidate models must be re-ranked in Python

### Best fit

- best short-term choice
- best if you want to preserve the current ASP model and add path awareness incrementally

## 4. Method 2: CP-SAT

### Mapping

Represent architecture decisions as Boolean/integer variables:

- `x_sec[c,f] = 1` if component `c` uses security feature `f`
- `x_log[c,l] = 1` if component `c` uses logging feature `l`
- `x_fw[n] = 1` if firewall is placed at location `n`
- `x_ps[n] = 1` if policy server is placed at location `n`
- `x_path[f,h,n] = 1` if hop `h` of flow `f` uses node `n`

Resource constraints become linear sums:

```text
sum x_sec[c,f] * lut_cost(c,f) <= LUT_budget
```

Path risk should not be modeled as a raw product in CP-SAT. Instead use a surrogate:

```text
path_weight(flow) = sum weight(node)
weight(node) ≈ round(K * -log(norm_prob(node)))
```

Then minimize:

```text
alpha * architecture_cost + beta * total_path_weight + gamma * residual_asset_risk
```

### Strengths

- very strong for discrete design-space search
- better than ASP when optimization becomes the dominant problem
- natural for activation, assignment, routing, and resource constraints
- easier to scale than product arithmetic inside Clingo

### Weaknesses

- less natural than ASP for recursive logical relations and derived policies
- exact multiplicative path probability still needs approximation or post-processing
- migration cost is higher than the hybrid option

### Best fit

- best medium-term choice if path-aware optimization becomes central
- especially good if the exploration problem is mostly discrete and budget-constrained

## 5. Method 3: MILP

### Mapping

Use binary decision variables similar to CP-SAT:

- feature selection
- topology/path activation
- firewall and policy-server placement

Use linear constraints for:

- one-of feature choices
- resource budgets
- path connectivity
- policy placement constraints

Use additive transformed path cost:

```text
node_cost(node) = round(K * -log(norm_prob(node)))
path_cost(flow) = sum node_cost(node) over selected hops
```

Then solve:

```text
minimize architecture_cost + path_cost + penalties
```

### Strengths

- exact mature optimization ecosystem
- strong support for multi-objective or lexicographic optimization
- good if most of the problem can be made linear

### Weaknesses

- pure logical relations and recursive graph-style policy reasoning are awkward
- exact raw products are still not solver-friendly
- may require many reformulations of the current ASP rules

### Best fit

- best if you want a more classical optimization formulation with strong numeric control
- best if path-aware optimization is expressed as additive weights, not direct products

## 6. Can Any Method Optimize the Raw Product Directly?

In principle yes, but it is usually the wrong engineering choice.

Raw path product:

```text
path_score_norm(flow) = Π norm_prob(node)
```

Problems:

- products grow or shrink quickly with path length
- solver arithmetic becomes numerically fragile
- exact dynamic products are difficult inside discrete optimizers

Better alternatives:

1. optimize additive transformed cost in the solver
2. compute exact product afterward in Python for the chosen candidates

## 7. Recommended Architecture for This Project

### Recommendation

Use a `Clingo + Python hybrid` now, and keep `CP-SAT` as the likely next step if path-aware exploration becomes the dominant task.

### Why

The current project already has:

- strong ASP encodings for topology and policy
- three existing tc9 phases
- Python orchestration already in place

That makes the hybrid approach the lowest-risk upgrade path.

### Proposed redesign

Inside Clingo:

- decide architecture/security/logging/path activation
- emit active path structure
- optimize a stable surrogate objective for path exposure

Inside Python:

- compute exact normalized per-node probabilities
- compute exact normalized path products
- compare equal-cost/equal-surrogate candidates
- generate final reports

## 8. Concrete Recommendation by Horizon

### Short term

Add path facts and path activation to the current Clingo model, and use Python to compute exact path products for selected candidates.

### Medium term

If the number of known flows and path alternatives grows, move the architecture/path optimizer to CP-SAT.

### Long term

If you want unified exact optimization over many numeric objectives, build a dedicated MILP or CP-SAT formulation and keep Python for exact reporting only.

## 9. Final Recommendation

Best fit for the current repository:

1. `Clingo + Python hybrid` now
2. `CP-SAT` if path-aware exploration becomes the main optimization driver
3. `MILP` only if you are willing to rewrite the model around additive linearized costs

If path risk must stay as a normalized product, the most practical implementation is:

- dynamic topology and decision logic in Clingo
- exact product evaluation in Python
- optional additive surrogate inside the solver for scalable search
