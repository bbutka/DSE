# Runtime-Adaptive Architecture — HOST26 tc9

This document explains the extended HOST26 architecture after adding runtime
monitor placement, anomaly scoring, trust-state updates, and adaptive policy
response on top of the original LUT-based Zero Trust design-space exploration
pipeline.

It is the companion to the original high-level architecture description, but it
focuses on the current implementation in this folder:

- `runClingo_tc9.py`
- `runClingo_tc9_runtime.py`
- `runClingo_tc9_runtime_joint.py`
- `Clingo/opt_redundancy_generic_enc.lp`
- `Clingo/zta_policy_enc.lp`
- `Clingo/resilience_tc9_enc.lp`
- `Clingo/runtime_monitor_tc9_inst.lp`
- `Clingo/runtime_adaptive_tc9_enc.lp`
- `Clingo/zta_policy_runtime_enc.lp`

---

## 1. What Changed

The original HOST26 pipeline was strong at:

- design-time security feature allocation
- design-time zero-trust policy synthesis
- offline scenario-based resilience analysis

The new architecture adds a fourth capability:

- runtime observability and adaptive response

This changes the tool from:

`feature allocation + policy synthesis + what-if scenario analysis`

into:

`feature allocation + policy synthesis + monitor co-placement + runtime trust/adaptation analysis`

The extension is still model-driven and ASP-based. It does not simulate live
traffic in real time, but it now explicitly models:

- where monitors are placed
- what they can observe
- how anomaly evidence becomes trust degradation
- how trust degradation triggers automatic mode transitions
- how mode transitions change the effective access policy

---

## 2. New Architectural View

The current HOST26 design should be understood as five connected layers:

1. Phase 1 security design-space exploration
2. Phase 2 zero-trust control-plane synthesis
3. Joint runtime observability synthesis
4. Runtime trust and response logic
5. Scenario-based resilience evaluation

At a system level, the data/control flow is:

```text
testCase9 instance facts
    ->
Phase 1: select security/logging features with LUT-based redundancy math
    ->
Phase 2: place firewalls and policy servers
    ->
Joint runtime synthesis: place monitors and optimize response readiness
    ->
Runtime detection model: score anomalies, update trust, switch modes
    ->
Adaptive policy output + scenario-based resilience analysis
```

---

## 3. Core Problem Solved by the New Architecture

The original three-phase pipeline answers:

- which security features should be deployed
- where should PEPs and PSes be placed
- what happens if a node or control-plane element is compromised or fails

The new runtime-adaptive architecture adds a fourth question:

- if suspicious behavior is observed at runtime, how quickly can the system
  detect it, degrade trust, transition policy mode, and restrict exposure

This is the key conceptual extension. The system now reasons not only about:

- static architecture risk
- static least-privilege gaps
- hypothetical compromise scenarios

but also about:

- runtime observability
- detector placement
- evidence-driven trust degradation
- automatic transition into `attack_suspected` or `attack_confirmed`

---

## 4. End-to-End Pipeline

## 4.1 Phase 1 — Security DSE

Files:

- `runClingo_tc9.py`
- `Clingo/opt_redundancy_generic_enc.lp`
- `Clingo/opt_latency_enc.lp`
- `Clingo/opt_power_enc.lp`
- `Clingo/opt_resource_enc.lp`
- `Clingo/bridge_enc.lp`

Purpose:

- choose one security feature and one logging feature per component
- enforce latency and hardware constraints
- compute base per-asset risk
- use a lookup-table replacement for the size-5 redundancy multiplication

Important implementation detail:

- Phase 1 now uses `opt_redundancy_generic_enc.lp`
- the original overflow-prone size-5 probability product is replaced with the
  exact precomputed LUT in `tc9_combined_prob_norm_size5_lut.lp`

Outputs:

- `selected_security(component, feature)`
- `selected_logging(component, feature)`
- `new_risk(component, asset, op, risk)`
- total LUT/FF/DSP/LUTRAM/BRAM/power usage
- Phase 1 summary facts injected downstream as:
  - `p1_security(...)`
  - `p1_logging(...)`
  - `p1_risk(asset, max_risk)`

Current tc9 baseline result:

- `c1..c7` mostly use `zero_trust`
- `c8` uses `mac + no_logging` due to tight latency
- total base risk = `520`

---

## 4.2 Phase 2 — Zero-Trust Policy Synthesis

Files:

- `Clingo/zta_policy_enc.lp`
- `runClingo_tc9.py`

Purpose:

- place policy enforcement points (PEPs)
- place policy servers (PSes)
- derive access policy from topology and access needs
- identify excess privilege and missing privilege
- compute trust-anchor findings
- derive mode-aware allow/deny behavior

Key model concepts:

- `place_fw(FW)`
- `place_ps(PS)`
- `protected(master, ip)`
- `governs_ip(ps, ip)`
- `policy_tightness(master, score)`
- `excess_privilege(master, component, op)`
- `trust_gap_*`
- `final_allow(...)`, `final_deny(...)`

Current tc9 baseline Phase 2 result in the main runner:

- firewalls:
  - `pep_group`
  - `pep_standalone`
- policy server:
  - `ps0`
- cost:
  - `450`

In the joint runtime-aware synthesis path, Phase 2 may keep `ps1` as well if
doing so improves runtime response readiness.

---

## 4.3 Runtime Observability Layer

Files:

- `Clingo/runtime_monitor_tc9_inst.lp`
- `Clingo/runtime_adaptive_tc9_enc.lp`
- `tc9_runtime_adaptive.py`

Purpose:

- model candidate runtime monitors
- model their cost, coverage, detection strength, latency, and false-positive cost
- compute which architectural elements are observable

Candidate monitors currently modeled:

- `mon_noc0`
- `mon_noc1`
- `mon_ctrl`
- `mon_c8`

These are abstract monitor placements, not HDL implementations. They represent
the existence of runtime observability at key parts of the architecture:

- bus-level observability for `noc0`
- bus-level observability for `noc1`
- control-plane observability for `ps0/ps1/PEPs`
- dedicated observability for `c8`

For each monitor, the model defines:

- placement cost
- detection strength
- detection latency
- false-positive handling cost
- coverage relation to masters, receivers, PEPs, and PSes

Examples:

- `mon_ctrl` covers:
  - `ps0`
  - `ps1`
  - `pep_group`
  - `pep_standalone`
- `mon_c8` covers:
  - `c8`

This is the first explicit runtime observability layer in the architecture.

---

## 4.4 Observability Scoring

The new runtime model combines two sources of visibility:

1. monitor coverage
2. logging choice from Phase 1

The logic is:

```text
observability_score(node) =
    monitor_visibility(node) + logging_visibility(node)
```

For receivers:

- `no_logging` contributes `0`
- `some_logging` contributes `6`
- `zero_trust_logger` contributes `15`

For control-plane elements and masters:

- logging contribution is `0`
- only monitor coverage matters

This means runtime visibility is no longer implicit. It is now an explicit
architectural quantity derived from:

- design-time logging selection
- monitor placement decisions

That is a major architectural difference from the older model.

---

## 4.5 Runtime Evidence and Anomaly Scoring

The new architecture introduces explicit anomaly evidence:

```text
observed(node, signal_kind, severity)
```

Current supported signal kinds:

- `rate_spike`
- `cross_domain`
- `privilege_creep`
- `sequence_violation`
- `policy_violation`
- `bypass_alert`
- `attestation_mismatch`

Each signal kind has a weight defined in `runtime_monitor_tc9_inst.lp`.

Example concept:

```text
alert_score(node) =
    sum(severity * signal_weight(signal_kind))
```

The architecture also keeps static security priors:

- unattested masters incur a trust penalty
- unsigned policy servers incur a trust penalty
- receivers lacking hardware root of trust, secure boot, or key storage
  incur trust penalties

The total anomaly score becomes:

```text
anomaly_score(node) =
    base_score(node) + alert_score(node) + observability_score(node)
```

This is the bridge between:

- static design-time trust posture
- runtime evidence of suspicious behavior

---

## 4.6 Dynamic Trust-State Model

The runtime extension adds explicit trust states:

- `high`
- `medium`
- `low`
- `compromised`

Current thresholds:

- `high`: score < 40
- `medium`: 40–69
- `low`: 70–99
- `compromised`: 100+

This is the first time trust becomes dynamic in the architecture.

In the original pipeline:

- trust was largely static
- domains and attestation status were fixed

In the new pipeline:

- trust can change at runtime based on anomaly evidence

That means a master or control-plane element can be:

- structurally trusted at design time
- but downgraded at runtime because of observed behavior

---

## 4.7 Automatic Mode Transition

The original policy model defined three modes:

- `normal`
- `attack_suspected`
- `attack_confirmed`

But those modes were effectively static policy states.

The new architecture adds explicit mode-selection logic:

```text
current_mode = normal | attack_suspected | attack_confirmed
```

Current behavior:

- `attack_confirmed` if any node becomes `compromised`
- `attack_confirmed` if a safety-critical node becomes `low`
- `attack_confirmed` if a deployed policy server becomes `low`
- `attack_suspected` if some node reaches `medium` or `low`
  and the stronger conditions do not hold

This creates the closed loop that was missing before:

```text
observed signals
    ->
anomaly score
    ->
trust degradation
    ->
mode transition
    ->
adaptive deny / response actions
```

---

## 4.8 Adaptive Response Layer

The runtime architecture adds response actions:

- `re_attest(master)`
- `quarantine(node)`
- `lockdown_pep(pep)`
- `force_signed_policy(ps)`

These are not yet full operational procedures, but they are the first explicit
response-orchestration objects in the model.

Examples:

- suspicious DMA behavior:
  - trigger `re_attest(dma)`
  - deny DMA access to critical receivers under `attack_suspected`
- suspicious `c8` behavior:
  - trigger `quarantine(c8)`
  - transition to `attack_confirmed`
  - lock down both PEPs
- suspicious `ps0` behavior:
  - lock down both deployed PEPs
  - force `attack_confirmed`

The adaptive allow/deny layer is currently separate from the original
`final_allow/final_deny` synthesis. It represents runtime restriction under
degraded trust rather than static topology-derived policy.

---

## 5. Joint Runtime-Aware Policy Synthesis

Files:

- `Clingo/zta_policy_runtime_enc.lp`
- `tc9_runtime_joint.py`
- `runClingo_tc9_runtime_joint.py`

This is the most important architectural addition.

Instead of treating runtime monitoring as a post-processing layer, the new
joint synthesis path optimizes:

- firewall placement
- policy-server placement
- monitor placement
- response readiness
- detection strength
- detection latency
- false-positive burden

all in the same Phase 2 solve.

The new joint objective gives priority to:

1. higher response readiness
2. higher detection strength
3. lower weighted detection latency
4. lower false-positive cost
5. lower monitor cost

This means the architecture can now explicitly trade:

- cheaper control plane

against

- better runtime detectability and response coverage

This is why the joint synthesis result can keep `ps1` even though the
baseline Phase 2 solver drops it:

- `ps1` improves control-plane observability and response readiness
- the runtime-aware objective values that extra resilience

Current tc9 joint synthesis result:

- PEPs:
  - `pep_group`
  - `pep_standalone`
- PSes:
  - `ps0`
  - `ps1`
- monitors:
  - `mon_c8`
  - `mon_ctrl`
  - `mon_noc0`
  - `mon_noc1`
- ZTA cost:
  - `630`
- monitor cost:
  - `380`
- joint cost:
  - `1010`
- response-readiness score:
  - `300`
- detection-strength score:
  - `4340`
- weighted detection latency:
  - `905`
- false-positive cost:
  - `52`

---

## 6. Runtime Scenarios

Files:

- `tc9_runtime_adaptive.py`
- `runClingo_tc9_runtime.py`
- `runClingo_tc9_runtime_joint.py`

The current runtime layer evaluates explicit anomaly scenarios:

- `baseline`
- `dma_rate_spike`
- `dma_privilege_creep`
- `c8_sequence_anomaly`
- `ps0_policy_tamper`

These scenarios are not the same as the Phase 3 compromise/failure scenarios.

Phase 3 still answers:

- what if this node is compromised or failed

The runtime scenarios answer:

- what if monitors observe behavior that suggests suspicious activity

That is a different architectural concern.

Current behavior:

- `baseline`
  - remains `normal`
- `dma_rate_spike`
  - enters `attack_suspected`
  - triggers `re_attest(dma)`
- `dma_privilege_creep`
  - enters `attack_suspected`
  - keeps DMA constrained
- `c8_sequence_anomaly`
  - enters `attack_confirmed`
  - quarantines `c8`
  - locks down PEPs
- `ps0_policy_tamper`
  - enters `attack_confirmed`
  - locks down both PEPs

This is the first explicit adaptive-response architecture in the HOST26 code.

---

## 7. How the New Pieces Connect

The new architecture can be understood as two tracks:

### Track A — design-time baseline

```text
Phase 1: choose security/logging
    ->
Phase 2: place PEPs / PSes
    ->
Phase 3: enumerate compromise/failure resilience scenarios
```

### Track B — runtime-adaptive extension

```text
Phase 1 facts
    +
Phase 2 placement facts
    +
runtime monitor placement
    +
runtime observations
    ->
anomaly score
    ->
trust state
    ->
mode transition
    ->
adaptive deny / response action
```

### Joint track — runtime-aware co-optimization

```text
Phase 1 facts
    ->
Joint Phase 2:
    PEP placement
    +
    PS placement
    +
    monitor placement
    +
    readiness / latency / false-positive objective
    ->
runtime-adaptive scenario evaluation
```

This joint track is the most complete representation of the new architecture.

---

## 8. File Reference

## 8.1 Original pipeline files

| File | Role |
|---|---|
| `runClingo_tc9.py` | Main three-phase runner |
| `Clingo/opt_redundancy_generic_enc.lp` | Generic Phase 1 redundancy risk model (any group size, no LUT) |
| `Clingo/zta_policy_enc.lp` | Original Phase 2 ZTA policy synthesis |
| `Clingo/resilience_tc9_enc.lp` | Phase 3 resilience analysis |

## 8.2 Runtime-adaptive extension

| File | Role |
|---|---|
| `Clingo/runtime_monitor_tc9_inst.lp` | Monitor definitions, costs, strengths, latencies, false-positive costs |
| `Clingo/runtime_adaptive_tc9_enc.lp` | Runtime observability, anomaly scoring, trust update, mode transition, response actions |
| `tc9_runtime_adaptive.py` | Python wrapper for runtime scenarios |
| `runClingo_tc9_runtime.py` | Standalone runtime-adaptive summary runner |
| `test_tc9_runtime_adaptive.py` | Focused runtime-adaptive tests |

## 8.3 Joint policy-runtime synthesis

| File | Role |
|---|---|
| `Clingo/zta_policy_runtime_enc.lp` | Joint Phase 2 policy + monitor placement synthesis |
| `tc9_runtime_joint.py` | Python orchestration for joint synthesis plus runtime scenarios |
| `runClingo_tc9_runtime_joint.py` | Joint architecture summary runner |
| `test_tc9_runtime_joint.py` | Tests for runtime-aware Phase 2 |

---

## 9. Strengths of the New Architecture

Compared with the original architecture, the current model now explicitly covers:

- runtime monitor placement
- runtime observability as an optimization concern
- anomaly evidence and signal weighting
- dynamic trust-state degradation
- automatic transition into `attack_suspected` / `attack_confirmed`
- adaptive response actions
- joint optimization of policy placement and runtime detection readiness
- explicit detection latency and false-positive burden in the synthesis objective

This is a significant improvement over the earlier design, which had:

- logging features
- mode-aware policies
- offline resilience scenarios

but no formal closed-loop detection-and-response mechanism.

---

## 10. What Is Still Missing

Even with the runtime extension, the architecture is still an abstraction.
Important missing pieces remain:

1. real detector RTL implementations for each monitor type
2. calibrated latency and false-positive data from Vivado or hardware
3. detector false negatives / missed detection probability
4. dwell time and response time in actual wall-clock terms
5. recovery / reinstatement workflows after isolation
6. operator / analyst workflow
7. tighter integration between adaptive deny logic and the original synthesized ACLs
8. real path-aware runtime observability for specific communication flows

So this architecture should currently be described as:

`runtime-aware co-optimization with abstract detection-and-response models`

not yet:

`fully calibrated real-time anomaly-detection deployment synthesis`

---

## 11. Recommended Next Steps

The next technical improvements should be:

1. calibrate monitor cost, latency, and power using Vivado builds
2. calibrate false-positive penalties from a detector design assumption
3. add false-negative / detection-coverage modeling
4. tie adaptive deny actions back into the Phase 2 ACL model
5. add time-aware containment metrics to Phase 3
6. add communication-path-aware runtime monitoring

If those steps are completed, the architecture will move from a strong
research prototype toward a substantially more defensible co-designed
runtime ZTA exploration framework.
