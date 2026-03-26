# System Architecture — ZTA Design Space Exploration (DSE)

This document describes what the tool does, how it is structured, and how the
pieces connect. It is written for readers who are comfortable with software and
security concepts but have not worked with this codebase before.

---

## 1. What Problem It Solves

Modern embedded systems-on-chip (SoCs) contain many IP cores (processor,
memory, DMA engine, timers, peripherals) connected by shared buses. Each IP
core can be configured with different security controls, and each configuration
trades off security strength against silicon area, power, and access latency.

Choosing the right security configuration by hand across 8+ components, with
interdependencies between latency budgets, resource limits, and threat
scenarios, is intractable. This tool automates that choice.

It answers three questions in sequence:

| Phase | Question |
|---|---|
| 1 — Security DSE | Which security and logging feature should each component use, subject to hardware constraints, to minimise total security risk? |
| 2 — ZTA Policy | Where should firewalls and policy servers be placed? Which accesses are over-privileged? What trust guarantees are missing? |
| 3 — Resilience | If a component is compromised or fails, how does total system risk change? Which services become unavailable? |

---

## 2. Target Hardware — testCase9

The worked example (testCase9) models a **PYNQ-Z2** FPGA development board
with eight IP cores and two interconnect buses.

```
                   ┌────────────────────────────────────────────┐
  sys_cpu ─────────┤                 noc0 (bus)                 ├──► c1, c2, c3, c4, c5
  (processor)      │          (compute group / redundancy)       │    (redundancy group 1)
                   └────────────────────────────────────────────┘

  dma ─────────────┤ noc0 (above, also drives compute group)    │
  (data mover)     └────────────────────────────────────────────┘
                   ┌────────────────────────────────────────────┐
  dma ─────────────┤                 noc1 (bus)                 ├──► c6, c7, c8
                   │          (standalone IPs)                  │    (monitor / log / IO)
                   └────────────────────────────────────────────┘
```

### Components

| ID | Role | Domain | Notes |
|---|---|---|---|
| c1–c5 | Compute cores | high | Redundancy group — 3-of-5 quorum required |
| c6 | Monitor / status store | high | Single point of failure for `monitor_svc` |
| c7 | Log sink | low | Low-value; not critical |
| c8 | Hardware timer / IO | high | Safety-critical; 5-cycle latency budget forces tightest security |

### Bus Masters (initiators)

| ID | Role | Notes |
|---|---|---|
| sys_cpu | Main processor | TPM-attested; drives all compute cores |
| dma | DMA engine | No attestation; highest blast radius (touches all buses) |

### Hardware Constraints (PYNQ-Z2)

| Resource | Limit |
|---|---|
| LUTs | 53 200 |
| Flip-flops | 106 400 |
| DSPs | 220 |
| BRAM | 140 |
| Power | 15 W |
| Max per-asset risk score | 500 |

---

## 3. Security Features Available per Component

The tool chooses one security feature and one logging feature for each
component. Tighter security lowers vulnerability but increases latency and
resource use.

### Security Features

| Feature | Vulnerability score | Latency added | Notes |
|---|---|---|---|
| `mac` | 30 (highest) | 3 cycles | Message Authentication Code only |
| `dynamic_mac` | 20 | 7 cycles | MAC with runtime policy update |
| `zero_trust` | 10 (lowest) | 7 cycles | Per-transaction policy check |

### Logging Features

| Feature | Logging score | Latency added | Notes |
|---|---|---|---|
| `no_logging` | 20 (worst) | 0 cycles | No audit trail |
| `some_logging` | 10 | 4 cycles | Lightweight anomaly log |
| `zero_trust_logger` | 5 (best) | 22 cycles | Full behavioural audit |

### Risk Formula

For a **standalone** component:

```
risk = impact × vulnerability × logging / 10
```

For a component in a **redundancy group** (all members must be compromised for
the group to fail), the combined probability of compromise across all members
is computed via a precomputed lookup table and used in place of the individual
probability. This produces a lower effective risk for groups where individual
members have low vulnerability scores.

---

## 4. Zero Trust Architecture (ZTA) Model

Zero Trust means **no implicit trust based on network location**. Every access
request is verified at a policy enforcement point regardless of whether the
requestor is "inside" the system.

### Key Concepts

**Policy Enforcement Point (PEP)** — A hardware firewall sitting on a bus path.
Every transaction from a master to a protected IP must pass through the PEP
guarding that path. The PEP allows or denies based on current policy.

**Policy Server (PS)** — The component that computes and distributes access
policy to PEPs. If the PS is compromised, the PEPs it controls can be
manipulated. If the PS fails, PEPs continue with their last-known (stale)
policy.

**Trust Domain** — Each node is assigned a trust level (`low` or `high`). A
`low`-domain master (e.g., an unattested DMA engine) accessing a `high`-domain
IP (e.g., a compute core) requires a PEP on the path.

**Operational Mode** — The system operates in one of three modes that tighten
or relax policy:

| Mode | Policy |
|---|---|
| `normal` | Standard access per declared access needs |
| `attack_suspected` | Unattested masters denied access to critical IPs |
| `attack_confirmed` | Only safety-critical operations allowed; c8 fully isolated |

**Attestation** — A cryptographic proof that a component's firmware has not
been tampered with. `sys_cpu` carries a TPM and is attested. `dma` is not.
Components lacking attestation are denied access to critical IPs when the
system is in `attack_suspected` mode.

### Control Plane in testCase9

```
  ps0 (signed policy) ──governs──► pep_group      (guards noc0 → c1-c5)
  ps0                 ──governs──► pep_standalone  (guards noc1 → c6-c8)
  ps1                 ──governs──► pep_group       (backup for compute group)
```

- **ps0** is the primary server. It uses cryptographically signed policy.
- **ps1** is a secondary server covering only the compute group. It does not
  enforce signed policy (identified as a trust gap).
- If ps0 is **compromised**, both PEPs accept attacker-controlled policy —
  the highest-impact single control-plane event.
- If ps0 **fails** (not compromised), ps1 continues to govern `pep_group` and
  both PEPs run on stale-but-legitimate policy — a degraded but not
  compromised state.

---

## 5. The Three-Phase Pipeline

### Phase 1 — Security DSE

**Input:** Component topology, asset impacts, latency budgets, resource limits,
security/logging feature costs.

**What it does:** Searches all combinations of (security feature × logging
feature) for each component simultaneously, enforces all hardware constraints,
and finds the assignment that minimises total risk.

**Output:** For each component — which security feature and logging feature to
use, the resulting per-asset risk score, and total resource utilisation.

**Key constraint example:** c8 has a 5-cycle read latency budget. `zero_trust`
adds 7 cycles, so it is infeasible. The solver is forced to assign `mac` to c8
regardless of its risk penalty.

---

### Phase 2 — ZTA Policy Synthesis

**Input:** The architecture from Phase 1 (injected as facts), plus the ZTA
topology, trust domain assignments, access-need declarations, role definitions,
mission phases, and trust anchor declarations.

**What it does:**

- Determines where firewalls (PEPs) and policy servers (PSes) must be placed
  to enforce the zero-trust requirement that low-domain masters cannot reach
  high-domain IPs without mediation.
- Identifies **excess privilege** — accesses that are topologically possible
  but not declared in `access_need`.
- Identifies **missing privilege** — access needs that have no valid path.
- Reports **trust anchor gaps** — components that lack hardware root-of-trust,
  secure boot, or attestation.
- Evaluates **role-based** and **mission-phase-based** access policies.
- Minimises the total cost of placed firewalls and policy servers.

**Output:** Placed PEPs and PSes, excess/missing privilege findings, trust gap
report, mode-aware allow/deny table, policy exception register.

---

### Phase 3 — Resilience Scenarios

**Input:** Phase 1 risk scores (injected as facts), the ZTA topology, and a
scenario specification (which nodes are compromised or failed).

**What it does:** For each scenario, evaluates:

- **Blast radius** — how many other nodes can be reached from a compromised
  node via the bus topology.
- **Exposure amplification** — risk multiplier applied to assets reachable from
  the compromised node. Cross-domain traversal (low-domain node reaches
  high-domain asset) is amplified more than same-domain exposure.
- **Control-plane health** — whether any PEP is ungoverned (its PS has failed),
  bypassed (its PS is compromised), or serving stale policy (PS has failed but
  PEP is still running last-known rules).
- **Service availability** — whether each named service (`compute_svc`,
  `monitor_svc`, `io_svc`) meets its quorum requirement given failed components.

**Output:** Per-scenario total risk, amplification factor, list of unavailable
assets, service availability status, and control-plane health flag.

---

## 6. How the Phases Connect

```
┌─────────────────────────────────┐
│      testCase9_inst.lp          │  ← architecture topology, impacts,
│   (single source of truth)      │    latency, ZTA facts, services
└──────────────┬──────────────────┘
               │ loaded by all three phases
               ▼
┌─────────────────────────────────┐
│          PHASE 1                │
│  security_features_inst.lp      │  feature definitions + costs
│  tgt_system_tc9_inst.lp         │  hardware resource limits
│  init_enc.lp                    │  choice rules (pick one feature per comp)
│  opt_redundancy_exact_lut_enc.lp│  risk model (with LUT for group of 5)
│  opt_latency_enc.lp             │  latency computation
│  opt_power_enc.lp               │  power computation
│  opt_resource_enc.lp            │  resource accounting (LUT/FF/DSP/BRAM)
│  bridge_enc.lp                  │  index translation + latency enforcement
└──────────────┬──────────────────┘
               │ selected_security, selected_logging, p1_risk (injected as facts)
               ▼
┌─────────────────────────────────┐
│          PHASE 2                │
│  zta_policy_enc.lp              │  firewall + PS placement, privilege analysis,
│                                 │  trust gaps, mode-aware policy, RBAC
└──────────────┬──────────────────┘
               │ placed PEPs, PSes (used as scenario context)
               ▼
┌─────────────────────────────────┐
│          PHASE 3                │
│  resilience_tc9_enc.lp          │  per-scenario risk, blast radius,
│                                 │  control-plane health, service availability
└─────────────────────────────────┘
```

Phase 2 and Phase 3 each receive Phase 1's output as injected Clingo facts
(via Python string interpolation in `runClingo_tc9.py`). No phase re-solves
the previous phase — each is an independent solve with the prior result baked
in as ground truth.

---

## 7. File Reference

### Instance Files (the "what")

| File | Purpose |
|---|---|
| `testCases/testCase9_inst.lp` | Full system description: components, assets, impacts, latency budgets, bus topology, ZTA topology, access needs, roles, mission phases, trust anchors, services, control-plane |
| `Clingo/security_features_inst.lp` | Security and logging feature definitions: vulnerability scores, logging scores, resource costs, latency costs |
| `Clingo/tgt_system_tc9_inst.lp` | PYNQ-Z2 hardware resource limits and per-asset risk cap |

### Encoding Files (the "how")

| File | Phase | Purpose |
|---|---|---|
| `Clingo/init_enc.lp` | 1 | Choice rules — generates all valid (security, logging) assignments |
| `Clingo/opt_redundancy_exact_lut_enc.lp` | 1 | Risk model for standalone and redundancy-group components; size-5 group uses precomputed LUT to avoid integer overflow |
| `Clingo/tc9_combined_prob_norm_size5_lut.lp` | 1 | 16 800-entry lookup table mapping five normalised probability values to their exact product |
| `Clingo/opt_latency_enc.lp` | 1 | Computes total latency per asset per operation |
| `Clingo/opt_power_enc.lp` | 1 | Computes total power consumption |
| `Clingo/opt_resource_enc.lp` | 1 | Computes and caps LUT, FF, DSP, LUTRAM, BUFG, BRAM usage |
| `Clingo/bridge_enc.lp` | 1 | Translates component-level feature selection to asset-level; enforces latency budget constraint |
| `Clingo/zta_policy_enc.lp` | 2 | Firewall and PS placement, privilege analysis, trust gap detection, mode-aware and mission-context policy |
| `Clingo/resilience_tc9_enc.lp` | 3 | Scenario analysis: blast radius, exposure amplification, control-plane health, service quorum |

### Runner and Support Files (the "when")

| File | Purpose |
|---|---|
| `runClingo_tc9.py` | Main entry point. Orchestrates all three phases, runs 17 resilience scenarios, performs sensitivity analysis, writes the full report |
| `test_suite_tc9.py` | 21 unit tests covering feature selection, resource constraints, redundancy, ZTA placement, privilege gaps, control-plane scenarios, and service availability |
| `generate_tc9_combined_prob_norm_lut.py` | Regenerates `tc9_combined_prob_norm_size5_lut.lp` if normalisation parameters change |

---

## 8. Resilience Scenarios Covered

The runner evaluates 17 scenarios automatically:

| Category | Scenarios |
|---|---|
| Bus master compromise | `sys_cpu`, `dma`, `dma + noc1 failure` |
| IP compromise | `c1` (compute), `c6` (monitor), `c8` (IO/timer), full group (c1-c5) |
| Bus failure | `noc0`, `noc1`, `c8` failure |
| Control-plane: PS compromise | `ps0`, `ps1`, `ps0 compromised + ps1 failed` |
| Control-plane: PS failure | `ps0 failed`, both PSes failed |
| Control-plane: PEP bypass | `pep_group` bypassed, `pep_standalone` bypassed |

Each scenario reports a risk multiplier relative to the no-incident baseline.
The worst single control-plane event is `ps0 compromised + ps1 failed` (2.5×
baseline) because it leaves all PEPs simultaneously ungoverned and bypassed.

---

## 9. Key Findings for testCase9

| Finding | Detail |
|---|---|
| ZTA improvement | 3× risk reduction vs. no-ZTA worst case |
| Dominant residual risk | c8: tight 5-cycle latency budget forces `mac + no_logging`; cannot be mitigated by feature choice alone |
| Common-mode failure | noc0 failure cuts all 5 compute cores simultaneously, regardless of redundancy group size |
| Trust gaps | dma is unattested; ps1 does not enforce signed policy |
| Excess privilege | 9 access grants exceed declared access needs |
| Worst architecture scenario | `c8_compromise` at 2.54× baseline |
| Worst control-plane scenario | `ps0_compromise + ps1_failure` at 2.50× baseline |

---

## 10. How to Run

### Prerequisites

- Python 3.10+
- Clingo Python API: `pip install clingo`

### Run the full analysis

```bash
cd HOST26/HOST26_Code
python runClingo_tc9.py
```

Output is printed to the console and written to `resilience_summary_tc9.txt`.

### Run the test suite

```bash
cd HOST26/HOST26_Code
python test_suite_tc9.py
```

Expected output: `21 PASS | 0 FAIL | 21 total`

### Add a new test case

1. Copy `testCases/testCase9_inst.lp` as a starting point.
2. Edit components, assets, impacts, latency budgets, and topology links.
3. Update `TESTCASE` in `runClingo_tc9.py` to point to the new file.
4. If the FPGA target changes, update or replace `tgt_system_tc9_inst.lp`.
