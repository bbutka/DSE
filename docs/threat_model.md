# Formal Threat Model for ASP-Based Security Design Space Exploration

## 1. System Under Analysis

The target system is a **System-on-Chip (SoC)** containing heterogeneous
hardware components interconnected by on-chip bus fabrics.  The SoC hosts
safety-critical and security-sensitive functions within a single silicon
die, requiring hardware-enforced isolation and access control.

### 1.1 System Abstraction

The SoC is modeled as a directed graph G = (V, E) where:

- **V** = V_M ∪ V_R ∪ V_B ∪ V_FW ∪ V_PS
  - V_M: Bus masters (processors, DMA controllers)
  - V_R: Receiver IP cores (accelerators, peripherals, sensors)
  - V_B: Bus interconnects (AXI, APB, NoC segments)
  - V_FW: Policy Enforcement Points (hardware firewalls)
  - V_PS: Policy Decision Points (policy servers)

- **E** ⊆ V × V: Directed communication links representing physical
  bus connections.  An edge (u, v) indicates that u can initiate a
  transaction toward v.

Each component c ∈ V is annotated with:

| Property | Type | Semantics |
|----------|------|-----------|
| domain(c) | {untrusted, low, normal, privileged, high, root} | Hardware trust domain assignment |
| impact(c, op) | [1,5] for op ∈ {read, write, avail} | CIA impact if compromised |
| exploitability(c) | [1,5] | Ease of exploitation (1=hardened, 5=trivial) |
| safety_critical(c) | bool | Requires isolation from untrusted domains |
| critical(c) | bool | Requires firewall mediation from low-trust masters |

### 1.2 Assets

An **asset** a is an addressable register, memory region, or functional
unit hosted on a receiver component.  Each asset has:

- A hosting component owner(a) ∈ V_R
- A direction ∈ {input, output, bidirectional} constraining valid operations
- Per-operation impact scores (confidentiality for read, integrity for write, availability for avail)

The set of all assets A = {a | asset(owner, a, op)} forms the attack surface.


## 2. Threat Model

### 2.1 Adversary Model

We consider a **network-capable adversary** with the following capabilities:

| Capability | Description | Justification |
|------------|-------------|---------------|
| **Bus-level access** | Adversary can inject or observe transactions on any bus segment reachable from a compromised master | Reflects compromised firmware, malicious DMA, or debug port exploitation |
| **Component compromise** | Adversary can fully compromise any single component, gaining read/write/execute control | Models software vulnerabilities, supply-chain attacks, or fault injection |
| **Cascading reach** | From a compromised node, the adversary can attempt to reach adjacent nodes through the bus topology | Reflects lateral movement via bus protocols (no authentication by default) |
| **Policy server compromise** | Compromising a PS allows the adversary to manipulate policies for all governed PEPs | Models the highest-value target in the ZTA architecture |

The adversary **cannot**:

- Physically tamper with the silicon die at runtime (no probe attacks)
- Compromise multiple independent components simultaneously without a
  topological attack path between them (no coordinated multi-party attacks)
- Break cryptographic primitives when properly implemented
  (hardware RoT, secure boot, and attestation are assumed correct when present)

### 2.2 Attack Scenarios

The resilience analysis evaluates the system under parameterized
**scenario specifications** σ = (C_comp, C_fail) where:

- C_comp ⊆ V: Set of compromised components (adversary has full control)
- C_fail ⊆ V: Set of failed components (hardware fault, denial-of-service)

These are combined into scenario classes:

| Class | Description | Example |
|-------|-------------|---------|
| **Single-master compromise** | One bus master is under adversary control | Compromised DMA via malicious firmware |
| **Bus failure** | A bus segment is non-functional | Manufacturing defect or targeted DoS |
| **Policy server compromise** | PS is compromised, poisoning all governed PEP policies | Supply-chain attack on PS firmware |
| **PEP bypass** | Firewall component itself is compromised | Hardware trojan in firewall IP |
| **Redundancy group compromise** | All members of a redundant group compromised | Common-mode vulnerability across identical IPs |
| **Combined** | Simultaneous compromise + failure | Master compromised while a bus is down |

### 2.3 Trust Boundaries

Trust boundaries are defined by the **domain hierarchy**:

```
Level 0: untrusted, low     — External interfaces, debug ports
Level 1: normal              — General-purpose processing
Level 2: privileged          — OS kernel, trusted peripherals
Level 3: high, root          — Crypto engines, safety-critical actuators
```

A **cross-trust boundary** access occurs when a component in domain D_src
accesses an asset in domain D_dst where level(D_src) < level(D_dst).
Cross-trust accesses are the primary vector for privilege escalation.

### 2.4 Trusted Computing Base (TCB)

The TCB for each security mode is:

| Mode | TCB Components | Assumption |
|------|---------------|------------|
| Normal | All V_PS ∪ V_FW ∪ {c : hardware_rot(c)} | Policy servers and firewalls enforce access control |
| Attack Suspected | V_PS ∪ V_FW ∪ {c : attested(c) ∧ ¬critical(c)} | Only attested masters retain limited access |
| Attack Confirmed | V_PS ∪ V_FW only | Full isolation — no master access to any receiver |

The TCB size is minimized by the ZTA policy synthesis (Phase 2), which
selects the minimum set of firewalls and policy servers satisfying all
security constraints.


## 3. Security Properties

### 3.1 Confidentiality (C)

**Property**: An asset a with direction ∈ {input, bidirectional} is
confidentiality-protected if no unauthorized master can read it.

**Formal**: For all masters m where ¬access_need(m, owner(a), read),
the system enforces deny(m, owner(a), read) in the active security mode,
OR a firewall on the path mediates the access.

**Violation metric**: `scenario_action_risk(a, read, R)` where R is
proportional to impact(a, read) × max_amp_factor(a).

### 3.2 Integrity (I)

**Property**: An asset a with direction ∈ {output, bidirectional} is
integrity-protected if no unauthorized master can write it.

**Formal**: For all masters m where ¬access_need(m, owner(a), write),
the system enforces deny(m, owner(a), write) in the active security mode,
OR a firewall on the path mediates the access.

**Violation metric**: `scenario_action_risk(a, write, R)` with
CIA_WEIGHT(write) = 1.5× to reflect that integrity violations in
embedded/safety-critical systems have immediate physical consequences.

### 3.3 Availability (A)

**Property**: A service S with quorum requirement Q is available if at
least Q of its member components are alive and not compromised.

**Formal**: service_ok(S) ↔ |{c ∈ members(S) : ¬failed(c) ∧ ¬compromised(c)}| ≥ Q

**Violation metric**: `scenario_action_risk(a, avail, R)` with
CIA_WEIGHT(avail) = 2.0× reflecting that denial-of-service against
a safety-critical actuator or sensor can cause physical harm.

### 3.4 Isolation

**Property**: Safety-critical components must be unreachable from
low-trust masters in at least one elevated security mode.

**Formal**: For all c where safety_critical(c), there exists a mode S ∈
{attack_suspected, attack_confirmed} such that for all masters m where
low_trust_domain(m): ¬reachable_low(c, S).

This is enforced as a hard constraint in Phase 2 (UNSAT if violated).

### 3.5 Least Privilege

**Property**: No master should have access beyond its declared
operational needs.

**Formal**: excess_privilege(m, c, op) ↔ granted_op(m, c, op) ∧
¬access_need(m, c, op)

This is a soft property — reported as a finding, not enforced as a
constraint, since topology may inherently grant reachability.

### 3.6 Functional Resilience

**Property**: The system remains mission-capable under component
compromise or failure.

**Formal**: A mission capability Cap is:
- **OK** if all required services, components, and access paths are functional
- **Degraded** if a required PEP is bypassed (access unmediated) or a service is degraded
- **Lost** if any required service is unavailable, any required component is down, or any required access path is broken

The system is:
- **Functional** if no essential capability is lost
- **Non-functional** if any essential capability is lost


## 4. Risk Quantification

### 4.1 Base Risk Model

Per-asset base risk R_base(a, op) is computed in Phase 1 as a function of:

- **Impact score** I(a, op) ∈ [1, 5]: CIA-dimension impact
- **Security feature** F(owner(a)): Selected protection mechanism
  - zero_trust: strongest protection (residual risk ≈ 0-1)
  - dynamic_mac: medium protection (residual risk ≈ 2-3)
  - mac: basic protection (residual risk ≈ 3-5)
- **Domain bonus** DB(owner(a)): Higher trust domains have more cross-trust exposure
- **Exploitability modifier** EM(owner(a)): exploitability − 3 (range [−2, +2])

R_base(a, op) = max(0, I(a, op) + DB − Protection(F) − LogProtection(L) + EM)

### 4.2 Scenario Risk Amplification

Under a compromise/failure scenario σ, the risk for each asset is
amplified by the maximum exposure factor:

R_scenario(a, op, σ) = R_base(a, op) × max_amp_factor(a, σ)

Where max_amp_factor is the maximum of:

| Exposure Type | Factor (×10) | Condition |
|---------------|-------------|-----------|
| Direct | 30 (3.0×) | Asset's owner is compromised |
| Cross-trust indirect | 20 (2.0×) | Reachable from compromised node across trust boundary |
| Same-trust indirect | 15 (1.5×) | Reachable from compromised node within same trust level |
| Unmediated | 25 (2.5×) | PEP guarding the asset is bypassed |
| PS conflict | 13 (1.3×) | Split-brain: one PS compromised, another alive |
| Stale policy | 12 (1.2×) | Governing PS failed; PEP operates on stale rules |
| Unsigned-only | 11 (1.1×) | All signed-policy PSes are down; only unsigned remain |
| Baseline | 10 (1.0×) | No exposure (sentinel value) |

### 4.3 Protection Discount

Phase 1 security and logging assignments reduce indirect exposure:

| Feature | Security Discount | Logging Discount |
|---------|-------------------|------------------|
| zero_trust | 5 | — |
| dynamic_mac | 3 | — |
| mac | 1 | — |
| zero_trust_logger | — | 2 |
| some_logging | — | 1 |

Combined discount D = min(security + logging, 7).  Applied to indirect
exposure factors: effective_factor = base_factor − D.

### 4.4 Resilience Score

The composite resilience score combines three sub-metrics:

**Resilience = 0.4 × BlastRadius + 0.4 × CapabilityRetention + 0.2 × ControlPlane**

| Sub-metric | Formula | Rationale |
|------------|---------|-----------|
| BlastRadius | 100 − (avg_max_blast / total_nodes × 100) | Lower blast radius = better containment |
| CapabilityRetention | avg(OK + 0.5×Degraded) / TotalCaps × 100 | Penalizes lost capabilities; 0.25× multiplier if essential caps lost |
| ControlPlane | avg(100 if OK, 40 if degraded, 0 if compromised) | Control plane is the ZTA enforcement mechanism |

**Weight justification**: Blast radius and capability retention are
weighted equally (40% each) because they measure complementary aspects:
blast radius captures *potential* damage scope while capability retention
captures *actual* mission impact.  Control plane health (20%) is weighted
lower because its effects are already partially captured through
capability degradation (PEP bypass → unmediated access → capability
degraded).

### 4.5 CIA Weighting

The composite security score applies CIA weights:

| Dimension | Weight | Justification |
|-----------|--------|---------------|
| Confidentiality (read) | 1.0× | Data leakage is serious but not immediately safety-affecting |
| Integrity (write) | 1.5× | Corrupted sensor data or actuator commands cause physical harm |
| Availability (avail) | 2.0× | Denial of a safety-critical function has immediate consequences |

These weights reflect the **embedded/safety-critical context** where the
SoC controls physical processes.  For a data-centric SoC (e.g., network
processor), the weights should be adjusted (C > I ≈ A).


## 5. Scope and Limitations

### 5.1 In Scope

- Hardware-level access control design decisions (security feature selection, firewall placement, policy server deployment)
- Topology-derived blast radius and attack path analysis
- Service availability under component failure/compromise
- Mission capability functional assessment
- Least-privilege policy analysis with RBAC and mission phases

### 5.2 Out of Scope

| Limitation | Rationale |
|------------|-----------|
| Software vulnerabilities | The tool operates at the hardware architecture level; software is abstracted as component exploitability |
| Side-channel attacks | Requires gate-level or RTL analysis beyond the scope of architectural DSE |
| Physical attacks | Assumes the die is not probed at runtime; physical security is orthogonal |
| Timing attacks | Latency is modeled as a hard constraint, not as a covert channel |
| Multi-step adaptive attacks | Scenarios are static (fixed compromised/failed sets); the adversary does not adapt to defenses mid-scenario |
| Formal verification | Results are *analytical* (based on ASP model checking), not *verified* against RTL implementations |

### 5.3 Assumptions

1. **Topology fidelity**: The graph model faithfully represents the physical bus topology and reachability.
2. **Domain correctness**: Trust domain assignments reflect the intended security architecture.
3. **Feature effectiveness**: Security features (zero_trust, mac, etc.) provide the modeled protection levels when correctly implemented in hardware.
4. **Clingo soundness**: The ASP solver produces correct stable models for the stratified encoding.
5. **Single-failure**: Scenarios consider a bounded number of simultaneous compromises/failures; unbounded adversaries are not modeled.


## 6. Relationship to Standards

| Standard | Mapping |
|----------|---------|
| NIST SP 800-207 (ZTA) | Phase 2 implements ZTA principles: PEP placement, PDP governance, least-privilege policy, trust evaluation |
| CVSS v3.1 | Exploitability scores map to CVSS Base Score attack complexity; impact scores map to CIA impact metrics |
| ISO 26262 (Functional Safety) | Safety-critical component isolation, service quorum requirements, system functional status |
| NIST SP 800-53 (AC, SI families) | Access control policy synthesis (AC), system integrity monitoring via logging features (SI) |
| IEC 62443 | Zone/conduit model maps to domain hierarchy; security levels map to protection features |
