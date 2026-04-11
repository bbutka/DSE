"""
asp_generator.py
================
Converts a NetworkModel Python object into an ASP (.lp) facts string
suitable for loading with clingo.

The generated facts mirror the integrated Clingo instance schema so the
active Phase 1/2/3 encodings work without handwritten testcase files.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from collections import deque
from typing import List, Dict, Tuple, Optional
import re


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Component:
    """A single hardware component / IP core in the network."""
    name: str
    comp_type: str          # processor | dma | ip_core | bus | policy_server | firewall
    domain: str             # untrusted | low | normal | privileged | high | root
    impact_read: int        # 1-5: confidentiality impact
    impact_write: int       # 1-5: integrity impact
    latency_read: int       # clock cycles (1000 = no constraint)
    latency_write: int      # clock cycles (1000 = no constraint)
    impact_avail: int = 0   # 1-5: availability/DoS impact (0 = not modelled)
    exploitability: int = 3 # 1-5: CVSS-style (1=hard, 3=neutral, 5=trivial)
    has_rot: bool = False
    has_sboot: bool = False
    has_attest: bool = False
    is_master: bool = False     # bus master (processor, dma)
    is_receiver: bool = True    # target IP
    is_critical: bool = False   # requires firewall coverage
    is_safety_critical: bool = False
    direction: str = "bidirectional"  # input | output | bidirectional


@dataclass
class Asset:
    """
    An explicitly named asset on a component.

    direction controls which operations are valid:
      - "input"         read-only  (e.g. temperature sensor, ADC)
      - "output"        write-only (e.g. PWM, DAC, GPIO output)
      - "bidirectional" both read and write (default for most IPs)

    Multiple assets per component are supported (e.g. separate read/write
    channels on a GPIO block).
    """
    asset_id: str
    component: str
    direction: str = "bidirectional"  # input | output | bidirectional
    impact_read: int = 3
    impact_write: int = 3
    impact_avail: int = 0   # 1-5: DoS impact (0 = not modelled)
    latency_read: int = 1000
    latency_write: int = 1000


@dataclass
class RedundancyGroup:
    """A named group of redundant components."""
    group_id: str
    members: List[str]


@dataclass
class Service:
    """A logical service composed of component members."""
    name: str
    members: List[str]
    quorum: int


@dataclass
class AccessNeed:
    """A declared least-privilege access requirement."""
    master: str
    component: str
    operation: str  # read | write


@dataclass
class TransitionTrigger:
    """A mode transition trigger for the ZTA security mode ladder."""
    condition: str   # e.g. anomaly_detected, attestation_failure, intrusion_confirmed
    from_mode: str   # normal | attack_suspected | attack_confirmed
    to_mode: str     # normal | attack_suspected | attack_confirmed


@dataclass
class MissionCapability:
    """
    A high-level mission function that the SoC must perform.

    Attributes
    ----------
    name : str
        Short identifier, e.g. ``"sensor_fusion"``, ``"crypto_ops"``.
    description : str
        Human-readable description of what this capability does.
    required_services : list[str]
        Service names that must be OK (quorum met) for this capability.
    required_components : list[str]
        Individual components that must be alive **and reachable** from at
        least one master.
    required_access : list[tuple[str, str, str]]
        (master, component, operation) access paths that must be functional
        (component alive, reachable, not cut off).
    criticality : str
        ``"essential"``  --  system cannot operate without it;
        ``"important"``  --  degraded operation possible;
        ``"optional"``   --  nice-to-have.
    mission_phases : list[str]
        Phases in which this capability is needed (empty = all phases).
    """
    name: str
    description: str = ""
    required_services: List[str] = field(default_factory=list)
    required_components: List[str] = field(default_factory=list)
    required_access: List[Tuple[str, str, str]] = field(default_factory=list)
    criticality: str = "essential"  # essential | important | optional
    mission_phases: List[str] = field(default_factory=list)


@dataclass
class FunctionSupport:
    """
    A component's standalone contribution to a mission function.

    The initial Phase 3 evaluator uses ``quality`` as a best-surviving-support
    score, not as a sensor-fusion contribution.  For example, GPS may provide
    high-quality standalone state estimation, while an IMU provides a usable
    but drift-limited fallback.
    """
    function: str
    component: str
    modality: str
    quality: int


@dataclass
class NetworkModel:
    """
    Complete description of the target SoC network for DSE analysis.

    Attributes
    ----------
    name : str
        Human-readable network name (used in reports).
    components : list[Component]
        All hardware components (processors, IPs, buses, PS, PEP).
    links : list[tuple[str, str]]
        Directed topology links (src, dst).
    redundancy_groups : list[RedundancyGroup]
        Redundancy groups (shared-fate sets).
    services : list[Service]
        Logical services with quorum requirements.
    access_needs : list[AccessNeed]
        Declared least-privilege access needs per master.
    system_caps : dict[str, int]
        FPGA resource budgets keyed by capability name.
    cand_fws : list[str]
        Candidate firewall (PEP) locations.
    cand_ps : list[str]
        Candidate policy server locations.
    on_paths : list[tuple[str, str, str]]
        (fw_location, master, ip) on-path facts.
    ip_locs : list[tuple[str, str]]
        (ip, fw_location) guarding facts.
    fw_governs : list[tuple[str, str]]
        (ps, pep) governance facts.
    fw_costs : dict[str, int]
        Hardware cost per FW location.
    ps_costs : dict[str, int]
        Hardware cost per PS.
    roles : list[tuple[str, str]]
        (master, role_name) role assignments.
    allow_rules : list[tuple[str, str, str]]
        (master, component, mode) explicit allow rules.
    policy_exceptions : list[tuple]
        (master, component, op, mode, reason) exceptions.
    trust_anchors : dict[str, list[str]]
        component -> list of trust properties present.
    pep_guards : list[tuple[str, str]]
        (pep, component) guarding facts.
    ps_governs_pep : list[tuple[str, str]]
        (ps, pep) governance facts for Phase 3.
    mission_phases : list[str]
        Declared mission phases.
    """
    name: str = "custom_network"
    components: List[Component] = field(default_factory=list)
    assets: List[Asset] = field(default_factory=list)
    links: List[Tuple[str, str]] = field(default_factory=list)
    redundancy_groups: List[RedundancyGroup] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    access_needs: List[AccessNeed] = field(default_factory=list)
    system_caps: Dict[str, int] = field(default_factory=lambda: {
        "max_power":      15000,
        "max_luts":       53200,
        "max_ffs":       106400,
        "max_dsps":         220,
        "max_lutram":     17400,
        "max_bufgs":         32,
        "max_bram":         140,
        "max_security_risk": 50,   # multiplicative cap: non-redundant components
        "max_avail_risk":    20,   # probabilistic cap: redundant groups
        "redundancy_beta_pct": 0,  # common-cause correction: 0 = independence-only
        "min_ps_count":       1,   # Phase 2: minimum policy servers (1 = no redundancy)
        "max_attack_depth":   5,   # Phase 3 attack-path search depth
    })
    cand_fws: List[str] = field(default_factory=list)
    cand_ps: List[str] = field(default_factory=list)
    on_paths: List[Tuple[str, str, str]] = field(default_factory=list)
    ip_locs: List[Tuple[str, str]] = field(default_factory=list)
    fw_governs: List[Tuple[str, str]] = field(default_factory=list)
    fw_costs: Dict[str, int] = field(default_factory=dict)
    ps_costs: Dict[str, int] = field(default_factory=dict)
    roles: List[Tuple[str, str]] = field(default_factory=list)
    allow_rules: List[Tuple[str, str, str]] = field(default_factory=list)
    mission_access_rules: List[str] = field(default_factory=list)
    role_need_rules: List[str] = field(default_factory=list)
    policy_exceptions: List[Tuple] = field(default_factory=list)
    trust_anchors: Dict[str, List[str]] = field(default_factory=dict)
    pep_guards: List[Tuple[str, str]] = field(default_factory=list)
    ps_governs_pep: List[Tuple[str, str]] = field(default_factory=list)
    transition_triggers: List[TransitionTrigger] = field(default_factory=list)
    mission_phases: List[str] = field(default_factory=lambda: [
        "operational", "maintenance", "emergency"
    ])
    buses: List[str] = field(default_factory=list)
    scenarios: List[dict] = field(default_factory=list)
    capabilities: List[MissionCapability] = field(default_factory=list)
    function_supports: List[FunctionSupport] = field(default_factory=list)
    function_thresholds: Dict[str, Dict[str, int]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

class ASPGenerator:
    """
    Converts a NetworkModel to an ASP facts string.

    Usage
    -----
    gen = ASPGenerator(model)
    facts_str = gen.generate()
    """

    def __init__(self, model: NetworkModel) -> None:
        self.model = model

    def _precompute_phase2_reachability(self) -> List[Tuple[str, str]]:
        """
        Pre-compute the directed master->receiver reachability facts used by
        Phase 2. This avoids grounding the recursive transitive closure in
        zta_policy_enc.lp while preserving the existing directed link
        semantics exactly.
        """
        adjacency: Dict[str, List[str]] = {}
        for src, dst in self.model.links:
            adjacency.setdefault(src, []).append(dst)

        receivers = {
            c.name for c in self.model.components
            if c.comp_type not in ("bus", "policy_server", "firewall") and not c.is_master
        }
        masters = [c.name for c in self.model.components if c.is_master]

        reachable_pairs: List[Tuple[str, str]] = []
        for master in masters:
            seen = set()
            q = deque(adjacency.get(master, []))
            while q:
                node = q.popleft()
                if node in seen:
                    continue
                seen.add(node)
                if node in receivers:
                    reachable_pairs.append((master, node))
                for nbr in adjacency.get(node, []):
                    if nbr not in seen:
                        q.append(nbr)
        return sorted(reachable_pairs)

    @staticmethod
    def _audit_capability(component: Component) -> str:
        if component.comp_type in {"policy_server", "firewall"}:
            return "no_audit"
        if component.is_master and component.has_rot:
            return "full_audit"
        if component.has_sboot or component.has_attest:
            return "standard_audit"
        if component.is_safety_critical or component.is_critical:
            return "standard_audit"
        if component.is_receiver and component.domain in {"privileged", "high", "root"}:
            return "standard_audit"
        if component.is_receiver:
            return "minimal_audit"
        return "no_audit"

    @staticmethod
    def _asp_identifier(value: str) -> str:
        """Normalize free-form labels into safe lowercase ASP constants."""
        ident = re.sub(r"[^a-zA-Z0-9_]+", "_", str(value).strip()).strip("_").lower()
        return ident or "unknown"

    def generate(self) -> str:
        """Return a complete .lp facts string for the network model."""
        m = self.model
        lines: List[str] = []
        lines.append(f"% Auto-generated ASP facts for network: {m.name}")
        lines.append("")

        # -€-€ Components -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        lines.append("% Components")
        ip_comps = [c for c in m.components
                    if c.comp_type not in ("bus",) and not c.is_master]
        masters   = [c for c in m.components if c.is_master]

        for c in ip_comps:
            if c.comp_type not in ("policy_server", "firewall"):
                lines.append(f"component({c.name}).")

        lines.append("")

        # -€-€ Assets -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        # Use explicit asset list if provided; otherwise auto-generate one
        # asset per component using its direction field.
        lines.append("% Assets")
        if m.assets:
            asset_list = m.assets
        else:
            asset_list = [
                Asset(
                    asset_id=f"{c.name}r1",
                    component=c.name,
                    direction=c.direction,
                    impact_read=c.impact_read,
                    impact_write=c.impact_write,
                    impact_avail=c.impact_avail,
                    latency_read=c.latency_read,
                    latency_write=c.latency_write,
                )
                for c in ip_comps
                if c.comp_type not in ("policy_server", "firewall", "bus")
            ]

        for a in asset_list:
            if a.direction in ("input", "bidirectional"):
                lines.append(f"asset({a.component}, {a.asset_id}, read).")
            if a.direction in ("output", "bidirectional"):
                lines.append(f"asset({a.component}, {a.asset_id}, write).")
            if a.impact_avail > 0:
                lines.append(f"asset({a.component}, {a.asset_id}, avail).")

        lines.append("")

        # -€-€ Impact -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        lines.append("% Asset impact values (C = read, I = write, A = avail)")
        for a in asset_list:
            if a.direction in ("input", "bidirectional"):
                lines.append(f"impact({a.asset_id}, read,  {a.impact_read}).")
            if a.direction in ("output", "bidirectional"):
                lines.append(f"impact({a.asset_id}, write, {a.impact_write}).")
            if a.impact_avail > 0:
                lines.append(f"impact({a.asset_id}, avail, {a.impact_avail}).")

        lines.append("")

        # -€-€ Latency -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        lines.append("% Allowable latency per asset")
        for a in asset_list:
            if a.direction in ("input", "bidirectional"):
                lines.append(f"allowable_latency({a.asset_id}, read,  {a.latency_read}).")
            if a.direction in ("output", "bidirectional"):
                lines.append(f"allowable_latency({a.asset_id}, write, {a.latency_write}).")

        lines.append("")

        # -€-€ Redundancy groups -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        lines.append("% Redundancy groups")
        for grp in m.redundancy_groups:
            gid = grp.group_id
            # Use integer group id if possible for compatibility with existing enc
            try:
                gid_val = int(gid.lstrip("g"))
            except ValueError:
                gid_val = gid
            for member in grp.members:
                lines.append(f"redundant_group({gid_val}, {member}).")

        lines.append("")

        # -€-€ ZTA Topology -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        lines.append("% ZTA topology - masters, receivers, buses, links")
        for c in masters:
            lines.append(f"master({c.name}).")
        for c in ip_comps:
            if c.comp_type not in ("policy_server", "firewall", "bus"):
                lines.append(f"receiver({c.name}).")
        for b in m.buses:
            lines.append(f"bus({b}).")
        lines.append("")

        for src, dst in m.links:
            lines.append(f"link({src}, {dst}).")
        lines.append("")

        lines.append("% Pre-computed master-to-receiver reachability for Phase 2")
        for master, receiver in self._precompute_phase2_reachability():
            lines.append(f"reachable({master}, {receiver}).")
        lines.append("")

        # -€-€ Trust domains -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        lines.append("% Trust domains (untrusted=0 | low=0 | normal=1 | privileged=2 | high=3 | root=3)")
        for c in m.components:
            if c.comp_type not in ("bus",):
                lines.append(f"domain({c.name}, {c.domain}).")
        lines.append("")

        # -€-€ Exploitability -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        lines.append("% Exploitability: 1=hard, 3=neutral, 5=trivial (default 3 when omitted)")
        lines.append("% Phase 1 emits receiver-side exploitability only; masters drive scenarios but do not carry Phase 1 assets.")
        for c in ip_comps:
            if c.comp_type not in ("policy_server", "firewall", "bus"):
                if c.exploitability != 3:   # only emit non-default values
                    lines.append(f"exploitability({c.name}, {c.exploitability}).")
        lines.append("")

        lines.append("% Audit capability (computed from component properties)")
        for c in m.components:
            if c.comp_type not in ("bus",):
                lines.append(f"audit_capability({c.name}, {self._audit_capability(c)}).")
        lines.append("")

        # -€-€ Critical components -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        lines.append("% Critical and safety-critical IPs")
        for c in ip_comps:
            if c.is_critical and c.comp_type not in ("policy_server", "firewall", "bus"):
                lines.append(f"critical({c.name}).")
        for c in m.components:
            if c.comp_type not in ("bus", "policy_server", "firewall") and c.is_safety_critical:
                lines.append(f"safety_critical({c.name}).")
        lines.append("")

        # -€-€ Firewall / PS candidates -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        lines.append("% Candidate firewalls and policy servers")
        for fw in m.cand_fws:
            lines.append(f"cand_fw({fw}).")
        for ps in m.cand_ps:
            lines.append(f"cand_ps({ps}).")
        lines.append("")

        # -€-€ On-path and ip_loc -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        lines.append("% On-path and ip_loc facts")
        for fw, master, ip in m.on_paths:
            lines.append(f"on_path({fw}, {master}, {ip}).")
        for ip, fw in m.ip_locs:
            lines.append(f"ip_loc({ip}, {fw}).")
        lines.append("")

        # -€-€ FW governance -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        lines.append("% Firewall governance by policy server")
        for ps, pep in m.fw_governs:
            lines.append(f"governs({ps}, {pep}).")
        lines.append("")

        # -€-€ Hardware costs -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        lines.append("% Hardware costs")
        for fw, cost in m.fw_costs.items():
            lines.append(f"fw_cost({fw}, {cost}).")
        for ps, cost in m.ps_costs.items():
            lines.append(f"ps_cost({ps}, {cost}).")
        lines.append("")

        # -€-€ System capabilities -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        lines.append("% System capabilities (resource budgets)")
        for cap, val in m.system_caps.items():
            lines.append(f"system_capability({cap}, {val}).")
        lines.append("")

        # -€-€ Allow rules -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        lines.append("% Explicit allow rules (normal mode)")
        for master, comp, mode in m.allow_rules:
            lines.append(f"allow({master}, {comp}, {mode}).")
        lines.append("")

        # -€-€ Access needs -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        lines.append("% Least-privilege access needs")
        for an in m.access_needs:
            lines.append(f"access_need({an.master}, {an.component}, {an.operation}).")
        lines.append("")

        # -€-€ Roles -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        lines.append("% Subject roles")
        for master, role in m.roles:
            lines.append(f"role({master}, {role}).")
        lines.append("")

        # -€-€ Policy exceptions -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        if m.policy_exceptions:
            lines.append("% Policy exceptions")
            for exc in m.policy_exceptions:
                master, comp, op, mode, reason = exc
                lines.append(f"policy_exception({master}, {comp}, {op}, {mode}, reason({reason})).")
            lines.append("")

        # -€-€ Trust anchors -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        lines.append("% Trust anchors and attestation")
        for comp, anchors in m.trust_anchors.items():
            if "rot" in anchors:
                lines.append(f"hardware_rot({comp}).")
            if "sboot" in anchors:
                lines.append(f"secure_boot({comp}).")
            if "attest" in anchors:
                lines.append(f"attested({comp}).")
            if "signed_policy" in anchors:
                lines.append(f"signed_policy({comp}).")
            if "key_storage" in anchors:
                lines.append(f"key_storage({comp}).")
            if "trusted_telemetry" in anchors:
                lines.append(f"trusted_telemetry({comp}).")
        lines.append("")

        # -€-€ Services -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        lines.append("% Services")
        for svc in m.services:
            for member in svc.members:
                lines.append(f"service_component({svc.name}, {member}).")
            lines.append(f"service_quorum({svc.name}, {svc.quorum}).")
        lines.append("")

        # -€-€ Control plane -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        lines.append("% Control plane")
        for ps in m.cand_ps:
            lines.append(f"policy_server({ps}).")
        for fw in m.cand_fws:
            lines.append(f"policy_enforcement_point({fw}).")
        for pep, ip in m.pep_guards:
            lines.append(f"pep_guards({pep}, {ip}).")
        for ps, pep in m.ps_governs_pep:
            lines.append(f"ps_governs_pep({ps}, {pep}).")
        lines.append("")

        # -€-€ Mission phases -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        lines.append("% Mission phases")
        for phase in m.mission_phases:
            lines.append(f"mission_phase({phase}).")
        lines.append("")

        # Mode transition triggers
        if m.transition_triggers:
            lines.append("% Mode transition triggers")
            for tt in m.transition_triggers:
                lines.append(
                    "transition_trigger("
                    f"{self._asp_identifier(tt.condition)}, "
                    f"{self._asp_identifier(tt.from_mode)}, "
                    f"{self._asp_identifier(tt.to_mode)})."
                )
            lines.append("")

        # -€-€ Mission access rules -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        # Derive primary processor and DMA master from topology for mission rules
        primary_proc = next((c.name for c in masters if c.comp_type == "processor"), None)
        dma_master = next((c.name for c in masters if c.comp_type == "dma"), None)
        lines.append("% Mission access rules")
        if m.mission_access_rules:
            lines.extend(m.mission_access_rules)
        else:
            lines.append("mission_access(M, C, Op, operational) :- access_need(M, C, Op).")
            if primary_proc:
                lines.append(f"mission_access({primary_proc}, C, read,  maintenance) :- receiver(C).")
                lines.append(f"mission_access({primary_proc}, C, write, maintenance) :- receiver(C).")
            if dma_master:
                lines.append(f"mission_access({dma_master}, C, Op, maintenance) :- access_need({dma_master}, C, Op).")
            lines.append("mission_access(M, C, read, emergency) :- master(M), receiver(C), access_need(M, C, read).")
        lines.append("")

        # -€-€ Role needs -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        # Derive from model roles and topology instead of hardcoding TC9 names
        lines.append("% Role-level access needs")
        if m.role_need_rules:
            lines.extend(m.role_need_rules)
        else:
            for _, role in m.roles:
                # Each role gets read access to high-trust receivers
                lines.append(f"role_need({role}, C, read)  :- receiver(C), domain(C, high).")
                lines.append(f"role_need({role}, C, read)  :- receiver(C), domain(C, root).")
            # DMA-type roles get write access to all receivers
            if dma_master:
                dma_role = next((role for master, role in m.roles if master == dma_master), None)
                if dma_role:
                    lines.append(f"role_need({dma_role}, C, write) :- receiver(C).")
        lines.append("")

        # -€-€ Static risk weights (amplification proxy for Phase 1 objective) -€-€
        # risk_weight(Asset, W): integer weight in [10, 50] derived from topology.
        # Phase 1 #minimize uses Risk * W so the solver prioritises reducing risk
        # on assets that scenario analysis will amplify most.
        #
        # Weight formula (all additive, capped at 50):
        #   base        = 10
        #   safety_crit = +20  (safety-critical: highest amplification)
        #   master      = +15  (masters have high blast radius)
        #   domain_root = +10  (privileged/high/root: more cross-domain paths)
        #   reachable   = +1 per other component reachable (topology proxy)
        lines.append("% Static risk weights for amplification-aware Phase 1 objective")
        lines.append("% risk_weight(Asset, W): W in [10,50]; higher = amplified more in Phase 3")

        # Build adjacency map for reachability count
        adj: Dict[str, set] = {}
        for src, dst in m.links:
            adj.setdefault(src, set()).add(dst)
            adj.setdefault(dst, set()).add(src)

        def bfs_count(start: str) -> int:
            visited = {start}
            queue = [start]
            while queue:
                cur = queue.pop(0)
                for nb in adj.get(cur, set()):
                    if nb not in visited:
                        visited.add(nb)
                        queue.append(nb)
            return len(visited) - 1  # exclude self

        # Domain level map (mirrors ASP domain_level/2)
        _dom_level = {
            "untrusted": 0, "low": 0, "normal": 1,
            "privileged": 2, "high": 3, "root": 3,
        }

        all_comps = {c.name: c for c in m.components
                     if c.comp_type not in ("bus", "policy_server", "firewall")}

        for c in all_comps.values():
            if c.comp_type in ("policy_server", "firewall"):
                continue
            base       = 10
            safety_add = 20 if c.is_safety_critical else 0
            master_add = 15 if c.is_master else 0
            dom_lv     = _dom_level.get(c.domain, 1)
            domain_add = 10 if dom_lv >= 2 else 0
            reach      = min(bfs_count(c.name), 5)   # cap reachability bonus at 5
            weight     = min(50, base + safety_add + master_add + domain_add + reach)

            # Emit one weight per generated asset of this component.
            # Using asset_list avoids synthesizing dead fallback weights for
            # components that do not actually own Phase 1 assets.
            comp_assets = [a for a in asset_list if a.component == c.name]
            if comp_assets:
                for a in comp_assets:
                    lines.append(f"risk_weight({a.asset_id}, {weight}).")
        lines.append("")

        # -€-€ Mission capabilities (functional resilience) -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
        if m.capabilities:
            lines.append("% Mission capabilities")
            for cap in m.capabilities:
                lines.append(f"capability({cap.name}).")
                lines.append(f"capability_criticality({cap.name}, {cap.criticality}).")
                if cap.description:
                    # Description as a comment for readability
                    lines.append(f"% {cap.name}: {cap.description}")
                for svc in cap.required_services:
                    lines.append(f"capability_requires_service({cap.name}, {svc}).")
                for comp in cap.required_components:
                    lines.append(f"capability_requires_component({cap.name}, {comp}).")
                for master, comp, op in cap.required_access:
                    lines.append(f"capability_requires_access({cap.name}, {master}, {comp}, {op}).")
                for phase in cap.mission_phases:
                    lines.append(f"capability_phase({cap.name}, {phase}).")
                if not cap.mission_phases:
                    # No phase restriction â†’ needed in all phases
                    for phase in m.mission_phases:
                        lines.append(f"capability_phase({cap.name}, {phase}).")
            lines.append("")

        return "\n".join(lines)

    def validate_topology(self) -> List[str]:
        """
        Check the network model for structural issues that would cause
        UNSAT in Phase 2 (ZTA policy encoding).

        Returns a list of warning/error strings.  Empty = no issues found.
        """
        m = self.model
        warnings: List[str] = []

        # Build directed reachability from links
        adj: Dict[str, set] = {}
        for src, dst in m.links:
            adj.setdefault(src, set()).add(dst)

        def reachable_from(start: str) -> set:
            visited = {start}
            queue = [start]
            while queue:
                cur = queue.pop(0)
                for nb in adj.get(cur, set()):
                    if nb not in visited:
                        visited.add(nb)
                        queue.append(nb)
            return visited

        # Domain classification
        _low_trust = {"untrusted", "low", "normal"}

        masters = [c for c in m.components if c.is_master]
        receivers = [c for c in m.components
                     if c.comp_type not in ("bus", "policy_server", "firewall")
                     and not c.is_master]
        low_masters = [c for c in masters if c.domain in _low_trust]

        # Check 1: Every critical IP reachable from a low-trust master
        # must have an on-path firewall candidate
        on_path_set = set()
        for fw, master, ip in m.on_paths:
            on_path_set.add((fw, master, ip))

        for master in low_masters:
            reach = reachable_from(master.name)
            for recv in receivers:
                if recv.is_critical and recv.name in reach:
                    has_fw = any(
                        (fw, master.name, recv.name) in on_path_set
                        for fw in m.cand_fws
                    )
                    if not has_fw:
                        warnings.append(
                            f"UNSAT risk: low-trust master '{master.name}' "
                            f"can reach critical IP '{recv.name}' but no "
                            f"candidate firewall has on_path({{}}, {master.name}, {recv.name})"
                        )

        # Check 2: Every candidate FW that would be forced to deploy
        # must have at least one governing PS candidate
        fw_governed_by = {fw: [] for fw in m.cand_fws}
        for ps, fw in m.fw_governs:
            if fw in fw_governed_by:
                fw_governed_by[fw].append(ps)

        for fw in m.cand_fws:
            if not fw_governed_by[fw]:
                warnings.append(
                    f"UNSAT risk: candidate firewall '{fw}' has no "
                    f"governing PS in fw_governs. If placed, it will "
                    f"violate the governance constraint."
                )

        # Check 3: Every ip_loc entry must match a candidate FW
        for ip, fw in m.ip_locs:
            if fw not in m.cand_fws:
                warnings.append(
                    f"Topology issue: ip_loc({ip}, {fw}) references "
                    f"non-candidate firewall '{fw}'"
                )

        # Check 4: Safety-critical components must be receivers
        for c in m.components:
            if c.is_safety_critical:
                if c.comp_type in ("bus", "policy_server", "firewall"):
                    warnings.append(
                        f"Safety-critical '{c.name}' has type '{c.comp_type}' "
                        f"but the model only supports safety-critical masters/receivers"
                    )

        return warnings

    def to_json(self) -> dict:
        """Serialize the model to a JSON-compatible dict."""
        import dataclasses
        return dataclasses.asdict(self.model)


# ---------------------------------------------------------------------------
# TC9 factory
# ---------------------------------------------------------------------------

def make_tc9_network() -> NetworkModel:
    """
    Create the tc9 NetworkModel matching the integrated tc9 Clingo facts.

    Returns the pre-loaded TC9 topology ready for the network editor and
    for direct use in analysis without the editor.
    """
    model = NetworkModel(name="testCase9")

    # -€-€ Components -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.components = [
        Component("sys_cpu", "processor",     "low",  1, 1, 1000, 1000,
                  has_attest=True, is_master=True, is_receiver=False),
        Component("dma",     "dma",            "low",  1, 1, 1000, 1000,
                  is_master=True, is_receiver=False),
        Component("c1", "ip_core", "high", 1, 5, 10, 1000,
                  has_rot=True, has_sboot=True,
                  is_critical=True),
        Component("c2", "ip_core", "high", 5, 2, 1000, 10,
                  has_rot=True, has_sboot=True,
                  is_critical=True),
        Component("c3", "ip_core", "high", 3, 3, 7, 22,
                  has_sboot=True, is_critical=True),
        Component("c4", "ip_core", "high", 3, 4, 22, 7,
                  has_sboot=True, is_critical=True),
        Component("c5", "ip_core", "high", 4, 1, 25, 22,
                  has_sboot=True, is_critical=True),
        Component("c6", "ip_core", "high", 5, 3, 22, 25,
                  is_critical=True),
        Component("c7", "ip_core", "low",  1, 2, 1000, 1000),
        Component("c8", "ip_core", "high", 2, 4, 5, 15,
                  is_critical=True, is_safety_critical=True),
        Component("ps0", "policy_server", "high", 1, 1, 1000, 1000,
                  is_receiver=False),
        Component("ps1", "policy_server", "high", 1, 1, 1000, 1000,
                  is_receiver=False),
    ]

    # -€-€ Buses -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.buses = ["noc0", "noc1"]

    # -€-€ Links -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.links = [
        ("sys_cpu", "noc0"),
        ("dma",     "noc0"),
        ("noc0", "c1"), ("noc0", "c2"), ("noc0", "c3"),
        ("noc0", "c4"), ("noc0", "c5"),
        ("dma",  "noc1"),
        ("noc1", "c6"), ("noc1", "c7"), ("noc1", "c8"),
    ]

    # -€-€ Redundancy groups -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.redundancy_groups = [
        RedundancyGroup("g1", ["c1", "c2", "c3", "c4", "c5"])
    ]

    # -€-€ Services -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.services = [
        Service("compute_svc", ["c1","c2","c3","c4","c5"], 3),
        Service("monitor_svc", ["c6"], 1),
        Service("io_svc",      ["c8"], 1),
    ]

    # -€-€ Access needs -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.access_needs = [
        AccessNeed("sys_cpu", "c1", "read"),  AccessNeed("sys_cpu", "c1", "write"),
        AccessNeed("sys_cpu", "c2", "read"),  AccessNeed("sys_cpu", "c2", "write"),
        AccessNeed("sys_cpu", "c3", "read"),  AccessNeed("sys_cpu", "c3", "write"),
        AccessNeed("sys_cpu", "c4", "read"),  AccessNeed("sys_cpu", "c4", "write"),
        AccessNeed("sys_cpu", "c5", "read"),  AccessNeed("sys_cpu", "c5", "write"),
        AccessNeed("sys_cpu", "c6", "read"),
        AccessNeed("dma", "c1", "write"),     AccessNeed("dma", "c2", "write"),
        AccessNeed("dma", "c3", "write"),     AccessNeed("dma", "c4", "write"),
        AccessNeed("dma", "c5", "write"),
        AccessNeed("dma", "c6", "write"),
        AccessNeed("dma", "c8", "read"),
    ]

    # -€-€ System capabilities -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.system_caps = {
        "max_power":      15000,
        "max_luts":       53200,
        "max_ffs":       106400,
        "max_dsps":         220,
        "max_lutram":     17400,
        "max_bufgs":         32,
        "max_bram":         140,
        "max_security_risk": 50,   # multiplicative cap: non-redundant components
        "max_avail_risk":    20,   # probabilistic cap: redundant groups
        "max_attack_depth":   5,   # Phase 3 attack-path search depth
    }

    # -€-€ Candidates -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.cand_fws = ["pep_group", "pep_standalone"]
    model.cand_ps  = ["ps0", "ps1"]

    # -€-€ On-path -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    for c in ["c1","c2","c3","c4","c5"]:
        model.on_paths.append(("pep_group", "sys_cpu", c))
        model.on_paths.append(("pep_group", "dma",     c))
    for c in ["c6","c7","c8"]:
        model.on_paths.append(("pep_standalone", "dma", c))

    # -€-€ ip_loc -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    for c in ["c1","c2","c3","c4","c5"]:
        model.ip_locs.append((c, "pep_group"))
    for c in ["c6","c7","c8"]:
        model.ip_locs.append((c, "pep_standalone"))

    # -€-€ Governance -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.fw_governs = [
        ("ps0", "pep_group"), ("ps0", "pep_standalone"),
        ("ps1", "pep_group"),
    ]
    model.fw_costs = {"pep_group": 150, "pep_standalone": 100}
    model.ps_costs = {"ps0": 200, "ps1": 180}

    # -€-€ Roles -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.roles = [("sys_cpu", "processor"), ("dma", "data_mover")]

    # -€-€ Allow rules -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    for c in ["c1","c2","c3","c4","c5"]:
        model.allow_rules.append(("sys_cpu", c, "normal"))
        model.allow_rules.append(("dma",     c, "normal"))
    for c in ["c6","c7","c8"]:
        model.allow_rules.append(("dma", c, "normal"))

    # -€-€ Policy exceptions -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.policy_exceptions = [
        ("dma", "c7", "write", "maintenance", "firmware_update")
    ]

    # -€-€ Trust anchors -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.trust_anchors = {
        "sys_cpu": ["attest", "trusted_telemetry"],
        "c1":      ["rot", "sboot", "key_storage", "trusted_telemetry"],
        "c2":      ["rot", "sboot", "key_storage", "trusted_telemetry"],
        "c3":      ["sboot"],
        "c4":      ["sboot"],
        "c5":      ["sboot"],
        "ps0":     ["signed_policy"],
    }

    # -€-€ PEP guards -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    for c in ["c1","c2","c3","c4","c5"]:
        model.pep_guards.append(("pep_group", c))
    for c in ["c6","c7","c8"]:
        model.pep_guards.append(("pep_standalone", c))

    # -€-€ PS governs PEP -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.ps_governs_pep = [
        ("ps0", "pep_group"), ("ps0", "pep_standalone"),
        ("ps1", "pep_group"),
    ]

    # -€-€ Mission capabilities -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.capabilities = [
        MissionCapability(
            name="compute",
            description="Parallel computation on accelerator group",
            required_services=["compute_svc"],
            required_components=[],
            required_access=[
                ("sys_cpu", "c1", "read"), ("sys_cpu", "c1", "write"),
                ("dma", "c1", "write"),
            ],
            criticality="essential",
        ),
        MissionCapability(
            name="monitoring",
            description="System health monitoring via monitor IP",
            required_services=["monitor_svc"],
            required_components=["c6"],
            required_access=[("sys_cpu", "c6", "read")],
            criticality="important",
        ),
        MissionCapability(
            name="io_transfer",
            description="External I/O data transfer",
            required_services=["io_svc"],
            required_components=["c8"],
            required_access=[("dma", "c8", "read")],
            criticality="important",
        ),
        MissionCapability(
            name="policy_management",
            description="ZTA policy distribution and enforcement",
            required_services=[],
            required_components=["ps0"],
            required_access=[],
            criticality="essential",
        ),
    ]

    return model


# ---------------------------------------------------------------------------
# DARPA CASE UAV factory
# ---------------------------------------------------------------------------

def make_darpa_uav_network() -> NetworkModel:
    """Create the DARPA CASE UAV benchmark as a first-class NetworkModel."""
    model = NetworkModel(name="darpa_case_uav")

    model.components = [
        Component("mc", "processor", "privileged", 0, 0, 1000, 1000,
                  exploitability=2, has_rot=True, has_sboot=True, has_attest=True,
                  is_master=True, is_receiver=False),
        Component("fc", "processor", "privileged", 0, 0, 1000, 1000,
                  exploitability=2, has_rot=True, has_sboot=True,
                  is_master=True, is_receiver=False, is_safety_critical=True),
        Component("gs", "processor", "untrusted", 0, 0, 1000, 1000,
                  exploitability=4, is_master=True, is_receiver=False),
        Component("radio_drv", "ip_core", "low", 4, 5, 10, 10,
                  impact_avail=4, exploitability=5),
        Component("fpln", "ip_core", "normal", 3, 5, 15, 15,
                  impact_avail=4, exploitability=3, is_critical=True),
        Component("wpm", "ip_core", "normal", 2, 5, 10, 10,
                  impact_avail=5, exploitability=3, is_critical=True),
        Component("cam_mgr", "ip_core", "normal", 2, 3, 1000, 1000,
                  exploitability=3),
        Component("wifi_drv", "ip_core", "untrusted", 3, 4, 1000, 1000,
                  impact_avail=2, exploitability=5),
        Component("uart_drv", "ip_core", "normal", 3, 5, 5, 5,
                  impact_avail=5, exploitability=3, is_critical=True,
                  is_safety_critical=True),
        Component("nfzdb", "ip_core", "high", 1, 5, 15, 1000,
                  impact_avail=4, exploitability=2, is_critical=True),
        Component("attest_gate", "ip_core", "root", 2, 0, 8, 1000,
                  impact_avail=5, exploitability=1, is_critical=True,
                  direction="input"),
        Component("geofence", "ip_core", "high", 2, 5, 10, 10,
                  impact_avail=5, exploitability=1, is_critical=True,
                  is_safety_critical=True),
        Component("fpln_filt", "ip_core", "high", 2, 5, 8, 8,
                  impact_avail=5, exploitability=1, is_critical=True,
                  is_safety_critical=True),
        Component("swu", "ip_core", "privileged", 3, 5, 1000, 1000,
                  exploitability=4, is_critical=True),
        Component("ps_mc", "policy_server", "root", 0, 0, 1000, 1000,
                  is_receiver=False),
        Component("ps_uart", "policy_server", "high", 0, 0, 1000, 1000,
                  is_receiver=False),
        Component("pep_mc", "firewall", "high", 0, 0, 1000, 1000,
                  is_receiver=False),
    ]

    model.assets = [
        Asset("radio_drvr1", "radio_drv", "bidirectional", 4, 5, 4, 10, 10),
        Asset("fplnr1", "fpln", "bidirectional", 3, 5, 4, 15, 15),
        Asset("wpmr1", "wpm", "bidirectional", 2, 5, 5, 10, 10),
        Asset("cam_mgrr1", "cam_mgr", "bidirectional", 2, 3, 0, 1000, 1000),
        Asset("wifi_drvr1", "wifi_drv", "bidirectional", 3, 4, 2, 1000, 1000),
        Asset("uart_drvr1", "uart_drv", "bidirectional", 3, 5, 5, 5, 5),
        Asset("nfzdbr1", "nfzdb", "bidirectional", 1, 5, 4, 15, 1000),
        Asset("attest_gater1", "attest_gate", "input", 2, 0, 5, 8, 1000),
        Asset("geofencer1", "geofence", "bidirectional", 2, 5, 5, 10, 10),
        Asset("fpln_filtr1", "fpln_filt", "bidirectional", 2, 5, 5, 8, 8),
        Asset("swur1", "swu", "bidirectional", 3, 5, 0, 1000, 1000),
    ]

    model.buses = ["bus_rf", "bus_mc", "bus_uart", "bus_wifi"]
    model.links = [
        ("gs", "bus_rf"),
        ("bus_rf", "radio_drv"),
        ("radio_drv", "bus_mc"),
        ("mc", "bus_mc"),
        ("bus_mc", "attest_gate"),
        ("bus_mc", "fpln"),
        ("bus_mc", "fpln_filt"),
        ("bus_mc", "geofence"),
        ("bus_mc", "wpm"),
        ("bus_mc", "cam_mgr"),
        ("bus_mc", "nfzdb"),
        ("bus_mc", "uart_drv"),
        ("bus_mc", "swu"),
        ("mc", "bus_wifi"),
        ("bus_wifi", "wifi_drv"),
        ("bus_wifi", "cam_mgr"),
        ("uart_drv", "bus_uart"),
        ("bus_uart", "fc"),
        ("fc", "bus_uart"),
    ]

    model.system_caps = {
        "max_power": 15000,
        "max_luts": 53200,
        "max_ffs": 106400,
        "max_dsps": 220,
        "max_lutram": 17400,
        "max_bufgs": 32,
        "max_bram": 140,
        "max_security_risk": 50,
        "max_avail_risk": 25,
        "max_attack_depth": 6,
    }

    model.cand_fws = ["pep_mc"]
    model.cand_ps = ["ps_mc", "ps_uart"]
    model.on_paths = [
        ("pep_mc", "gs", "attest_gate"),
        ("pep_mc", "gs", "fpln"),
        ("pep_mc", "gs", "fpln_filt"),
        ("pep_mc", "gs", "geofence"),
        ("pep_mc", "gs", "wpm"),
        ("pep_mc", "gs", "cam_mgr"),
        ("pep_mc", "gs", "nfzdb"),
        ("pep_mc", "gs", "uart_drv"),
        ("pep_mc", "gs", "swu"),
    ]
    model.ip_locs = [
        ("attest_gate", "pep_mc"),
        ("fpln", "pep_mc"),
        ("fpln_filt", "pep_mc"),
        ("geofence", "pep_mc"),
        ("wpm", "pep_mc"),
        ("cam_mgr", "pep_mc"),
        ("nfzdb", "pep_mc"),
        ("uart_drv", "pep_mc"),
        ("swu", "pep_mc"),
    ]
    model.fw_governs = [("ps_mc", "pep_mc"), ("ps_uart", "pep_mc")]
    model.fw_costs = {"pep_mc": 200}
    model.ps_costs = {"ps_mc": 200, "ps_uart": 150}
    model.pep_guards = [("pep_mc", comp) for comp, _fw in model.ip_locs]
    model.ps_governs_pep = list(model.fw_governs)

    model.allow_rules = [
        ("mc", "attest_gate", "normal"),
        ("mc", "fpln", "normal"),
        ("mc", "fpln_filt", "normal"),
        ("mc", "geofence", "normal"),
        ("mc", "wpm", "normal"),
        ("mc", "cam_mgr", "normal"),
        ("mc", "nfzdb", "normal"),
        ("mc", "uart_drv", "normal"),
        ("mc", "swu", "normal"),
        ("gs", "radio_drv", "normal"),
        ("fc", "uart_drv", "normal"),
    ]
    model.access_needs = [
        AccessNeed("mc", "fpln", "read"), AccessNeed("mc", "fpln", "write"),
        AccessNeed("mc", "fpln_filt", "read"), AccessNeed("mc", "fpln_filt", "write"),
        AccessNeed("mc", "geofence", "read"), AccessNeed("mc", "geofence", "write"),
        AccessNeed("mc", "wpm", "read"), AccessNeed("mc", "wpm", "write"),
        AccessNeed("mc", "cam_mgr", "read"), AccessNeed("mc", "cam_mgr", "write"),
        AccessNeed("mc", "uart_drv", "read"), AccessNeed("mc", "uart_drv", "write"),
        AccessNeed("mc", "nfzdb", "read"),
        AccessNeed("mc", "attest_gate", "read"),
        AccessNeed("mc", "radio_drv", "read"), AccessNeed("mc", "radio_drv", "write"),
        AccessNeed("gs", "radio_drv", "write"), AccessNeed("gs", "radio_drv", "read"),
        AccessNeed("fc", "uart_drv", "read"), AccessNeed("fc", "uart_drv", "write"),
    ]
    model.roles = [
        ("mc", "mission_computer"),
        ("gs", "ground_station"),
        ("fc", "flight_controller"),
    ]
    model.mission_access_rules = [
        "mission_access(M, C, Op, operational) :- access_need(M, C, Op).",
        "mission_access(mc, swu, read, maintenance).",
        "mission_access(mc, swu, write, maintenance).",
        "mission_access(mc, wifi_drv, read, maintenance).",
        "mission_access(mc, wifi_drv, write, maintenance).",
        "mission_access(M, C, Op, maintenance) :- access_need(M, C, Op).",
        "mission_access(M, C, read, emergency) :- master(M), receiver(C), access_need(M, C, read).",
    ]
    model.role_need_rules = [
        "role_need(mission_computer, C, read)  :- receiver(C), link(bus_mc, C).",
        "role_need(mission_computer, C, write) :- receiver(C), link(bus_mc, C), not C = nfzdb.",
        "role_need(ground_station, radio_drv, read).",
        "role_need(ground_station, radio_drv, write).",
        "role_need(flight_controller, uart_drv, read).",
        "role_need(flight_controller, uart_drv, write).",
    ]
    model.policy_exceptions = [
        ("gs", "fpln", "write", "emergency", "emergency_recovery"),
    ]

    model.trust_anchors = {
        "mc": ["rot", "sboot", "attest", "key_storage", "trusted_telemetry"],
        "fc": ["rot", "sboot"],
        "attest_gate": ["rot", "sboot", "key_storage", "trusted_telemetry"],
        "geofence": ["sboot"],
        "fpln_filt": ["sboot"],
        "nfzdb": ["key_storage"],
        "ps_mc": ["signed_policy"],
    }

    model.services = [
        Service("flight_safety_svc", ["fpln", "fpln_filt", "geofence", "wpm", "uart_drv"], quorum=5),
        Service("navigation_svc", ["nfzdb", "geofence"], quorum=2),
        Service("surveillance_svc", ["cam_mgr"], quorum=1),
        Service("comms_svc", ["radio_drv"], quorum=1),
        Service("maintenance_svc", ["wifi_drv", "swu"], quorum=2),
    ]

    model.capabilities = [
        MissionCapability(
            name="flight_control",
            description="Flight control command path from MC to FC.",
            required_services=["flight_safety_svc"],
            required_components=["fc", "uart_drv"],
            required_access=[("mc", "wpm", "write"), ("mc", "uart_drv", "write")],
            criticality="essential",
            mission_phases=["operational", "emergency"],
        ),
        MissionCapability(
            name="navigation",
            description="No-fly-zone-aware navigation and geofence enforcement.",
            required_services=["navigation_svc"],
            required_components=["geofence", "nfzdb"],
            required_access=[("mc", "geofence", "read"), ("mc", "nfzdb", "read")],
            criticality="essential",
            mission_phases=["operational"],
        ),
        MissionCapability(
            name="surveillance",
            description="Payload camera management and surveillance data handling.",
            required_services=["surveillance_svc"],
            required_components=["cam_mgr"],
            required_access=[("mc", "cam_mgr", "read")],
            criticality="important",
            mission_phases=["operational"],
        ),
        MissionCapability(
            name="ground_comms",
            description="Ground-station command and telemetry exchange.",
            required_services=["comms_svc"],
            required_components=["radio_drv"],
            required_access=[("mc", "radio_drv", "read"), ("gs", "radio_drv", "write")],
            criticality="essential",
            mission_phases=["operational", "emergency"],
        ),
        MissionCapability(
            name="ota_update",
            description="Maintenance-mode over-the-air update path.",
            required_services=["maintenance_svc"],
            required_components=["swu", "wifi_drv"],
            required_access=[("mc", "swu", "write")],
            criticality="important",
            mission_phases=["maintenance"],
        ),
        MissionCapability(
            name="policy_management",
            description="Policy distribution and enforcement control plane.",
            required_services=[],
            required_components=["ps_mc"],
            required_access=[],
            criticality="essential",
            mission_phases=["operational", "emergency"],
        ),
        MissionCapability(
            name="attestation",
            description="Attestation gate verification of mission-computer trust state.",
            required_services=[],
            required_components=["attest_gate"],
            required_access=[("mc", "attest_gate", "read")],
            criticality="essential",
            mission_phases=["operational"],
        ),
    ]

    model.scenarios = [
        {"name": "baseline", "compromised": [], "failed": []},
        {"name": "mc_compromise", "compromised": ["mc"], "failed": []},
        {"name": "fc_compromise", "compromised": ["fc"], "failed": []},
        {"name": "gs_compromise", "compromised": ["gs"], "failed": []},
        {"name": "radio_drv_compromise", "compromised": ["radio_drv"], "failed": []},
        {"name": "wifi_drv_compromise", "compromised": ["wifi_drv"], "failed": []},
        {"name": "swu_compromise", "compromised": ["swu"], "failed": []},
        {"name": "geofence_compromise", "compromised": ["geofence"], "failed": []},
        {"name": "fpln_filt_compromise", "compromised": ["fpln_filt"], "failed": []},
        {"name": "uart_drv_compromise", "compromised": ["uart_drv"], "failed": []},
        {"name": "bus_rf_failure", "compromised": [], "failed": ["bus_rf"]},
        {"name": "bus_mc_failure", "compromised": [], "failed": ["bus_mc"]},
        {"name": "bus_uart_failure", "compromised": [], "failed": ["bus_uart"]},
        {"name": "bus_wifi_failure", "compromised": [], "failed": ["bus_wifi"]},
        {"name": "fc_failure", "compromised": [], "failed": ["fc"]},
        {"name": "geofence_failure", "compromised": [], "failed": ["geofence"]},
        {"name": "uart_drv_failure", "compromised": [], "failed": ["uart_drv"]},
        {"name": "ps_mc_compromise", "compromised": ["ps_mc"], "failed": []},
        {"name": "ps_uart_compromise", "compromised": ["ps_uart"], "failed": []},
        {"name": "pep_mc_bypass", "compromised": ["pep_mc"], "failed": []},
        {"name": "all_ps_failure", "compromised": [], "failed": ["ps_mc", "ps_uart"]},
        {"name": "radio_drv_comp_bus_mc_fail", "compromised": ["radio_drv"], "failed": ["bus_mc"]},
        {"name": "mc_comp_bus_uart_fail", "compromised": ["mc"], "failed": ["bus_uart"]},
        {"name": "gs_radio_chain", "compromised": ["gs", "radio_drv"], "failed": []},
    ]

    return model


# ---------------------------------------------------------------------------
# OpenTitan-derived factory (ICCAD paper)
# ---------------------------------------------------------------------------

_OT_PROFILES: Dict[str, Dict[str, int]] = {
    "OT-A": {
        "max_power": 15000,
        "max_luts": 254200,
        "max_ffs": 508400,
        "max_dsps": 1540,
        "max_lutram": 80000,
        "max_bufgs": 32,
        "max_bram": 795,
        "max_security_risk": 200,
        "max_avail_risk": 200,
        "max_attack_depth": 6,
    },
    "OT-B": {
        "max_power": 15000,
        "max_luts": 25000,
        "max_ffs": 508400,
        "max_dsps": 1540,
        "max_lutram": 80000,
        "max_bufgs": 32,
        "max_bram": 795,
        "max_security_risk": 500,
        "max_avail_risk": 500,
        "max_attack_depth": 6,
    },
    "OT-C": {
        "max_power": 800,
        "max_luts": 254200,
        "max_ffs": 508400,
        "max_dsps": 1540,
        "max_lutram": 80000,
        "max_bufgs": 32,
        "max_bram": 795,
        "max_security_risk": 200,
        "max_avail_risk": 200,
        "max_attack_depth": 6,
    },
}


def make_opentitan_network(profile: str = "OT-A") -> NetworkModel:
    """
    Create the OpenTitan-derived ICCAD benchmark topology.

    The topology follows the paper's 20 protected components and two
    redundancy groups, with OT-A / OT-B / OT-C profile overlays applied
    through system_caps.
    """
    if profile not in _OT_PROFILES:
        raise ValueError(f"Unknown OpenTitan profile: {profile}")

    comps = [
        Component("cpu", "processor", "privileged", 5, 5, 5, 5,
                  exploitability=2, has_rot=True, has_sboot=True,
                  has_attest=True, is_master=True, is_receiver=False,
                  is_critical=True),
        Component("dma", "dma", "normal", 4, 4, 5, 5,
                  exploitability=3, is_master=True, is_receiver=False,
                  is_critical=True),
        Component("ot_bus", "bus", "normal", 0, 0, 1000, 1000,
                  is_master=False, is_receiver=False),
        Component("pep_ot", "firewall", "high", 0, 0, 1000, 1000,
                  is_master=False, is_receiver=False),
        Component("ps_ot", "policy_server", "root", 0, 0, 1000, 1000,
                  has_rot=True, has_sboot=True, is_master=False, is_receiver=False),
        Component("aes", "ip_core", "high", 5, 5, 7, 7,
                  exploitability=2, is_critical=True),
        Component("hmac", "ip_core", "high", 4, 5, 8, 8,
                  exploitability=2, is_critical=True),
        Component("kmac", "ip_core", "high", 4, 5, 8, 8,
                  exploitability=2, is_critical=True),
        Component("otbn", "ip_core", "high", 5, 5, 7, 7,
                  exploitability=2, is_critical=True),
        Component("keymgr", "ip_core", "root", 5, 5, 5, 5,
                  exploitability=1, has_rot=True, has_sboot=True, is_critical=True),
        Component("otp", "ip_core", "root", 5, 4, 8, 8,
                  exploitability=1, has_rot=True, is_critical=True),
        Component("lc", "ip_core", "root", 5, 4, 8, 8,
                  exploitability=2, is_critical=True),
        Component("flash", "ip_core", "privileged", 4, 4, 8, 8,
                  exploitability=3, is_critical=True),
        Component("sram", "ip_core", "normal", 3, 3, 8, 8,
                  exploitability=3),
        Component("rom", "ip_core", "root", 3, 2, 8, 8,
                  exploitability=1, has_sboot=True, is_critical=True),
        Component("uart0", "ip_core", "low", 2, 2, 8, 8,
                  exploitability=4, direction="bidirectional"),
        Component("uart1", "ip_core", "low", 2, 2, 8, 8,
                  exploitability=4, direction="bidirectional"),
        Component("gpio", "ip_core", "low", 1, 2, 8, 8,
                  exploitability=4, direction="bidirectional"),
        Component("spi", "ip_core", "normal", 2, 3, 8, 8,
                  exploitability=3, direction="bidirectional"),
        Component("i2c", "ip_core", "normal", 2, 2, 8, 8,
                  exploitability=3, direction="bidirectional"),
        Component("timer", "ip_core", "normal", 1, 1, 8, 8,
                  exploitability=3),
        Component("alert", "ip_core", "high", 4, 3, 8, 8,
                  exploitability=2, is_critical=True, is_safety_critical=True,
                  direction="input"),
        Component("entropy", "ip_core", "root", 4, 4, 8, 8,
                  exploitability=2, is_critical=True, direction="output"),
    ]

    protected_names = [
        "cpu", "dma", "aes", "hmac", "kmac", "otbn", "keymgr", "otp", "lc",
        "flash", "sram", "rom", "uart0", "uart1", "gpio", "spi", "i2c",
        "timer", "alert", "entropy",
    ]
    comp_map = {c.name: c for c in comps}
    assets = [
        Asset(
            asset_id=f"{name}_a0",
            component=name,
            direction=comp_map[name].direction,
            impact_read=comp_map[name].impact_read,
            impact_write=comp_map[name].impact_write,
            impact_avail=0,
            latency_read=comp_map[name].latency_read,
            latency_write=comp_map[name].latency_write,
        )
        for name in protected_names
    ]

    links = [
        ("cpu", "ot_bus"),
        ("dma", "ot_bus"),
        ("ps_ot", "ot_bus"),
        ("ot_bus", "pep_ot"),
    ]
    links.extend(("pep_ot", name) for name in protected_names if name not in {"cpu", "dma"})

    model = NetworkModel(
        name=f"OpenTitan ({profile})",
        components=comps,
        assets=assets,
        links=links,
        buses=["ot_bus"],
        redundancy_groups=[
            RedundancyGroup("crypto_cover", ["aes", "hmac", "kmac"]),
            RedundancyGroup("uart_cover", ["uart0", "uart1"]),
        ],
        services=[
            Service("boot_chain", ["rom", "flash", "keymgr", "otp", "lc", "alert"], quorum=5),
            Service("crypto_svc", ["aes", "hmac", "kmac", "otbn", "entropy"], quorum=3),
            Service("peripheral_svc", ["uart0", "uart1", "gpio", "spi", "i2c", "timer"], quorum=3),
        ],
        access_needs=[
            AccessNeed("cpu", "rom", "read"),
            AccessNeed("cpu", "flash", "read"),
            AccessNeed("cpu", "sram", "read"),
            AccessNeed("cpu", "sram", "write"),
            AccessNeed("cpu", "keymgr", "read"),
            AccessNeed("cpu", "otp", "read"),
            AccessNeed("cpu", "lc", "read"),
            AccessNeed("cpu", "aes", "read"),
            AccessNeed("cpu", "hmac", "read"),
            AccessNeed("cpu", "kmac", "read"),
            AccessNeed("cpu", "otbn", "read"),
            AccessNeed("cpu", "uart0", "write"),
            AccessNeed("cpu", "uart1", "write"),
            AccessNeed("cpu", "gpio", "write"),
            AccessNeed("cpu", "spi", "read"),
            AccessNeed("cpu", "i2c", "read"),
            AccessNeed("dma", "sram", "read"),
            AccessNeed("dma", "sram", "write"),
            AccessNeed("dma", "flash", "read"),
            AccessNeed("dma", "uart0", "write"),
            AccessNeed("dma", "uart1", "write"),
        ],
        system_caps=dict(_OT_PROFILES[profile]),
        cand_fws=["pep_ot"],
        cand_ps=["ps_ot"],
        on_paths=[("pep_ot", master, ip) for master in ("cpu", "dma") for ip in protected_names if ip not in {"cpu", "dma"}],
        ip_locs=[(ip, "pep_ot") for ip in protected_names if ip not in {"cpu", "dma"}],
        fw_governs=[("ps_ot", "pep_ot")],
        fw_costs={"pep_ot": 250},
        ps_costs={"ps_ot": 180},
        roles=[("cpu", "ot_cpu"), ("dma", "ot_dma")],
        allow_rules=[],
        policy_exceptions=[
            ("cpu", "rom", "read", "normal", "boot_rom_required"),
            ("cpu", "alert", "read", "normal", "alert_status_visible"),
        ],
        trust_anchors={
            "cpu": ["rot", "sboot", "attest", "key_storage"],
            "ps_ot": ["rot", "sboot", "signed_policy"],
            "keymgr": ["rot", "sboot", "key_storage"],
            "otp": ["rot", "key_storage"],
            "rom": ["sboot"],
            "alert": ["trusted_telemetry"],
            "entropy": ["trusted_telemetry"],
        },
        pep_guards=[("pep_ot", ip) for ip in protected_names if ip not in {"cpu", "dma"}],
        ps_governs_pep=[("ps_ot", "pep_ot")],
        mission_phases=["boot", "normal", "maintenance"],
        capabilities=[
            MissionCapability(
                name="secure_boot",
                description="Boot from trusted immutable code and provision keys",
                required_services=["boot_chain"],
                required_components=["cpu", "rom", "flash", "keymgr", "otp", "lc"],
                required_access=[("cpu", "rom", "read"), ("cpu", "flash", "read"), ("cpu", "keymgr", "read")],
                criticality="essential",
                mission_phases=["boot"],
            ),
            MissionCapability(
                name="crypto_ops",
                description="Symmetric and asymmetric cryptographic services",
                required_services=["crypto_svc"],
                required_components=["aes", "hmac", "kmac", "otbn", "entropy"],
                required_access=[("cpu", "aes", "read"), ("cpu", "otbn", "read")],
                criticality="essential",
            ),
            MissionCapability(
                name="serial_io",
                description="Serial and peripheral communication",
                required_services=["peripheral_svc"],
                required_components=["uart0", "uart1", "gpio", "spi", "i2c"],
                required_access=[("cpu", "uart0", "write"), ("cpu", "spi", "read")],
                criticality="important",
            ),
            MissionCapability(
                name="secure_lifecycle",
                description="Lifecycle and alert management",
                required_services=["boot_chain"],
                required_components=["lc", "alert", "keymgr"],
                required_access=[("cpu", "lc", "read"), ("cpu", "alert", "read")],
                criticality="essential",
            ),
        ],
    )
    return model


def make_pixhawk6x_platform() -> NetworkModel:
    """
    Create a documentation-faithful Pixhawk 6X platform model.

    This model captures board-level structure only. Vehicle integration choices
    such as radios, GPS receivers, companion computers, ESC topology, and
    logging devices are added by ``make_pixhawk6x_uav_network()``.
    """
    model = NetworkModel(name="Pixhawk 6X Platform")

    model.components = [
        Component(
            "fmu_h753", "processor", "privileged", 5, 5, 4, 4,
            impact_avail=5, exploitability=2,
            has_rot=True, has_sboot=True, has_attest=True,
            is_master=True, is_receiver=False,
            is_critical=True, is_safety_critical=True,
        ),
        Component(
            "io_mcu", "processor", "normal", 2, 4, 8, 8,
            impact_avail=5, exploitability=2,
            is_master=False, is_receiver=True,
            is_critical=True, is_safety_critical=True,
        ),
        Component(
            "ps_fmu", "policy_server", "root", 1, 1, 1000, 1000,
            is_master=False, is_receiver=False,
        ),
        Component(
            "imu_1", "ip_core", "high", 4, 1, 4, 1000,
            impact_avail=4, exploitability=2,
            direction="input", is_critical=True, is_safety_critical=True,
        ),
        Component(
            "imu_2", "ip_core", "high", 4, 1, 4, 1000,
            impact_avail=4, exploitability=2,
            direction="input", is_critical=True, is_safety_critical=True,
        ),
        Component(
            "imu_3", "ip_core", "high", 4, 1, 4, 1000,
            impact_avail=4, exploitability=2,
            direction="input", is_critical=True, is_safety_critical=True,
        ),
        Component(
            "baro_1", "ip_core", "normal", 3, 1, 8, 1000,
            impact_avail=3, exploitability=2,
            direction="input", is_critical=True,
        ),
        Component(
            "baro_2", "ip_core", "normal", 3, 1, 8, 1000,
            impact_avail=3, exploitability=2,
            direction="input", is_critical=True,
        ),
        Component(
            "mag", "ip_core", "normal", 2, 1, 8, 1000,
            impact_avail=2, exploitability=2,
            direction="input", is_critical=True,
        ),
        Component(
            "se050", "ip_core", "root", 5, 5, 10, 10,
            impact_avail=2, exploitability=1,
            direction="bidirectional", is_critical=True,
            has_rot=True, has_sboot=True,
        ),
    ]

    model.assets = [
        Asset("imu1_data", "imu_1", direction="input", impact_read=4, impact_write=0, impact_avail=4, latency_read=4),
        Asset("imu2_data", "imu_2", direction="input", impact_read=4, impact_write=0, impact_avail=4, latency_read=4),
        Asset("imu3_data", "imu_3", direction="input", impact_read=4, impact_write=0, impact_avail=4, latency_read=4),
        Asset("baro1_data", "baro_1", direction="input", impact_read=3, impact_write=0, impact_avail=3, latency_read=8),
        Asset("baro2_data", "baro_2", direction="input", impact_read=3, impact_write=0, impact_avail=3, latency_read=8),
        Asset("mag_data", "mag", direction="input", impact_read=2, impact_write=0, impact_avail=2, latency_read=8),
        Asset("se050_ctrl", "se050", direction="bidirectional", impact_read=5, impact_write=5, impact_avail=2, latency_read=10, latency_write=10),
        Asset("px4io_status", "io_mcu", direction="bidirectional", impact_read=2, impact_write=4, impact_avail=5, latency_read=8, latency_write=8),
    ]

    # Bus topology notes (verified against PX4-Autopilot FMUv6X source):
    #
    # IMU buses  --  TRUE physical isolation.
    #   spi.cpp confirms each ICM-45686 on a dedicated SPI peripheral:
    #     imu_bus_1 → SPI1 (CS: PI9,  DRDY: PF2)
    #     imu_bus_2 → SPI2 (CS: PH5,  DRDY: PA10)
    #     imu_bus_3 → SPI3 (CS: PI4,  DRDY: PI7)
    #   A single SPI peripheral failure affects only one IMU.
    #
    # Barometer buses  --  separate via internal/external I2C split.
    #   i2c.cpp defines only ONE internal I2C bus (bus 4, hardware I2C4).
    #   rc.board_sensors shows the Pixhawk 6X runs one baro internally
    #   (ICP-201xx at 0x64 or BMP388 at 0x77, variant-dependent) on I2C
    #   bus 4, and one baro externally on I2C bus 1/2/3. This gives true
    #   bus-level isolation between baro_bus_1 (internal) and baro_bus_2
    #   (external), since they use different I2C peripheral blocks on the
    #   STM32H753. Modeling them as separate buses is correct.
    #   ArduPilot wiki (common-holybro-pixhawk6X.rst) independently confirms:
    #   "double redundant barometers on separate buses".
    #
    # Sources:
    #   github.com/PX4/PX4-Autopilot/blob/main/boards/px4/fmu-v6x/src/spi.cpp
    #   github.com/PX4/PX4-Autopilot/blob/main/boards/px4/fmu-v6x/src/i2c.cpp
    #   github.com/PX4/PX4-Autopilot/blob/main/boards/px4/fmu-v6x/init/rc.board_sensors
    model.buses = [
        "imu_bus_1", "imu_bus_2", "imu_bus_3",
        "baro_bus_1", "baro_bus_2", "mag_bus",
        "gps1_port", "gps2_port",
        "telem1_port", "telem2_port", "telem3_port",
        "uart4_i2c_port", "eth_port", "spi5_ext",
        "can1", "can2", "px4io_link",
    ]

    model.links = [
        ("fmu_h753", "imu_bus_1"), ("imu_bus_1", "imu_1"),
        ("fmu_h753", "imu_bus_2"), ("imu_bus_2", "imu_2"),
        ("fmu_h753", "imu_bus_3"), ("imu_bus_3", "imu_3"),
        ("fmu_h753", "baro_bus_1"), ("baro_bus_1", "baro_1"),
        ("fmu_h753", "baro_bus_2"), ("baro_bus_2", "baro_2"),
        ("fmu_h753", "mag_bus"), ("mag_bus", "mag"),
        ("fmu_h753", "gps1_port"),
        ("fmu_h753", "gps2_port"),
        ("fmu_h753", "telem1_port"),
        ("fmu_h753", "telem2_port"),
        ("fmu_h753", "telem3_port"),
        ("fmu_h753", "uart4_i2c_port"),
        ("fmu_h753", "eth_port"),
        ("fmu_h753", "spi5_ext"),
        ("fmu_h753", "can1"),
        ("fmu_h753", "can2"),
        ("fmu_h753", "px4io_link"), ("px4io_link", "io_mcu"),
        ("fmu_h753", "se050"),
    ]

    model.redundancy_groups = [
        RedundancyGroup("imu_group", ["imu_1", "imu_2", "imu_3"]),
        RedundancyGroup("baro_group", ["baro_1", "baro_2"]),
    ]

    model.services = [
        Service("attitude_sensor_svc", ["imu_1", "imu_2", "imu_3"], 2),
        Service("altitude_sensor_svc", ["baro_1", "baro_2"], 1),
        Service("mag_sensor_svc", ["mag"], 1),
        Service("crypto_svc", ["se050"], 1),
        Service("io_failsafe_svc", ["io_mcu"], 1),
    ]

    model.access_needs = [
        AccessNeed("fmu_h753", "imu_1", "read"),
        AccessNeed("fmu_h753", "imu_2", "read"),
        AccessNeed("fmu_h753", "imu_3", "read"),
        AccessNeed("fmu_h753", "baro_1", "read"),
        AccessNeed("fmu_h753", "baro_2", "read"),
        AccessNeed("fmu_h753", "mag", "read"),
        AccessNeed("fmu_h753", "se050", "read"),
        AccessNeed("fmu_h753", "se050", "write"),
        AccessNeed("fmu_h753", "io_mcu", "read"),
        AccessNeed("fmu_h753", "io_mcu", "write"),
    ]

    model.system_caps = {
        "max_power": 15000,
        "max_luts": 53200,
        "max_ffs": 106400,
        "max_dsps": 220,
        "max_lutram": 17400,
        "max_bufgs": 32,
        "max_bram": 140,
        "max_security_risk": 60,
        "max_avail_risk": 25,
        "max_attack_depth": 8,
    }

    model.cand_fws = ["pep_px4io", "pep_se050"]
    model.cand_ps = ["ps_fmu"]
    model.on_paths = [
        ("pep_px4io", "fmu_h753", "io_mcu"),
        ("pep_se050", "fmu_h753", "se050"),
    ]
    model.ip_locs = [("io_mcu", "pep_px4io"), ("se050", "pep_se050")]
    model.fw_governs = [("ps_fmu", "pep_px4io"), ("ps_fmu", "pep_se050")]
    model.fw_costs = {"pep_px4io": 120, "pep_se050": 100}
    model.ps_costs = {"ps_fmu": 180}
    model.roles = [("fmu_h753", "flight_controller")]
    model.allow_rules = [(an.master, an.component, "normal") for an in model.access_needs]
    model.trust_anchors = {
        "fmu_h753": ["rot", "sboot", "attest"],
        "se050": ["rot", "key_storage"],
        "ps_fmu": ["signed_policy"],
    }
    model.pep_guards = [("pep_px4io", "io_mcu"), ("pep_se050", "se050")]
    model.ps_governs_pep = [("ps_fmu", "pep_px4io"), ("ps_fmu", "pep_se050")]
    model.capabilities = [
        MissionCapability(
            name="flight_stabilization_base",
            description="On-board inertial and barometric sensing for flight stabilization",
            required_services=["attitude_sensor_svc", "altitude_sensor_svc"],
            required_components=["fmu_h753"],
            # Preserve quorum semantics from the backing services instead of
            # pinning this capability to one IMU and one barometer member.
            required_access=[],
            criticality="essential",
            mission_phases=["operational", "emergency"],
        ),
        MissionCapability(
            name="failsafe_io",
            description="Independent IO processing path for RC and failsafe functions",
            required_services=["io_failsafe_svc"],
            required_components=["io_mcu"],
            required_access=[("fmu_h753", "io_mcu", "write")],
            criticality="essential",
            mission_phases=["operational", "emergency"],
        ),
        MissionCapability(
            name="crypto_anchor",
            description="Board-integrated hardware root of trust and key handling",
            required_services=["crypto_svc"],
            required_components=["se050"],
            required_access=[
                ("fmu_h753", "se050", "read"),
                ("fmu_h753", "se050", "write"),
            ],
            criticality="important",
        ),
    ]

    return model


def make_pixhawk6x_uav_network() -> NetworkModel:
    """
    Create a Pixhawk 6X UAV integration overlay on top of the base platform.
    """
    model = make_pixhawk6x_platform()
    model.name = "Pixhawk 6X UAV"

    model.components.extend([
        Component(
            "ground_station", "processor", "untrusted", 3, 3, 1000, 1000,
            impact_avail=1, exploitability=5,
            is_master=True, is_receiver=False,
        ),
        Component(
            "gps_1", "ip_core", "low", 4, 1, 12, 1000,
            impact_avail=4, exploitability=4,
            direction="input", is_critical=True,
        ),
        Component(
            "gps_2", "ip_core", "low", 4, 1, 12, 1000,
            impact_avail=4, exploitability=4,
            direction="input", is_critical=True,
        ),
        Component(
            "telem_radio", "ip_core", "untrusted", 4, 4, 15, 15,
            impact_avail=4, exploitability=5,
            direction="bidirectional", is_critical=True,
        ),
        Component(
            "rc_receiver", "ip_core", "low", 2, 1, 20, 1000,
            impact_avail=5, exploitability=4,
            direction="input", is_critical=True, is_safety_critical=True,
        ),
        Component(
            "esc_bus_1", "ip_core", "privileged", 1, 5, 1000, 5,
            impact_avail=5, exploitability=2,
            direction="output", is_critical=True, is_safety_critical=True,
        ),
        Component(
            "esc_bus_2", "ip_core", "privileged", 1, 5, 1000, 5,
            impact_avail=5, exploitability=2,
            direction="output", is_critical=True, is_safety_critical=True,
        ),
        Component(
            "companion", "ip_core", "normal", 3, 3, 20, 20,
            impact_avail=3, exploitability=4,
            direction="bidirectional", is_critical=True,
        ),
        Component(
            "camera", "ip_core", "normal", 3, 1, 20, 1000,
            impact_avail=2, exploitability=3,
            direction="input",
        ),
        Component(
            "flash_fram", "ip_core", "privileged", 3, 4, 12, 12,
            impact_avail=3, exploitability=2,
            direction="bidirectional", is_critical=True,
        ),
    ])

    model.assets.extend([
        Asset("gps1_nav", "gps_1", direction="input", impact_read=4, impact_write=0, impact_avail=4, latency_read=12),
        Asset("gps2_nav", "gps_2", direction="input", impact_read=4, impact_write=0, impact_avail=4, latency_read=12),
        Asset("telem_link", "telem_radio", direction="bidirectional", impact_read=4, impact_write=4, impact_avail=4, latency_read=15, latency_write=15),
        Asset("rc_input", "rc_receiver", direction="input", impact_read=2, impact_write=0, impact_avail=5, latency_read=20),
        Asset("motor_cmd_1", "esc_bus_1", direction="output", impact_read=0, impact_write=5, impact_avail=5, latency_write=5),
        Asset("motor_cmd_2", "esc_bus_2", direction="output", impact_read=0, impact_write=5, impact_avail=5, latency_write=5),
        Asset("companion_eth", "companion", direction="bidirectional", impact_read=3, impact_write=3, impact_avail=3, latency_read=20, latency_write=20),
        Asset("camera_stream", "camera", direction="input", impact_read=3, impact_write=0, impact_avail=2, latency_read=20),
        Asset("log_store", "flash_fram", direction="bidirectional", impact_read=3, impact_write=4, impact_avail=3, latency_read=12, latency_write=12),
    ])

    model.links.extend([
        ("ground_station", "telem_radio"),
        ("fmu_h753", "gps1_port"), ("gps1_port", "gps_1"),
        ("fmu_h753", "gps2_port"), ("gps2_port", "gps_2"),
        ("fmu_h753", "telem1_port"), ("telem1_port", "telem_radio"),
        ("fmu_h753", "px4io_link"), ("px4io_link", "rc_receiver"),
        ("fmu_h753", "can1"), ("can1", "esc_bus_1"),
        ("fmu_h753", "can2"), ("can2", "esc_bus_2"),
        ("fmu_h753", "eth_port"), ("eth_port", "companion"),
        ("companion", "camera"),
        ("fmu_h753", "spi5_ext"), ("spi5_ext", "flash_fram"),
    ])

    model.redundancy_groups.extend([
        RedundancyGroup("gps_group", ["gps_1", "gps_2"]),
        RedundancyGroup("motor_bus_group", ["esc_bus_1", "esc_bus_2"]),
    ])

    model.services = [
        Service("attitude_svc", ["imu_1", "imu_2", "imu_3"], 2),
        Service("altitude_svc", ["baro_1", "baro_2"], 1),
        Service("navigation_svc", ["gps_1", "gps_2"], 1),
        Service("motor_svc", ["esc_bus_1", "esc_bus_2"], 1),
        Service("comms_svc", ["telem_radio"], 1),
        Service("failsafe_svc", ["io_mcu", "rc_receiver"], 2),
        Service("crypto_svc", ["se050"], 1),
        Service("payload_svc", ["companion", "camera"], 2),
        Service("logging_svc", ["flash_fram"], 1),
    ]

    model.access_needs.extend([
        AccessNeed("ground_station", "telem_radio", "read"),
        AccessNeed("ground_station", "telem_radio", "write"),
        AccessNeed("fmu_h753", "gps_1", "read"),
        AccessNeed("fmu_h753", "gps_2", "read"),
        AccessNeed("fmu_h753", "telem_radio", "read"),
        AccessNeed("fmu_h753", "telem_radio", "write"),
        AccessNeed("fmu_h753", "rc_receiver", "read"),
        AccessNeed("fmu_h753", "esc_bus_1", "write"),
        AccessNeed("fmu_h753", "esc_bus_2", "write"),
        AccessNeed("fmu_h753", "companion", "read"),
        AccessNeed("fmu_h753", "companion", "write"),
        AccessNeed("fmu_h753", "camera", "read"),
        AccessNeed("fmu_h753", "flash_fram", "read"),
        AccessNeed("fmu_h753", "flash_fram", "write"),
    ])

    model.cand_fws = [
        "pep_px4io", "pep_se050",
        "pep_telem1", "pep_eth", "pep_can1", "pep_can2", "pep_gps2",
    ]
    model.on_paths = [
        ("pep_px4io", "fmu_h753", "io_mcu"),
        ("pep_se050", "fmu_h753", "se050"),
        ("pep_telem1", "fmu_h753", "telem_radio"),
        ("pep_telem1", "ground_station", "telem_radio"),
        ("pep_eth", "fmu_h753", "companion"),
        ("pep_can1", "fmu_h753", "esc_bus_1"),
        ("pep_can2", "fmu_h753", "esc_bus_2"),
        ("pep_gps2", "fmu_h753", "gps_2"),
    ]
    model.ip_locs = [
        ("io_mcu", "pep_px4io"),
        ("se050", "pep_se050"),
        ("telem_radio", "pep_telem1"),
        ("companion", "pep_eth"),
        ("esc_bus_1", "pep_can1"),
        ("esc_bus_2", "pep_can2"),
        ("gps_2", "pep_gps2"),
    ]
    model.fw_governs = [("ps_fmu", fw) for fw in model.cand_fws]
    model.fw_costs = {
        "pep_px4io": 120,
        "pep_se050": 100,
        "pep_telem1": 160,
        "pep_eth": 180,
        "pep_can1": 140,
        "pep_can2": 140,
        "pep_gps2": 110,
    }
    model.roles = [
        ("fmu_h753", "flight_controller"),
        ("ground_station", "external_operator"),
    ]
    model.allow_rules = [(an.master, an.component, "normal") for an in model.access_needs]
    model.policy_exceptions = [
        ("fmu_h753", "telem_radio", "write", "emergency", "status_broadcast"),
        ("fmu_h753", "flash_fram", "write", "maintenance", "log_export"),
    ]
    model.pep_guards = [
        ("pep_px4io", "io_mcu"),
        ("pep_se050", "se050"),
        ("pep_telem1", "telem_radio"),
        ("pep_eth", "companion"),
        ("pep_can1", "esc_bus_1"),
        ("pep_can2", "esc_bus_2"),
        ("pep_gps2", "gps_2"),
    ]
    model.ps_governs_pep = [("ps_fmu", fw) for fw in model.cand_fws]
    model.capabilities = [
        MissionCapability(
            name="flight_control",
            description="Stabilized flight using inertial sensing and actuator command paths",
            required_services=["attitude_svc", "motor_svc"],
            required_components=["fmu_h753"],
            # Preserve redundant sensor/actuator quorum semantics rather than
            # forcing one specific IMU and one specific motor bus.
            required_access=[],
            criticality="essential",
            mission_phases=["operational", "emergency"],
        ),
        MissionCapability(
            name="navigation",
            description="Position and altitude estimation using dual GPS and barometric sensing",
            required_services=["navigation_svc", "altitude_svc"],
            required_components=[],
            # Navigation should track service-level sensor availability rather
            # than requiring one named GPS and one named barometer.
            required_access=[],
            criticality="essential",
            mission_phases=["operational"],
        ),
        MissionCapability(
            name="ground_comms",
            description="Bidirectional telemetry exchange with the ground station",
            required_services=["comms_svc"],
            required_components=["telem_radio"],
            required_access=[
                ("fmu_h753", "telem_radio", "read"),
                ("fmu_h753", "telem_radio", "write"),
            ],
            criticality="essential",
            mission_phases=["operational", "emergency"],
        ),
        MissionCapability(
            name="rc_override",
            description="Independent RC-based override and failsafe path",
            required_services=["failsafe_svc"],
            required_components=["io_mcu", "rc_receiver"],
            required_access=[("fmu_h753", "rc_receiver", "read")],
            criticality="essential",
            mission_phases=["operational", "emergency"],
        ),
        MissionCapability(
            name="surveillance",
            description="Payload observation path via companion compute and camera",
            required_services=["payload_svc"],
            required_components=["companion", "camera"],
            required_access=[("fmu_h753", "companion", "read")],
            criticality="important",
            mission_phases=["operational"],
        ),
        MissionCapability(
            name="crypto_ops",
            description="Hardware-rooted cryptographic operations and key handling",
            required_services=["crypto_svc"],
            required_components=["se050"],
            required_access=[
                ("fmu_h753", "se050", "read"),
                ("fmu_h753", "se050", "write"),
            ],
            criticality="important",
            mission_phases=["operational", "maintenance"],
        ),
        MissionCapability(
            name="logging",
            description="Persistent flight logging to SPI-attached storage",
            required_services=["logging_svc"],
            required_components=["flash_fram"],
            required_access=[
                ("fmu_h753", "flash_fram", "read"),
                ("fmu_h753", "flash_fram", "write"),
            ],
            criticality="important",
            mission_phases=["operational", "maintenance"],
        ),
    ]

    return model


def make_pixhawk6x_uav_dual_ps_network() -> NetworkModel:
    """
    Create a revised Pixhawk 6X UAV overlay with split control-plane governance.

    This variant preserves the documented board and UAV topology but adds a
    second candidate policy server (`ps_io`) associated with the I/O/safety
    side of the architecture. The intent is to compare the baseline single-PS
    design against a decentralized control-plane option.
    """
    model = make_pixhawk6x_uav_network()
    model.name = "Pixhawk 6X UAV (Dual-PS)"

    model.components.append(
        Component(
            "ps_io", "policy_server", "root", 1, 1, 1000, 1000,
            is_master=False, is_receiver=False,
        )
    )

    model.links.append(("io_mcu", "ps_io"))

    model.cand_ps = ["ps_fmu", "ps_io"]
    model.fw_governs = [
        ("ps_fmu", "pep_se050"),
        ("ps_fmu", "pep_telem1"),
        ("ps_fmu", "pep_eth"),
        ("ps_fmu", "pep_gps2"),
        ("ps_io", "pep_px4io"),
        ("ps_io", "pep_can1"),
        ("ps_io", "pep_can2"),
    ]
    model.ps_costs = {
        "ps_fmu": 180,
        "ps_io": 160,
    }
    model.trust_anchors["ps_io"] = ["signed_policy"]
    model.ps_governs_pep = list(model.fw_governs)

    return model


def make_pixhawk6x_dual_ps_network() -> NetworkModel:
    """Compatibility alias for the revised Pixhawk 6X dual-policy-server UAV variant."""
    return make_pixhawk6x_uav_dual_ps_network()


# ---------------------------------------------------------------------------
# Reference SoC factory  --  exercises every DSE tool feature
# ---------------------------------------------------------------------------

def make_reference_soc() -> NetworkModel:
    """
    Create a generic reference SoC that exercises every DSE tool feature.

    SecureSoC-16 Reference Architecture
    ====================================

    Designed to exercise:
      - All 6 domain levels (untrusted, low, normal, privileged, high, root)
      - Full CIA triad (read / write / avail impacts)
      - Exploitability range 1-5
      - Redundancy groups (triple-redundant sensors)
      - Safety-critical and non-safety-critical components
      - All trust anchor types (RoT, sboot, attest, signed_policy, key_storage)
      - Multiple bus segments with distinct trust boundaries
      - Meaningful access patterns for least-privilege analysis
      - Policy exceptions and mission phases
      - Services with quorum requirements

    Topology
    --------
    Masters:
      arm_a53      --  App processor, privileged, RoT+sboot+attest, exploitability=2
      arm_m4       --  RT processor, normal, sboot only, exploitability=3
      dma0         --  DMA controller, normal, exploitability=4 (DMA attack class)

    Buses:
      axi_main     --  Primary AXI interconnect
      axi_sec      --  Secure AXI segment (crypto, NVRAM)
      apb_periph   --  APB peripheral bus (sensors, GPIO, debug)

    IP Cores:
      crypto_eng   --  Crypto accelerator, root, safety-critical, exploit=1
      sensor_a     --  Temp sensor, input, normal, avail=4 (redundant group)
      sensor_b     --  Pressure sensor, input, normal, avail=4 (redundant group)
      sensor_c     --  Voltage monitor, input, normal, avail=3 (redundant group)
      actuator     --  Motor/PWM controller, output, privileged, safety-critical
      comm_eth     --  Ethernet interface, bidirectional, untrusted, exploit=5
      watchdog     --  Watchdog timer, privileged, avail=5, low C/I
      nvram        --  Non-volatile storage, privileged, high C/I
      gpio         --  GPIO block, bidirectional, low domain
      debug_jtag   --  Debug port, untrusted, exploit=5

    Firewalls:
      fw_secure    --  Guards axi_sec segment (crypto, nvram)
      fw_periph    --  Guards apb_periph (sensors, gpio, debug, watchdog)

    Policy Servers:
      ps_main      --  Primary PS, signed policy
      ps_backup    --  Backup PS

    Redundancy:
      Group g1: sensor_a, sensor_b, sensor_c (triple-redundant)

    Services:
      sensor_svc   --  {sensor_a, sensor_b, sensor_c}, quorum=2
      control_svc  --  {actuator, watchdog}, quorum=2
      comms_svc    --  {comm_eth}, quorum=1
      crypto_svc   --  {crypto_eng}, quorum=1
    """
    model = NetworkModel(name="SecureSoC-16")

    # -€-€ Components -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    # Component(name, type, domain, imp_r, imp_w, lat_r, lat_w, impact_avail, exploitability, ...)
    model.components = [
        # Masters
        Component("arm_a53", "processor", "privileged", 5, 5, 1000, 1000,
                  impact_avail=3, exploitability=2,
                  is_master=True, is_receiver=False,
                  has_rot=True, has_sboot=True, has_attest=True),
        Component("arm_m4",  "processor", "normal",     3, 4, 1000, 1000,
                  impact_avail=4, exploitability=3,
                  is_master=True, is_receiver=False,
                  has_sboot=True),
        Component("dma0",    "dma",       "normal",     4, 4, 1000, 1000,
                  impact_avail=2, exploitability=4,
                  is_master=True, is_receiver=False),

        # Secure-domain IP cores
        Component("crypto_eng", "ip_core", "root",       4, 3, 5, 8,
                  impact_avail=2, exploitability=1,
                  is_critical=True, is_safety_critical=True,
                  has_rot=True, has_sboot=True),
        Component("nvram",      "ip_core", "privileged", 5, 5, 8, 12,
                  impact_avail=3, exploitability=2,
                  is_critical=True),

        # Triple-redundant sensor array (normal domain)
        Component("sensor_a",   "ip_core", "normal",     3, 1, 5, 1000,
                  impact_avail=4, exploitability=3,
                  direction="input", is_critical=True,
                  has_sboot=True),
        Component("sensor_b",   "ip_core", "normal",     3, 1, 5, 1000,
                  impact_avail=4, exploitability=3,
                  direction="input", is_critical=True,
                  has_sboot=True),
        Component("sensor_c",   "ip_core", "normal",     2, 1, 5, 1000,
                  impact_avail=3, exploitability=3,
                  direction="input", is_critical=True),

        # Safety-critical actuator (output only)
        Component("actuator",   "ip_core", "privileged", 1, 5, 1000, 5,
                  impact_avail=5, exploitability=3,
                  direction="output", is_critical=True, is_safety_critical=True),

        # Network-facing communication (untrusted, high exploitability)
        Component("comm_eth",   "ip_core", "untrusted",  4, 3, 10, 15,
                  impact_avail=4, exploitability=5,
                  is_critical=True),

        # Watchdog timer (availability-critical, low C/I impact)
        Component("watchdog",   "ip_core", "privileged", 1, 2, 4, 4,
                  impact_avail=5, exploitability=2,
                  is_critical=True, is_safety_critical=True),

        # GPIO (low-trust peripheral)
        Component("gpio",       "ip_core", "low",        1, 2, 5, 5,
                  impact_avail=1, exploitability=3),

        # Debug interface (untrusted, max exploitability)
        Component("debug_jtag", "ip_core", "untrusted",  5, 5, 1000, 1000,
                  impact_avail=2, exploitability=5,
                  is_critical=True),

        # Policy servers
        Component("ps_main",   "policy_server", "high", 1, 1, 1000, 1000,
                  is_receiver=False),
        Component("ps_backup", "policy_server", "high", 1, 1, 1000, 1000,
                  is_receiver=False),
    ]

    # -€-€ Buses -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.buses = ["axi_main", "axi_sec", "apb_periph"]

    # -€-€ Links (topology) -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    #   arm_a53 -€-€-€ axi_main -€-¬-€ axi_sec -€-€-€-€ crypto_eng
    #   arm_m4  -€-€-€-˜           -‚                nvram
    #   dma0    -€-€-€-˜           -‚
    #                          -œ-€ apb_periph -€-€ sensor_a, sensor_b, sensor_c
    #                          -‚                actuator, watchdog, gpio
    #                          -‚                debug_jtag
    #                          -"-€ comm_eth (directly on main bus)
    model.links = [
        # Masters to main bus
        ("arm_a53", "axi_main"),
        ("arm_m4",  "axi_main"),
        ("dma0",    "axi_main"),
        # Main bus to secure segment
        ("axi_main", "axi_sec"),
        ("axi_sec",  "crypto_eng"),
        ("axi_sec",  "nvram"),
        # Main bus to peripheral bus
        ("axi_main",  "apb_periph"),
        ("apb_periph", "sensor_a"),
        ("apb_periph", "sensor_b"),
        ("apb_periph", "sensor_c"),
        ("apb_periph", "actuator"),
        ("apb_periph", "watchdog"),
        ("apb_periph", "gpio"),
        ("apb_periph", "debug_jtag"),
        # Comm directly on main bus (externally-facing)
        ("axi_main", "comm_eth"),
    ]

    # -€-€ Redundancy groups -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.redundancy_groups = [
        RedundancyGroup("g1", ["sensor_a", "sensor_b", "sensor_c"]),
    ]

    # -€-€ Services -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.services = [
        Service("sensor_svc",  ["sensor_a", "sensor_b", "sensor_c"], 2),
        Service("control_svc", ["actuator", "watchdog"], 2),
        Service("comms_svc",   ["comm_eth"], 1),
        Service("crypto_svc",  ["crypto_eng"], 1),
    ]

    # -€-€ Access needs (least-privilege declarations) -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.access_needs = [
        # arm_a53: app processor reads sensors, manages crypto and NVRAM
        AccessNeed("arm_a53", "sensor_a",  "read"),
        AccessNeed("arm_a53", "sensor_b",  "read"),
        AccessNeed("arm_a53", "sensor_c",  "read"),
        AccessNeed("arm_a53", "crypto_eng", "read"),
        AccessNeed("arm_a53", "crypto_eng", "write"),
        AccessNeed("arm_a53", "nvram",      "read"),
        AccessNeed("arm_a53", "nvram",      "write"),
        AccessNeed("arm_a53", "comm_eth",   "read"),
        AccessNeed("arm_a53", "comm_eth",   "write"),
        # arm_m4: RT processor reads sensors, writes actuator
        AccessNeed("arm_m4", "sensor_a", "read"),
        AccessNeed("arm_m4", "sensor_b", "read"),
        AccessNeed("arm_m4", "sensor_c", "read"),
        AccessNeed("arm_m4", "actuator",  "write"),
        AccessNeed("arm_m4", "watchdog",  "write"),
        # dma0: bulk transfers  --  sensor data to NVRAM, NVRAM to comm
        AccessNeed("dma0", "sensor_a", "read"),
        AccessNeed("dma0", "sensor_b", "read"),
        AccessNeed("dma0", "sensor_c", "read"),
        AccessNeed("dma0", "nvram",    "write"),
        AccessNeed("dma0", "comm_eth", "write"),
        # NOTE: no master has declared need for gpio or debug_jtag
        # â†’ these will appear as excess_privilege in Phase 2 analysis
    ]

    # -€-€ System capabilities (PYNQ-Z2 xc7z020) -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.system_caps = {
        "max_power":         15000,
        "max_luts":          53200,
        "max_ffs":          106400,
        "max_dsps":            220,
        "max_lutram":        17400,
        "max_bufgs":            32,
        "max_bram":            140,
        "max_security_risk":   50,  # multiplicative cap for non-redundant assets
        "max_avail_risk":      25,  # allows sensor group with moderate security
        "max_attack_depth":     8,  # larger topology benefits from deeper reachability analysis
    }

    # -€-€ Candidate firewalls and policy servers -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.cand_fws = ["fw_secure", "fw_periph", "fw_comm"]
    model.cand_ps  = ["ps_main", "ps_backup"]

    # -€-€ On-path relationships -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    # fw_secure guards axi_sec segment
    for ip in ["crypto_eng", "nvram"]:
        for master in ["arm_a53", "arm_m4", "dma0"]:
            model.on_paths.append(("fw_secure", master, ip))

    # fw_periph guards apb_periph segment
    for ip in ["sensor_a", "sensor_b", "sensor_c",
               "actuator", "watchdog", "gpio", "debug_jtag"]:
        for master in ["arm_a53", "arm_m4", "dma0"]:
            model.on_paths.append(("fw_periph", master, ip))

    # fw_comm guards comm_eth on the main bus (externally-facing)
    for master in ["arm_a53", "arm_m4", "dma0"]:
        model.on_paths.append(("fw_comm", master, "comm_eth"))

    # -€-€ ip_loc -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    for ip in ["crypto_eng", "nvram"]:
        model.ip_locs.append((ip, "fw_secure"))
    for ip in ["sensor_a", "sensor_b", "sensor_c",
               "actuator", "watchdog", "gpio", "debug_jtag"]:
        model.ip_locs.append((ip, "fw_periph"))
    model.ip_locs.append(("comm_eth", "fw_comm"))

    # -€-€ Governance -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.fw_governs = [
        ("ps_main",   "fw_secure"),
        ("ps_main",   "fw_periph"),
        ("ps_main",   "fw_comm"),
        ("ps_backup", "fw_secure"),
    ]
    model.fw_costs = {"fw_secure": 200, "fw_periph": 150, "fw_comm": 120}
    model.ps_costs = {"ps_main": 220, "ps_backup": 180}

    # -€-€ Roles -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.roles = [
        ("arm_a53", "app_processor"),
        ("arm_m4",  "rt_controller"),
        ("dma0",    "data_mover"),
    ]

    # -€-€ Allow rules -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    # Normal-mode allows derived from access_needs
    for an in model.access_needs:
        model.allow_rules.append((an.master, an.component, "normal"))

    # -€-€ Policy exceptions -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.policy_exceptions = [
        # Debug access allowed in maintenance mode only
        ("arm_a53", "debug_jtag", "read",  "maintenance", "hw_debug"),
        ("arm_a53", "debug_jtag", "write", "maintenance", "hw_debug"),
        # DMA can access GPIO during maintenance (firmware update)
        ("dma0",    "gpio",       "write", "maintenance", "firmware_update"),
        # Emergency: arm_a53 can write actuator directly (bypass arm_m4)
        ("arm_a53", "actuator",   "write", "emergency",   "emergency_override"),
    ]

    # -€-€ Trust anchors -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.trust_anchors = {
        "arm_a53":    ["rot", "sboot", "attest", "key_storage"],
        "arm_m4":     ["sboot"],
        "crypto_eng": ["rot", "sboot", "key_storage"],
        "nvram":      ["rot", "key_storage"],
        "sensor_a":   ["sboot"],
        "sensor_b":   ["sboot"],
        "ps_main":    ["signed_policy", "key_storage"],
    }

    # -€-€ PEP guards -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    for ip in ["crypto_eng", "nvram"]:
        model.pep_guards.append(("fw_secure", ip))
    for ip in ["sensor_a", "sensor_b", "sensor_c",
               "actuator", "watchdog", "gpio", "debug_jtag"]:
        model.pep_guards.append(("fw_periph", ip))
    model.pep_guards.append(("fw_comm", "comm_eth"))

    # -€-€ PS governs PEP -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.ps_governs_pep = [
        ("ps_main",   "fw_secure"),
        ("ps_main",   "fw_periph"),
        ("ps_main",   "fw_comm"),
        ("ps_backup", "fw_secure"),
    ]

    # -€-€ Mission capabilities -€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€-€
    model.capabilities = [
        MissionCapability(
            name="sensor_fusion",
            description="Aggregate sensor data for situational awareness",
            required_services=["sensor_svc"],
            required_components=[],
            required_access=[
                ("arm_a53", "sensor_a", "read"),
                ("arm_m4",  "sensor_a", "read"),
            ],
            criticality="essential",
        ),
        MissionCapability(
            name="control_loop",
            description="Real-time sensor-to-actuator control loop",
            required_services=["sensor_svc", "control_svc"],
            required_components=["actuator"],
            required_access=[
                ("arm_m4", "sensor_a", "read"),
                ("arm_m4", "actuator", "write"),
                ("arm_m4", "watchdog", "write"),
            ],
            criticality="essential",
        ),
        MissionCapability(
            name="crypto_ops",
            description="Cryptographic key management and data encryption",
            required_services=["crypto_svc"],
            required_components=["crypto_eng", "nvram"],
            required_access=[
                ("arm_a53", "crypto_eng", "read"),
                ("arm_a53", "crypto_eng", "write"),
                ("arm_a53", "nvram", "read"),
                ("arm_a53", "nvram", "write"),
            ],
            criticality="essential",
        ),
        MissionCapability(
            name="external_comms",
            description="External network communication via Ethernet",
            required_services=["comms_svc"],
            required_components=["comm_eth"],
            required_access=[
                ("arm_a53", "comm_eth", "read"),
                ("arm_a53", "comm_eth", "write"),
            ],
            criticality="important",
        ),
        MissionCapability(
            name="data_logging",
            description="Bulk sensor data transfer to NVRAM for logging",
            required_services=["sensor_svc"],
            required_components=["nvram"],
            required_access=[
                ("dma0", "sensor_a", "read"),
                ("dma0", "nvram", "write"),
            ],
            criticality="important",
        ),
        MissionCapability(
            name="policy_management",
            description="ZTA policy distribution and enforcement",
            required_services=[],
            required_components=["ps_main"],
            required_access=[],
            criticality="essential",
        ),
        MissionCapability(
            name="hw_debug",
            description="Hardware debug and diagnostics access",
            required_services=[],
            required_components=["debug_jtag"],
            required_access=[
                ("arm_a53", "debug_jtag", "read"),
                ("arm_a53", "debug_jtag", "write"),
            ],
            criticality="optional",
            mission_phases=["maintenance"],
        ),
        MissionCapability(
            name="emergency_override",
            description="Direct actuator control bypassing RT controller",
            required_services=["control_svc"],
            required_components=["actuator"],
            required_access=[
                ("arm_a53", "actuator", "write"),
            ],
            criticality="essential",
            mission_phases=["emergency"],
        ),
    ]

    return model
