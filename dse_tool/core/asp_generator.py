"""
asp_generator.py
================
Converts a NetworkModel Python object into an ASP (.lp) facts string
suitable for loading with clingo.

The generated facts mirror the schema used by testCase9_inst.lp so that
the existing Clingo/ encodings work without modification.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional


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
        ``"essential"`` — system cannot operate without it;
        ``"important"`` — degraded operation possible;
        ``"optional"``  — nice-to-have.
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
        "max_security_risk":  3,   # additive cap: non-redundant components
        "max_avail_risk":    20,   # probabilistic cap: redundant groups
        "max_bufg":          32,
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
    policy_exceptions: List[Tuple] = field(default_factory=list)
    trust_anchors: Dict[str, List[str]] = field(default_factory=dict)
    pep_guards: List[Tuple[str, str]] = field(default_factory=list)
    ps_governs_pep: List[Tuple[str, str]] = field(default_factory=list)
    mission_phases: List[str] = field(default_factory=lambda: [
        "operational", "maintenance", "emergency"
    ])
    buses: List[str] = field(default_factory=list)
    scenarios: List[dict] = field(default_factory=list)
    capabilities: List[MissionCapability] = field(default_factory=list)


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

    def generate(self) -> str:
        """Return a complete .lp facts string for the network model."""
        m = self.model
        lines: List[str] = []
        lines.append(f"% Auto-generated ASP facts for network: {m.name}")
        lines.append("")

        # ── Components ──────────────────────────────────────────────────────
        lines.append("% Components")
        ip_comps = [c for c in m.components
                    if c.comp_type not in ("bus",) and not c.is_master]
        masters   = [c for c in m.components if c.is_master]

        for c in ip_comps:
            if c.comp_type not in ("policy_server", "firewall"):
                lines.append(f"component({c.name}).")

        lines.append("")

        # ── Assets ──────────────────────────────────────────────────────────
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

        # ── Impact ──────────────────────────────────────────────────────────
        lines.append("% Asset impact values (C = read, I = write, A = avail)")
        for a in asset_list:
            if a.direction in ("input", "bidirectional"):
                lines.append(f"impact({a.asset_id}, read,  {a.impact_read}).")
            if a.direction in ("output", "bidirectional"):
                lines.append(f"impact({a.asset_id}, write, {a.impact_write}).")
            if a.impact_avail > 0:
                lines.append(f"impact({a.asset_id}, avail, {a.impact_avail}).")

        lines.append("")

        # ── Latency ─────────────────────────────────────────────────────────
        lines.append("% Allowable latency per asset")
        for a in asset_list:
            if a.direction in ("input", "bidirectional"):
                lines.append(f"allowable_latency({a.asset_id}, read,  {a.latency_read}).")
            if a.direction in ("output", "bidirectional"):
                lines.append(f"allowable_latency({a.asset_id}, write, {a.latency_write}).")

        lines.append("")

        # ── Redundancy groups ────────────────────────────────────────────────
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

        # ── ZTA Topology ─────────────────────────────────────────────────────
        lines.append("% ZTA topology — masters, receivers, buses, links")
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

        # ── Trust domains ────────────────────────────────────────────────────
        lines.append("% Trust domains (untrusted=0 | low=0 | normal=1 | privileged=2 | high=3 | root=3)")
        for c in m.components:
            if c.comp_type not in ("bus",):
                lines.append(f"domain({c.name}, {c.domain}).")
        lines.append("")

        # ── Exploitability ──────────────────────────────────────────────────
        lines.append("% Exploitability: 1=hard, 3=neutral, 5=trivial (default 3 when omitted)")
        for c in ip_comps:
            if c.comp_type not in ("policy_server", "firewall", "bus"):
                if c.exploitability != 3:   # only emit non-default values
                    lines.append(f"exploitability({c.name}, {c.exploitability}).")
        lines.append("")

        # ── Critical components ──────────────────────────────────────────────
        lines.append("% Critical and safety-critical IPs")
        for c in ip_comps:
            if c.is_critical and c.comp_type not in ("policy_server", "firewall", "bus"):
                lines.append(f"critical({c.name}).")
        for c in ip_comps:
            if c.is_safety_critical:
                lines.append(f"safety_critical({c.name}).")
        lines.append("")

        # ── Firewall / PS candidates ──────────────────────────────────────────
        lines.append("% Candidate firewalls and policy servers")
        for fw in m.cand_fws:
            lines.append(f"cand_fw({fw}).")
        for ps in m.cand_ps:
            lines.append(f"cand_ps({ps}).")
        lines.append("")

        # ── On-path and ip_loc ───────────────────────────────────────────────
        lines.append("% On-path and ip_loc facts")
        for fw, master, ip in m.on_paths:
            lines.append(f"on_path({fw}, {master}, {ip}).")
        for ip, fw in m.ip_locs:
            lines.append(f"ip_loc({ip}, {fw}).")
        lines.append("")

        # ── FW governance ────────────────────────────────────────────────────
        lines.append("% Firewall governance by policy server")
        for ps, pep in m.fw_governs:
            lines.append(f"governs({ps}, {pep}).")
        lines.append("")

        # ── Hardware costs ───────────────────────────────────────────────────
        lines.append("% Hardware costs")
        for fw, cost in m.fw_costs.items():
            lines.append(f"fw_cost({fw}, {cost}).")
        for ps, cost in m.ps_costs.items():
            lines.append(f"ps_cost({ps}, {cost}).")
        lines.append("")

        # ── System capabilities ──────────────────────────────────────────────
        lines.append("% System capabilities (resource budgets)")
        for cap, val in m.system_caps.items():
            lines.append(f"system_capability({cap}, {val}).")
        lines.append("")

        # ── Allow rules ──────────────────────────────────────────────────────
        lines.append("% Explicit allow rules (normal mode)")
        for master, comp, mode in m.allow_rules:
            lines.append(f"allow({master}, {comp}, {mode}).")
        lines.append("")

        # ── Access needs ─────────────────────────────────────────────────────
        lines.append("% Least-privilege access needs")
        for an in m.access_needs:
            lines.append(f"access_need({an.master}, {an.component}, {an.operation}).")
        lines.append("")

        # ── Roles ────────────────────────────────────────────────────────────
        lines.append("% Subject roles")
        for master, role in m.roles:
            lines.append(f"role({master}, {role}).")
        lines.append("")

        # ── Policy exceptions ────────────────────────────────────────────────
        if m.policy_exceptions:
            lines.append("% Policy exceptions")
            for exc in m.policy_exceptions:
                master, comp, op, mode, reason = exc
                lines.append(f"policy_exception({master}, {comp}, {op}, {mode}, reason({reason})).")
            lines.append("")

        # ── Trust anchors ────────────────────────────────────────────────────
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

        # ── Services ─────────────────────────────────────────────────────────
        lines.append("% Services")
        for svc in m.services:
            for member in svc.members:
                lines.append(f"service_component({svc.name}, {member}).")
            lines.append(f"service_quorum({svc.name}, {svc.quorum}).")
        lines.append("")

        # ── Control plane ────────────────────────────────────────────────────
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

        # ── Mission phases ───────────────────────────────────────────────────
        lines.append("% Mission phases")
        for phase in m.mission_phases:
            lines.append(f"mission_phase({phase}).")
        lines.append("")

        # ── Mission access rules ──────────────────────────────────────────────
        # Derive primary processor and DMA master from topology for mission rules
        primary_proc = next((c.name for c in masters if c.comp_type == "processor"), None)
        dma_master = next((c.name for c in masters if c.comp_type == "dma"), None)
        lines.append("% Mission access rules")
        lines.append("mission_access(M, C, Op, operational) :- access_need(M, C, Op).")
        if primary_proc:
            lines.append(f"mission_access({primary_proc}, C, read,  maintenance) :- receiver(C).")
            lines.append(f"mission_access({primary_proc}, C, write, maintenance) :- receiver(C).")
        if dma_master:
            lines.append(f"mission_access({dma_master}, C, Op, maintenance) :- access_need({dma_master}, C, Op).")
        lines.append("mission_access(M, C, read, emergency) :- master(M), receiver(C), access_need(M, C, read).")
        lines.append("")

        # ── Role needs ───────────────────────────────────────────────────────
        # Derive from model roles and topology instead of hardcoding TC9 names
        lines.append("% Role-level access needs")
        role_names = {role for _, role in m.roles}
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

        # ── Static risk weights (amplification proxy for Phase 1 objective) ──
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

            # Emit one weight per asset of this component
            # Asset ids may come from explicit list or auto-generated
            comp_assets = [a for a in (m.assets or []) if a.component == c.name]
            if comp_assets:
                for a in comp_assets:
                    lines.append(f"risk_weight({a.asset_id}, {weight}).")
            else:
                lines.append(f"risk_weight({c.name}r1, {weight}).")
        lines.append("")

        # ── Mission capabilities (functional resilience) ────────────────────
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
                    # No phase restriction → needed in all phases
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
                        f"but isolation rules require receiver/1"
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
    Create the testCase9 NetworkModel matching testCase9_inst.lp exactly.

    Returns the pre-loaded TC9 topology ready for the network editor and
    for direct use in analysis without the editor.
    """
    model = NetworkModel(name="testCase9")

    # ── Components ──────────────────────────────────────────────────────────
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

    # ── Buses ────────────────────────────────────────────────────────────────
    model.buses = ["noc0", "noc1"]

    # ── Links ────────────────────────────────────────────────────────────────
    model.links = [
        ("sys_cpu", "noc0"),
        ("dma",     "noc0"),
        ("noc0", "c1"), ("noc0", "c2"), ("noc0", "c3"),
        ("noc0", "c4"), ("noc0", "c5"),
        ("dma",  "noc1"),
        ("noc1", "c6"), ("noc1", "c7"), ("noc1", "c8"),
    ]

    # ── Redundancy groups ────────────────────────────────────────────────────
    model.redundancy_groups = [
        RedundancyGroup("g1", ["c1", "c2", "c3", "c4", "c5"])
    ]

    # ── Services ─────────────────────────────────────────────────────────────
    model.services = [
        Service("compute_svc", ["c1","c2","c3","c4","c5"], 3),
        Service("monitor_svc", ["c6"], 1),
        Service("io_svc",      ["c8"], 1),
    ]

    # ── Access needs ─────────────────────────────────────────────────────────
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

    # ── System capabilities ──────────────────────────────────────────────────
    model.system_caps = {
        "max_power":      15000,
        "max_luts":       53200,
        "max_ffs":       106400,
        "max_dsps":         220,
        "max_lutram":     17400,
        "max_bufgs":         32,
        "max_bram":         140,
        "max_security_risk":  3,   # additive cap: non-redundant components
        "max_avail_risk":    20,   # probabilistic cap: redundant groups
        "max_bufg":          32,
    }

    # ── Candidates ───────────────────────────────────────────────────────────
    model.cand_fws = ["pep_group", "pep_standalone"]
    model.cand_ps  = ["ps0", "ps1"]

    # ── On-path ──────────────────────────────────────────────────────────────
    for c in ["c1","c2","c3","c4","c5"]:
        model.on_paths.append(("pep_group", "sys_cpu", c))
        model.on_paths.append(("pep_group", "dma",     c))
    for c in ["c6","c7","c8"]:
        model.on_paths.append(("pep_standalone", "dma", c))

    # ── ip_loc ───────────────────────────────────────────────────────────────
    for c in ["c1","c2","c3","c4","c5"]:
        model.ip_locs.append((c, "pep_group"))
    for c in ["c6","c7","c8"]:
        model.ip_locs.append((c, "pep_standalone"))

    # ── Governance ───────────────────────────────────────────────────────────
    model.fw_governs = [
        ("ps0", "pep_group"), ("ps0", "pep_standalone"),
        ("ps1", "pep_group"),
    ]
    model.fw_costs = {"pep_group": 150, "pep_standalone": 100}
    model.ps_costs = {"ps0": 200, "ps1": 180}

    # ── Roles ────────────────────────────────────────────────────────────────
    model.roles = [("sys_cpu", "processor"), ("dma", "data_mover")]

    # ── Allow rules ──────────────────────────────────────────────────────────
    for c in ["c1","c2","c3","c4","c5"]:
        model.allow_rules.append(("sys_cpu", c, "normal"))
        model.allow_rules.append(("dma",     c, "normal"))
    for c in ["c6","c7","c8"]:
        model.allow_rules.append(("dma", c, "normal"))

    # ── Policy exceptions ────────────────────────────────────────────────────
    model.policy_exceptions = [
        ("dma", "c7", "write", "maintenance", "firmware_update")
    ]

    # ── Trust anchors ────────────────────────────────────────────────────────
    model.trust_anchors = {
        "sys_cpu": ["attest", "trusted_telemetry"],
        "c1":      ["rot", "sboot", "key_storage", "trusted_telemetry"],
        "c2":      ["rot", "sboot", "key_storage", "trusted_telemetry"],
        "c3":      ["sboot"],
        "c4":      ["sboot"],
        "c5":      ["sboot"],
        "ps0":     ["signed_policy"],
    }

    # ── PEP guards ───────────────────────────────────────────────────────────
    for c in ["c1","c2","c3","c4","c5"]:
        model.pep_guards.append(("pep_group", c))
    for c in ["c6","c7","c8"]:
        model.pep_guards.append(("pep_standalone", c))

    # ── PS governs PEP ───────────────────────────────────────────────────────
    model.ps_governs_pep = [
        ("ps0", "pep_group"), ("ps0", "pep_standalone"),
        ("ps1", "pep_group"),
    ]

    # ── Mission capabilities ────────────────────────────────────────────────
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
# Reference SoC factory — exercises every DSE tool feature
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
      arm_a53     — App processor, privileged, RoT+sboot+attest, exploitability=2
      arm_m4      — RT processor, normal, sboot only, exploitability=3
      dma0        — DMA controller, normal, exploitability=4 (DMA attack class)

    Buses:
      axi_main    — Primary AXI interconnect
      axi_sec     — Secure AXI segment (crypto, NVRAM)
      apb_periph  — APB peripheral bus (sensors, GPIO, debug)

    IP Cores:
      crypto_eng  — Crypto accelerator, root, safety-critical, exploit=1
      sensor_a    — Temp sensor, input, normal, avail=4 (redundant group)
      sensor_b    — Pressure sensor, input, normal, avail=4 (redundant group)
      sensor_c    — Voltage monitor, input, normal, avail=3 (redundant group)
      actuator    — Motor/PWM controller, output, privileged, safety-critical
      comm_eth    — Ethernet interface, bidirectional, untrusted, exploit=5
      watchdog    — Watchdog timer, privileged, avail=5, low C/I
      nvram       — Non-volatile storage, privileged, high C/I
      gpio        — GPIO block, bidirectional, low domain
      debug_jtag  — Debug port, untrusted, exploit=5

    Firewalls:
      fw_secure   — Guards axi_sec segment (crypto, nvram)
      fw_periph   — Guards apb_periph (sensors, gpio, debug, watchdog)

    Policy Servers:
      ps_main     — Primary PS, signed policy
      ps_backup   — Backup PS

    Redundancy:
      Group g1: sensor_a, sensor_b, sensor_c (triple-redundant)

    Services:
      sensor_svc  — {sensor_a, sensor_b, sensor_c}, quorum=2
      control_svc — {actuator, watchdog}, quorum=2
      comms_svc   — {comm_eth}, quorum=1
      crypto_svc  — {crypto_eng}, quorum=1
    """
    model = NetworkModel(name="SecureSoC-16")

    # ── Components ───────────────────────────────────────────────────────
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

    # ── Buses ────────────────────────────────────────────────────────────
    model.buses = ["axi_main", "axi_sec", "apb_periph"]

    # ── Links (topology) ─────────────────────────────────────────────────
    #   arm_a53 ─── axi_main ─┬─ axi_sec ──── crypto_eng
    #   arm_m4  ───┘           │                nvram
    #   dma0    ───┘           │
    #                          ├─ apb_periph ── sensor_a, sensor_b, sensor_c
    #                          │                actuator, watchdog, gpio
    #                          │                debug_jtag
    #                          └─ comm_eth (directly on main bus)
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

    # ── Redundancy groups ────────────────────────────────────────────────
    model.redundancy_groups = [
        RedundancyGroup("g1", ["sensor_a", "sensor_b", "sensor_c"]),
    ]

    # ── Services ─────────────────────────────────────────────────────────
    model.services = [
        Service("sensor_svc",  ["sensor_a", "sensor_b", "sensor_c"], 2),
        Service("control_svc", ["actuator", "watchdog"], 2),
        Service("comms_svc",   ["comm_eth"], 1),
        Service("crypto_svc",  ["crypto_eng"], 1),
    ]

    # ── Access needs (least-privilege declarations) ──────────────────────
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
        # dma0: bulk transfers — sensor data to NVRAM, NVRAM to comm
        AccessNeed("dma0", "sensor_a", "read"),
        AccessNeed("dma0", "sensor_b", "read"),
        AccessNeed("dma0", "sensor_c", "read"),
        AccessNeed("dma0", "nvram",    "write"),
        AccessNeed("dma0", "comm_eth", "write"),
        # NOTE: no master has declared need for gpio or debug_jtag
        # → these will appear as excess_privilege in Phase 2 analysis
    ]

    # ── System capabilities (PYNQ-Z2 xc7z020) ───────────────────────────
    model.system_caps = {
        "max_power":         15000,
        "max_luts":          53200,
        "max_ffs":          106400,
        "max_dsps":            220,
        "max_lutram":        17400,
        "max_bufgs":            32,
        "max_bram":            140,
        "max_security_risk":    4,  # tighter: forces mac+ on high-impact assets
        "max_avail_risk":      25,  # allows sensor group with moderate security
        "max_bufg":             32,
    }

    # ── Candidate firewalls and policy servers ───────────────────────────
    model.cand_fws = ["fw_secure", "fw_periph", "fw_comm"]
    model.cand_ps  = ["ps_main", "ps_backup"]

    # ── On-path relationships ────────────────────────────────────────────
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

    # ── ip_loc ───────────────────────────────────────────────────────────
    for ip in ["crypto_eng", "nvram"]:
        model.ip_locs.append((ip, "fw_secure"))
    for ip in ["sensor_a", "sensor_b", "sensor_c",
               "actuator", "watchdog", "gpio", "debug_jtag"]:
        model.ip_locs.append((ip, "fw_periph"))
    model.ip_locs.append(("comm_eth", "fw_comm"))

    # ── Governance ───────────────────────────────────────────────────────
    model.fw_governs = [
        ("ps_main",   "fw_secure"),
        ("ps_main",   "fw_periph"),
        ("ps_main",   "fw_comm"),
        ("ps_backup", "fw_secure"),
    ]
    model.fw_costs = {"fw_secure": 200, "fw_periph": 150, "fw_comm": 120}
    model.ps_costs = {"ps_main": 220, "ps_backup": 180}

    # ── Roles ────────────────────────────────────────────────────────────
    model.roles = [
        ("arm_a53", "app_processor"),
        ("arm_m4",  "rt_controller"),
        ("dma0",    "data_mover"),
    ]

    # ── Allow rules ──────────────────────────────────────────────────────
    # Normal-mode allows derived from access_needs
    for an in model.access_needs:
        model.allow_rules.append((an.master, an.component, "normal"))

    # ── Policy exceptions ────────────────────────────────────────────────
    model.policy_exceptions = [
        # Debug access allowed in maintenance mode only
        ("arm_a53", "debug_jtag", "read",  "maintenance", "hw_debug"),
        ("arm_a53", "debug_jtag", "write", "maintenance", "hw_debug"),
        # DMA can access GPIO during maintenance (firmware update)
        ("dma0",    "gpio",       "write", "maintenance", "firmware_update"),
        # Emergency: arm_a53 can write actuator directly (bypass arm_m4)
        ("arm_a53", "actuator",   "write", "emergency",   "emergency_override"),
    ]

    # ── Trust anchors ────────────────────────────────────────────────────
    model.trust_anchors = {
        "arm_a53":    ["rot", "sboot", "attest", "key_storage"],
        "arm_m4":     ["sboot"],
        "crypto_eng": ["rot", "sboot", "key_storage"],
        "nvram":      ["rot", "key_storage"],
        "sensor_a":   ["sboot"],
        "sensor_b":   ["sboot"],
        "ps_main":    ["signed_policy", "key_storage"],
    }

    # ── PEP guards ───────────────────────────────────────────────────────
    for ip in ["crypto_eng", "nvram"]:
        model.pep_guards.append(("fw_secure", ip))
    for ip in ["sensor_a", "sensor_b", "sensor_c",
               "actuator", "watchdog", "gpio", "debug_jtag"]:
        model.pep_guards.append(("fw_periph", ip))
    model.pep_guards.append(("fw_comm", "comm_eth"))

    # ── PS governs PEP ───────────────────────────────────────────────────
    model.ps_governs_pep = [
        ("ps_main",   "fw_secure"),
        ("ps_main",   "fw_periph"),
        ("ps_main",   "fw_comm"),
        ("ps_backup", "fw_secure"),
    ]

    # ── Mission capabilities ────────────────────────────────────────────
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
