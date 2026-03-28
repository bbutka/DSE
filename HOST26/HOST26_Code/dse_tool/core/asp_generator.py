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
    domain: str             # low | high
    impact_read: int        # 1-5
    impact_write: int       # 1-5
    latency_read: int       # clock cycles (1000 = no constraint)
    latency_write: int      # clock cycles (1000 = no constraint)
    has_rot: bool = False
    has_sboot: bool = False
    has_attest: bool = False
    is_master: bool = False     # bus master (processor, dma)
    is_receiver: bool = True    # target IP
    is_critical: bool = False   # requires firewall coverage
    is_safety_critical: bool = False


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
        "max_asset_risk":   500,
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
        lines.append("% Assets (one per component, read+write)")
        for c in ip_comps:
            if c.comp_type not in ("policy_server", "firewall", "bus"):
                asset = f"{c.name}r1"
                lines.append(f"asset({c.name}, {asset}, read).")
                lines.append(f"asset({c.name}, {asset}, write).")

        lines.append("")

        # ── Impact ──────────────────────────────────────────────────────────
        lines.append("% Asset impact values")
        for c in ip_comps:
            if c.comp_type not in ("policy_server", "firewall", "bus"):
                asset = f"{c.name}r1"
                lines.append(f"impact({asset}, read,  {c.impact_read}).")
                lines.append(f"impact({asset}, write, {c.impact_write}).")

        lines.append("")

        # ── Latency ─────────────────────────────────────────────────────────
        lines.append("% Allowable latency per asset")
        for c in ip_comps:
            if c.comp_type not in ("policy_server", "firewall", "bus"):
                asset = f"{c.name}r1"
                lines.append(f"allowable_latency({asset}, read,  {c.latency_read}).")
                lines.append(f"allowable_latency({asset}, write, {c.latency_write}).")

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
        lines.append("% Trust domains")
        for c in m.components:
            if c.comp_type not in ("bus",):
                lines.append(f"domain({c.name}, {c.domain}).")
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
        lines.append("% Mission access rules")
        lines.append("mission_access(M, C, Op, operational) :- access_need(M, C, Op).")
        lines.append("mission_access(sys_cpu, C, read,  maintenance) :- receiver(C).")
        lines.append("mission_access(sys_cpu, C, write, maintenance) :- receiver(C).")
        lines.append("mission_access(dma, C, Op, maintenance) :- access_need(dma, C, Op).")
        lines.append("mission_access(M, C, read, emergency) :- master(M), receiver(C), access_need(M, C, read).")
        lines.append("")

        # ── Role needs ───────────────────────────────────────────────────────
        lines.append("% Role-level access needs")
        lines.append("role_need(processor,  C, read)  :- receiver(C), domain(C, high).")
        lines.append("role_need(processor,  C, write) :- receiver(C), link(noc0, C).")
        lines.append("role_need(data_mover, C, write) :- receiver(C).")
        lines.append("role_need(data_mover, c8, read).")
        lines.append("")

        return "\n".join(lines)

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
        "max_asset_risk":   500,
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

    return model
