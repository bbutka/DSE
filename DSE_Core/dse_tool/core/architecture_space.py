"""Architecture seed generation for bounded ASE exploration."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import List

from .architecture_delta import ArchitectureDelta, compare_network_models
from .asp_generator import (
    AccessNeed,
    Asset,
    Component,
    FunctionSupport,
    NetworkModel,
    Service,
    make_pixhawk6x_uav_dual_ps_network,
    make_pixhawk6x_uav_network,
)


@dataclass
class ArchitectureSeed:
    """A structurally distinct starting point for an ASE run."""

    name: str
    objective_bias: str
    description: str
    model: NetworkModel
    delta_from_baseline: ArchitectureDelta
    notes: List[str] = field(default_factory=list)


def generate_pixhawk6x_architecture_seeds(
    baseline: NetworkModel | None = None,
) -> List[ArchitectureSeed]:
    """
    Return curated Pixhawk 6X architecture seeds with different objective biases.

    These are intentionally not local mutations of one solver result. They are
    hand-curated starting structures that let downstream ASE compare a baseline,
    a low-resource cut, a distributed control-plane option, a security-hardened
    option, and a diversity-first resilience option.
    """
    baseline_model = deepcopy(baseline) if baseline is not None else make_pixhawk6x_uav_network()
    seeds: List[tuple[str, str, str, NetworkModel, List[str]]] = []

    base = deepcopy(baseline_model)
    base.name = "Pixhawk 6X UAV Seed - Baseline"
    seeds.append((
        "baseline",
        "baseline",
        "Reference UAV integration with the documented sensor and control topology.",
        base,
        ["Reference point for structural deltas and downstream scoring."],
    ))

    low_resource = _make_low_resource_seed(baseline_model)
    seeds.append((
        "low_resource",
        "low_resource",
        "Drops optional payload and logging hardware to preserve core flight functions.",
        low_resource,
        ["Cost/weight pressure is represented as removed non-flight-critical hardware."],
    ))

    balanced = make_pixhawk6x_uav_dual_ps_network()
    balanced.name = "Pixhawk 6X UAV Seed - Balanced Dual PS"
    seeds.append((
        "balanced_dual_ps",
        "balanced",
        "Splits policy-server governance between FMU and I/O domains.",
        balanced,
        ["Balanced seed uses control-plane diversity without adding new sensing modalities."],
    ))

    max_security = _make_security_hardened_seed()
    seeds.append((
        "max_security",
        "max_security",
        "Adds candidate PEPs for GPS1, RC override, and flight logging paths.",
        max_security,
        ["Security bias widens enforcement placement before Phase 2 optimization."],
    ))

    max_resilience = _make_resilience_diverse_seed()
    seeds.append((
        "max_resilience",
        "max_resilience",
        "Adds optical-flow support as a vision modality and keeps dual policy servers.",
        max_resilience,
        ["Resilience bias adds modality diversity, not just duplicate GPS sensors."],
    ))

    return [
        ArchitectureSeed(
            name=name,
            objective_bias=bias,
            description=description,
            model=model,
            delta_from_baseline=compare_network_models(baseline_model, model),
            notes=notes,
        )
        for name, bias, description, model, notes in seeds
    ]


def _make_low_resource_seed(baseline: NetworkModel) -> NetworkModel:
    model = deepcopy(baseline)
    model.name = "Pixhawk 6X UAV Seed - Low Resource"
    _remove_components(model, {"companion", "camera", "flash_fram"})
    _remove_buses(model, {"eth_port", "spi5_ext"})
    _remove_firewalls(model, {"pep_eth"})
    _remove_services(model, {"payload_svc", "logging_svc"})
    _remove_capabilities(model, {"surveillance", "logging"})
    return model


def _make_security_hardened_seed() -> NetworkModel:
    model = make_pixhawk6x_uav_dual_ps_network()
    model.name = "Pixhawk 6X UAV Seed - Max Security"
    _add_firewall_candidate(model, "pep_gps1", "gps_1", "ps_fmu", cost=110)
    _add_firewall_candidate(model, "pep_rc", "rc_receiver", "ps_io", cost=120)
    _add_firewall_candidate(model, "pep_log", "flash_fram", "ps_fmu", cost=130)
    return model


def _make_resilience_diverse_seed() -> NetworkModel:
    model = make_pixhawk6x_uav_dual_ps_network()
    model.name = "Pixhawk 6X UAV Seed - Max Resilience"
    _append_unique(
        model.components,
        Component(
            "optical_flow",
            "ip_core",
            "low",
            3,
            1,
            18,
            1000,
            impact_avail=4,
            exploitability=3,
            direction="input",
            is_critical=True,
        ),
        key=lambda component: component.name,
    )
    _append_unique(model.buses, "flow_port")
    _append_unique(model.links, ("fmu_h753", "flow_port"))
    _append_unique(model.links, ("flow_port", "optical_flow"))
    _append_unique(
        model.assets,
        Asset(
            "flow_motion",
            "optical_flow",
            direction="input",
            impact_read=3,
            impact_write=0,
            impact_avail=4,
            latency_read=18,
        ),
        key=lambda asset: asset.asset_id,
    )
    _append_unique(model.access_needs, AccessNeed("fmu_h753", "optical_flow", "read"))
    _append_unique(
        model.services,
        Service("visual_odometry_svc", ["optical_flow"], 1),
        key=lambda service: service.name,
    )
    _append_unique(
        model.function_supports,
        FunctionSupport("state_estimation", "optical_flow", "vision", 65, bus="flow_port"),
        key=_function_support_key,
    )
    _append_unique(
        model.function_supports,
        FunctionSupport("navigation", "optical_flow", "vision", 60, bus="flow_port"),
        key=_function_support_key,
    )
    _add_firewall_candidate(model, "pep_flow", "optical_flow", "ps_fmu", cost=135)
    model.allow_rules = [(an.master, an.component, "normal") for an in model.access_needs]
    return model


def _remove_components(model: NetworkModel, names: set[str]) -> None:
    model.components = [component for component in model.components if component.name not in names]
    model.assets = [asset for asset in model.assets if asset.component not in names]
    model.links = [
        (src, dst)
        for src, dst in model.links
        if src not in names and dst not in names
    ]
    model.access_needs = [
        need for need in model.access_needs
        if need.master not in names and need.component not in names
    ]
    model.allow_rules = [
        rule for rule in model.allow_rules
        if rule[0] not in names and rule[1] not in names
    ]
    model.function_supports = [
        support for support in model.function_supports
        if support.component not in names
    ]
    model.redundancy_groups = [
        group for group in model.redundancy_groups
        if all(member not in names for member in group.members)
    ]


def _remove_buses(model: NetworkModel, buses: set[str]) -> None:
    model.buses = [bus for bus in model.buses if bus not in buses]
    model.links = [
        (src, dst)
        for src, dst in model.links
        if src not in buses and dst not in buses
    ]
    model.function_supports = [
        support for support in model.function_supports
        if support.bus not in buses
    ]


def _remove_firewalls(model: NetworkModel, firewalls: set[str]) -> None:
    model.cand_fws = [fw for fw in model.cand_fws if fw not in firewalls]
    model.on_paths = [entry for entry in model.on_paths if entry[0] not in firewalls]
    model.ip_locs = [entry for entry in model.ip_locs if entry[1] not in firewalls]
    model.fw_governs = [entry for entry in model.fw_governs if entry[1] not in firewalls]
    model.ps_governs_pep = [entry for entry in model.ps_governs_pep if entry[1] not in firewalls]
    model.pep_guards = [entry for entry in model.pep_guards if entry[0] not in firewalls]
    for fw in firewalls:
        model.fw_costs.pop(fw, None)


def _remove_services(model: NetworkModel, services: set[str]) -> None:
    model.services = [service for service in model.services if service.name not in services]


def _remove_capabilities(model: NetworkModel, capabilities: set[str]) -> None:
    model.capabilities = [
        capability for capability in model.capabilities
        if capability.name not in capabilities
    ]


def _add_firewall_candidate(
    model: NetworkModel,
    firewall: str,
    component: str,
    policy_server: str,
    *,
    cost: int,
) -> None:
    _append_unique(model.cand_fws, firewall)
    _append_unique(model.on_paths, (firewall, "fmu_h753", component))
    _append_unique(model.ip_locs, (component, firewall))
    _append_unique(model.fw_governs, (policy_server, firewall))
    _append_unique(model.ps_governs_pep, (policy_server, firewall))
    _append_unique(model.pep_guards, (firewall, component))
    model.fw_costs[firewall] = cost


def _append_unique(items: list, value, key=None) -> None:
    if key is None:
        if value not in items:
            items.append(value)
        return
    value_key = key(value)
    if all(key(item) != value_key for item in items):
        items.append(value)


def _function_support_key(support: FunctionSupport) -> tuple[str, str, str, str]:
    return (support.function, support.component, support.modality, support.bus)
