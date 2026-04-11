"""Architecture-level repair helpers driven by Phase 3 deficiencies."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, List, Tuple

from .asp_generator import Component, NetworkModel


def apply_architecture_repair_intents(model: NetworkModel, intents: List[dict]) -> NetworkModel:
    """Return a revised architecture candidate for supported repair intents."""
    candidate = deepcopy(model)
    if not intents:
        return candidate

    changed = False
    for intent in intents:
        if intent.get("repair") == "split_function_support_buses":
            changed = _split_function_support_buses(
                candidate,
                function=str(intent.get("function", "")),
                min_domains=int(intent.get("minimum_independent_domains", 2) or 2),
            ) or changed
    if changed:
        candidate.name = f"{model.name} (repaired)"
    return candidate


def serialize_architecture_repair_candidate(candidate: dict) -> dict:
    """Return a JSON-compatible representation of a repair candidate."""
    return {
        "source_strategy": candidate.get("source_strategy", ""),
        "source_label": candidate.get("source_label", ""),
        "promotion_status": candidate.get("promotion_status", ""),
        "repair_intents": list(candidate.get("repair_intents") or []),
        "delta": _asdict_or_none(candidate.get("delta")),
        "model": _asdict_or_none(candidate.get("model")),
        "reevaluation": _serialize_reevaluation(candidate.get("reevaluation")),
    }


def serialize_architecture_repair_candidates(candidates: List[dict]) -> dict:
    """Return a JSON-compatible repair-candidate bundle."""
    return {
        "architecture_repair_candidates": [
            serialize_architecture_repair_candidate(candidate)
            for candidate in candidates
        ]
    }


def _split_function_support_buses(model: NetworkModel, *, function: str, min_domains: int) -> bool:
    supports = [
        support for support in model.function_supports
        if support.function == function and support.bus
    ]
    if len(supports) < min_domains:
        return False

    existing_buses = {support.bus for support in supports}
    if len(existing_buses) >= min_domains:
        return False

    links = set(model.links)
    upstream_by_bus: Dict[str, List[str]] = {
        bus: sorted(src for src, dst in links if dst == bus)
        for bus in existing_buses
    }

    used_buses = set(model.buses)
    kept_first_bus: set[str] = set()
    for support in supports:
        if support.bus not in kept_first_bus:
            kept_first_bus.add(support.bus)
            continue

        old_bus = support.bus
        new_bus = _unique_bus_name(model, support.component, used_buses)
        used_buses.add(new_bus)
        model.buses.append(new_bus)
        _ensure_bus_component(model, new_bus)
        support.bus = new_bus

        links.discard((old_bus, support.component))
        upstreams = upstream_by_bus.get(old_bus, [])
        for upstream in upstreams:
            links.add((upstream, new_bus))
        links.add((new_bus, support.component))

    model.buses = sorted(set(model.buses), key=model.buses.index)
    model.links = sorted(links, key=_link_sort_key(model.links))
    return True


def _ensure_bus_component(model: NetworkModel, bus_name: str) -> None:
    if any(component.name == bus_name for component in model.components):
        return
    model.components.append(
        Component(
            bus_name,
            "bus",
            "normal",
            1,
            1,
            1000,
            1000,
            is_receiver=False,
        )
    )


def _unique_bus_name(model: NetworkModel, component: str, used_buses: set[str]) -> str:
    base = f"{component}_repair_bus"
    if base not in used_buses:
        return base
    idx = 2
    while f"{base}_{idx}" in used_buses:
        idx += 1
    return f"{base}_{idx}"


def _link_sort_key(original_links: List[Tuple[str, str]]):
    original_index = {link: idx for idx, link in enumerate(original_links)}
    return lambda link: (original_index.get(link, len(original_index)), link)


def _asdict_or_none(value: Any) -> dict | None:
    if value is None:
        return None
    if isinstance(value, dict):
        return dict(value)
    if not is_dataclass(value):
        raise TypeError(f"Cannot serialize repair candidate value of type {type(value).__name__}")
    return asdict(value)


def _serialize_reevaluation(value: Any) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise TypeError(f"Cannot serialize repair candidate reevaluation of type {type(value).__name__}")
    serialized = dict(value)
    serialized["scenarios"] = [
        asdict(scenario) if is_dataclass(scenario) else dict(scenario)
        for scenario in value.get("scenarios", [])
    ]
    return serialized
