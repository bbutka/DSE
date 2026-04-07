"""Helpers for comparing a baseline architecture to a revised architecture."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

from .asp_generator import NetworkModel


@dataclass
class ArchitectureDelta:
    """Structural delta between two NetworkModel objects.

    This is intentionally separate from Phase 1 security overhead accounting.
    Use it to answer questions such as "what hardware was added or removed in a
    revised architecture?" before layering on security-IP and ZTA overhead.
    """

    baseline_name: str
    candidate_name: str
    added_components: List[str] = field(default_factory=list)
    removed_components: List[str] = field(default_factory=list)
    added_buses: List[str] = field(default_factory=list)
    removed_buses: List[str] = field(default_factory=list)
    added_links: List[Tuple[str, str]] = field(default_factory=list)
    removed_links: List[Tuple[str, str]] = field(default_factory=list)
    added_redundancy_groups: List[str] = field(default_factory=list)
    removed_redundancy_groups: List[str] = field(default_factory=list)
    added_services: List[str] = field(default_factory=list)
    removed_services: List[str] = field(default_factory=list)
    added_capabilities: List[str] = field(default_factory=list)
    removed_capabilities: List[str] = field(default_factory=list)
    added_fw_candidates: List[str] = field(default_factory=list)
    removed_fw_candidates: List[str] = field(default_factory=list)
    added_ps_candidates: List[str] = field(default_factory=list)
    removed_ps_candidates: List[str] = field(default_factory=list)

    def has_changes(self) -> bool:
        return any(
            (
                self.added_components,
                self.removed_components,
                self.added_buses,
                self.removed_buses,
                self.added_links,
                self.removed_links,
                self.added_redundancy_groups,
                self.removed_redundancy_groups,
                self.added_services,
                self.removed_services,
                self.added_capabilities,
                self.removed_capabilities,
                self.added_fw_candidates,
                self.removed_fw_candidates,
                self.added_ps_candidates,
                self.removed_ps_candidates,
            )
        )


def compare_network_models(baseline: NetworkModel, candidate: NetworkModel) -> ArchitectureDelta:
    """Return the structural delta from *baseline* to *candidate*."""

    baseline_components = {c.name for c in baseline.components}
    candidate_components = {c.name for c in candidate.components}
    baseline_buses = set(baseline.buses)
    candidate_buses = set(candidate.buses)
    baseline_links = set(baseline.links)
    candidate_links = set(candidate.links)
    baseline_groups = {g.group_id for g in baseline.redundancy_groups}
    candidate_groups = {g.group_id for g in candidate.redundancy_groups}
    baseline_services = {s.name for s in baseline.services}
    candidate_services = {s.name for s in candidate.services}
    baseline_caps = {c.name for c in baseline.capabilities}
    candidate_caps = {c.name for c in candidate.capabilities}
    baseline_fws = set(baseline.cand_fws)
    candidate_fws = set(candidate.cand_fws)
    baseline_ps = set(baseline.cand_ps)
    candidate_ps = set(candidate.cand_ps)

    return ArchitectureDelta(
        baseline_name=baseline.name,
        candidate_name=candidate.name,
        added_components=sorted(candidate_components - baseline_components),
        removed_components=sorted(baseline_components - candidate_components),
        added_buses=sorted(candidate_buses - baseline_buses),
        removed_buses=sorted(baseline_buses - candidate_buses),
        added_links=sorted(candidate_links - baseline_links),
        removed_links=sorted(baseline_links - candidate_links),
        added_redundancy_groups=sorted(candidate_groups - baseline_groups),
        removed_redundancy_groups=sorted(baseline_groups - candidate_groups),
        added_services=sorted(candidate_services - baseline_services),
        removed_services=sorted(baseline_services - candidate_services),
        added_capabilities=sorted(candidate_caps - baseline_caps),
        removed_capabilities=sorted(baseline_caps - candidate_caps),
        added_fw_candidates=sorted(candidate_fws - baseline_fws),
        removed_fw_candidates=sorted(baseline_fws - candidate_fws),
        added_ps_candidates=sorted(candidate_ps - baseline_ps),
        removed_ps_candidates=sorted(baseline_ps - candidate_ps),
    )
