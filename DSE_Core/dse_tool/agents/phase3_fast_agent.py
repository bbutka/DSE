"""
phase3_fast_agent.py
====================
Pure-Python Phase 3 evaluator for resilience scenarios.

This mirrors the current ASP Phase 3 semantics closely enough for
strategy ranking, reporting, and closed-loop Phase 2 optimization while
avoiding repeated Clingo load/ground/solve cycles for each scenario.
"""

from __future__ import annotations

import queue
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

from ..core.asp_generator import ASPGenerator, Asset, Component
from ..core.solution_parser import Phase1Result, Phase2Result, ScenarioResult


_DOMAIN_LEVEL = {
    "untrusted": 0,
    "low": 0,
    "normal": 1,
    "privileged": 2,
    "high": 3,
    "root": 3,
}

_SECURITY_DISCOUNT = {
    "zero_trust": 5,
    "authenticated_encryption": 4,
    "dynamic_mac": 3,
    "mac": 1,
    "basic_access_control": 1,
    "no_security": 0,
}

_REALTIME_DISCOUNT = {
    "runtime_attestation": 2,
    "bus_monitor": 2,
    "watchdog": 1,
    "no_realtime": 0,
}

_AUDIT_DISCOUNT = {
    "full_audit": 3,
    "standard_audit": 2,
    "minimal_audit": 1,
    "no_audit": 0,
}


@dataclass(frozen=True)
class _CapabilityAccess:
    master: str
    component: str
    operation: str


class Phase3FastAgent:
    """Pure-Python Phase 3 evaluator."""

    def __init__(
        self,
        *,
        network_model,
        phase1_result: Phase1Result,
        phase2_result: Phase2Result,
        strategy: str = "max_security",
        progress_queue: Optional[queue.Queue] = None,
        full_scenarios: bool = False,
        timeout: int = 30,
        extra_instance_facts: str = "",
        solver_config: Optional[dict] = None,
    ) -> None:
        self.network_model = network_model
        self.phase1_result = phase1_result
        self.phase2_result = phase2_result
        self.strategy = strategy
        self.progress_queue = progress_queue
        self.full_scenarios = full_scenarios
        self.timeout = timeout
        self.extra_instance_facts = extra_instance_facts
        self.solver_config = solver_config or {}

        self._components = {c.name: c for c in network_model.components}
        self._receivers = [
            c.name for c in network_model.components
            if c.comp_type not in ("bus", "policy_server", "firewall") and not c.is_master
        ]
        self._masters = [c.name for c in network_model.components if c.is_master]
        self._assets = self._resolve_assets()
        self._assets_by_component = defaultdict(list)
        for asset in self._assets:
            self._assets_by_component[asset.component].append(asset)
        self._capabilities = {cap.name: cap for cap in network_model.capabilities}
        self._service_members = {svc.name: list(svc.members) for svc in network_model.services}
        self._service_quorum = {svc.name: svc.quorum for svc in network_model.services}
        self._domains = {
            c.name: c.domain
            for c in network_model.components
            if c.comp_type != "bus"
        }
        self._trust_anchors = network_model.trust_anchors or {}
        self._signed_policy = {
            node for node, anchors in self._trust_anchors.items()
            if "signed_policy" in anchors
        }
        self._pep_guards = self._guards_by_pep()
        self._critical_targets = {
            c.name for c in network_model.components
            if c.comp_type not in ("bus", "policy_server", "firewall")
            and (c.is_critical or c.is_safety_critical)
        }
        self._adj = self._build_undirected_graph()
        self._reachable = {
            node: self._bfs_reachable(node, self._neighbors_all)
            for node in self._all_nodes()
        }
        self._attack_depth = int(network_model.system_caps.get("max_attack_depth", 5) or 5)

    def run(self, model_scenarios: Optional[List[dict]] = None) -> List[ScenarioResult]:
        scenarios = model_scenarios or [{"name": "baseline", "compromised": [], "failed": []}]
        self._post(f"[Phase 3/{self.strategy}] Python evaluator running {len(scenarios)} scenario(s)...")

        results: List[ScenarioResult] = []
        for i, sc in enumerate(scenarios, 1):
            self._post(f"[Phase 3/{self.strategy}] Scenario {i}/{len(scenarios)}: {sc['name']}...")
            results.append(self._evaluate_scenario(sc))

        sat_results = [r for r in results if r.satisfiable]
        if sat_results:
            worst = max(sat_results, key=lambda r: r.total_risk_scaled)
            self._post(
                f"[Phase 3/{self.strategy}] Python done — "
                f"Worst blast radius: {max(r.max_blast_radius for r in sat_results)}, "
                f"Worst scenario: {worst.name} (risk={worst.total_risk:.1f})"
            )
        else:
            self._post(f"[Phase 3/{self.strategy}] Python done — all scenarios UNSAT")
        return results

    def _evaluate_scenario(self, scenario: dict) -> ScenarioResult:
        compromised = set(scenario.get("compromised", []))
        failed = set(scenario.get("failed", []))
        active_ps, active_peps = self._active_control_plane()
        pep_to_guards = self._pep_guards
        ps_to_peps = defaultdict(set)
        for ps, pep in self.network_model.ps_governs_pep:
            if ps in active_ps and pep in active_peps:
                ps_to_peps[ps].add(pep)

        ps_compromised = sorted(ps for ps in active_ps if ps in compromised)
        pep_bypassed = set(pep for pep in active_peps if pep in compromised)
        for ps in ps_compromised:
            pep_bypassed.update(ps_to_peps.get(ps, set()))

        def fw_blocked(src: str, dst: str) -> bool:
            if src in failed or dst in failed:
                return True
            for pep in active_peps:
                if pep in failed:
                    continue
                if pep in pep_bypassed:
                    continue
                if dst in pep_to_guards.get(pep, set()):
                    return True
            return False

        active_reachable = {
            master: self._bfs_reachable(master, lambda n: self._neighbors_active(n, failed))
            for master in self._masters
            if master not in failed
        }
        effective_reachable = {
            node: self._bfs_reachable(node, lambda n: self._neighbors_effective(n, failed, fw_blocked))
            for node in self._all_nodes()
            if node not in failed
        }

        blast_radii = {
            comp: len(self._reachable.get(comp, set()) - {comp})
            for comp in self._receivers
        }
        effective_blast_radii = {
            comp: len(effective_reachable.get(comp, set()) - {comp})
            for comp in self._receivers
            if comp not in failed
        }

        cut_off = sorted(
            comp for comp in self._receivers
            if comp not in failed
            and all(comp not in reachable for reachable in active_reachable.values())
        )

        service_counts: Dict[str, int] = {}
        services_ok: List[str] = []
        services_deg: List[str] = []
        services_unavail: List[str] = []
        for svc, members in self._service_members.items():
            live = 0
            for member in members:
                if member in failed or member in compromised or member in cut_off:
                    continue
                live += 1
            service_counts[svc] = live
            quorum = self._service_quorum[svc]
            if live >= quorum:
                services_ok.append(svc)
            elif live > 0:
                services_deg.append(svc)
            else:
                services_unavail.append(svc)

        active_ps_count = sum(1 for ps in active_ps if ps not in failed and ps not in compromised)
        healthy_governed = set()
        for ps, peps in ps_to_peps.items():
            if ps in failed or ps in compromised:
                continue
            healthy_governed.update(peps)
        ungoverned_peps = sorted(
            pep for pep in active_peps
            if pep not in failed and pep not in healthy_governed
        )

        stale_policy = False
        for ps, peps in ps_to_peps.items():
            if ps not in failed:
                continue
            for pep in peps:
                if pep in failed or pep in pep_bypassed:
                    continue
                if pep_to_guards.get(pep):
                    stale_policy = True
                    break
            if stale_policy:
                break

        asset_unavailable = []
        asset_compromised = []
        direct_exp = []
        cross_exp = []
        same_exp = []
        unmediated_exp = []
        scenario_action_risks: Dict[Tuple[str, str], int] = {}
        scenario_asset_risks: Dict[str, int] = {}

        for asset in self._assets:
            owner = asset.component
            if owner in failed:
                asset_unavailable.append(asset.asset_id)
            if owner in compromised:
                asset_compromised.append(asset.asset_id)

            factor_candidates = []  # sentinel removed — only real exposures contribute
            for node in compromised:
                if owner == node:
                    factor_candidates.append(30)
                    direct_exp.append((asset.asset_id, node, 30))
                    continue
                if owner not in self._reachable.get(node, set()):
                    continue
                disc = self._protection_discount(owner)
                if disc is None:
                    continue
                node_domain = self._domains.get(node, "normal")
                owner_domain = self._domains.get(owner, "normal")
                if _DOMAIN_LEVEL.get(node_domain, 1) < _DOMAIN_LEVEL.get(owner_domain, 1):
                    factor = 20 - disc
                    cross_exp.append((asset.asset_id, node, factor))
                else:
                    factor = 15 - disc
                    same_exp.append((asset.asset_id, node, factor))
                factor_candidates.append(factor)

            for pep in pep_bypassed:
                for guarded in pep_to_guards.get(pep, set()):
                    if guarded != owner:
                        continue
                    for master in self._masters:
                        if master in compromised or master in failed or owner in failed:
                            continue
                        factor_candidates.append(25)
                        unmediated_exp.append((asset.asset_id, master, 25))

            if stale_policy:
                for ps, peps in ps_to_peps.items():
                    if ps not in failed:
                        continue
                    if any(owner in pep_to_guards.get(pep, set()) for pep in peps if pep not in failed and pep not in pep_bypassed):
                        factor_candidates.append(12)
                        break

            if self._unsigned_only_exposure(active_ps, failed, compromised, ps_to_peps, owner):
                factor_candidates.append(11)
            if self._ps_conflict_exposure(active_ps, failed, compromised, ps_to_peps, owner):
                factor_candidates.append(13)

            factor = max(factor_candidates) if factor_candidates else 10  # baseline 1.0x
            for (asset_id, action), base_risk in self.phase1_result.risk_per_asset_action().items():
                if asset_id != asset.asset_id:
                    continue
                scenario_action_risks[(asset_id, action)] = base_risk * factor
            if factor and any(aid == asset.asset_id for (aid, _op) in scenario_action_risks):
                scenario_asset_risks[asset.asset_id] = max(
                    risk for (aid, _op), risk in scenario_action_risks.items() if aid == asset.asset_id
                )

        attack_paths, escalation_paths = self._attack_metrics(
            compromised=compromised,
            failed=failed,
            effective_neighbor_fn=lambda n: self._neighbors_effective(n, failed, fw_blocked),
        )
        structural_paths, _ = self._attack_metrics(
            compromised=compromised,
            failed=failed,
            effective_neighbor_fn=lambda n: self._neighbors_active(n, failed),
        )

        capabilities_ok: List[str] = []
        capabilities_degraded: List[str] = []
        capabilities_lost: List[str] = []
        essential_caps_lost: List[str] = []
        capability_reasons: Dict[str, List[str]] = {}

        for cap_name, cap in self._capabilities.items():
            reasons: List[str] = []
            lost = False
            for svc in cap.required_services:
                if svc in services_unavail or svc in services_deg:
                    reasons.append(f"service {svc} unavailable")
                    lost = True
            for comp in cap.required_components:
                if comp in failed or comp in compromised or comp in cut_off:
                    reasons.append(f"component {comp} down")
                    lost = True
            unmediated = False
            for access in cap.required_access:
                acc = _CapabilityAccess(*access)
                broken, unmed = self._evaluate_access(acc, compromised, failed, active_reachable, pep_to_guards, pep_bypassed)
                if broken:
                    reasons.append(f"{acc.master}->{acc.component} ({acc.operation}) broken")
                    lost = True
                elif unmed:
                    reasons.append(f"{acc.master}->{acc.component} ({acc.operation}) unmediated (PEP bypassed)")
                    unmediated = True
            if lost:
                capabilities_lost.append(cap_name)
                if cap.criticality == "essential":
                    essential_caps_lost.append(cap_name)
            elif unmediated:
                reasons.append("PEP bypass — access unmediated")
                capabilities_degraded.append(cap_name)
            else:
                capabilities_ok.append(cap_name)
            if reasons:
                capability_reasons[cap_name] = reasons

        has_capabilities = bool(self._capabilities)
        system_non_functional = bool(essential_caps_lost)
        system_functional = (not has_capabilities) or not system_non_functional
        system_degraded = system_functional and bool(capabilities_lost or capabilities_degraded)

        result = ScenarioResult(
            name=scenario["name"],
            compromised=sorted(compromised),
            failed=sorted(failed),
            scenario_risks=scenario_asset_risks,
            scenario_action_risks=scenario_action_risks,
            total_risk_scaled=sum(scenario_asset_risks.values()),
            blast_radii=blast_radii,
            unavailable=sorted(asset_unavailable),
            assets_compromised=sorted(asset_compromised),
            cut_off=cut_off,
            services_ok=sorted(services_ok),
            services_degraded=sorted(services_deg),
            services_unavail=sorted(services_unavail),
            service_counts=service_counts,
            active_ps_count=active_ps_count,
            ungoverned_peps=ungoverned_peps,
            cp_degraded=bool(ungoverned_peps or pep_bypassed or stale_policy),
            cp_stale=stale_policy,
            cp_compromised=bool(ps_compromised),
            peps_bypassed=sorted(pep_bypassed),
            ps_compromised=ps_compromised,
            direct_exp=sorted(set(direct_exp)),
            cross_exp=sorted(set(cross_exp)),
            same_exp=sorted(set(same_exp)),
            unmediated_exp=sorted(set(unmediated_exp)),
            satisfiable=True,
            effective_blast_radii=effective_blast_radii,
            attack_paths=sorted(attack_paths),
            escalation_paths=sorted(escalation_paths),
            structural_attack_paths=sorted(structural_paths),
            capabilities_ok=sorted(capabilities_ok),
            capabilities_degraded=sorted(capabilities_degraded),
            capabilities_lost=sorted(capabilities_lost),
            essential_caps_lost=sorted(essential_caps_lost),
            capability_reasons=capability_reasons,
            system_functional=system_functional,
            system_degraded=system_degraded,
            system_non_functional=system_non_functional,
        )
        return result

    def _resolve_assets(self) -> List[Asset]:
        if self.network_model.assets:
            return list(self.network_model.assets)
        assets: List[Asset] = []
        for c in self.network_model.components:
            if c.comp_type in ("bus", "policy_server", "firewall") or c.is_master:
                continue
            assets.append(
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
            )
        return assets

    def _build_undirected_graph(self) -> Dict[str, Set[str]]:
        adj: Dict[str, Set[str]] = defaultdict(set)
        for src, dst in self.network_model.links:
            adj[src].add(dst)
            adj[dst].add(src)
        return adj

    def _all_nodes(self) -> Set[str]:
        nodes = set(self._adj)
        nodes.update(self.network_model.buses)
        nodes.update(self._components)
        nodes.update(self.network_model.cand_fws)
        nodes.update(self.network_model.cand_ps)
        return nodes

    def _neighbors_all(self, node: str) -> Iterable[str]:
        return self._adj.get(node, set())

    def _neighbors_active(self, node: str, failed: Set[str]) -> Iterable[str]:
        if node in failed:
            return ()
        return [nbr for nbr in self._adj.get(node, set()) if nbr not in failed]

    def _neighbors_effective(self, node: str, failed: Set[str], fw_blocked) -> Iterable[str]:
        if node in failed:
            return ()
        return [
            nbr for nbr in self._adj.get(node, set())
            if nbr not in failed and not fw_blocked(node, nbr)
        ]

    @staticmethod
    def _bfs_reachable(start: str, neighbor_fn) -> Set[str]:
        seen = {start}
        q = deque([start])
        while q:
            node = q.popleft()
            for nbr in neighbor_fn(node):
                if nbr in seen:
                    continue
                seen.add(nbr)
                q.append(nbr)
        return seen

    def _active_control_plane(self) -> Tuple[Set[str], Set[str]]:
        if self.phase2_result.satisfiable and (self.phase2_result.placed_fws or self.phase2_result.placed_ps):
            return set(self.phase2_result.placed_ps), set(self.phase2_result.placed_fws)
        return set(self.network_model.cand_ps), set(self.network_model.cand_fws)

    def _protection_discount(self, component: str) -> Optional[int]:
        security = self.phase1_result.security.get(component, "no_security")
        realtime = self.phase1_result.realtime.get(component, "no_realtime")
        comp_obj = self._components.get(component)
        audit = ASPGenerator._audit_capability(comp_obj) if comp_obj else "no_audit"
        # Match current ASP semantics exactly: explicit no_realtime and
        # explicit no_audit do not derive a protection_discount/2 atom.
        # Protected indirect exposure then disappears entirely rather than
        # falling back to a zero discount.
        if realtime == "no_realtime" or audit == "no_audit":
            return None
        return min(
            10,
            _SECURITY_DISCOUNT.get(security, 0)
            + _REALTIME_DISCOUNT.get(realtime, 0)
            + _AUDIT_DISCOUNT.get(audit, 0),
        )

    def _unsigned_only_exposure(
        self,
        active_ps: Set[str],
        failed: Set[str],
        compromised: Set[str],
        ps_to_peps: Dict[str, Set[str]],
        owner: str,
    ) -> bool:
        unsigned_alive = [
            ps for ps in active_ps
            if ps not in failed and ps not in compromised and ps not in self._signed_policy
        ]
        signed_alive = [
            ps for ps in active_ps
            if ps not in failed and ps not in compromised and ps in self._signed_policy
        ]
        if not unsigned_alive or signed_alive:
            return False
        for ps in unsigned_alive:
            if any(owner in self._pep_guards.get(pep, set()) for pep in ps_to_peps.get(ps, set())):
                return True
        return False

    def _ps_conflict_exposure(
        self,
        active_ps: Set[str],
        failed: Set[str],
        compromised: Set[str],
        ps_to_peps: Dict[str, Set[str]],
        owner: str,
    ) -> bool:
        compromised_ps = [ps for ps in active_ps if ps in compromised]
        healthy_ps = [ps for ps in active_ps if ps not in failed and ps not in compromised]
        if not compromised_ps or not healthy_ps:
            return False
        return any(owner in guards for guards in self._pep_guards.values())

    def _guards_by_pep(self) -> Dict[str, Set[str]]:
        guards: Dict[str, Set[str]] = defaultdict(set)
        for pep, comp in self.network_model.pep_guards:
            guards[pep].add(comp)
        return guards

    def _evaluate_access(
        self,
        access: _CapabilityAccess | Tuple[str, str, str],
        compromised: Set[str],
        failed: Set[str],
        active_reachable: Dict[str, Set[str]],
        pep_to_guards: Dict[str, Set[str]],
        pep_bypassed: Set[str],
    ) -> Tuple[bool, bool]:
        if not isinstance(access, _CapabilityAccess):
            access = _CapabilityAccess(*access)
        if access.component in failed or access.master in failed or access.component in compromised:
            return True, False
        if access.master != access.component and access.component not in active_reachable.get(access.master, set()):
            return True, False
        for pep, guards in pep_to_guards.items():
            if access.component in guards and pep in pep_bypassed:
                return False, True
        return False, False

    def _attack_metrics(
        self,
        *,
        compromised: Set[str],
        failed: Set[str],
        effective_neighbor_fn,
    ) -> Tuple[List[Tuple[str, str, int]], List[Tuple[str, str, str, str]]]:
        min_paths: Dict[Tuple[str, str], int] = {}
        escalation: Set[Tuple[str, str, str, str]] = set()
        for src in compromised:
            if src in failed:
                continue
            distances = self._bounded_bfs(src, effective_neighbor_fn)
            src_domain = self._domains.get(src, "normal")
            for dst, dist in distances.items():
                if dst in self._critical_targets:
                    key = (src, dst)
                    cur = min_paths.get(key)
                    if cur is None or dist < cur:
                        min_paths[key] = dist
                dst_domain = self._domains.get(dst)
                if dst_domain is not None and _DOMAIN_LEVEL.get(src_domain, 1) < _DOMAIN_LEVEL.get(dst_domain, 1):
                    escalation.add((src, dst, src_domain, dst_domain))
        paths = [(src, dst, dist) for (src, dst), dist in min_paths.items()]
        return paths, list(escalation)

    def _bounded_bfs(self, start: str, neighbor_fn) -> Dict[str, int]:
        q = deque([(start, 0)])
        seen = {start: 0}
        while q:
            node, dist = q.popleft()
            if dist >= self._attack_depth:
                continue
            for nbr in neighbor_fn(node):
                nd = dist + 1
                prev = seen.get(nbr)
                if prev is not None and prev <= nd:
                    continue
                seen[nbr] = nd
                q.append((nbr, nd))
        seen.pop(start, None)
        return seen

    def _post(self, msg: str) -> None:
        if self.progress_queue is not None:
            try:
                self.progress_queue.put_nowait(("INFO", msg))
            except queue.Full:
                pass
