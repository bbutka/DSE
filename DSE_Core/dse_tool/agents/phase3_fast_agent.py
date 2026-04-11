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
        self._function_supports = list(getattr(network_model, "function_supports", []) or [])
        self._function_thresholds = dict(getattr(network_model, "function_thresholds", {}) or {})
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
        if model_scenarios:
            scenarios = model_scenarios
        else:
            from .phase3_agent import generate_scenarios

            scenarios = generate_scenarios(self.network_model, full=self.full_scenarios)
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
                f"Worst scenario: {worst.name} (score={worst.total_risk:.1f})"
            )
        else:
            self._post(f"[Phase 3/{self.strategy}] Python done — all scenarios UNSAT")
        return results

    def _scenario_mode(self, compromised: Set[str]) -> Optional[str]:
        """Mirror ASP scenario_mode/1 when Phase 2 mode-aware policy exists."""
        if not self.phase2_result.final_allows:
            return None
        if not compromised:
            return "normal"
        active_ps, _active_peps = self._active_control_plane()
        if any(node in active_ps for node in compromised):
            return "attack_confirmed"
        if any(getattr(self._components.get(node), "is_safety_critical", False) for node in compromised):
            return "attack_confirmed"
        return "attack_suspected"

    def _mode_denied_access(self, master: str, component: str, scenario_mode: Optional[str]) -> bool:
        if scenario_mode is None:
            return False
        return (master, component, scenario_mode) not in set(self.phase2_result.final_allows)

    def _evaluate_scenario(self, scenario: dict) -> ScenarioResult:
        compromised = set(scenario.get("compromised", []))
        failed = set(scenario.get("failed", []))
        failed_modalities = set(scenario.get("failed_modalities", []))
        scenario_mode = self._scenario_mode(compromised)
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
        healthy_master_reachable = {
            master: reachable
            for master, reachable in active_reachable.items()
            if master not in compromised
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
            and all(comp not in reachable for reachable in healthy_master_reachable.values())
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
        mode_denied_accesses: List[Tuple[str, str]] = []
        scenario_action_risks: Dict[Tuple[str, str], int] = {}
        scenario_asset_risks: Dict[str, int] = {}
        scenario_asset_max_risks: Dict[str, int] = {}
        amp_factors: Dict[str, int] = {}
        effective_risk_weights: Dict[str, int] = {}
        baseline_risks = self.phase1_result.risk_per_asset_action()
        fallback_asset_risks = self.phase1_result.max_risk_per_asset()

        for asset in self._assets:
            owner = asset.component
            if owner in failed:
                asset_unavailable.append(asset.asset_id)
            if owner in compromised:
                asset_compromised.append(asset.asset_id)

            factor_candidates = []  # sentinel removed — only real exposures contribute
            for node in compromised:
                trust_amp = self._trust_amp(node)
                if owner == node:
                    disc = self._protection_discount(owner)
                    factor = max(10, 30 - disc + trust_amp)
                    factor_candidates.append(factor)
                    direct_exp.append((asset.asset_id, node, factor))
                    continue
                if owner not in effective_reachable.get(node, set()):
                    continue
                disc = self._protection_discount(owner)
                node_domain = self._domains.get(node, "normal")
                owner_domain = self._domains.get(owner, "normal")
                if _DOMAIN_LEVEL.get(node_domain, 1) < _DOMAIN_LEVEL.get(owner_domain, 1):
                    factor = max(10, 20 - disc + trust_amp)
                    cross_exp.append((asset.asset_id, node, factor))
                else:
                    factor = max(10, 15 - disc + trust_amp)
                    same_exp.append((asset.asset_id, node, factor))
                factor_candidates.append(factor)

            for pep in pep_bypassed:
                for guarded in pep_to_guards.get(pep, set()):
                    if guarded != owner:
                        continue
                    for master in self._masters:
                        if master in compromised or master in failed or owner in failed:
                            continue
                        if owner not in self._reachable.get(master, set()):
                            continue
                        if self._mode_denied_access(master, owner, scenario_mode):
                            mode_denied_accesses.append((master, owner))
                            continue
                        disc = self._protection_discount(owner)
                        factor = max(10, 25 - disc)
                        factor_candidates.append(factor)
                        unmediated_exp.append((asset.asset_id, master, factor))

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

            factor = max(factor_candidates) if factor_candidates else 10
            amp_factors[asset.asset_id] = factor
            weight = self.phase1_result.risk_weights.get(asset.asset_id, 1)
            effective_risk_weights[asset.asset_id] = weight
            has_action_risk = False
            for (asset_id, action), base_risk in baseline_risks.items():
                if asset_id != asset.asset_id:
                    continue
                has_action_risk = True
                scenario_action_risks[(asset_id, action)] = base_risk * factor
            if has_action_risk:
                asset_action_risks = [
                    risk for (aid, _op), risk in scenario_action_risks.items() if aid == asset.asset_id
                ]
                scenario_asset_max_risks[asset.asset_id] = max(asset_action_risks)
                scenario_asset_risks[asset.asset_id] = weight * sum(asset_action_risks)
            elif asset.asset_id in fallback_asset_risks:
                base_risk = fallback_asset_risks[asset.asset_id]
                scaled_risk = base_risk * factor
                scenario_asset_max_risks[asset.asset_id] = scaled_risk
                scenario_asset_risks[asset.asset_id] = weight * scaled_risk

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
        function_eval = self._evaluate_function_supports(
            failed=failed,
            compromised=compromised,
            cut_off=set(cut_off),
            failed_modalities=failed_modalities,
            failed_buses=failed.intersection(set(self.network_model.buses)),
        )

        result = ScenarioResult(
            name=scenario["name"],
            compromised=sorted(compromised),
            failed=sorted(failed),
            failed_modalities=sorted(failed_modalities),
            scenario_risks=scenario_asset_risks,
            scenario_action_risks=scenario_action_risks,
            total_risk_scaled=sum(scenario_asset_risks.values()),
            blast_radii=blast_radii,
            unavailable=sorted(asset_unavailable),
            assets_compromised=sorted(asset_compromised),
            cut_off=cut_off,
            component_bus_cut=cut_off,
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
            amp_factors=amp_factors,
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
            has_capabilities=has_capabilities,
            capability_ok_count=len(capabilities_ok),
            capability_degraded_count=len(capabilities_degraded),
            capability_lost_count=len(capabilities_lost),
            function_scores=function_eval["scores"],
            function_statuses=function_eval["statuses"],
            functions_ok=function_eval["ok"],
            functions_degraded=function_eval["degraded"],
            functions_lost=function_eval["lost"],
            function_findings=function_eval["findings"],
        )
        result.scenario_asset_max_risks = scenario_asset_max_risks
        result.effective_risk_weights = effective_risk_weights
        if scenario_mode is not None:
            result.scenario_modes = [scenario_mode]
        result.mode_denied_accesses = sorted(set(mode_denied_accesses))
        return result

    def _evaluate_function_supports(
        self,
        *,
        failed: Set[str],
        compromised: Set[str],
        cut_off: Set[str],
        failed_modalities: Set[str],
        failed_buses: Set[str],
    ) -> Dict[str, object]:
        """
        Evaluate function-level resilience using a max-quality fallback model.

        ``max(quality)`` is a single-best-surviving-support approximation, not
        a sensor-fusion model. It means a GPS quality of 90 can be high-quality
        standalone state estimation while an IMU quality of 70 is a usable but
        drift-limited fallback.
        """
        supports_by_function: Dict[str, List[object]] = defaultdict(list)
        for support in self._function_supports:
            supports_by_function[support.function].append(support)

        scores: Dict[str, int] = {}
        statuses: Dict[str, str] = {}
        functions_ok: List[str] = []
        functions_degraded: List[str] = []
        functions_lost: List[str] = []
        findings: List[str] = []

        for function_name, supports in supports_by_function.items():
            thresholds = self._function_thresholds.get(function_name, {})
            ok_threshold = int(thresholds.get("ok", 80))
            degraded_threshold = int(thresholds.get("degraded", 50))

            available_scores = [
                int(support.quality)
                for support in supports
                if support.component not in failed
                and support.component not in compromised
                and support.component not in cut_off
                and support.modality not in failed_modalities
                and (not getattr(support, "bus", "") or support.bus not in failed_buses)
            ]
            score = max(available_scores, default=0)
            scores[function_name] = score

            if score >= ok_threshold:
                statuses[function_name] = "ok"
                functions_ok.append(function_name)
            elif score >= degraded_threshold:
                statuses[function_name] = "degraded"
                functions_degraded.append(function_name)
            else:
                statuses[function_name] = "lost"
                functions_lost.append(function_name)

            modalities = {support.modality for support in supports}
            if len(modalities) < 2:
                findings.append(f"{function_name}_lacks_modality_diversity")
            if (
                function_name == "state_estimation"
                and "satellite" in failed_modalities
                and statuses[function_name] == "lost"
            ):
                findings.append("state_estimation_lost_under_satellite_failure")
            if failed_modalities and score < degraded_threshold:
                findings.append(f"{function_name}_fallback_below_degraded_threshold")

            support_buses = {support.bus for support in supports if getattr(support, "bus", "")}
            if support_buses and len(support_buses) < 2:
                findings.append(f"{function_name}_lacks_bus_diversity")
            if (
                function_name == "state_estimation"
                and failed_buses
                and statuses[function_name] == "lost"
            ):
                findings.append("state_estimation_lost_under_bus_failure")
            if failed_buses and score < degraded_threshold:
                findings.append(f"{function_name}_bus_fallback_below_degraded_threshold")

        return {
            "scores": scores,
            "statuses": statuses,
            "ok": sorted(functions_ok),
            "degraded": sorted(functions_degraded),
            "lost": sorted(functions_lost),
            "findings": sorted(set(findings)),
        }

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
        phase2_context_present = bool(
            self.phase2_result.placed_fws
            or self.phase2_result.placed_ps
            or self.phase2_result.final_allows
        )
        assume_all_cp = int(self.network_model.system_caps.get("assume_all_cp_active", 0)) == 1
        if assume_all_cp and not phase2_context_present:
            return set(self.network_model.cand_ps), set(self.network_model.cand_fws)
        return set(), set()

    def _protection_discount(self, component: str) -> int:
        """Compute combined protection discount matching ASP resilience_enc.lp.

        Always returns an int (0-10).  The ASP encoding assigns
        audit_discount(C, 0) for components without audit_capability,
        so the Python backend must do the same — never return None.
        """
        security = self.phase1_result.security.get(component, "no_security")
        realtime = self.phase1_result.realtime.get(component, "no_realtime")
        comp_obj = self._components.get(component)
        audit = ASPGenerator._audit_capability(comp_obj) if comp_obj else "no_audit"
        return min(
            10,
            _SECURITY_DISCOUNT.get(security, 0)
            + _REALTIME_DISCOUNT.get(realtime, 0)
            + _AUDIT_DISCOUNT.get(audit, 0),
        )

    def _trust_amp(self, node: str) -> int:
        """Return trust-level amplification available to the current Phase 3 contract.

        Phase 3 currently consumes deployed PEP/PS placement and optional
        mode-aware allows.  Trust-level diagnostics exist in Phase 2 results but
        are not serialized into Phase 3 facts, so the Python evaluator must
        ignore them to stay aligned with the ASP backend.
        """
        return 0

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
        owner_peps = {
            pep for pep, guards in self._pep_guards.items()
            if owner in guards
        }
        if not owner_peps:
            return False
        for bad_ps in compromised_ps:
            bad_peps = ps_to_peps.get(bad_ps, set())
            if not bad_peps:
                continue
            for good_ps in healthy_ps:
                if owner_peps.intersection(bad_peps, ps_to_peps.get(good_ps, set())):
                    return True
        return False

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
