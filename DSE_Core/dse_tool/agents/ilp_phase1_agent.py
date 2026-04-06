"""
ilp_phase1_agent.py
===================
Phase 1 worker implemented as an integer linear program using PuLP + CBC.

This agent is a drop-in producer of Phase1Result so the existing ASP-based
Phase 2 and Phase 3 remain unchanged.

Strategy semantics match the active ASP path:

- max_security: minimize weighted total risk
- min_resources: lexicographic minimize LUTs, then weighted total risk
- balanced: lexicographic minimize weighted total risk, then LUTs
"""

from __future__ import annotations

import itertools
import queue
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

try:
    import pulp
except ImportError:  # pragma: no cover - dependency may be absent locally
    pulp = None

from ip_catalog.xilinx_ip_catalog import (
    LOGGING_FEATURE_EXPORT_ORDER,
    LOGGING_RISK_VALUES,
    SECURITY_FEATURE_EXPORT_ORDER,
    VULNERABILITY_VALUES,
    get_calibrated_estimate,
)

from ..core.asp_generator import Asset, Component, NetworkModel
from ..core.solution_parser import Phase1Result


MU = 25
OMEGA = 1000
RESOURCES = ("luts", "ffs", "dsps", "lutram", "bram", "bufg", "power_cost")


@dataclass(frozen=True)
class _PairOption:
    security: str
    logging: str
    latency: int


class ILPPhase1Agent:
    """Runs the Phase 1 optimisation using a PuLP/CBC MILP backend."""

    def __init__(
        self,
        network_model: NetworkModel,
        strategy: str = "max_security",
        progress_queue: Optional[queue.Queue] = None,
        timeout: int = 60,
        solver_config: Optional[dict] = None,
    ) -> None:
        self.network_model = network_model
        self.strategy = strategy
        self.progress_queue = progress_queue
        self.timeout = timeout
        self.solver_config = solver_config or {}

    def run(self) -> Phase1Result:
        self._post(f"[Phase 1/{self.strategy}/ILP] Starting security DSE optimisation...")
        if pulp is None:
            self._post("[Phase 1/ILP] PuLP is not installed; ILP backend unavailable.")
            return Phase1Result(strategy=self.strategy, satisfiable=False)

        try:
            result = self._solve()
        except Exception as exc:  # noqa: BLE001
            self._post(f"[Phase 1/{self.strategy}/ILP] ERROR: {exc}")
            return Phase1Result(strategy=self.strategy, satisfiable=False)

        if result.satisfiable:
            self._post(
                f"[Phase 1/{self.strategy}/ILP] Done - "
                f"Risk: {result.total_risk()}, "
                f"LUTs: {result.total_luts:,}, "
                f"Power: {result.total_power:,} mW"
            )
        return result

    def _solve(self) -> Phase1Result:
        protected_components = self._protected_components()
        if not protected_components:
            return Phase1Result(strategy=self.strategy, satisfiable=False)

        component_assets = self._component_assets(protected_components)
        component_lookup = self._component_lookup()
        latency_caps = self._component_latency_caps(component_assets)
        modern_dual_risk = (
            "max_security_risk" in self.network_model.system_caps
            or "max_avail_risk" in self.network_model.system_caps
        )
        max_asset_risk = int(self.network_model.system_caps.get("max_asset_risk", 500))
        max_security_risk = int(self.network_model.system_caps.get("max_security_risk", max_asset_risk))
        max_avail_risk = int(self.network_model.system_caps.get("max_avail_risk", max_asset_risk))
        asset_weights = self._asset_weights(component_assets, component_lookup, modern_dual_risk)

        pair_options = tuple(
            _PairOption(
                security=security,
                logging=logging,
                latency=self._security_latency(security) + self._logging_latency(logging),
            )
            for security in SECURITY_FEATURE_EXPORT_ORDER
            for logging in LOGGING_FEATURE_EXPORT_ORDER
        )

        groups = [
            tuple(member for member in group.members if member in protected_components)
            for group in self.network_model.redundancy_groups
        ]
        groups = [group for group in groups if group]
        grouped_components = {component for group in groups for component in group}
        standalone_components = [component for component in protected_components if component not in grouped_components]

        feasible_pairs: Dict[str, List[int]] = {}
        standalone_risk_rows: Dict[Tuple[str, int], List[Tuple[str, str, int]]] = {}
        standalone_risk_totals: Dict[Tuple[str, int], int] = {}

        for component in protected_components:
            feasible_pairs[component] = []
            for pair_index, pair in enumerate(pair_options):
                if pair.latency > latency_caps[component]:
                    continue
                risk_rows = self._component_risk_rows(
                    component_assets[component],
                    pair.security,
                    pair.logging,
                )
                if component not in grouped_components:
                    cap = max_security_risk if modern_dual_risk else max_asset_risk
                    if not self._rows_within_cap(risk_rows, cap):
                        continue
                feasible_pairs[component].append(pair_index)
                standalone_risk_rows[(component, pair_index)] = risk_rows
                standalone_risk_totals[(component, pair_index)] = self._weighted_risk_total(
                    risk_rows, asset_weights
                )

            if not feasible_pairs[component]:
                self._post(f"[Phase 1/{self.strategy}/ILP] No feasible selections for component {component}.")
                return Phase1Result(strategy=self.strategy, satisfiable=False)

        model = pulp.LpProblem(f"phase1_{self.strategy}", pulp.LpMinimize)
        x: Dict[Tuple[str, int], pulp.LpVariable] = {}
        for component in protected_components:
            for pair_index in feasible_pairs[component]:
                x[(component, pair_index)] = pulp.LpVariable(
                    f"x_{component}_{pair_index}",
                    lowBound=0,
                    upBound=1,
                    cat=pulp.LpBinary,
                )
            model += pulp.lpSum(x[(component, pair_index)] for pair_index in feasible_pairs[component]) == 1

        group_combo_vars: Dict[Tuple[int, int], pulp.LpVariable] = {}
        group_combo_defs: Dict[Tuple[int, int], Tuple[int, ...]] = {}
        group_combo_risks: Dict[Tuple[int, int], Dict[str, List[Tuple[str, str, int]]]] = {}
        group_combo_totals: Dict[Tuple[int, int], int] = {}

        combo_limit = int(self.solver_config.get("group_combo_limit", 100000))
        for group_index, members in enumerate(groups):
            domains = [tuple(feasible_pairs[component]) for component in members]
            combo_count = 1
            for domain in domains:
                combo_count *= len(domain)
            if combo_count > combo_limit:
                raise ValueError(
                    f"Redundancy group {group_index + 1} expands to {combo_count} combinations; "
                    f"limit is {combo_limit}."
                )

            valid_combo_keys: List[Tuple[int, int]] = []
            combo_index = 0
            for pair_indices in itertools.product(*domains):
                combo_risks = self._group_combo_risks(
                    members,
                    pair_indices,
                    component_assets,
                    pair_options,
                )
                combo_cap = max_avail_risk if modern_dual_risk else max_asset_risk
                if any(not self._rows_within_cap(rows, combo_cap) for rows in combo_risks.values()):
                    continue

                combo_key = (group_index, combo_index)
                group_combo_defs[combo_key] = pair_indices
                group_combo_risks[combo_key] = combo_risks
                group_combo_totals[combo_key] = sum(
                    self._weighted_risk_total(rows, asset_weights)
                    for rows in combo_risks.values()
                )
                group_combo_vars[combo_key] = pulp.LpVariable(
                    f"g_{group_index}_{combo_index}",
                    lowBound=0,
                    upBound=1,
                    cat=pulp.LpBinary,
                )
                valid_combo_keys.append(combo_key)
                combo_index += 1

            if not valid_combo_keys:
                self._post(f"[Phase 1/{self.strategy}/ILP] No feasible redundancy selections for group {members}.")
                return Phase1Result(strategy=self.strategy, satisfiable=False)

            model += pulp.lpSum(group_combo_vars[key] for key in valid_combo_keys) == 1

            for member_offset, component in enumerate(members):
                for pair_index in feasible_pairs[component]:
                    model += (
                        x[(component, pair_index)]
                        == pulp.lpSum(
                            group_combo_vars[key]
                            for key in valid_combo_keys
                            if group_combo_defs[key][member_offset] == pair_index
                        )
                    )

        totals: Dict[str, pulp.LpAffineExpression] = {}
        for resource_name in RESOURCES:
            totals[resource_name] = pulp.lpSum(
                x[(component, pair_index)]
                * (
                    self._feature_cost(pair_options[pair_index].security, resource_name)
                    + self._feature_cost(pair_options[pair_index].logging, resource_name)
                )
                for component in protected_components
                for pair_index in feasible_pairs[component]
            )

        self._constrain_resource(model, totals["luts"], "max_luts")
        self._constrain_resource(model, totals["ffs"], "max_ffs")
        self._constrain_resource(model, totals["dsps"], "max_dsps")
        self._constrain_resource(model, totals["lutram"], "max_lutram")
        self._constrain_resource(model, totals["bram"], "max_bram")
        self._constrain_resource(model, totals["bufg"], "max_bufgs")
        self._constrain_resource(model, totals["power_cost"], "max_power")

        total_weighted_risk = (
            pulp.lpSum(
                x[(component, pair_index)] * standalone_risk_totals[(component, pair_index)]
                for component in standalone_components
                for pair_index in feasible_pairs[component]
            )
            + pulp.lpSum(group_combo_vars[key] * group_combo_totals[key] for key in group_combo_vars)
        )
        total_luts = totals["luts"]

        if self.strategy == "min_resources":
            self._solve_primary_then_secondary(model, total_luts, total_weighted_risk)
        elif self.strategy == "balanced":
            self._solve_primary_then_secondary(model, total_weighted_risk, total_luts)
        else:
            self._solve_with_objective(model, total_weighted_risk)

        if pulp.LpStatus.get(model.status) != "Optimal":
            self._post(
                f"[Phase 1/{self.strategy}/ILP] Solve status: "
                f"{pulp.LpStatus.get(model.status, model.status)}"
            )
            return Phase1Result(strategy=self.strategy, satisfiable=False)

        security: Dict[str, str] = {}
        logging: Dict[str, str] = {}
        security_risk: List[Tuple[str, str, str, int]] = []
        avail_risk: List[Tuple[str, str, str, int]] = []

        chosen_pairs: Dict[str, int] = {}
        for component in protected_components:
            for pair_index in feasible_pairs[component]:
                value = pulp.value(x[(component, pair_index)])
                if value is not None and value > 0.5:
                    chosen_pairs[component] = pair_index
                    pair = pair_options[pair_index]
                    security[component] = pair.security
                    logging[component] = pair.logging
                    break

        for component in standalone_components:
            for asset_id, action, risk in standalone_risk_rows[(component, chosen_pairs[component])]:
                security_risk.append((component, asset_id, action, risk))

        for combo_key, combo_var in group_combo_vars.items():
            value = pulp.value(combo_var)
            if value is None or value <= 0.5:
                continue
            combo_risks = group_combo_risks[combo_key]
            for component, rows in combo_risks.items():
                for asset_id, action, risk in rows:
                    avail_risk.append((component, asset_id, action, risk))

        security_risk.sort(key=lambda row: (row[0], row[1], row[2]))
        avail_risk.sort(key=lambda row: (row[0], row[1], row[2]))
        new_risk = sorted(security_risk + avail_risk, key=lambda row: (row[0], row[1], row[2]))

        return Phase1Result(
            security=security,
            logging=logging,
            new_risk=new_risk,
            security_risk=security_risk,
            avail_risk=avail_risk,
            risk_weights=asset_weights,
            total_luts=int(round(pulp.value(total_luts) or 0)),
            total_ffs=int(round(pulp.value(totals["ffs"]) or 0)),
            total_dsps=int(round(pulp.value(totals["dsps"]) or 0)),
            total_lutram=int(round(pulp.value(totals["lutram"]) or 0)),
            total_bram=int(round(pulp.value(totals["bram"]) or 0)),
            total_power=int(round(pulp.value(totals["power_cost"]) or 0)),
            optimal=True,
            satisfiable=True,
            strategy=self.strategy,
        )

    def _solve_primary_then_secondary(
        self,
        model: "pulp.LpProblem",
        primary_obj: "pulp.LpAffineExpression",
        secondary_obj: "pulp.LpAffineExpression",
    ) -> None:
        self._solve_with_objective(model, primary_obj)
        if pulp.LpStatus.get(model.status) != "Optimal":
            return
        primary_opt = int(round(pulp.value(primary_obj) or 0))
        model += primary_obj <= primary_opt
        self._solve_with_objective(model, secondary_obj)

    def _solve_with_objective(
        self,
        model: "pulp.LpProblem",
        objective: "pulp.LpAffineExpression",
    ) -> None:
        model.objective = objective
        solver = pulp.PULP_CBC_CMD(
            msg=bool(self.solver_config.get("ilp_solver_msg", False)),
            timeLimit=self.timeout,
        )
        model.solve(solver)

    def _protected_components(self) -> List[str]:
        if self.network_model.assets:
            allowed = {
                component.name
                for component in self.network_model.components
                if component.comp_type not in ("policy_server", "firewall", "bus")
            }
            protected = []
            seen = set()
            for asset in self.network_model.assets:
                if asset.component in allowed and asset.component not in seen:
                    protected.append(asset.component)
                    seen.add(asset.component)
            return protected

        protected: List[str] = []
        for component in self.network_model.components:
            if component.comp_type in ("policy_server", "firewall", "bus"):
                continue
            if getattr(component, "is_master", False):
                continue
            if component.name not in protected:
                protected.append(component.name)
        return protected

    def _component_assets(self, protected_components: List[str]) -> Dict[str, List[Asset]]:
        protected = set(protected_components)
        if self.network_model.assets:
            assets = [asset for asset in self.network_model.assets if asset.component in protected]
        else:
            component_by_name = {component.name: component for component in self.network_model.components}
            assets = []
            for component_name in protected_components:
                component = component_by_name[component_name]
                assets.append(
                    Asset(
                        asset_id=f"{component.name}r1",
                        component=component.name,
                        direction=component.direction,
                        impact_read=component.impact_read,
                        impact_write=component.impact_write,
                        impact_avail=int(getattr(component, "impact_avail", 0)),
                        latency_read=component.latency_read,
                        latency_write=component.latency_write,
                    )
                )

        component_assets: Dict[str, List[Asset]] = {component: [] for component in protected_components}
        for asset in assets:
            component_assets.setdefault(asset.component, []).append(asset)
        return component_assets

    def _component_latency_caps(self, component_assets: Dict[str, List[Asset]]) -> Dict[str, int]:
        caps: Dict[str, int] = {}
        for component, assets in component_assets.items():
            per_action_caps: List[int] = []
            for asset in assets:
                if asset.direction in ("input", "bidirectional"):
                    per_action_caps.append(asset.latency_read)
                if asset.direction in ("output", "bidirectional"):
                    per_action_caps.append(asset.latency_write)
            caps[component] = min(per_action_caps) if per_action_caps else 1000
        return caps

    def _component_risk_rows(
        self,
        assets: List[Asset],
        security: str,
        logging: str,
    ) -> List[Tuple[str, str, int]]:
        rows: List[Tuple[str, str, int]] = []
        vulnerability = int(VULNERABILITY_VALUES[security])
        logging_score = int(LOGGING_RISK_VALUES[logging])
        for asset in assets:
            for action, impact in self._iter_asset_actions(asset):
                rows.append(
                    (
                        asset.asset_id,
                        action,
                        self._div_trunc_zero(impact * vulnerability * logging_score, 10),
                    )
                )
        return rows

    def _group_combo_risks(
        self,
        members: Tuple[str, ...],
        pair_indices: Tuple[int, ...],
        component_assets: Dict[str, List[Asset]],
        pair_options: Tuple[_PairOption, ...],
    ) -> Dict[str, List[Tuple[str, str, int]]]:
        partial = None
        for component, pair_index in zip(members, pair_indices):
            pair = pair_options[pair_index]
            original_prob = int(VULNERABILITY_VALUES[pair.security]) * int(LOGGING_RISK_VALUES[pair.logging])
            normalized = self._div_trunc_zero((original_prob - MU) * 1000, OMEGA - MU)
            if partial is None:
                partial = normalized
            else:
                partial = self._div_trunc_zero(partial * normalized, 1000)

        if partial is None:
            return {}

        denorm = self._div_trunc_zero(partial * (OMEGA - MU), 1000) + MU * 10
        combo_risks: Dict[str, List[Tuple[str, str, int]]] = {}
        for component in members:
            rows: List[Tuple[str, str, int]] = []
            for asset in component_assets[component]:
                for action, impact in self._iter_asset_actions(asset):
                    rows.append((asset.asset_id, action, self._div_trunc_zero(impact * denorm, 100)))
            combo_risks[component] = rows
        return combo_risks

    def _component_lookup(self) -> Dict[str, Component]:
        return {component.name: component for component in self.network_model.components}

    def _iter_asset_actions(self, asset: Asset) -> List[Tuple[str, int]]:
        rows: List[Tuple[str, int]] = []
        if asset.direction in ("input", "bidirectional"):
            rows.append(("read", asset.impact_read))
        if asset.direction in ("output", "bidirectional"):
            rows.append(("write", asset.impact_write))
        if int(getattr(asset, "impact_avail", 0)) > 0:
            rows.append(("avail", int(getattr(asset, "impact_avail", 0))))
        return rows

    def _rows_within_cap(self, rows: List[Tuple[str, str, int]], cap: int) -> bool:
        return all(risk <= cap for _asset, _action, risk in rows)

    def _weighted_risk_total(
        self,
        rows: List[Tuple[str, str, int]],
        asset_weights: Dict[str, int],
    ) -> int:
        return sum(risk * asset_weights.get(asset, 1) for asset, _action, risk in rows)

    def _asset_weights(
        self,
        component_assets: Dict[str, List[Asset]],
        component_lookup: Dict[str, Component],
        modern_dual_risk: bool,
    ) -> Dict[str, int]:
        if not modern_dual_risk:
            return {
                asset.asset_id: 1
                for assets in component_assets.values()
                for asset in assets
            }

        adjacency: Dict[str, set] = {}
        for src, dst in self.network_model.links:
            adjacency.setdefault(src, set()).add(dst)
            adjacency.setdefault(dst, set()).add(src)

        def bfs_count(start: str) -> int:
            visited = {start}
            frontier = [start]
            while frontier:
                current = frontier.pop(0)
                for neighbor in adjacency.get(current, set()):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        frontier.append(neighbor)
            return max(0, len(visited) - 1)

        weights: Dict[str, int] = {}
        for component_name, assets in component_assets.items():
            component = component_lookup[component_name]
            base = 10
            safety_add = 20 if getattr(component, "is_safety_critical", False) else 0
            master_add = 15 if getattr(component, "is_master", False) else 0
            domain_add = 10 if self._domain_bonus(getattr(component, "domain", "normal")) >= 2 else 0
            reach = min(bfs_count(component_name), 5)
            weight = min(50, base + safety_add + master_add + domain_add + reach)
            for asset in assets:
                weights[asset.asset_id] = weight
        return weights

    def _domain_bonus(self, domain: str) -> int:
        return {
            "untrusted": 0,
            "low": 0,
            "normal": 1,
            "privileged": 2,
            "high": 3,
            "root": 3,
        }.get(domain, 1)

    def _feature_cost(self, feature: str, resource_name: str) -> int:
        est = get_calibrated_estimate(feature)
        attr_name = {
            "luts": "luts",
            "ffs": "ffs",
            "dsps": "dsps",
            "lutram": "lutrams",
            "bram": "brams",
            "power_cost": "power_mw",
        }.get(resource_name)
        if attr_name is None:
            return 0
        value = getattr(est, attr_name, 0)
        return int(round(value))

    def _security_latency(self, feature: str) -> int:
        return int(get_calibrated_estimate(feature).latency)

    def _logging_latency(self, feature: str) -> int:
        return int(get_calibrated_estimate(feature).latency)

    def _constrain_resource(
        self,
        model: "pulp.LpProblem",
        expr: "pulp.LpAffineExpression",
        cap_name: str,
    ) -> None:
        if cap_name in self.network_model.system_caps:
            model += expr <= int(self.network_model.system_caps[cap_name])
            return
        if cap_name == "max_bufgs" and "max_bufg" in self.network_model.system_caps:
            model += expr <= int(self.network_model.system_caps["max_bufg"])

    def _post(self, msg: str) -> None:
        if self.progress_queue is not None:
            try:
                self.progress_queue.put_nowait(("INFO", msg))
            except queue.Full:
                pass

    @staticmethod
    def _div_trunc_zero(numerator: int, denominator: int) -> int:
        """Match Clingo integer division semantics, which truncate toward zero."""
        if denominator == 0:
            raise ZeroDivisionError("denominator must be non-zero")
        quotient = abs(numerator) // abs(denominator)
        if (numerator < 0) ^ (denominator < 0):
            return -quotient
        return quotient
