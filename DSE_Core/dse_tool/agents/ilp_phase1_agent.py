"""
ilp_phase1_agent.py
===================
Compatibility wrapper for the Phase 1 math-optimisation agent.

The active implementation now supports multiple mathematical backends:
- CP-SAT is the default
- CBC remains available as an optional MILP solver

This module keeps the older ``ILPPhase1Agent`` public name as a compatibility
alias, but the primary class is now ``Phase1MathOptAgent``.
"""

from __future__ import annotations

import itertools
import os
import queue
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

try:
    import pulp
except ImportError:  # pragma: no cover - dependency may be absent locally
    pulp = None

try:
    from ortools.sat.python import cp_model
except ImportError:  # pragma: no cover - dependency may be absent locally
    cp_model = None

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


class Phase1MathOptAgent:
    """Runs the Phase 1 optimisation using a selectable math-optimisation backend."""

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
        solver_name = self._selected_solver()
        threads = self._solver_threads()
        thread_msg = f" ({solver_name.upper()} threads={threads})" if threads and threads > 1 else ""
        self._post(f"[Phase 1/{self.strategy}/MATHOPT] Starting security DSE optimisation using {solver_name.upper()}{thread_msg}...")
        if solver_name == "cpsat" and cp_model is None:
            self._post("[Phase 1/MATHOPT] OR-Tools CP-SAT is not installed; math backend unavailable.")
            return Phase1Result(strategy=self.strategy, satisfiable=False)
        if solver_name == "cbc" and pulp is None:
            self._post("[Phase 1/MATHOPT] PuLP/CBC is not installed; math backend unavailable.")
            return Phase1Result(strategy=self.strategy, satisfiable=False)

        try:
            result = self._solve()
        except Exception as exc:  # noqa: BLE001
            self._post(f"[Phase 1/{self.strategy}/MATHOPT] ERROR: {exc}")
            return Phase1Result(strategy=self.strategy, satisfiable=False)

        if result.satisfiable:
            self._post(
                f"[Phase 1/{self.strategy}/MATHOPT] Done - "
                f"Risk: {result.total_risk()}, "
                f"LUTs: {result.total_luts:,}, "
                f"Power: {result.total_power:,} mW"
            )
        return result

    def _solve(self) -> Phase1Result:
        protected_components = self._protected_components()
        if not protected_components:
            return Phase1Result(strategy=self.strategy, satisfiable=False)
        self._post(
            f"[Phase 1/{self.strategy}/MATHOPT] Modeling {len(protected_components)} protected components."
        )

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
                self._post(f"[Phase 1/{self.strategy}/MATHOPT] No feasible selections for component {component}.")
                return Phase1Result(strategy=self.strategy, satisfiable=False)
        self._post(
            f"[Phase 1/{self.strategy}/MATHOPT] Built feasible feature pairs for "
            f"{len(protected_components)} components."
        )

        solver_name = self._selected_solver()
        if solver_name == "cpsat":
            return self._solve_cpsat(
                protected_components=protected_components,
                component_assets=component_assets,
                feasible_pairs=feasible_pairs,
                standalone_risk_rows=standalone_risk_rows,
                standalone_risk_totals=standalone_risk_totals,
                pair_options=pair_options,
                groups=groups,
                standalone_components=standalone_components,
                asset_weights=asset_weights,
                modern_dual_risk=modern_dual_risk,
                max_asset_risk=max_asset_risk,
                max_security_risk=max_security_risk,
                max_avail_risk=max_avail_risk,
            )

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
            self._post(
                f"[Phase 1/{self.strategy}/MATHOPT] Evaluating redundancy group "
                f"{group_index + 1}/{len(groups)} with {combo_count} combinations."
            )
            if combo_count > combo_limit:
                raise ValueError(
                    f"Redundancy group {group_index + 1} expands to {combo_count} combinations; "
                    f"limit is {combo_limit}."
                )

            valid_combo_keys: List[Tuple[int, int]] = []
            combo_index = 0
            progress_stride = max(1000, min(10000, combo_count // 10 or 1000))
            for pair_indices in itertools.product(*domains):
                if combo_index and combo_index % progress_stride == 0:
                    self._post(
                        f"[Phase 1/{self.strategy}/MATHOPT] Redundancy group "
                        f"{group_index + 1}: checked {combo_index}/{combo_count} combinations."
                    )
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
                self._post(f"[Phase 1/{self.strategy}/MATHOPT] No feasible redundancy selections for group {members}.")
                return Phase1Result(strategy=self.strategy, satisfiable=False)
            self._post(
                f"[Phase 1/{self.strategy}/MATHOPT] Redundancy group {group_index + 1} "
                f"has {len(valid_combo_keys)} feasible combinations."
            )

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
            self._solve_primary_then_secondary(
                model,
                total_luts,
                total_weighted_risk,
                primary_label="primary LUT objective",
                secondary_label="secondary weighted-risk objective",
            )
        elif self.strategy == "balanced":
            self._solve_primary_then_secondary(
                model,
                total_weighted_risk,
                total_luts,
                primary_label="primary weighted-risk objective",
                secondary_label="secondary LUT objective",
            )
        else:
            self._solve_with_objective(
                model,
                total_weighted_risk,
                objective_label="weighted-risk objective",
            )

        if pulp.LpStatus.get(model.status) != "Optimal":
            self._post(
                f"[Phase 1/{self.strategy}/MATHOPT] Solve status: "
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

    def _solve_cpsat(
        self,
        *,
        protected_components: List[str],
        component_assets: Dict[str, List[Asset]],
        feasible_pairs: Dict[str, List[int]],
        standalone_risk_rows: Dict[Tuple[str, int], List[Tuple[str, str, int]]],
        standalone_risk_totals: Dict[Tuple[str, int], int],
        pair_options: Tuple[_PairOption, ...],
        groups: List[Tuple[str, ...]],
        standalone_components: List[str],
        asset_weights: Dict[str, int],
        modern_dual_risk: bool,
        max_asset_risk: int,
        max_security_risk: int,
        max_avail_risk: int,
    ) -> Phase1Result:
        model = cp_model.CpModel()
        x: Dict[Tuple[str, int], "cp_model.IntVar"] = {}
        for component in protected_components:
            for pair_index in feasible_pairs[component]:
                x[(component, pair_index)] = model.NewBoolVar(f"x_{component}_{pair_index}")
            model.Add(sum(x[(component, pair_index)] for pair_index in feasible_pairs[component]) == 1)

        group_combo_vars: Dict[Tuple[int, int], "cp_model.IntVar"] = {}
        group_combo_defs: Dict[Tuple[int, int], Tuple[int, ...]] = {}
        group_combo_risks: Dict[Tuple[int, int], Dict[str, List[Tuple[str, str, int]]]] = {}
        group_combo_totals: Dict[Tuple[int, int], int] = {}

        combo_limit = int(self.solver_config.get("group_combo_limit", 100000))
        for group_index, members in enumerate(groups):
            domains = [tuple(feasible_pairs[component]) for component in members]
            combo_count = 1
            for domain in domains:
                combo_count *= len(domain)
            self._post(
                f"[Phase 1/{self.strategy}/MATHOPT] Evaluating redundancy group "
                f"{group_index + 1}/{len(groups)} with {combo_count} combinations."
            )
            if combo_count > combo_limit:
                raise ValueError(
                    f"Redundancy group {group_index + 1} expands to {combo_count} combinations; "
                    f"limit is {combo_limit}."
                )

            valid_combo_keys: List[Tuple[int, int]] = []
            combo_index = 0
            progress_stride = max(1000, min(10000, combo_count // 10 or 1000))
            for pair_indices in itertools.product(*domains):
                if combo_index and combo_index % progress_stride == 0:
                    self._post(
                        f"[Phase 1/{self.strategy}/MATHOPT] Redundancy group "
                        f"{group_index + 1}: checked {combo_index}/{combo_count} combinations."
                    )
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
                group_combo_vars[combo_key] = model.NewBoolVar(f"g_{group_index}_{combo_index}")
                valid_combo_keys.append(combo_key)
                combo_index += 1

            if not valid_combo_keys:
                self._post(f"[Phase 1/{self.strategy}/MATHOPT] No feasible redundancy selections for group {members}.")
                return Phase1Result(strategy=self.strategy, satisfiable=False)

            model.Add(sum(group_combo_vars[key] for key in valid_combo_keys) == 1)
            self._post(
                f"[Phase 1/{self.strategy}/MATHOPT] Redundancy group {group_index + 1} "
                f"has {len(valid_combo_keys)} feasible combinations."
            )

            for member_offset, component in enumerate(members):
                for pair_index in feasible_pairs[component]:
                    model.Add(
                        x[(component, pair_index)]
                        == sum(
                            group_combo_vars[key]
                            for key in valid_combo_keys
                            if group_combo_defs[key][member_offset] == pair_index
                        )
                    )

        totals: Dict[str, "cp_model.LinearExpr"] = {}
        for resource_name in RESOURCES:
            totals[resource_name] = sum(
                x[(component, pair_index)]
                * (
                    self._feature_cost(pair_options[pair_index].security, resource_name)
                    + self._feature_cost(pair_options[pair_index].logging, resource_name)
                )
                for component in protected_components
                for pair_index in feasible_pairs[component]
            )

        self._constrain_cp_resource(model, totals["luts"], "max_luts")
        self._constrain_cp_resource(model, totals["ffs"], "max_ffs")
        self._constrain_cp_resource(model, totals["dsps"], "max_dsps")
        self._constrain_cp_resource(model, totals["lutram"], "max_lutram")
        self._constrain_cp_resource(model, totals["bram"], "max_bram")
        self._constrain_cp_resource(model, totals["bufg"], "max_bufgs")
        self._constrain_cp_resource(model, totals["power_cost"], "max_power")

        total_weighted_risk = (
            sum(
                x[(component, pair_index)] * standalone_risk_totals[(component, pair_index)]
                for component in standalone_components
                for pair_index in feasible_pairs[component]
            )
            + sum(group_combo_vars[key] * group_combo_totals[key] for key in group_combo_vars)
        )
        total_luts = totals["luts"]

        if self.strategy == "min_resources":
            solver, status = self._solve_cp_primary_then_secondary(
                model,
                total_luts,
                total_weighted_risk,
                primary_label="primary LUT objective",
                secondary_label="secondary weighted-risk objective",
            )
        elif self.strategy == "balanced":
            solver, status = self._solve_cp_primary_then_secondary(
                model,
                total_weighted_risk,
                total_luts,
                primary_label="primary weighted-risk objective",
                secondary_label="secondary LUT objective",
            )
        else:
            solver, status = self._solve_cp_with_objective(
                model,
                total_weighted_risk,
                objective_label="weighted-risk objective",
            )

        if status not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
            self._post(
                f"[Phase 1/{self.strategy}/MATHOPT] Solve status: "
                f"{self._cp_status_name(status)}"
            )
            return Phase1Result(strategy=self.strategy, satisfiable=False)

        security: Dict[str, str] = {}
        logging: Dict[str, str] = {}
        security_risk: List[Tuple[str, str, str, int]] = []
        avail_risk: List[Tuple[str, str, str, int]] = []

        chosen_pairs: Dict[str, int] = {}
        for component in protected_components:
            for pair_index in feasible_pairs[component]:
                if solver.Value(x[(component, pair_index)]):
                    chosen_pairs[component] = pair_index
                    pair = pair_options[pair_index]
                    security[component] = pair.security
                    logging[component] = pair.logging
                    break

        for component in standalone_components:
            for asset_id, action, risk in standalone_risk_rows[(component, chosen_pairs[component])]:
                security_risk.append((component, asset_id, action, risk))

        for combo_key, combo_var in group_combo_vars.items():
            if not solver.Value(combo_var):
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
            total_luts=int(solver.Value(total_luts)),
            total_ffs=int(solver.Value(totals["ffs"])),
            total_dsps=int(solver.Value(totals["dsps"])),
            total_lutram=int(solver.Value(totals["lutram"])),
            total_bram=int(solver.Value(totals["bram"])),
            total_power=int(solver.Value(totals["power_cost"])),
            optimal=(status == cp_model.OPTIMAL),
            satisfiable=True,
            strategy=self.strategy,
        )

    def _solve_cp_primary_then_secondary(
        self,
        model: "cp_model.CpModel",
        primary_obj,
        secondary_obj,
        *,
        primary_label: str,
        secondary_label: str,
    ):
        solver, status = self._solve_cp_with_objective(model, primary_obj, objective_label=primary_label)
        if status not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
            return solver, status
        primary_opt = int(solver.Value(primary_obj))
        self._post(
            f"[Phase 1/{self.strategy}/MATHOPT] Locked {primary_label} at {primary_opt}; "
            f"starting {secondary_label}."
        )
        model.Add(primary_obj <= primary_opt)
        return self._solve_cp_with_objective(model, secondary_obj, objective_label=secondary_label)

    def _solve_cp_with_objective(
        self,
        model: "cp_model.CpModel",
        objective,
        *,
        objective_label: str,
    ):
        model.Minimize(objective)
        solver = cp_model.CpSolver()
        solver.parameters.max_time_in_seconds = float(self.timeout)
        solver.parameters.num_search_workers = self._cpsat_threads()
        solver.parameters.log_search_progress = bool(self.solver_config.get("cpsat_log_progress", False))
        self._post(
            f"[Phase 1/{self.strategy}/MATHOPT] CP-SAT solving {objective_label} "
            f"(threads={self._cpsat_threads()}, timeout={self.timeout}s)."
        )
        done = threading.Event()
        start = time.perf_counter()
        result_holder = {"status": cp_model.UNKNOWN}

        def _heartbeat() -> None:
            while not done.wait(10):
                elapsed = int(time.perf_counter() - start)
                self._post(
                    f"[Phase 1/{self.strategy}/MATHOPT] CP-SAT still solving {objective_label} "
                    f"after {elapsed}s."
                )

        def _solve() -> None:
            result_holder["status"] = solver.Solve(model)
            done.set()

        heartbeat = threading.Thread(target=_heartbeat, daemon=True)
        heartbeat.start()
        worker = threading.Thread(target=_solve, daemon=True)
        worker.start()
        worker.join(self.timeout + 5)
        done.set()
        worker.join()
        elapsed = int(time.perf_counter() - start)
        status = result_holder["status"]
        self._post(
            f"[Phase 1/{self.strategy}/MATHOPT] CP-SAT finished {objective_label} in "
            f"{elapsed}s with status {self._cp_status_name(status)}."
        )
        return solver, status

    def _solve_primary_then_secondary(
        self,
        model: "pulp.LpProblem",
        primary_obj: "pulp.LpAffineExpression",
        secondary_obj: "pulp.LpAffineExpression",
        primary_label: str,
        secondary_label: str,
    ) -> None:
        self._solve_with_objective(model, primary_obj, objective_label=primary_label)
        if pulp.LpStatus.get(model.status) != "Optimal":
            return
        primary_opt = int(round(pulp.value(primary_obj) or 0))
        self._post(
            f"[Phase 1/{self.strategy}/MATHOPT] Locked {primary_label} at {primary_opt}; "
            f"starting {secondary_label}."
        )
        model += primary_obj <= primary_opt
        self._solve_with_objective(model, secondary_obj, objective_label=secondary_label)

    def _solve_with_objective(
        self,
        model: "pulp.LpProblem",
        objective: "pulp.LpAffineExpression",
        objective_label: str,
    ) -> None:
        model.objective = objective
        solver_kwargs = {
            "msg": bool(self.solver_config.get("ilp_solver_msg", False)),
            "timeLimit": self.timeout,
        }
        threads = self._cbc_threads()
        if threads and threads > 1:
            solver_kwargs["threads"] = threads
        solver = pulp.PULP_CBC_CMD(**solver_kwargs)
        self._post(
            f"[Phase 1/{self.strategy}/MATHOPT] CBC solving {objective_label} "
            f"(threads={threads}, timeout={self.timeout}s)."
        )
        done = threading.Event()
        start = time.perf_counter()

        def _heartbeat() -> None:
            while not done.wait(10):
                elapsed = int(time.perf_counter() - start)
                self._post(
                    f"[Phase 1/{self.strategy}/MATHOPT] CBC still solving {objective_label} "
                    f"after {elapsed}s."
                )

        heartbeat = threading.Thread(target=_heartbeat, daemon=True)
        heartbeat.start()
        try:
            model.solve(solver)
        finally:
            done.set()
        elapsed = int(time.perf_counter() - start)
        self._post(
            f"[Phase 1/{self.strategy}/MATHOPT] CBC finished {objective_label} in "
            f"{elapsed}s with status {pulp.LpStatus.get(model.status, model.status)}."
        )

    def _selected_solver(self) -> str:
        backend = str(self.solver_config.get("phase1_backend", "")).strip().lower()
        if backend in {"cpsat", "cbc"}:
            return backend
        solver = str(self.solver_config.get("ilp_solver", "cpsat")).strip().lower()
        if solver not in {"cpsat", "cbc"}:
            raise ValueError(f"Unsupported math solver '{solver}'. Expected 'cpsat' or 'cbc'.")
        return solver

    def _solver_threads(self) -> int:
        if self._selected_solver() == "cpsat":
            return self._cpsat_threads()
        return self._cbc_threads()

    def _cpsat_threads(self) -> int:
        return max(
            1,
            int(
                self.solver_config.get("cpsat_threads")
                or os.getenv("DSE_CPSAT_THREADS")
                or self.solver_config.get("ilp_threads")
                or 1
            ),
        )

    def _cbc_threads(self) -> int:
        return max(
            1,
            int(
                self.solver_config.get("cbc_threads")
                or os.getenv("DSE_CBC_THREADS")
                or self.solver_config.get("ilp_threads")
                or 1
            ),
        )

    @staticmethod
    def _cp_status_name(status: int) -> str:
        return {
            cp_model.UNKNOWN: "UNKNOWN",
            cp_model.MODEL_INVALID: "MODEL_INVALID",
            cp_model.FEASIBLE: "FEASIBLE",
            cp_model.INFEASIBLE: "INFEASIBLE",
            cp_model.OPTIMAL: "OPTIMAL",
        }.get(status, str(status))

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

    def _constrain_cp_resource(self, model: "cp_model.CpModel", expr, cap_name: str) -> None:
        if cap_name in self.network_model.system_caps:
            model.Add(expr <= int(self.network_model.system_caps[cap_name]))
            return
        if cap_name == "max_bufgs" and "max_bufg" in self.network_model.system_caps:
            model.Add(expr <= int(self.network_model.system_caps["max_bufg"]))

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


ILPPhase1Agent = Phase1MathOptAgent
