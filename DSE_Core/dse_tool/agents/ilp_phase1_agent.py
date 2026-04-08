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
    EXPLOIT_FACTOR_MAP,
    EXPOSURE_VALUES,
    REALTIME_DETECTION_VALUES,
    REALTIME_FEATURE_EXPORT_ORDER,
    SECURITY_FEATURE_EXPORT_ORDER,
    get_calibrated_estimate,
)

from ..core.asp_generator import Asset, Component, NetworkModel
from ..core.solution_parser import Phase1Result


MU = 25
OMEGA = 1000
START_STATE = -1
RESOURCES = ("luts", "ffs", "dsps", "lutram", "bram", "bufg", "power_cost")


@dataclass(frozen=True)
class _PairOption:
    security: str
    realtime: str
    latency: int


@dataclass(frozen=True)
class _GroupTransition:
    prev_state: int
    pair_index: int
    next_state: int


@dataclass
class _GroupSpec:
    group_index: int
    members: Tuple[str, ...]
    transitions_by_stage: List[List[_GroupTransition]]
    final_state_rows: Dict[int, Dict[str, List[Tuple[str, str, int]]]]
    final_state_totals: Dict[int, int]


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
                realtime=logging,
                latency=self._security_latency(security) + self._realtime_latency(logging),
            )
            for security in SECURITY_FEATURE_EXPORT_ORDER
            for logging in REALTIME_FEATURE_EXPORT_ORDER
        )
        pair_risk_metric = {
            pair_index: int(EXPOSURE_VALUES[pair.security]) * int(REALTIME_DETECTION_VALUES[pair.realtime])
            for pair_index, pair in enumerate(pair_options)
        }
        pair_resource_vectors = {
            pair_index: tuple(
                self._feature_cost(pair_options[pair_index].security, resource_name)
                + self._feature_cost(pair_options[pair_index].realtime, resource_name)
                for resource_name in RESOURCES
            )
            for pair_index in range(len(pair_options))
        }

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
                    pair.realtime,
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
            feasible_pairs[component] = self._prune_pair_indices(
                feasible_pairs[component],
                pair_resource_vectors,
                pair_risk_metric,
            )
        self._post(
            f"[Phase 1/{self.strategy}/MATHOPT] Built feasible feature pairs for "
            f"{len(protected_components)} components."
        )

        combo_cap = max_avail_risk if modern_dual_risk else max_asset_risk
        group_specs = self._build_group_specs(
            groups=groups,
            feasible_pairs=feasible_pairs,
            component_assets=component_assets,
            pair_options=pair_options,
            asset_weights=asset_weights,
            combo_cap=combo_cap,
        )
        if group_specs is None:
            return Phase1Result(strategy=self.strategy, satisfiable=False)

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
                group_specs=group_specs,
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

        group_transition_vars: Dict[Tuple[int, int, int], pulp.LpVariable] = {}
        group_state_vars: Dict[Tuple[int, int, int], pulp.LpVariable] = {}
        group_last_stage_states: Dict[int, List[int]] = {}

        for spec in group_specs:
            last_stage = len(spec.members) - 1
            final_states = sorted(spec.final_state_rows)
            group_last_stage_states[spec.group_index] = final_states
            for stage_index, transitions in enumerate(spec.transitions_by_stage):
                transition_vars = []
                for transition_index, transition in enumerate(transitions):
                    var = pulp.LpVariable(
                        f"gt_{spec.group_index}_{stage_index}_{transition_index}",
                        lowBound=0,
                        upBound=1,
                        cat=pulp.LpBinary,
                    )
                    group_transition_vars[(spec.group_index, stage_index, transition_index)] = var
                    transition_vars.append(var)
                model += pulp.lpSum(transition_vars) == 1

                next_states = sorted({transition.next_state for transition in transitions})
                for state in next_states:
                    state_var = pulp.LpVariable(
                        f"gs_{spec.group_index}_{stage_index}_{state}",
                        lowBound=0,
                        upBound=1,
                        cat=pulp.LpBinary,
                    )
                    group_state_vars[(spec.group_index, stage_index, state)] = state_var
                    model += (
                        state_var
                        == pulp.lpSum(
                            group_transition_vars[(spec.group_index, stage_index, transition_index)]
                            for transition_index, transition in enumerate(transitions)
                            if transition.next_state == state
                        )
                    )

                if stage_index > 0:
                    prev_states = sorted({transition.prev_state for transition in transitions})
                    for state in prev_states:
                        model += (
                            pulp.lpSum(
                                group_transition_vars[(spec.group_index, stage_index, transition_index)]
                                for transition_index, transition in enumerate(transitions)
                                if transition.prev_state == state
                            )
                            == group_state_vars[(spec.group_index, stage_index - 1, state)]
                        )

                component = spec.members[stage_index]
                for pair_index in feasible_pairs[component]:
                    model += (
                        x[(component, pair_index)]
                        == pulp.lpSum(
                            group_transition_vars[(spec.group_index, stage_index, transition_index)]
                            for transition_index, transition in enumerate(transitions)
                            if transition.pair_index == pair_index
                        )
                    )

        totals: Dict[str, pulp.LpAffineExpression] = {}
        for resource_name in RESOURCES:
            totals[resource_name] = pulp.lpSum(
                x[(component, pair_index)]
                * (
                    self._feature_cost(pair_options[pair_index].security, resource_name)
                    + self._feature_cost(pair_options[pair_index].realtime, resource_name)
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
            + pulp.lpSum(
                group_state_vars[(spec.group_index, len(spec.members) - 1, final_state)]
                * spec.final_state_totals[final_state]
                for spec in group_specs
                for final_state in group_last_stage_states[spec.group_index]
            )
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
        realtime: Dict[str, str] = {}
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
                    realtime[component] = pair.realtime
                    break

        for component in standalone_components:
            for asset_id, action, risk in standalone_risk_rows[(component, chosen_pairs[component])]:
                security_risk.append((component, asset_id, action, risk))

        for spec in group_specs:
            last_stage = len(spec.members) - 1
            chosen_state = None
            for final_state in group_last_stage_states[spec.group_index]:
                value = pulp.value(group_state_vars[(spec.group_index, last_stage, final_state)])
                if value is not None and value > 0.5:
                    chosen_state = final_state
                    break
            if chosen_state is None:
                continue
            for component, rows in spec.final_state_rows[chosen_state].items():
                for asset_id, action, risk in rows:
                    avail_risk.append((component, asset_id, action, risk))

        security_risk.sort(key=lambda row: (row[0], row[1], row[2]))
        avail_risk.sort(key=lambda row: (row[0], row[1], row[2]))
        new_risk = sorted(security_risk + avail_risk, key=lambda row: (row[0], row[1], row[2]))

        return Phase1Result(
            security=security,
            realtime=realtime,
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
        group_specs: List[_GroupSpec],
    ) -> Phase1Result:
        model = cp_model.CpModel()
        x: Dict[Tuple[str, int], "cp_model.IntVar"] = {}
        for component in protected_components:
            for pair_index in feasible_pairs[component]:
                x[(component, pair_index)] = model.NewBoolVar(f"x_{component}_{pair_index}")
            model.Add(sum(x[(component, pair_index)] for pair_index in feasible_pairs[component]) == 1)

        group_transition_vars: Dict[Tuple[int, int, int], "cp_model.IntVar"] = {}
        group_state_vars: Dict[Tuple[int, int, int], "cp_model.IntVar"] = {}
        group_last_stage_states: Dict[int, List[int]] = {}

        for spec in group_specs:
            final_states = sorted(spec.final_state_rows)
            group_last_stage_states[spec.group_index] = final_states
            for stage_index, transitions in enumerate(spec.transitions_by_stage):
                transition_vars = []
                for transition_index, transition in enumerate(transitions):
                    var = model.NewBoolVar(f"gt_{spec.group_index}_{stage_index}_{transition_index}")
                    group_transition_vars[(spec.group_index, stage_index, transition_index)] = var
                    transition_vars.append(var)
                model.Add(sum(transition_vars) == 1)

                next_states = sorted({transition.next_state for transition in transitions})
                for state in next_states:
                    state_var = model.NewBoolVar(f"gs_{spec.group_index}_{stage_index}_{state}")
                    group_state_vars[(spec.group_index, stage_index, state)] = state_var
                    model.Add(
                        state_var
                        == sum(
                            group_transition_vars[(spec.group_index, stage_index, transition_index)]
                            for transition_index, transition in enumerate(transitions)
                            if transition.next_state == state
                        )
                    )

                if stage_index > 0:
                    prev_states = sorted({transition.prev_state for transition in transitions})
                    for state in prev_states:
                        model.Add(
                            sum(
                                group_transition_vars[(spec.group_index, stage_index, transition_index)]
                                for transition_index, transition in enumerate(transitions)
                                if transition.prev_state == state
                            )
                            == group_state_vars[(spec.group_index, stage_index - 1, state)]
                        )

                component = spec.members[stage_index]
                for pair_index in feasible_pairs[component]:
                    model.Add(
                        x[(component, pair_index)]
                        == sum(
                            group_transition_vars[(spec.group_index, stage_index, transition_index)]
                            for transition_index, transition in enumerate(transitions)
                            if transition.pair_index == pair_index
                        )
                    )

        totals: Dict[str, "cp_model.LinearExpr"] = {}
        for resource_name in RESOURCES:
            totals[resource_name] = sum(
                x[(component, pair_index)]
                * (
                    self._feature_cost(pair_options[pair_index].security, resource_name)
                    + self._feature_cost(pair_options[pair_index].realtime, resource_name)
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
            + sum(
                group_state_vars[(spec.group_index, len(spec.members) - 1, final_state)]
                * spec.final_state_totals[final_state]
                for spec in group_specs
                for final_state in group_last_stage_states[spec.group_index]
            )
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
        realtime: Dict[str, str] = {}
        security_risk: List[Tuple[str, str, str, int]] = []
        avail_risk: List[Tuple[str, str, str, int]] = []

        chosen_pairs: Dict[str, int] = {}
        for component in protected_components:
            for pair_index in feasible_pairs[component]:
                if solver.Value(x[(component, pair_index)]):
                    chosen_pairs[component] = pair_index
                    pair = pair_options[pair_index]
                    security[component] = pair.security
                    realtime[component] = pair.realtime
                    break

        for component in standalone_components:
            for asset_id, action, risk in standalone_risk_rows[(component, chosen_pairs[component])]:
                security_risk.append((component, asset_id, action, risk))

        for spec in group_specs:
            last_stage = len(spec.members) - 1
            chosen_state = None
            for final_state in group_last_stage_states[spec.group_index]:
                if solver.Value(group_state_vars[(spec.group_index, last_stage, final_state)]):
                    chosen_state = final_state
                    break
            if chosen_state is None:
                continue
            for component, rows in spec.final_state_rows[chosen_state].items():
                for asset_id, action, risk in rows:
                    avail_risk.append((component, asset_id, action, risk))

        security_risk.sort(key=lambda row: (row[0], row[1], row[2]))
        avail_risk.sort(key=lambda row: (row[0], row[1], row[2]))
        new_risk = sorted(security_risk + avail_risk, key=lambda row: (row[0], row[1], row[2]))

        return Phase1Result(
            security=security,
            realtime=realtime,
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
        realtime: str,
    ) -> List[Tuple[str, str, int]]:
        rows: List[Tuple[str, str, int]] = []
        exposure = int(EXPOSURE_VALUES[security])
        realtime_score = int(REALTIME_DETECTION_VALUES[realtime])
        for asset in assets:
            exploit_factor = EXPLOIT_FACTOR_MAP.get(int(self._component_exploitability(asset.component)), 10)
            for action, impact in self._iter_asset_actions(asset):
                rows.append(
                    (
                        asset.asset_id,
                        action,
                        self._div_trunc_zero(impact * exposure * realtime_score * exploit_factor, 100),
                    )
                )
        return rows

    def _build_group_specs(
        self,
        *,
        groups: List[Tuple[str, ...]],
        feasible_pairs: Dict[str, List[int]],
        component_assets: Dict[str, List[Asset]],
        pair_options: Tuple[_PairOption, ...],
        asset_weights: Dict[str, int],
        combo_cap: int,
    ) -> Optional[List[_GroupSpec]]:
        specs: List[_GroupSpec] = []
        for group_index, members in enumerate(groups):
            domains = [tuple(feasible_pairs[component]) for component in members]
            combo_count = 1
            for domain in domains:
                combo_count *= len(domain)
            self._post(
                f"[Phase 1/{self.strategy}/MATHOPT] Evaluating redundancy group "
                f"{group_index + 1}/{len(groups)} with {combo_count} Cartesian combinations."
            )
            transitions_by_stage = self._build_group_transitions(members, feasible_pairs, pair_options)
            final_state_rows, final_state_totals = self._build_group_final_states(
                members=members,
                transitions_by_stage=transitions_by_stage,
                component_assets=component_assets,
                asset_weights=asset_weights,
                combo_cap=combo_cap,
            )
            if not final_state_rows:
                self._post(
                    f"[Phase 1/{self.strategy}/MATHOPT] No feasible redundancy selections for group {members}."
                )
                return None
            self._post(
                f"[Phase 1/{self.strategy}/MATHOPT] Redundancy group {group_index + 1} "
                f"compressed to {sum(len(stage) for stage in transitions_by_stage)} transitions "
                f"and {len(final_state_rows)} feasible final states."
            )
            specs.append(
                _GroupSpec(
                    group_index=group_index,
                    members=members,
                    transitions_by_stage=transitions_by_stage,
                    final_state_rows=final_state_rows,
                    final_state_totals=final_state_totals,
                )
            )
        return specs

    def _build_group_transitions(
        self,
        members: Tuple[str, ...],
        feasible_pairs: Dict[str, List[int]],
        pair_options: Tuple[_PairOption, ...],
    ) -> List[List[_GroupTransition]]:
        transitions_by_stage: List[List[_GroupTransition]] = []
        prior_states = {START_STATE}
        for component in members:
            stage_transitions: List[_GroupTransition] = []
            next_states = set()
            for prev_state in prior_states:
                for pair_index in feasible_pairs[component]:
                    next_state = self._apply_group_pair_state(prev_state, pair_options[pair_index])
                    stage_transitions.append(
                        _GroupTransition(prev_state=prev_state, pair_index=pair_index, next_state=next_state)
                    )
                    next_states.add(next_state)
            transitions_by_stage.append(stage_transitions)
            prior_states = next_states
        return transitions_by_stage

    def _build_group_final_states(
        self,
        *,
        members: Tuple[str, ...],
        transitions_by_stage: List[List[_GroupTransition]],
        component_assets: Dict[str, List[Asset]],
        asset_weights: Dict[str, int],
        combo_cap: int,
    ) -> Tuple[Dict[int, Dict[str, List[Tuple[str, str, int]]]], Dict[int, int]]:
        candidate_final_states = {transition.next_state for transition in transitions_by_stage[-1]}
        final_state_rows: Dict[int, Dict[str, List[Tuple[str, str, int]]]] = {}
        final_state_totals: Dict[int, int] = {}
        valid_final_states = set()
        for final_state in candidate_final_states:
            rows = self._group_state_rows(members, final_state, component_assets)
            if any(not self._rows_within_cap(component_rows, combo_cap) for component_rows in rows.values()):
                continue
            final_state_rows[final_state] = rows
            final_state_totals[final_state] = sum(
                self._weighted_risk_total(component_rows, asset_weights)
                for component_rows in rows.values()
            )
            valid_final_states.add(final_state)

        if not valid_final_states:
            return {}, {}

        reachable_next_states = set(valid_final_states)
        for stage_index in reversed(range(len(transitions_by_stage))):
            transitions_by_stage[stage_index] = [
                transition
                for transition in transitions_by_stage[stage_index]
                if transition.next_state in reachable_next_states
            ]
            if stage_index > 0:
                reachable_next_states = {
                    transition.prev_state
                    for transition in transitions_by_stage[stage_index]
                    if transition.prev_state != START_STATE
                }
        return final_state_rows, final_state_totals

    def _apply_group_pair_state(self, prev_state: int, pair: _PairOption) -> int:
        normalized = self._pair_normalized_prob(pair)
        if prev_state == START_STATE:
            return normalized
        return self._div_trunc_zero(prev_state * normalized, 1000)

    def _pair_normalized_prob(self, pair: _PairOption) -> int:
        original_prob = int(EXPOSURE_VALUES[pair.security]) * int(REALTIME_DETECTION_VALUES[pair.realtime])
        return self._div_trunc_zero((original_prob - MU) * 1000, OMEGA - MU)

    def _group_state_rows(
        self,
        members: Tuple[str, ...],
        final_state: int,
        component_assets: Dict[str, List[Asset]],
    ) -> Dict[str, List[Tuple[str, str, int]]]:
        denorm = self._div_trunc_zero(final_state * (OMEGA - MU), 1000) + MU * 10
        rows_by_component: Dict[str, List[Tuple[str, str, int]]] = {}
        for component in members:
            exploit_factor = EXPLOIT_FACTOR_MAP.get(int(self._component_exploitability(component)), 10)
            rows: List[Tuple[str, str, int]] = []
            for asset in component_assets[component]:
                for action, impact in self._iter_asset_actions(asset):
                    # Match the ASP model: redundancy compounds the exposure/realtime probability
                    # across the group first, then applies each component's exploitability to the
                    # resulting group-level availability risk.
                    rows.append(
                        (
                            asset.asset_id,
                            action,
                            self._div_trunc_zero(impact * denorm * exploit_factor, 1000),
                        )
                    )
            rows_by_component[component] = rows
        return rows_by_component

    def _component_lookup(self) -> Dict[str, Component]:
        return {component.name: component for component in self.network_model.components}

    def _prune_pair_indices(
        self,
        pair_indices: List[int],
        pair_resource_vectors: Dict[int, Tuple[int, ...]],
        pair_risk_metric: Dict[int, int],
    ) -> List[int]:
        pruned: List[int] = []
        for pair_index in pair_indices:
            dominated = False
            for other_index in pair_indices:
                if other_index == pair_index:
                    continue
                other_resources = pair_resource_vectors[other_index]
                pair_resources = pair_resource_vectors[pair_index]
                if (
                    all(o <= p for o, p in zip(other_resources, pair_resources))
                    and pair_risk_metric[other_index] <= pair_risk_metric[pair_index]
                    and (
                        any(o < p for o, p in zip(other_resources, pair_resources))
                        or pair_risk_metric[other_index] < pair_risk_metric[pair_index]
                    )
                ):
                    dominated = True
                    break
            if not dominated:
                pruned.append(pair_index)
        return pruned

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

    def _realtime_latency(self, feature: str) -> int:
        return int(get_calibrated_estimate(feature).latency)

    def _component_exploitability(self, component_name: str) -> int:
        for component in self.network_model.components:
            if component.name == component_name:
                return int(getattr(component, "exploitability", 3))
        return 3

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
