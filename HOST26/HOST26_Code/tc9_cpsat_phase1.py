from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from itertools import product
from pathlib import Path
from time import perf_counter
import re

from ortools.sat.python import cp_model

from tc9_precise_math import (
    PrecisePhase1Math,
    compute_precise_phase1_math,
    load_tc9_math_facts,
)


BASE_DIR = Path(__file__).resolve().parent
COMPONENTS = tuple(f"c{i}" for i in range(1, 9))
GROUP_COMPONENTS = ("c1", "c2", "c3", "c4", "c5")
STANDALONE_COMPONENTS = ("c6", "c7", "c8")
RESOURCES = ("luts", "ffs", "dsps", "lutram", "bram", "power")


@dataclass(frozen=True)
class PairOption:
    index: int
    security: str
    logging: str
    security_rank: int
    logging_rank: int
    original_prob: int
    unit_normalized_prob: Fraction
    latency: int
    by_component: dict[str, int]


@dataclass(frozen=True)
class FlowPath:
    flow_id: str
    master: str
    target: str
    nodes: tuple[str, ...]


@dataclass(frozen=True)
class Tc9CpSatData:
    pair_options: tuple[PairOption, ...]
    feasible_pair_indices: dict[str, tuple[int, ...]]
    base_dir: Path
    budgets: dict[str, int]
    any_base_costs: dict[str, dict[str, int]]
    count_base_costs: dict[str, dict[str, int]]
    exact_frontier_rows: tuple[tuple[int, ...], ...]
    exact_frontier_size: int
    known_flows: tuple[FlowPath, ...]
    path_node_unit_prob: dict[str, Fraction]


@dataclass(frozen=True)
class CpSatPhase1Selection:
    security: dict[str, str]
    logging: dict[str, str]
    precise_math: PrecisePhase1Math
    resources: dict[str, int]
    stage_optima: dict[str, int]
    solve_time_seconds: float
    exact_frontier_size: int
    exact_frontier_truncated: bool
    exact_frontier_limit: int
    optimal: bool


@dataclass(frozen=True)
class BenchmarkResult:
    precise_runtime_seconds: float
    cpsat_runtime_seconds: float
    precise_selection: object
    cpsat_selection: CpSatPhase1Selection
    path_rows: tuple[tuple[str, str, str, str], ...]


def _parse_security_features(base_dir: Path) -> tuple[dict[str, dict[str, dict[str, int]]], dict[str, int], dict[str, int], dict[str, int]]:
    path = base_dir / "Clingo" / "security_features_inst.lp"
    triple_re = re.compile(r"^\s*(power_cost|luts|ffs|dsps|lutram|bram)\(([^,]+),\s*([^,]+),\s*(-?\d+)\)\.")
    vulnerability_re = re.compile(r"^\s*vulnerability\(([^,]+),\s*(-?\d+)\)\.")
    logging_re = re.compile(r"^\s*logging\(([^,]+),\s*(-?\d+)\)\.")
    latency_re = re.compile(r"^\s*latency_cost\(([^,]+),\s*(-?\d+)\)\.")

    resource_costs: dict[str, dict[str, dict[str, int]]] = {name: {} for name in RESOURCES}
    vulnerabilities: dict[str, int] = {}
    logging_scores: dict[str, int] = {}
    latency_costs: dict[str, int] = {}

    for line in path.read_text(encoding="utf-8").splitlines():
        if match := triple_re.match(line):
            resource_name, feature, kind, value = match.groups()
            name = "power" if resource_name == "power_cost" else resource_name
            resource_costs[name].setdefault(feature, {})[kind] = int(value)
        elif match := vulnerability_re.match(line):
            feature, value = match.groups()
            vulnerabilities[feature] = int(value)
        elif match := logging_re.match(line):
            feature, value = match.groups()
            logging_scores[feature] = int(value)
        elif match := latency_re.match(line):
            feature, value = match.groups()
            latency_costs[feature] = int(value)

    return resource_costs, vulnerabilities, logging_scores, latency_costs


def _parse_budgets(base_dir: Path) -> dict[str, int]:
    path = base_dir / "Clingo" / "tgt_system_tc9_inst.lp"
    capability_re = re.compile(r"^\s*system_capability\(([^,]+),\s*(-?\d+)\)\.")
    budgets: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if match := capability_re.match(line):
            name, value = match.groups()
            budgets[name] = int(value)
    return budgets


def _parse_testcase_topology(base_dir: Path) -> tuple[dict[str, tuple[str, ...]], tuple[str, ...], tuple[tuple[str, str], ...]]:
    path = base_dir / "testCases" / "testCase9_inst.lp"
    link_re = re.compile(r"^\s*link\(([^,]+),\s*([^)]+)\)\.")
    master_re = re.compile(r"^\s*master\(([^)]+)\)\.")
    access_need_re = re.compile(r"^\s*access_need\(([^,]+),\s*([^,]+),\s*(read|write)\)\.")

    adjacency: dict[str, list[str]] = {}
    masters: list[str] = []
    access_pairs: set[tuple[str, str]] = set()

    for line in path.read_text(encoding="utf-8").splitlines():
        if match := link_re.match(line):
            left, right = match.groups()
            adjacency.setdefault(left, []).append(right)
        elif match := master_re.match(line):
            masters.append(match.group(1))
        elif match := access_need_re.match(line):
            master, component, _op = match.groups()
            access_pairs.add((master, component))

    return {node: tuple(neighbors) for node, neighbors in adjacency.items()}, tuple(sorted(masters)), tuple(sorted(access_pairs))


def _parse_allowable_latency(base_dir: Path) -> dict[str, int]:
    path = base_dir / "testCases" / "testCase9_inst.lp"
    latency_re = re.compile(r"^\s*allowable_latency\(([^,]+),\s*(read|write),\s*(-?\d+)\)\.")
    per_asset: dict[str, dict[str, int]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if match := latency_re.match(line):
            asset, operation, value = match.groups()
            per_asset.setdefault(asset, {})[operation] = int(value)
    return {asset: min(ops.values()) for asset, ops in per_asset.items()}


def _shortest_path(adjacency: dict[str, tuple[str, ...]], start: str, goal: str) -> tuple[str, ...] | None:
    frontier: list[tuple[str, ...]] = [(start,)]
    seen = {start}
    while frontier:
        path = frontier.pop(0)
        node = path[-1]
        if node == goal:
            return path
        for neighbor in adjacency.get(node, ()):
            if neighbor not in seen:
                seen.add(neighbor)
                frontier.append(path + (neighbor,))
    return None


def _build_known_flows(base_dir: Path) -> tuple[FlowPath, ...]:
    adjacency, _masters, access_pairs = _parse_testcase_topology(base_dir)
    flows: list[FlowPath] = []
    for master, component in access_pairs:
        path = _shortest_path(adjacency, master, component)
        if path is None:
            continue
        flows.append(FlowPath(flow_id=f"{master}_to_{component}", master=master, target=component, nodes=path))
    return tuple(sorted(flows, key=lambda flow: flow.flow_id))


def _count_base_costs(resource_costs: dict[str, dict[str, dict[str, int]]], feature_name: str, resource_name: str) -> int:
    return resource_costs.get(resource_name, {}).get(feature_name, {}).get("base", 0)


def _pair_options(base_dir: Path) -> tuple[tuple[PairOption, ...], dict[str, tuple[int, ...]], dict[str, dict[str, int]], dict[str, dict[str, int]], dict[str, int]]:
    facts = load_tc9_math_facts(base_dir)
    resource_costs, vulnerabilities, logging_scores, latency_costs = _parse_security_features(base_dir)
    allowable = _parse_allowable_latency(base_dir)
    security_names = sorted(vulnerabilities)
    logging_names = sorted(logging_scores)
    security_rank = {name: rank for rank, name in enumerate(sorted(security_names))}
    logging_rank = {name: rank for rank, name in enumerate(sorted(logging_names))}

    pair_options: list[PairOption] = []
    by_component_indices: dict[str, list[int]] = {component: [] for component in COMPONENTS}

    for index, (security, logging) in enumerate((s, l) for s in security_names for l in logging_names):
        original_prob = vulnerabilities[security] * logging_scores[logging]
        option = PairOption(
            index=index,
            security=security,
            logging=logging,
            security_rank=security_rank[security],
            logging_rank=logging_rank[logging],
            original_prob=original_prob,
            unit_normalized_prob=Fraction(original_prob - facts.mu, facts.omega - facts.mu),
            latency=latency_costs[security] + latency_costs[logging],
            by_component={
                resource: resource_costs[resource].get(security, {}).get("byAsset", 0)
                + resource_costs[resource].get(security, {}).get("byComponent", 0)
                for resource in RESOURCES
            },
        )
        pair_options.append(option)
        for asset, component in facts.asset_to_component.items():
            if option.latency <= allowable[asset]:
                by_component_indices[component].append(index)

    any_base_costs = {
        "dynamic_mac": {resource: _count_base_costs(resource_costs, "dynamic_mac", resource) for resource in RESOURCES},
        "zero_trust": {resource: _count_base_costs(resource_costs, "zero_trust", resource) for resource in RESOURCES},
        "zero_trust_logger": {resource: _count_base_costs(resource_costs, "zero_trust_logger", resource) for resource in RESOURCES},
    }
    count_base_costs = {
        "some_logging": {resource: _count_base_costs(resource_costs, "some_logging", resource) for resource in RESOURCES},
        "dynamic_mac": {resource: _count_base_costs(resource_costs, "dynamic_mac", resource) for resource in RESOURCES},
        "zero_trust": {resource: _count_base_costs(resource_costs, "zero_trust", resource) for resource in RESOURCES},
        "zero_trust_logger": {resource: _count_base_costs(resource_costs, "zero_trust_logger", resource) for resource in RESOURCES},
    }
    return tuple(pair_options), {component: tuple(indices) for component, indices in by_component_indices.items()}, any_base_costs, count_base_costs, vulnerabilities


def _security_logging_dict(pair_options: tuple[PairOption, ...], assignment: dict[str, int]) -> tuple[dict[str, str], dict[str, str]]:
    security = {component: pair_options[index].security for component, index in assignment.items()}
    logging = {component: pair_options[index].logging for component, index in assignment.items()}
    return security, logging


def _resource_totals(
    pair_options: tuple[PairOption, ...],
    assignment: dict[str, int],
    any_base_costs: dict[str, dict[str, int]],
    count_base_costs: dict[str, dict[str, int]],
) -> dict[str, int]:
    selected = {component: pair_options[index] for component, index in assignment.items()}
    count_dynamic = sum(1 for option in selected.values() if option.security == "dynamic_mac")
    count_zero = sum(1 for option in selected.values() if option.security == "zero_trust")
    count_some = sum(1 for option in selected.values() if option.logging == "some_logging")
    count_ztl = sum(1 for option in selected.values() if option.logging == "zero_trust_logger")

    totals: dict[str, int] = {}
    for resource in RESOURCES:
        total = sum(option.by_component[resource] for option in selected.values())
        total += count_some * count_base_costs["some_logging"][resource]
        if resource == "luts":
            if count_dynamic:
                total += any_base_costs["dynamic_mac"][resource]
            if count_zero:
                total += any_base_costs["zero_trust"][resource]
            if count_ztl:
                total += any_base_costs["zero_trust_logger"][resource]
        else:
            total += count_dynamic * count_base_costs["dynamic_mac"][resource]
            total += count_zero * count_base_costs["zero_trust"][resource]
            total += count_ztl * count_base_costs["zero_trust_logger"][resource]
        totals[resource] = total
    return totals


def _risk_table_rows(base_dir: Path, pair_options: tuple[PairOption, ...], feasible_pair_indices: dict[str, tuple[int, ...]]) -> tuple[tuple[int, ...], ...]:
    facts = load_tc9_math_facts(base_dir)
    rows: list[tuple[int, ...]] = []
    group_domains = [feasible_pair_indices[component] for component in GROUP_COMPONENTS]
    standalone_domains = [feasible_pair_indices[component] for component in STANDALONE_COMPONENTS]

    for indices in product(*group_domains, *standalone_domains):
        assignment = {component: index for component, index in zip(COMPONENTS, indices)}
        security, logging = _security_logging_dict(pair_options, assignment)
        precise_math = compute_precise_phase1_math(facts, security, logging)
        rows.append(
            tuple(indices)
            + (
                precise_math.rounded_max_risk["c1r1"],
                precise_math.rounded_max_risk["c2r1"],
                precise_math.rounded_max_risk["c3r1"],
                precise_math.rounded_max_risk["c4r1"],
                precise_math.rounded_max_risk["c5r1"],
                precise_math.rounded_max_risk["c6r1"],
                precise_math.rounded_max_risk["c7r1"],
                precise_math.rounded_max_risk["c8r1"],
                precise_math.total_risk,
            )
        )
    return tuple(rows)


def load_cpsat_data(base_dir: str | Path = BASE_DIR) -> Tc9CpSatData:
    base_dir = Path(base_dir)
    pair_options, feasible_pair_indices, any_base_costs, count_base_costs, _ = _pair_options(base_dir)
    exact_frontier_rows = _risk_table_rows(base_dir, pair_options, feasible_pair_indices)
    path_node_unit_prob = {flow_node: Fraction(1, 1) for flow in _build_known_flows(base_dir) for flow_node in flow.nodes}
    return Tc9CpSatData(
        pair_options=pair_options,
        feasible_pair_indices=feasible_pair_indices,
        base_dir=base_dir,
        budgets=_parse_budgets(base_dir),
        any_base_costs=any_base_costs,
        count_base_costs=count_base_costs,
        exact_frontier_rows=exact_frontier_rows,
        exact_frontier_size=len(exact_frontier_rows),
        known_flows=_build_known_flows(base_dir),
        path_node_unit_prob=path_node_unit_prob,
    )


@dataclass
class _ModelBundle:
    model: cp_model.CpModel
    pair_idx: dict[str, cp_model.IntVar]
    security_rank: dict[str, cp_model.IntVar]
    logging_rank: dict[str, cp_model.IntVar]
    total_risk: cp_model.IntVar
    total_luts: cp_model.IntVar
    total_ffs: cp_model.IntVar
    total_dsps: cp_model.IntVar
    total_lutram: cp_model.IntVar
    total_bram: cp_model.IntVar
    total_power: cp_model.IntVar


def _build_model(data: Tc9CpSatData, fixed: dict[str, int] | None = None) -> _ModelBundle:
    fixed = fixed or {}
    model = cp_model.CpModel()
    max_pair_index = max(option.index for option in data.pair_options)
    pair_idx: dict[str, cp_model.IntVar] = {}
    security_rank: dict[str, cp_model.IntVar] = {}
    logging_rank: dict[str, cp_model.IntVar] = {}
    choose: dict[str, dict[int, cp_model.IntVar]] = {}

    for component in COMPONENTS:
        pair_idx[component] = model.NewIntVar(0, max_pair_index, f"pair_{component}")
        security_rank[component] = model.NewIntVar(0, 10, f"sec_rank_{component}")
        logging_rank[component] = model.NewIntVar(0, 10, f"log_rank_{component}")
        choose[component] = {}
        feasible = set(data.feasible_pair_indices[component])
        vars_for_component = []
        sec_expr = []
        log_expr = []
        pair_expr = []
        for option in data.pair_options:
            decision = model.NewBoolVar(f"choose_{component}_{option.index}")
            choose[component][option.index] = decision
            if option.index not in feasible:
                model.Add(decision == 0)
            vars_for_component.append(decision)
            sec_expr.append(option.security_rank * decision)
            log_expr.append(option.logging_rank * decision)
            pair_expr.append(option.index * decision)
        model.Add(sum(vars_for_component) == 1)
        model.Add(pair_idx[component] == sum(pair_expr))
        model.Add(security_rank[component] == sum(sec_expr))
        model.Add(logging_rank[component] == sum(log_expr))

    resource_vars: dict[str, cp_model.IntVar] = {}
    count_dynamic = model.NewIntVar(0, len(COMPONENTS), "count_dynamic")
    count_zero = model.NewIntVar(0, len(COMPONENTS), "count_zero")
    count_some = model.NewIntVar(0, len(COMPONENTS), "count_some")
    count_ztl = model.NewIntVar(0, len(COMPONENTS), "count_ztl")
    any_dynamic = model.NewBoolVar("any_dynamic")
    any_zero = model.NewBoolVar("any_zero")
    any_ztl = model.NewBoolVar("any_ztl")

    model.Add(count_dynamic == sum(choose[component][option.index] for component in COMPONENTS for option in data.pair_options if option.security == "dynamic_mac"))
    model.Add(count_zero == sum(choose[component][option.index] for component in COMPONENTS for option in data.pair_options if option.security == "zero_trust"))
    model.Add(count_some == sum(choose[component][option.index] for component in COMPONENTS for option in data.pair_options if option.logging == "some_logging"))
    model.Add(count_ztl == sum(choose[component][option.index] for component in COMPONENTS for option in data.pair_options if option.logging == "zero_trust_logger"))

    model.Add(count_dynamic >= 1).OnlyEnforceIf(any_dynamic)
    model.Add(count_dynamic == 0).OnlyEnforceIf(any_dynamic.Not())
    model.Add(count_zero >= 1).OnlyEnforceIf(any_zero)
    model.Add(count_zero == 0).OnlyEnforceIf(any_zero.Not())
    model.Add(count_ztl >= 1).OnlyEnforceIf(any_ztl)
    model.Add(count_ztl == 0).OnlyEnforceIf(any_ztl.Not())

    for resource in RESOURCES:
        upper_bound = data.budgets.get(f"max_{resource}", 1_000_000)
        if resource == "power":
            upper_bound = data.budgets.get("max_power", upper_bound)
        if resource == "luts":
            upper_bound = data.budgets.get("max_luts", upper_bound)
        if resource == "ffs":
            upper_bound = data.budgets.get("max_ffs", upper_bound)
        if resource == "dsps":
            upper_bound = data.budgets.get("max_dsps", upper_bound)
        if resource == "lutram":
            upper_bound = data.budgets.get("max_lutram", upper_bound)
        if resource == "bram":
            upper_bound = data.budgets.get("max_bram", upper_bound)
        resource_vars[resource] = model.NewIntVar(0, upper_bound, f"total_{resource}")
        base_expr = count_some * data.count_base_costs["some_logging"][resource]
        if resource == "luts":
            total_expr = (
                sum(option.by_component[resource] * choose[component][option.index] for component in COMPONENTS for option in data.pair_options)
                + base_expr
                + any_dynamic * data.any_base_costs["dynamic_mac"][resource]
                + any_zero * data.any_base_costs["zero_trust"][resource]
                + any_ztl * data.any_base_costs["zero_trust_logger"][resource]
            )
        else:
            total_expr = (
                sum(option.by_component[resource] * choose[component][option.index] for component in COMPONENTS for option in data.pair_options)
                + base_expr
                + count_dynamic * data.count_base_costs["dynamic_mac"][resource]
                + count_zero * data.count_base_costs["zero_trust"][resource]
                + count_ztl * data.count_base_costs["zero_trust_logger"][resource]
            )
        model.Add(resource_vars[resource] == total_expr)
        budget_name = f"max_{resource}"
        if resource == "power":
            budget_name = "max_power"
        model.Add(resource_vars[resource] <= data.budgets[budget_name])

    risk_domains = {asset: model.NewIntVar(0, 100000, f"max_risk_{asset}") for asset in ("c1r1", "c2r1", "c3r1", "c4r1", "c5r1", "c6r1", "c7r1", "c8r1")}
    total_risk = model.NewIntVar(0, 1_000_000, "total_risk")
    table_vars = [pair_idx[component] for component in COMPONENTS] + [risk_domains[asset] for asset in ("c1r1", "c2r1", "c3r1", "c4r1", "c5r1", "c6r1", "c7r1", "c8r1")] + [total_risk]
    model.AddAllowedAssignments(table_vars, list(data.exact_frontier_rows))

    named_vars = {
        "total_risk": total_risk,
        "total_luts": resource_vars["luts"],
        "total_ffs": resource_vars["ffs"],
        "total_dsps": resource_vars["dsps"],
        "total_lutram": resource_vars["lutram"],
        "total_bram": resource_vars["bram"],
        "total_power": resource_vars["power"],
    }
    for name, value in fixed.items():
        if name in named_vars:
            model.Add(named_vars[name] == value)
    for component in COMPONENTS:
        if f"sec_{component}" in fixed:
            model.Add(security_rank[component] == fixed[f"sec_{component}"])
        if f"log_{component}" in fixed:
            model.Add(logging_rank[component] == fixed[f"log_{component}"])

    return _ModelBundle(
        model=model,
        pair_idx=pair_idx,
        security_rank=security_rank,
        logging_rank=logging_rank,
        total_risk=total_risk,
        total_luts=resource_vars["luts"],
        total_ffs=resource_vars["ffs"],
        total_dsps=resource_vars["dsps"],
        total_lutram=resource_vars["lutram"],
        total_bram=resource_vars["bram"],
        total_power=resource_vars["power"],
    )


def solve_cpsat_phase1(base_dir: str | Path = BASE_DIR, frontier_limit: int = 50000) -> CpSatPhase1Selection:
    data = load_cpsat_data(base_dir)
    stage_values: dict[str, int] = {}
    stage_order = [
        ("total_risk", lambda bundle: bundle.total_risk),
        ("total_luts", lambda bundle: bundle.total_luts),
        ("total_ffs", lambda bundle: bundle.total_ffs),
        ("total_dsps", lambda bundle: bundle.total_dsps),
        ("total_lutram", lambda bundle: bundle.total_lutram),
        ("total_bram", lambda bundle: bundle.total_bram),
        ("total_power", lambda bundle: bundle.total_power),
    ]

    start = perf_counter()
    final_bundle: _ModelBundle | None = None
    final_solver: cp_model.CpSolver | None = None

    for stage_name, objective_getter in stage_order:
        bundle = _build_model(data, stage_values)
        bundle.model.Minimize(objective_getter(bundle))
        solver = cp_model.CpSolver()
        solver.parameters.num_search_workers = 8
        solver.parameters.max_time_in_seconds = 120.0
        status = solver.Solve(bundle.model)
        if status not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
            raise RuntimeError(f"CP-SAT failed during stage {stage_name}: {solver.StatusName(status)}")
        stage_values[stage_name] = solver.Value(objective_getter(bundle))
        final_bundle = bundle
        final_solver = solver

    assert final_bundle is not None and final_solver is not None

    for component in COMPONENTS:
        bundle = _build_model(data, stage_values)
        bundle.model.Minimize(bundle.security_rank[component])
        solver = cp_model.CpSolver()
        solver.parameters.num_search_workers = 8
        solver.parameters.max_time_in_seconds = 120.0
        status = solver.Solve(bundle.model)
        if status not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
            raise RuntimeError(f"CP-SAT failed during security tie-break for {component}: {solver.StatusName(status)}")
        stage_values[f"sec_{component}"] = solver.Value(bundle.security_rank[component])
        final_bundle = bundle
        final_solver = solver

    for component in COMPONENTS:
        bundle = _build_model(data, stage_values)
        bundle.model.Minimize(bundle.logging_rank[component])
        solver = cp_model.CpSolver()
        solver.parameters.num_search_workers = 8
        solver.parameters.max_time_in_seconds = 120.0
        status = solver.Solve(bundle.model)
        if status not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
            raise RuntimeError(f"CP-SAT failed during logging tie-break for {component}: {solver.StatusName(status)}")
        stage_values[f"log_{component}"] = solver.Value(bundle.logging_rank[component])
        final_bundle = bundle
        final_solver = solver

    final_model = _build_model(data, stage_values)
    final_solver = cp_model.CpSolver()
    final_solver.parameters.num_search_workers = 8
    final_solver.parameters.max_time_in_seconds = 120.0
    final_status = final_solver.Solve(final_model.model)
    if final_status not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        raise RuntimeError(f"CP-SAT final solve failed: {final_solver.StatusName(final_status)}")

    assignment = {component: final_solver.Value(final_model.pair_idx[component]) for component in COMPONENTS}
    security, logging = _security_logging_dict(data.pair_options, assignment)
    facts = load_tc9_math_facts(data.base_dir)
    precise_math = compute_precise_phase1_math(facts, security, logging)
    resources = _resource_totals(data.pair_options, assignment, data.any_base_costs, data.count_base_costs)

    class FrontierCounter(cp_model.CpSolverSolutionCallback):
        def __init__(self, limit: int) -> None:
            super().__init__()
            self.limit = limit
            self.count = 0
            self.truncated = False

        def on_solution_callback(self) -> None:
            self.count += 1
            if self.count >= self.limit:
                self.truncated = True
                self.StopSearch()

    frontier_bundle = _build_model(data, {"total_risk": precise_math.total_risk})
    frontier_solver = cp_model.CpSolver()
    frontier_solver.parameters.enumerate_all_solutions = True
    frontier_solver.parameters.max_time_in_seconds = 30.0
    frontier_solver.parameters.num_search_workers = 1
    frontier_counter = FrontierCounter(frontier_limit)
    frontier_solver.Solve(frontier_bundle.model, frontier_counter)

    return CpSatPhase1Selection(
        security=security,
        logging=logging,
        precise_math=precise_math,
        resources=resources,
        stage_optima={
            "total_risk": precise_math.total_risk,
            "total_luts": resources["luts"],
            "total_ffs": resources["ffs"],
            "total_dsps": resources["dsps"],
            "total_lutram": resources["lutram"],
            "total_bram": resources["bram"],
            "total_power": resources["power"],
        },
        solve_time_seconds=perf_counter() - start,
        exact_frontier_size=frontier_counter.count,
        exact_frontier_truncated=frontier_counter.truncated,
        exact_frontier_limit=frontier_limit,
        optimal=final_status == cp_model.OPTIMAL,
    )


def benchmark_against_precise_helper(base_dir: str | Path = BASE_DIR) -> BenchmarkResult:
    import runClingo_tc9_precise as precise_runner

    precise_start = perf_counter()
    precise_selection = precise_runner.phase1_precise()
    precise_runtime = perf_counter() - precise_start

    cpsat_selection = solve_cpsat_phase1(base_dir)
    data = load_cpsat_data(base_dir)

    def _flow_rows(name: str, math: PrecisePhase1Math) -> list[tuple[str, str, str, str]]:
        rows: list[tuple[str, str, str, str]] = []
        for flow in data.known_flows:
            component_probs = {
                component: Fraction(
                    math.original_prob[component] - load_tc9_math_facts(base_dir).mu,
                    load_tc9_math_facts(base_dir).omega - load_tc9_math_facts(base_dir).mu,
                )
                for component in COMPONENTS
            }
            product_value = Fraction(1, 1)
            for node in flow.nodes:
                product_value *= component_probs.get(node, Fraction(1, 1))
            rows.append((name, flow.flow_id, " -> ".join(flow.nodes), f"{float(product_value):.6f} ({product_value.numerator}/{product_value.denominator})"))
        return rows

    path_rows = tuple(_flow_rows("precise_helper", precise_selection.precise_math) + _flow_rows("cpsat", cpsat_selection.precise_math))
    return BenchmarkResult(
        precise_runtime_seconds=precise_runtime,
        cpsat_runtime_seconds=cpsat_selection.solve_time_seconds,
        precise_selection=precise_selection,
        cpsat_selection=cpsat_selection,
        path_rows=path_rows,
    )
