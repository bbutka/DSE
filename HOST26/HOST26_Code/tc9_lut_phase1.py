from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from pathlib import Path
from time import perf_counter
import re

import runClingo_tc9 as legacy
from tc9_cpsat_phase1 import (
    GROUP_COMPONENTS,
    STANDALONE_COMPONENTS,
    _pair_options,
    _resource_totals,
    _security_logging_dict,
)
from tc9_precise_math import PrecisePhase1Math, compute_precise_phase1_math, load_tc9_math_facts


BASE_DIR = Path(__file__).resolve().parent
COMPONENTS = tuple(sorted(legacy.COMPONENTS))


@dataclass(frozen=True)
class PairLogFacts:
    prob_scaled: int
    log_weight: int


@dataclass(frozen=True)
class LutPhase1Candidate:
    approx_cost: tuple[int, ...]
    security: dict[str, str]
    logging: dict[str, str]
    resources: dict[str, int]
    group_ln_sum: dict[int, int]
    member_prob_scaled: dict[str, int]
    member_log_weight: dict[str, int]
    precise_math: PrecisePhase1Math


@dataclass(frozen=True)
class LutPhase1Selection:
    phase1: legacy.Phase1Result
    precise_math: PrecisePhase1Math
    approx_frontier_size: int
    approx_opt_cost: tuple[int, ...]
    solve_time_seconds: float
    group_ln_sum: dict[int, int]
    member_prob_scaled: dict[str, int]
    member_log_weight: dict[str, int]


@dataclass(frozen=True)
class LutBenchmarkResult:
    precise_runtime_seconds: float
    lut_runtime_seconds: float
    cpsat_runtime_seconds: float
    precise_selection: object
    lut_selection: LutPhase1Selection
    cpsat_selection: object


def _load_pair_log_facts(base_dir: str | Path = BASE_DIR) -> dict[tuple[str, str], PairLogFacts]:
    path = Path(base_dir) / "Clingo" / "tc9_pair_log_facts.lp"
    prob_re = re.compile(r"^\s*pair_prob_scaled\(([^,]+),\s*([^,]+),\s*(-?\d+)\)\.")
    log_re = re.compile(r"^\s*pair_log_weight\(([^,]+),\s*([^,]+),\s*(-?\d+)\)\.")
    facts: dict[tuple[str, str], dict[str, int]] = {}

    for line in path.read_text(encoding="utf-8").splitlines():
        if match := prob_re.match(line):
            security, logging, value = match.groups()
            facts.setdefault((security, logging), {})["prob_scaled"] = int(value)
        elif match := log_re.match(line):
            security, logging, value = match.groups()
            facts.setdefault((security, logging), {})["log_weight"] = int(value)

    return {
        key: PairLogFacts(prob_scaled=value["prob_scaled"], log_weight=value["log_weight"])
        for key, value in facts.items()
    }


def _standalone_objective_risk_sum(
    facts,
    security: dict[str, str],
    logging: dict[str, str],
) -> int:
    grouped = {component for members in facts.redundancy_groups.values() for component in members}
    total = 0
    for asset, component in facts.asset_to_component.items():
        if component in grouped:
            continue
        base = facts.vulnerability_scores[security[component]] * facts.logging_scores[logging[component]]
        for impact in facts.impacts[asset].values():
            total += impact * base // 10
    return total


def _candidate_sort_key(candidate: LutPhase1Candidate) -> tuple:
    resources = candidate.resources
    return (
        candidate.precise_math.total_risk,
        resources.get("luts", 0),
        resources.get("ffs", 0),
        resources.get("dsps", 0),
        resources.get("lutram", 0),
        resources.get("bram", 0),
        resources.get("power", 0),
        tuple(sorted(candidate.security.items())),
        tuple(sorted(candidate.logging.items())),
    )


def collect_lut_candidates(base_dir: str | Path = BASE_DIR) -> list[LutPhase1Candidate]:
    base_dir = Path(base_dir)
    facts = load_tc9_math_facts(base_dir)
    pair_options, feasible_pair_indices, any_base_costs, count_base_costs, _ = _pair_options(base_dir)
    pair_log_facts = _load_pair_log_facts(base_dir)
    group_map = facts.redundancy_groups
    grouped_components = {component for members in group_map.values() for component in members}

    domains = [feasible_pair_indices[component] for component in COMPONENTS]
    candidates: list[LutPhase1Candidate] = []

    for indices in product(*domains):
        assignment = {component: index for component, index in zip(COMPONENTS, indices)}
        security, logging = _security_logging_dict(pair_options, assignment)
        resources = _resource_totals(pair_options, assignment, any_base_costs, count_base_costs)
        precise_math = compute_precise_phase1_math(facts, security, logging)

        member_prob_scaled: dict[str, int] = {}
        member_log_weight: dict[str, int] = {}
        group_ln_sum: dict[int, int] = {}
        group_prob_sum_total = 0
        group_ln_sum_total = 0

        for group_id, members in group_map.items():
            current_sum = 0
            for component in members:
                pair = pair_log_facts[(security[component], logging[component])]
                member_prob_scaled[component] = pair.prob_scaled
                member_log_weight[component] = pair.log_weight
                current_sum += pair.log_weight
                group_prob_sum_total += pair.prob_scaled
            group_ln_sum[group_id] = current_sum
            group_ln_sum_total += current_sum

        standalone_risk_sum = _standalone_objective_risk_sum(facts, security, logging)
        approx_cost = (
            group_ln_sum_total,
            group_prob_sum_total,
            standalone_risk_sum,
            resources["luts"],
            resources["ffs"],
            resources["dsps"],
            resources["lutram"],
            resources["bram"],
            resources["power"],
        )

        candidates.append(
            LutPhase1Candidate(
                approx_cost=approx_cost,
                security=security,
                logging=logging,
                resources=resources,
                group_ln_sum=group_ln_sum,
                member_prob_scaled=member_prob_scaled,
                member_log_weight=member_log_weight,
                precise_math=precise_math,
            )
        )

    if not candidates:
        raise RuntimeError("No LUT candidates generated")
    return candidates


def phase1_lut(base_dir: str | Path = BASE_DIR) -> LutPhase1Selection:
    start = perf_counter()
    facts = load_tc9_math_facts(base_dir)
    candidates = collect_lut_candidates(base_dir)
    min_cost = min(candidate.approx_cost for candidate in candidates)
    frontier = [candidate for candidate in candidates if candidate.approx_cost == min_cost]
    chosen = min(frontier, key=_candidate_sort_key)

    phase1 = legacy.Phase1Result()
    phase1.security = dict(chosen.security)
    phase1.logging = dict(chosen.logging)
    phase1.new_risk = [
        (facts.asset_to_component[asset], asset, action, risk)
        for asset, action_risks in chosen.precise_math.rounded_risk.items()
        for action, risk in action_risks.items()
    ]
    phase1.total_luts = chosen.resources["luts"]
    phase1.total_ffs = chosen.resources["ffs"]
    phase1.total_dsps = chosen.resources["dsps"]
    phase1.total_lutram = chosen.resources["lutram"]
    phase1.total_bram = chosen.resources["bram"]
    phase1.total_power = chosen.resources["power"]
    phase1.optimal = True

    return LutPhase1Selection(
        phase1=phase1,
        precise_math=chosen.precise_math,
        approx_frontier_size=len(frontier),
        approx_opt_cost=min_cost,
        solve_time_seconds=perf_counter() - start,
        group_ln_sum=chosen.group_ln_sum,
        member_prob_scaled=chosen.member_prob_scaled,
        member_log_weight=chosen.member_log_weight,
    )


def benchmark_against_existing(base_dir: str | Path = BASE_DIR) -> LutBenchmarkResult:
    import runClingo_tc9_precise as precise_runner
    from tc9_cpsat_phase1 import solve_cpsat_phase1

    precise_start = perf_counter()
    precise_selection = precise_runner.phase1_precise()
    precise_runtime = perf_counter() - precise_start

    lut_selection = phase1_lut(base_dir)
    cpsat_selection = solve_cpsat_phase1(base_dir)

    return LutBenchmarkResult(
        precise_runtime_seconds=precise_runtime,
        lut_runtime_seconds=lut_selection.solve_time_seconds,
        cpsat_runtime_seconds=cpsat_selection.solve_time_seconds,
        precise_selection=precise_selection,
        lut_selection=lut_selection,
        cpsat_selection=cpsat_selection,
    )
