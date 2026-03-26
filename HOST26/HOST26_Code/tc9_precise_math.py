from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from math import prod
from pathlib import Path
import re


GROUP_DIVISORS = {
    2: 100000,
    3: 100000,
    4: 100000,
    5: 100000000,
}


@dataclass(frozen=True)
class Tc9MathFacts:
    asset_to_component: dict[str, str]
    impacts: dict[str, dict[str, int]]
    redundancy_groups: dict[int, tuple[str, ...]]
    vulnerability_scores: dict[str, int]
    logging_scores: dict[str, int]
    mu: int
    omega: int


@dataclass(frozen=True)
class PrecisePhase1Math:
    original_prob: dict[str, int]
    original_prob_normalized: dict[str, Fraction]
    combined_prob_norm: dict[int, Fraction]
    new_prob_denormalized: dict[str, Fraction]
    exact_risk: dict[str, dict[str, Fraction]]
    rounded_risk: dict[str, dict[str, int]]
    rounded_max_risk: dict[str, int]
    total_risk: int


def load_tc9_math_facts(base_dir: str | Path) -> Tc9MathFacts:
    base_dir = Path(base_dir)
    testcase = base_dir / "testCases" / "testCase9_inst.lp"
    security = base_dir / "Clingo" / "security_features_inst.lp"
    redundancy = base_dir / "Clingo" / "opt_redundancy_enc.lp"

    asset_re = re.compile(r"^\s*asset\(([^,]+),\s*([^,]+),\s*(read|write)\)\.")
    impact_re = re.compile(r"^\s*impact\(([^,]+),\s*(read|write),\s*(-?\d+)\)\.")
    group_re = re.compile(r"^\s*redundant_group\((\d+),\s*([^)]+)\)\.")
    vulnerability_re = re.compile(r"^\s*vulnerability\(([^,]+),\s*(-?\d+)\)\.")
    logging_re = re.compile(r"^\s*logging\(([^,]+),\s*(-?\d+)\)\.")
    mu_re = re.compile(r"^\s*mu\(([-\d]+)\)\.")
    omega_re = re.compile(r"^\s*omega\(([-\d]+)\)\.")

    asset_to_component: dict[str, str] = {}
    impacts: dict[str, dict[str, int]] = {}
    redundancy_groups: dict[int, list[str]] = {}
    vulnerability_scores: dict[str, int] = {}
    logging_scores: dict[str, int] = {}
    mu: int | None = None
    omega: int | None = None

    for line in testcase.read_text(encoding="utf-8").splitlines():
        if match := asset_re.match(line):
            component, asset, _operation = match.groups()
            asset_to_component[asset] = component
        elif match := impact_re.match(line):
            asset, operation, value = match.groups()
            impacts.setdefault(asset, {})[operation] = int(value)
        elif match := group_re.match(line):
            group_id, component = match.groups()
            members = redundancy_groups.setdefault(int(group_id), [])
            if component not in members:
                members.append(component)

    for line in security.read_text(encoding="utf-8").splitlines():
        if match := vulnerability_re.match(line):
            feature, value = match.groups()
            vulnerability_scores[feature] = int(value)
        elif match := logging_re.match(line):
            feature, value = match.groups()
            logging_scores[feature] = int(value)

    for line in redundancy.read_text(encoding="utf-8").splitlines():
        if match := mu_re.match(line):
            mu = int(match.group(1))
        elif match := omega_re.match(line):
            omega = int(match.group(1))

    if mu is None or omega is None:
        raise ValueError("Could not locate mu/omega in opt_redundancy_enc.lp")

    return Tc9MathFacts(
        asset_to_component=asset_to_component,
        impacts=impacts,
        redundancy_groups={group_id: tuple(members) for group_id, members in redundancy_groups.items()},
        vulnerability_scores=vulnerability_scores,
        logging_scores=logging_scores,
        mu=mu,
        omega=omega,
    )


def round_fraction_half_up(value: Fraction) -> int:
    if value < 0:
        raise ValueError("round_fraction_half_up only supports non-negative values")
    return (value.numerator * 2 + value.denominator) // (2 * value.denominator)


def compute_precise_phase1_math(
    facts: Tc9MathFacts,
    security_by_component: dict[str, str],
    logging_by_component: dict[str, str],
) -> PrecisePhase1Math:
    original_prob: dict[str, int] = {}
    original_prob_normalized: dict[str, Fraction] = {}
    combined_prob_norm: dict[int, Fraction] = {}
    new_prob_denormalized: dict[str, Fraction] = {}
    exact_risk: dict[str, dict[str, Fraction]] = {}
    rounded_risk: dict[str, dict[str, int]] = {}
    rounded_max_risk: dict[str, int] = {}

    component_to_asset = {component: asset for asset, component in facts.asset_to_component.items()}
    grouped_components = {component for members in facts.redundancy_groups.values() for component in members}

    for component, security in security_by_component.items():
        logging = logging_by_component[component]
        probability = facts.vulnerability_scores[security] * facts.logging_scores[logging]
        original_prob[component] = probability
        original_prob_normalized[component] = Fraction(
            (probability - facts.mu) * 1000,
            facts.omega - facts.mu,
        )

    for group_id, members in facts.redundancy_groups.items():
        group_size = len(members)
        if group_size not in GROUP_DIVISORS:
            raise ValueError(f"Unsupported redundancy group size {group_size}")
        combined = Fraction(prod(original_prob_normalized[component] for component in members), GROUP_DIVISORS[group_size])
        combined_prob_norm[group_id] = combined
        denormalized = combined * Fraction(facts.omega - facts.mu, 1000) + facts.mu * 10
        for component in members:
            new_prob_denormalized[component] = denormalized

    for asset, component in facts.asset_to_component.items():
        impacts = facts.impacts[asset]
        exact_risk[asset] = {}
        rounded_risk[asset] = {}

        if component in grouped_components:
            probability_term = new_prob_denormalized[component]
            for operation, impact in impacts.items():
                risk_value = Fraction(impact, 100) * probability_term
                exact_risk[asset][operation] = risk_value
                rounded_risk[asset][operation] = round_fraction_half_up(risk_value)
        else:
            original_risk_base = facts.vulnerability_scores[security_by_component[component]] * facts.logging_scores[logging_by_component[component]]
            for operation, impact in impacts.items():
                risk_value = Fraction(impact * original_risk_base, 10)
                exact_risk[asset][operation] = risk_value
                rounded_risk[asset][operation] = round_fraction_half_up(risk_value)

        rounded_max_risk[asset] = max(rounded_risk[asset].values())

    return PrecisePhase1Math(
        original_prob=original_prob,
        original_prob_normalized=original_prob_normalized,
        combined_prob_norm=combined_prob_norm,
        new_prob_denormalized=new_prob_denormalized,
        exact_risk=exact_risk,
        rounded_risk=rounded_risk,
        rounded_max_risk=rounded_max_risk,
        total_risk=sum(rounded_max_risk.values()),
    )
