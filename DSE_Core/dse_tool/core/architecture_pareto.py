"""Pareto filtering for architecture-space exploration results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List

from .solution_parser import SolutionResult


PARETO_AXES = (
    "security",
    "resilience",
    "resource",
    "power",
    "policy",
)


@dataclass(frozen=True)
class ArchitectureParetoPoint:
    """A ranked architecture seed/strategy point on the tradeoff surface."""

    architecture_seed: str
    objective_bias: str
    strategy: str
    label: str
    scores: Dict[str, float]

    @property
    def total_score(self) -> float:
        return sum(self.scores.values()) / len(self.scores) if self.scores else 0.0


def build_architecture_pareto_front(
    solutions: Iterable[SolutionResult],
) -> List[ArchitectureParetoPoint]:
    """Return nondominated feasible architecture seed solutions."""
    points = [
        _point_from_solution(solution)
        for solution in solutions
        if _is_feasible_solution(solution)
    ]
    front = [
        point for point in points
        if not any(_dominates(other, point) for other in points if other is not point)
    ]
    return sorted(
        front,
        key=lambda point: (
            -point.total_score,
            point.architecture_seed,
            point.strategy,
        ),
    )


def _is_feasible_solution(solution: SolutionResult) -> bool:
    return bool(
        solution.phase1
        and solution.phase1.satisfiable
        and solution.phase2
        and solution.phase2.satisfiable
        and any(scenario.satisfiable for scenario in solution.scenarios)
    )


def _point_from_solution(solution: SolutionResult) -> ArchitectureParetoPoint:
    return ArchitectureParetoPoint(
        architecture_seed=solution.architecture_seed or "unseeded",
        objective_bias=solution.architecture_objective_bias or "unknown",
        strategy=solution.strategy,
        label=solution.label or solution.strategy,
        scores={
            "security": float(solution.security_score),
            "resilience": float(solution.resilience_score),
            "resource": float(solution.resource_score),
            "power": float(solution.power_score),
            "policy": float(solution.policy_score),
        },
    )


def _dominates(candidate: ArchitectureParetoPoint, other: ArchitectureParetoPoint) -> bool:
    candidate_scores = [candidate.scores[axis] for axis in PARETO_AXES]
    other_scores = [other.scores[axis] for axis in PARETO_AXES]
    return (
        all(candidate_value >= other_value for candidate_value, other_value in zip(candidate_scores, other_scores))
        and any(candidate_value > other_value for candidate_value, other_value in zip(candidate_scores, other_scores))
    )
