"""
solution_ranker.py
==================
Computes normalised 0-100 scores for each SolutionResult across six axes
(Security, Resources, Power, Latency, Resilience, Policy Coverage) used in
the radar charts and metric tables.
"""

from __future__ import annotations

from typing import List, Optional

from .solution_parser import SolutionResult


# ---------------------------------------------------------------------------
# Constants (PYNQ-Z2 maxima, mirroring tgt_system_tc9_inst.lp)
# ---------------------------------------------------------------------------

MAX_LUTS          = 53_200
MAX_FFS           = 106_400
MAX_POWER_MW      = 15_000
MAX_RISK_POSSIBLE = 500      # max_asset_risk cap
TOTAL_NODES       = 12       # sys_cpu, dma, c1-c8, ps0, ps1


class SolutionRanker:
    """
    Normalises SolutionResult metrics and populates score fields.

    Usage
    -----
    ranker = SolutionRanker(solutions)
    ranker.rank()
    # After rank(), each SolutionResult has .security_score etc. populated.
    """

    def __init__(self, solutions: List[SolutionResult]) -> None:
        self.solutions = solutions

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def rank(self) -> None:
        """Compute and store scores on all SolutionResult objects in-place."""
        for sol in self.solutions:
            self._score_solution(sol)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _score_solution(self, sol: SolutionResult) -> None:
        """Populate the six score fields on *sol*."""
        p1 = sol.phase1
        p2 = sol.phase2

        # ── Security score ─────────────────────────────────────────────────
        if p1 and p1.satisfiable and p1.total_risk() > 0:
            # Lower risk → higher security score
            sol.security_score = max(
                0.0,
                100.0 - (p1.total_risk() / MAX_RISK_POSSIBLE * 100.0),
            )
        else:
            sol.security_score = 0.0

        # ── Resource score ─────────────────────────────────────────────────
        if p1 and p1.satisfiable and p1.total_luts >= 0:
            sol.resource_score = max(
                0.0,
                100.0 - (p1.total_luts / MAX_LUTS * 100.0),
            )
        else:
            sol.resource_score = 0.0

        # ── Power score ────────────────────────────────────────────────────
        if p1 and p1.satisfiable and p1.total_power >= 0:
            sol.power_score = max(
                0.0,
                100.0 - (p1.total_power / MAX_POWER_MW * 100.0),
            )
        else:
            sol.power_score = 0.0

        # ── Latency score ──────────────────────────────────────────────────
        # The ASP encoding enforces latency as a hard constraint; if Phase 1
        # is SAT then all latency budgets are satisfied.
        sol.latency_score = 100.0 if (p1 and p1.satisfiable) else 0.0

        # ── Resilience score ───────────────────────────────────────────────
        if sol.scenarios:
            sat_sc = [s for s in sol.scenarios if s.satisfiable]
            if sat_sc:
                avg_br = sum(s.max_blast_radius for s in sat_sc) / len(sat_sc)
                sol.resilience_score = max(
                    0.0,
                    100.0 - (avg_br / TOTAL_NODES * 100.0),
                )
            else:
                sol.resilience_score = 0.0
        else:
            sol.resilience_score = 0.0

        # ── Policy coverage score ──────────────────────────────────────────
        if p2 and p2.satisfiable:
            avg_tight = p2.avg_policy_tightness()
            # policy_tightness from ASP is already a 0-100 type metric;
            # treat it directly (or fall back to firewall coverage ratio).
            if avg_tight > 0:
                sol.policy_score = min(100.0, float(avg_tight))
            else:
                # Approximate from placed firewalls vs candidates
                cands = 2  # pep_group, pep_standalone
                placed = len(set(p2.placed_fws))
                sol.policy_score = (placed / cands) * 100.0 if cands else 0.0
        else:
            sol.policy_score = 0.0

    # ------------------------------------------------------------------
    # Convenience: return score dict for one solution
    # ------------------------------------------------------------------

    @staticmethod
    def get_scores(sol: SolutionResult) -> dict:
        """Return a dict of axis-name → score for radar chart use."""
        return {
            "Security":     round(sol.security_score,   1),
            "Resources":    round(sol.resource_score,    1),
            "Power":        round(sol.power_score,       1),
            "Latency":      round(sol.latency_score,     1),
            "Resilience":   round(sol.resilience_score,  1),
            "Policy":       round(sol.policy_score,      1),
        }

    # ------------------------------------------------------------------
    # Cross-solution relative ranks (used by comparison engine)
    # ------------------------------------------------------------------

    def relative_ranks(self) -> dict:
        """
        Return a dict mapping (solution_index, metric) → rank (0=best).
        Allows comparison.py to identify which solution leads each metric.
        """
        metrics = [
            "security_score", "resource_score", "power_score",
            "latency_score", "resilience_score", "policy_score",
        ]
        ranks: dict = {}
        for metric in metrics:
            vals = [(i, getattr(s, metric)) for i, s in enumerate(self.solutions)]
            # Sort descending (higher = better)
            vals_sorted = sorted(vals, key=lambda x: x[1], reverse=True)
            for rank, (idx, _) in enumerate(vals_sorted):
                ranks[(idx, metric)] = rank
        return ranks
