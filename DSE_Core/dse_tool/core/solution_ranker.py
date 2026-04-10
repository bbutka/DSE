"""
solution_ranker.py
==================
Computes normalised 0-100 scores for each SolutionResult across six axes
(Security, Resources, Power, Latency, Resilience, Policy Coverage) used in
the radar charts and metric tables.
"""

from __future__ import annotations

from typing import List, Optional

from ip_catalog.xilinx_ip_catalog import PHASE1_INTERNAL_RISK_SCALE
from .solution_parser import SolutionResult


# ---------------------------------------------------------------------------
# Constants (PYNQ-Z2 maxima, mirroring tgt_system_tc9_inst.lp)
# ---------------------------------------------------------------------------

MAX_LUTS          = 53_200
MAX_FFS           = 106_400
MAX_POWER_MW      = 15_000
# Normalisation ceiling for risk score.
# Under the multiplicative model, Phase 1 now uses internal milli-risk units.
# Preserve the pre-scaling GUI headroom by applying the same internal scale.
MAX_RISK_POSSIBLE = 3000 * PHASE1_INTERNAL_RISK_SCALE

# CIA weighting for the composite security score.
# Integrity and Availability are weighted higher than Confidentiality
# for embedded/safety-critical SoC systems: a write or DoS attack has
# more immediate physical consequences than a read.
CIA_WEIGHTS = {"read": 1.0, "write": 1.5, "avail": 2.0}


class SolutionRanker:
    """
    Normalises SolutionResult metrics and populates score fields.

    Usage
    -----
    ranker = SolutionRanker(solutions)
    ranker.rank()
    # After rank(), each SolutionResult has .security_score etc. populated.
    """

    def __init__(
        self,
        solutions: List[SolutionResult],
        max_luts: int = 0,
        max_power: int = 0,
    ) -> None:
        self.solutions = solutions
        # Use topology-specific caps if provided, else fall back to defaults
        self._max_luts  = max_luts  if max_luts  > 0 else MAX_LUTS
        self._max_power = max_power if max_power > 0 else MAX_POWER_MW

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

        # ── Security score (CIA-weighted) ──────────────────────────────────
        # Uses per-action risk when available (from security_risk
        # and avail_risk) with CIA_WEIGHTS to reflect impact severity.
        # Falls back to the weighted Phase 1 objective when action-level data
        # is absent.
        if p1 and p1.satisfiable:
            cia_risk = self._cia_weighted_risk(p1)
            if cia_risk > 0:
                sol.security_score = max(0.0, 100.0 - (cia_risk / MAX_RISK_POSSIBLE * 100.0))
            elif p1.total_risk() > 0:
                sol.security_score = max(0.0, 100.0 - (p1.total_risk() / MAX_RISK_POSSIBLE * 100.0))
            else:
                sol.security_score = 0.0
            # Store CIA sub-scores on the solution for display
            sol.cia_scores = self._cia_subscores(p1)
        else:
            sol.security_score = 0.0
            sol.cia_scores = {"C": 0.0, "I": 0.0, "A": 0.0}

        # ── Resource score ─────────────────────────────────────────────────
        if p1 and p1.satisfiable and p1.total_luts >= 0:
            sol.resource_score = max(
                0.0,
                100.0 - (p1.total_luts / self._max_luts * 100.0),
            )
        else:
            sol.resource_score = 0.0

        # ── Power score ────────────────────────────────────────────────────
        if p1 and p1.satisfiable and p1.total_power >= 0:
            sol.power_score = max(
                0.0,
                100.0 - (p1.total_power / self._max_power * 100.0),
            )
        else:
            sol.power_score = 0.0

        # ── Latency score ──────────────────────────────────────────────────
        # The ASP encoding enforces latency as a hard constraint; if Phase 1
        # is SAT then all latency budgets are satisfied.
        sol.latency_score = 100.0 if (p1 and p1.satisfiable) else 0.0

        # ── Resilience score ───────────────────────────────────────────────
        # Combines blast radius (40%), capability retention (40%),
        # and control plane health (20%) for a holistic resilience picture.
        if sol.scenarios:
            sat_sc = [s for s in sol.scenarios if s.satisfiable]
            if sat_sc:
                total_nodes = max(len(sat_sc[0].blast_radii), 1)
                # Sub-score 1: Blast radius (lower is better)
                avg_br = sum(s.max_blast_radius for s in sat_sc) / len(sat_sc)
                br_score = max(0.0, 100.0 - (avg_br / total_nodes * 100.0))

                # Sub-score 2: Capability retention (higher is better)
                cap_scores: list = []
                for s in sat_sc:
                    total_caps = (len(s.capabilities_ok)
                                  + len(s.capabilities_degraded)
                                  + len(s.capabilities_lost))
                    if total_caps > 0:
                        # OK = full credit, degraded = half, lost = 0
                        retained = ((len(s.capabilities_ok)
                                     + 0.5 * len(s.capabilities_degraded))
                                    / total_caps)
                        # Essential capabilities lost tanks the score
                        if s.essential_caps_lost:
                            retained *= 0.25
                        cap_scores.append(retained * 100.0)
                # If no capability data, treat as neutral (100)
                cap_score = (sum(cap_scores) / len(cap_scores)
                             if cap_scores else 100.0)

                # Sub-score 3: Control plane health
                cp_scores: list = []
                for s in sat_sc:
                    cp = 100.0
                    if s.cp_compromised:
                        cp = 0.0
                    elif s.cp_degraded:
                        cp = 40.0
                    elif s.cp_stale:
                        cp = 60.0
                    cp_scores.append(cp)
                cp_score = (sum(cp_scores) / len(cp_scores)
                            if cp_scores else 100.0)

                # Tool-internal composite for GUI strategy comparison.
                # Not defined in the paper; the paper uses β_S, β_E,
                # α, and capability-loss counts as its resilience metrics.
                sol.resilience_score = (0.4 * br_score
                                        + 0.4 * cap_score
                                        + 0.2 * cp_score)
            else:
                sol.resilience_score = 0.0
        else:
            sol.resilience_score = 0.0

        # ── Policy coverage score ──────────────────────────────────────────
        if p2 and p2.satisfiable:
            if p2.effective_policy_tightness:
                sol.policy_score = min(
                    100.0,
                    float(p2.avg_effective_policy_tightness(mode="normal")),
                )
            else:
                avg_tight = p2.avg_policy_tightness()
                # policy_tightness from ASP is already a 0-100 type metric;
                # treat it directly (or fall back to composite heuristic).
                if avg_tight > 0:
                    sol.policy_score = min(100.0, float(avg_tight))
                else:
                    # Composite heuristic when tightness atoms are absent:
                    #   - FW coverage: proportion of placed vs total candidate FWs
                    #   - Excess penalty: each excess privilege costs 2 points
                    #   - Trust gap penalty: each missing anchor costs 3 points
                    placed = len(set(p2.placed_fws))
                    # Estimate total candidates from the union of all placed FWs
                    # across all solutions (the superset approximates cand_fws)
                    all_fws: set = set()
                    for other in self.solutions:
                        if other.phase2 and other.phase2.satisfiable:
                            all_fws.update(other.phase2.placed_fws)
                    total_cands = max(len(all_fws), placed, 1)
                    fw_ratio = placed / total_cands if total_cands > 0 else 0
                    excess_penalty = min(30.0, len(p2.excess_privileges) * 2.0)
                    gap_penalty = min(20.0, (
                        len(p2.trust_gap_rot)
                        + len(p2.trust_gap_sboot)
                        + len(p2.trust_gap_attest)
                    ) * 3.0)
                    sol.policy_score = max(0.0, min(100.0,
                        fw_ratio * 50.0 + 50.0 - excess_penalty - gap_penalty
                    ))
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
    # CIA helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _cia_weighted_risk(p1) -> float:
        """
        Compute CIA-weighted total risk from per-action risk data.

        Uses security_risk and avail_risk when available;
        falls back to new_risk.  Applies CIA_WEIGHTS per action type.
        """
        # Prefer typed risk lists (security_risk + avail_risk)
        all_entries = list(p1.security_risk) + list(p1.avail_risk)
        if not all_entries:
            all_entries = list(p1.new_risk)
        if not all_entries:
            return 0.0

        # Sum weighted risk across all (comp, asset, action, risk) entries
        total = 0.0
        for _comp, _asset, action, risk in all_entries:
            w = CIA_WEIGHTS.get(action, 1.0)
            total += risk * w
        return total

    @staticmethod
    def _cia_subscores(p1) -> dict:
        """
        Return per-CIA-dimension total risk for display.
        Keys: "C" (read), "I" (write), "A" (avail).
        """
        subscores = {"C": 0, "I": 0, "A": 0}
        all_entries = list(p1.security_risk) + list(p1.avail_risk)
        if not all_entries:
            all_entries = list(p1.new_risk)
        action_map = {"read": "C", "write": "I", "avail": "A"}
        for _comp, _asset, action, risk in all_entries:
            dim = action_map.get(action)
            if dim:
                subscores[dim] += risk
        return subscores

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
