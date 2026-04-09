from __future__ import annotations

import unittest
from types import SimpleNamespace

from dse_tool.agents.closed_loop_phase2_agent import ClosedLoopPhase2Agent
from dse_tool.core.solution_parser import Phase1Result, Phase2Result, ScenarioResult


class TestClosedLoopPhase2Agent(unittest.TestCase):
    def _make_agent(self) -> ClosedLoopPhase2Agent:
        model = SimpleNamespace(cand_fws=["fw1", "fw2"], cand_ps=["ps1", "ps2"])
        return ClosedLoopPhase2Agent(
            network_model=model,
            clingo_dir=".",
            testcase_lp="",
            phase1_result=Phase1Result(satisfiable=True),
            strategy="max_security",
            extra_instance_facts="",
        )

    def test_candidate_count_matches_exact_powerset_enumeration(self) -> None:
        agent = self._make_agent()
        candidates = list(agent._iter_candidate_placements())
        self.assertEqual(agent._candidate_count(), 12)
        self.assertEqual(len(candidates), 12)

    def test_score_prioritizes_phase3_risk_before_phase2_cost(self) -> None:
        low_cost = Phase2Result(satisfiable=True, total_cost=1)
        high_cost = Phase2Result(satisfiable=True, total_cost=100)

        worse_risk = [
            ScenarioResult(name="baseline", compromised=[], failed=[], satisfiable=True, total_risk_scaled=200),
        ]
        better_risk = [
            ScenarioResult(name="baseline", compromised=[], failed=[], satisfiable=True, total_risk_scaled=100),
        ]

        worse_score = ClosedLoopPhase2Agent._score_candidate(worse_risk, low_cost)
        better_score = ClosedLoopPhase2Agent._score_candidate(better_risk, high_cost)

        self.assertLess(better_score, worse_score)


if __name__ == "__main__":
    unittest.main()
