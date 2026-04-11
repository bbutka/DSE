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

    def test_collects_structured_function_deficiencies_without_changing_score(self) -> None:
        p2 = Phase2Result(satisfiable=True, total_cost=10)
        scenarios = [
            ScenarioResult(
                name="sensor_bus_failure",
                compromised=[],
                failed=["sensor_bus"],
                failed_buses=["sensor_bus"],
                satisfiable=True,
                total_risk_scaled=100,
                function_scores={"state_estimation": 0},
                function_statuses={"state_estimation": "lost"},
                functions_lost=["state_estimation"],
                function_findings=[
                    "state_estimation_lacks_bus_diversity",
                    "state_estimation_lost_under_bus_failure",
                ],
            )
        ]

        deficiencies = ClosedLoopPhase2Agent._collect_function_deficiencies(scenarios)
        p2.closed_loop_function_deficiencies = deficiencies
        p2.closed_loop_repair_intents = ClosedLoopPhase2Agent._propose_repair_intents(deficiencies)

        self.assertEqual(
            p2.closed_loop_function_deficiencies,
            [
                {
                    "function": "state_estimation",
                    "issue": "lacks_bus_diversity",
                    "finding": "state_estimation_lacks_bus_diversity",
                    "scenario": "sensor_bus_failure",
                    "status": "lost",
                    "score": 0,
                    "failed_domain": "bus",
                    "failed_domain_values": [],
                },
                {
                    "function": "state_estimation",
                    "issue": "lost_under_domain_failure",
                    "finding": "state_estimation_lost_under_bus_failure",
                    "scenario": "sensor_bus_failure",
                    "status": "lost",
                    "score": 0,
                    "failed_domain": "bus",
                    "failed_domain_values": ["sensor_bus"],
                },
            ],
        )
        self.assertEqual(
            p2.closed_loop_repair_intents,
            [
                {
                    "stage": "architecture_generation",
                    "status": "pending_architecture_revision",
                    "function": "state_estimation",
                    "repair": "split_function_support_buses",
                    "required_diversity_axis": "bus",
                    "minimum_independent_domains": 2,
                    "source_finding": "state_estimation_lacks_bus_diversity",
                    "source_scenario": "sensor_bus_failure",
                    "rationale": (
                        "State-estimation supports lose fallback quality under bus-domain failure; "
                        "revise the architecture so supporting modalities are not all carried by the same bus."
                    ),
                }
            ],
        )
        self.assertEqual(
            ClosedLoopPhase2Agent._score_candidate(scenarios, p2),
            (0, 100, 0, 0, 100, 10),
        )

    def test_repair_intents_ignore_non_bus_deficiencies(self) -> None:
        deficiencies = [
            {
                "function": "state_estimation",
                "issue": "lacks_modality_diversity",
                "finding": "state_estimation_lacks_modality_diversity",
                "scenario": "modality_satellite_failure",
                "status": "lost",
                "score": 0,
                "failed_domain": "modality",
                "failed_domain_values": ["satellite"],
            }
        ]

        self.assertEqual(ClosedLoopPhase2Agent._propose_repair_intents(deficiencies), [])


if __name__ == "__main__":
    unittest.main()
