from __future__ import annotations

import os
import unittest

from dse_tool.agents.phase1_mathopt_agent import Phase1MathOptAgent
from dse_tool.agents.phase2_agent import Phase2Agent
from dse_tool.agents.phase3_agent import Phase3Agent, generate_scenarios
from dse_tool.agents.phase3_fast_agent import Phase3FastAgent
from dse_tool.core.asp_generator import (
    ASPGenerator,
    make_pixhawk6x_uav_dual_ps_network,
    make_pixhawk6x_uav_network,
    make_tc9_network,
)
from dse_tool.core.solution_parser import Phase2Result


CLINGO_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "Clingo",
)


class TestPhase3FastParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            import clingo  # noqa: F401
            cls.has_clingo = True
        except ImportError:
            cls.has_clingo = False

        cls.model = make_tc9_network()
        cls.instance_facts = ASPGenerator(cls.model).generate()
        cls.p1 = Phase1MathOptAgent(
            network_model=cls.model,
            strategy="max_security",
            timeout=60,
            solver_config={"cpsat_threads": 1},
        ).run()
        cls.p2 = Phase2Result(
            satisfiable=True,
            optimal=True,
            placed_fws=["pep_group", "pep_standalone"],
            placed_ps=["ps0"],
        )

    def setUp(self) -> None:
        if not self.has_clingo:
            self.skipTest("clingo not available")
        if not self.p1.satisfiable:
            self.skipTest("Phase 1 baseline unavailable")

    def _run_pair(self, scenario: dict):
        asp = Phase3Agent(
            clingo_dir=CLINGO_DIR,
            testcase_lp="",
            phase1_result=self.p1,
            phase2_result=self.p2,
            strategy="max_security",
            timeout=30,
            extra_instance_facts=self.instance_facts,
            solver_config={"clingo_threads": 1},
        ).run(model_scenarios=[scenario])[0]

        fast = Phase3FastAgent(
            network_model=self.model,
            phase1_result=self.p1,
            phase2_result=self.p2,
            strategy="max_security",
            timeout=30,
            extra_instance_facts=self.instance_facts,
            solver_config={"phase3_backend": "python"},
        ).run(model_scenarios=[scenario])[0]
        return asp, fast

    def _assert_core_parity(self, asp, fast) -> None:
        self.assertEqual(fast.total_risk_scaled, asp.total_risk_scaled)
        self.assertEqual(fast.active_ps_count, asp.active_ps_count)
        self.assertEqual(sorted(fast.ungoverned_peps), sorted(asp.ungoverned_peps))
        self.assertEqual(fast.cp_degraded, asp.cp_degraded)
        self.assertEqual(fast.cp_stale, asp.cp_stale)
        self.assertEqual(fast.cp_compromised, asp.cp_compromised)
        self.assertEqual(sorted(fast.services_ok), sorted(asp.services_ok))
        self.assertEqual(sorted(fast.services_degraded), sorted(asp.services_degraded))
        self.assertEqual(sorted(fast.services_unavail), sorted(asp.services_unavail))
        self.assertEqual(sorted(fast.capabilities_ok), sorted(asp.capabilities_ok))
        self.assertEqual(sorted(fast.capabilities_degraded), sorted(asp.capabilities_degraded))
        self.assertEqual(sorted(fast.capabilities_lost), sorted(asp.capabilities_lost))
        self.assertEqual(sorted(fast.essential_caps_lost), sorted(asp.essential_caps_lost))
        self.assertEqual(fast.system_functional, asp.system_functional)
        self.assertEqual(fast.system_degraded, asp.system_degraded)
        self.assertEqual(fast.system_non_functional, asp.system_non_functional)

    def test_baseline_parity(self) -> None:
        asp, fast = self._run_pair({"name": "baseline", "compromised": [], "failed": []})
        self._assert_core_parity(asp, fast)

    def test_ps_compromise_parity(self) -> None:
        asp, fast = self._run_pair({"name": "ps0_compromise", "compromised": ["ps0"], "failed": []})
        self._assert_core_parity(asp, fast)


class TestPhase3FastPixhawkParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            import clingo  # noqa: F401
            cls.has_clingo = True
        except ImportError:
            cls.has_clingo = False

        cls.model = make_pixhawk6x_uav_network()
        cls.instance_facts = ASPGenerator(cls.model).generate()
        cls.p1 = Phase1MathOptAgent(
            network_model=cls.model,
            strategy="max_security",
            timeout=120,
            solver_config={"cpsat_threads": 1},
        ).run()
        cls.p2 = Phase2Result(
            satisfiable=True,
            optimal=True,
            placed_fws=["pep_telem1"],
            placed_ps=["ps_fmu"],
        )

    def setUp(self) -> None:
        if not self.has_clingo:
            self.skipTest("clingo not available")
        if not self.p1.satisfiable:
            self.skipTest("Phase 1 baseline unavailable")

    def _run_pair_map(self, scenarios: list[dict]):
        asp_results = Phase3Agent(
            clingo_dir=CLINGO_DIR,
            testcase_lp="",
            phase1_result=self.p1,
            phase2_result=self.p2,
            strategy="max_security",
            timeout=60,
            extra_instance_facts=self.instance_facts,
            solver_config={"clingo_threads": 1},
        ).run(model_scenarios=scenarios)

        fast_results = Phase3FastAgent(
            network_model=self.model,
            phase1_result=self.p1,
            phase2_result=self.p2,
            strategy="max_security",
            timeout=60,
            extra_instance_facts=self.instance_facts,
            solver_config={"phase3_backend": "python"},
        ).run(model_scenarios=scenarios)
        return (
            {result.name: result for result in asp_results},
            {result.name: result for result in fast_results},
        )

    def _assert_parity(self, asp, fast) -> None:
        self.assertEqual(fast.total_risk_scaled, asp.total_risk_scaled)
        self.assertEqual(sorted(fast.services_ok), sorted(asp.services_ok))
        self.assertEqual(sorted(fast.services_degraded), sorted(asp.services_degraded))
        self.assertEqual(sorted(fast.services_unavail), sorted(asp.services_unavail))
        self.assertEqual(sorted(fast.capabilities_ok), sorted(asp.capabilities_ok))
        self.assertEqual(sorted(fast.capabilities_lost), sorted(asp.capabilities_lost))
        self.assertEqual(sorted(fast.capabilities_degraded), sorted(asp.capabilities_degraded))
        self.assertEqual(sorted(fast.essential_caps_lost), sorted(asp.essential_caps_lost))
        self.assertEqual(fast.active_ps_count, asp.active_ps_count)
        self.assertEqual(sorted(fast.ungoverned_peps), sorted(asp.ungoverned_peps))
        self.assertEqual(fast.cp_degraded, asp.cp_degraded)
        self.assertEqual(fast.cp_stale, asp.cp_stale)
        self.assertEqual(fast.cp_compromised, asp.cp_compromised)
        self.assertEqual(fast.system_functional, asp.system_functional)
        self.assertEqual(fast.system_degraded, asp.system_degraded)
        self.assertEqual(fast.system_non_functional, asp.system_non_functional)

    def test_group_gps_compromise_parity(self) -> None:
        scenarios = [{
            "name": "group_gps_group_compromise",
            "compromised": ["gps_1", "gps_2"],
            "failed": [],
        }]
        asp_map, fast_map = self._run_pair_map(scenarios)
        self._assert_parity(asp_map["group_gps_group_compromise"], fast_map["group_gps_group_compromise"])

    def test_core_scenario_set_parity(self) -> None:
        scenarios = generate_scenarios(self.model, full=False)
        asp_map, fast_map = self._run_pair_map(scenarios)
        for scenario in scenarios:
            name = scenario["name"]
            with self.subTest(scenario=name):
                self._assert_parity(asp_map[name], fast_map[name])

    def test_full_scenario_set_parity(self) -> None:
        scenarios = generate_scenarios(self.model, full=True)
        asp_map, fast_map = self._run_pair_map(scenarios)
        for scenario in scenarios:
            name = scenario["name"]
            with self.subTest(scenario=name):
                self._assert_parity(asp_map[name], fast_map[name])


class TestPhase3FastPixhawkDualPsParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            import clingo  # noqa: F401
            cls.has_clingo = True
        except ImportError:
            cls.has_clingo = False

        cls.model = make_pixhawk6x_uav_dual_ps_network()
        cls.instance_facts = ASPGenerator(cls.model).generate()
        cls.p1 = Phase1MathOptAgent(
            network_model=cls.model,
            strategy="max_security",
            timeout=120,
            solver_config={"cpsat_threads": 1},
        ).run()
        cls.p2 = Phase2Agent(
            clingo_dir=CLINGO_DIR,
            testcase_lp="",
            phase1_result=cls.p1,
            strategy="max_security",
            timeout=60,
            extra_instance_facts=cls.instance_facts,
            solver_config={"clingo_threads": 1},
        ).run()

    def setUp(self) -> None:
        if not self.has_clingo:
            self.skipTest("clingo not available")
        if not self.p1.satisfiable:
            self.skipTest("Phase 1 baseline unavailable")
        if not self.p2.satisfiable:
            self.skipTest("Phase 2 baseline unavailable")

    def _run_pair_map(self, scenarios: list[dict]):
        asp_results = Phase3Agent(
            clingo_dir=CLINGO_DIR,
            testcase_lp="",
            phase1_result=self.p1,
            phase2_result=self.p2,
            strategy="max_security",
            timeout=60,
            extra_instance_facts=self.instance_facts,
            solver_config={"clingo_threads": 1},
        ).run(model_scenarios=scenarios)

        fast_results = Phase3FastAgent(
            network_model=self.model,
            phase1_result=self.p1,
            phase2_result=self.p2,
            strategy="max_security",
            timeout=60,
            extra_instance_facts=self.instance_facts,
            solver_config={"phase3_backend": "python"},
        ).run(model_scenarios=scenarios)
        return (
            {result.name: result for result in asp_results},
            {result.name: result for result in fast_results},
        )

    def _assert_parity(self, asp, fast) -> None:
        self.assertEqual(fast.total_risk_scaled, asp.total_risk_scaled)
        self.assertEqual(sorted(fast.services_ok), sorted(asp.services_ok))
        self.assertEqual(sorted(fast.services_degraded), sorted(asp.services_degraded))
        self.assertEqual(sorted(fast.services_unavail), sorted(asp.services_unavail))
        self.assertEqual(sorted(fast.capabilities_ok), sorted(asp.capabilities_ok))
        self.assertEqual(sorted(fast.capabilities_lost), sorted(asp.capabilities_lost))
        self.assertEqual(sorted(fast.capabilities_degraded), sorted(asp.capabilities_degraded))
        self.assertEqual(sorted(fast.essential_caps_lost), sorted(asp.essential_caps_lost))
        self.assertEqual(fast.active_ps_count, asp.active_ps_count)
        self.assertEqual(sorted(fast.ungoverned_peps), sorted(asp.ungoverned_peps))
        self.assertEqual(fast.cp_degraded, asp.cp_degraded)
        self.assertEqual(fast.cp_stale, asp.cp_stale)
        self.assertEqual(fast.cp_compromised, asp.cp_compromised)
        self.assertEqual(fast.system_functional, asp.system_functional)
        self.assertEqual(fast.system_degraded, asp.system_degraded)
        self.assertEqual(fast.system_non_functional, asp.system_non_functional)

    def test_core_scenario_set_parity(self) -> None:
        scenarios = generate_scenarios(self.model, full=False)
        asp_map, fast_map = self._run_pair_map(scenarios)
        for scenario in scenarios:
            name = scenario["name"]
            with self.subTest(scenario=name):
                self._assert_parity(asp_map[name], fast_map[name])

    def test_full_scenario_set_parity(self) -> None:
        scenarios = generate_scenarios(self.model, full=True)
        asp_map, fast_map = self._run_pair_map(scenarios)
        for scenario in scenarios:
            name = scenario["name"]
            with self.subTest(scenario=name):
                self._assert_parity(asp_map[name], fast_map[name])


if __name__ == "__main__":
    unittest.main()
