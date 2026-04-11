from __future__ import annotations

import copy
import os
import unittest

from dse_tool.agents.phase1_mathopt_agent import Phase1MathOptAgent
from dse_tool.agents.phase2_agent import Phase2Agent
from dse_tool.agents.phase3_agent import Phase3Agent, generate_scenarios
from dse_tool.agents.phase3_fast_agent import Phase3FastAgent
from dse_tool.core.asp_generator import (
    ASPGenerator,
    Component,
    FunctionSupport,
    NetworkModel,
    make_pixhawk6x_uav_dual_ps_network,
    make_pixhawk6x_uav_network,
    make_tc9_network,
)
from dse_tool.core.solution_parser import Phase1Result, Phase2Result


CLINGO_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "Clingo",
)


class TestPhase3FunctionSupportSemantics(unittest.TestCase):
    def _make_model(self, supports: list[FunctionSupport]) -> NetworkModel:
        component_names = sorted({support.component for support in supports})
        support_buses = sorted({support.bus for support in supports if support.bus})
        components = [
            Component(
                "fmu", "processor", "privileged", 1, 1, 1000, 1000,
                is_master=True, is_receiver=False,
            )
        ]
        for name in component_names:
            components.append(
                Component(
                    name, "ip_core", "normal", 1, 1, 1000, 1000,
                    direction="input",
                )
            )
        for bus in support_buses:
            components.append(
                Component(
                    bus, "bus", "normal", 1, 1, 1000, 1000,
                    is_receiver=False,
                )
            )
        bus_by_component = {
            support.component: support.bus
            for support in supports
            if support.bus
        }
        links = []
        for name in component_names:
            bus = bus_by_component.get(name, "")
            if bus:
                links.append(("fmu", bus))
                links.append((bus, name))
            else:
                links.append(("fmu", name))
        return NetworkModel(
            name="function_support_fixture",
            components=components,
            links=links,
            buses=support_buses,
            function_supports=supports,
            function_thresholds={"state_estimation": {"ok": 80, "degraded": 50}},
        )

    def _run(self, supports: list[FunctionSupport], scenario: dict):
        model = self._make_model(supports)
        return Phase3FastAgent(
            network_model=model,
            phase1_result=Phase1Result(satisfiable=True),
            phase2_result=Phase2Result(satisfiable=True),
            strategy="max_security",
            timeout=30,
            solver_config={"phase3_backend": "python"},
        ).run(model_scenarios=[scenario])[0]

    def test_gps_only_satellite_failure_loses_state_estimation(self) -> None:
        result = self._run(
            [FunctionSupport("state_estimation", "gps_1", "satellite", 90)],
            {"name": "satellite_loss", "compromised": [], "failed": [], "failed_modalities": ["satellite"]},
        )

        self.assertEqual(result.function_scores["state_estimation"], 0)
        self.assertEqual(result.function_statuses["state_estimation"], "lost")
        self.assertIn("state_estimation", result.functions_lost)
        self.assertIn("state_estimation_lost_under_satellite_failure", result.function_findings)
        self.assertIn("state_estimation_lacks_modality_diversity", result.function_findings)
        self.assertIn("state_estimation_fallback_below_degraded_threshold", result.function_findings)

    def test_mixed_modalities_degrade_after_satellite_failure(self) -> None:
        result = self._run(
            [
                FunctionSupport("state_estimation", "gps_1", "satellite", 90),
                FunctionSupport("state_estimation", "imu_1", "inertial", 70),
                FunctionSupport("state_estimation", "baro_1", "pressure", 40),
            ],
            {"name": "satellite_loss", "compromised": [], "failed": [], "failed_modalities": ["satellite"]},
        )

        self.assertEqual(result.function_scores["state_estimation"], 70)
        self.assertEqual(result.function_statuses["state_estimation"], "degraded")
        self.assertIn("state_estimation", result.functions_degraded)
        self.assertNotIn("state_estimation_lost_under_satellite_failure", result.function_findings)
        self.assertNotIn("state_estimation_lacks_modality_diversity", result.function_findings)
        self.assertNotIn("state_estimation_fallback_below_degraded_threshold", result.function_findings)

    def test_same_modality_duplication_loses_under_modality_failure(self) -> None:
        result = self._run(
            [
                FunctionSupport("state_estimation", "gps_1", "satellite", 90),
                FunctionSupport("state_estimation", "gps_2", "satellite", 88),
            ],
            {"name": "satellite_loss", "compromised": [], "failed": [], "failed_modalities": ["satellite"]},
        )

        self.assertEqual(result.function_scores["state_estimation"], 0)
        self.assertEqual(result.function_statuses["state_estimation"], "lost")
        self.assertIn("state_estimation", result.functions_lost)
        self.assertIn("state_estimation_lost_under_satellite_failure", result.function_findings)
        self.assertIn("state_estimation_lacks_modality_diversity", result.function_findings)
        self.assertIn("state_estimation_fallback_below_degraded_threshold", result.function_findings)

    def test_gps_imu_mixed_modality_survives_satellite_failure(self) -> None:
        result = self._run(
            [
                FunctionSupport("state_estimation", "gps_1", "satellite", 90),
                FunctionSupport("state_estimation", "imu_1", "inertial", 70),
            ],
            {"name": "satellite_loss", "compromised": [], "failed": [], "failed_modalities": ["satellite"]},
        )

        self.assertEqual(result.function_scores["state_estimation"], 70)
        self.assertEqual(result.function_statuses["state_estimation"], "degraded")
        self.assertIn("state_estimation", result.functions_degraded)

    def test_auto_generates_modality_failure_scenarios_for_opt_in_models(self) -> None:
        model = self._make_model([
            FunctionSupport("state_estimation", "gps_1", "satellite", 90),
            FunctionSupport("state_estimation", "imu_1", "inertial", 70),
        ])

        scenarios = generate_scenarios(model, full=False)

        self.assertIn("modality_satellite_failure", {scenario["name"] for scenario in scenarios})
        satellite = next(s for s in scenarios if s["name"] == "modality_satellite_failure")
        self.assertEqual(satellite["failed_modalities"], ["satellite"])

    def test_shared_bus_failure_loses_mixed_modality_supports(self) -> None:
        result = self._run(
            [
                FunctionSupport("state_estimation", "gps_1", "satellite", 90, bus="sensor_bus"),
                FunctionSupport("state_estimation", "imu_1", "inertial", 70, bus="sensor_bus"),
                FunctionSupport("state_estimation", "baro_1", "pressure", 40, bus="sensor_bus"),
            ],
            {"name": "sensor_bus_failure", "compromised": [], "failed": ["sensor_bus"]},
        )

        self.assertEqual(result.function_scores["state_estimation"], 0)
        self.assertEqual(result.function_statuses["state_estimation"], "lost")
        self.assertIn("state_estimation", result.functions_lost)
        self.assertIn("state_estimation_lacks_bus_diversity", result.function_findings)
        self.assertIn("state_estimation_lost_under_bus_failure", result.function_findings)
        self.assertIn("state_estimation_bus_fallback_below_degraded_threshold", result.function_findings)
        lost = next(
            deficiency for deficiency in result.function_deficiencies
            if deficiency["finding"] == "state_estimation_lost_under_bus_failure"
        )
        self.assertEqual(lost["function"], "state_estimation")
        self.assertEqual(lost["issue"], "lost_under_domain_failure")
        self.assertEqual(lost["status"], "lost")
        self.assertEqual(lost["score"], 0)
        self.assertEqual(lost["failed_domain"], "bus")
        self.assertEqual(lost["failed_domain_values"], ["sensor_bus"])
        fallback = next(
            deficiency for deficiency in result.function_deficiencies
            if deficiency["finding"] == "state_estimation_bus_fallback_below_degraded_threshold"
        )
        self.assertEqual(fallback["function"], "state_estimation")
        self.assertEqual(fallback["issue"], "fallback_below_degraded_threshold")
        self.assertEqual(fallback["failed_domain"], "bus")
        self.assertEqual(fallback["failed_domain_values"], ["sensor_bus"])

    def test_split_bus_failure_degrades_but_preserves_state_estimation(self) -> None:
        result = self._run(
            [
                FunctionSupport("state_estimation", "gps_1", "satellite", 90, bus="gps_bus"),
                FunctionSupport("state_estimation", "imu_1", "inertial", 70, bus="imu_bus"),
                FunctionSupport("state_estimation", "baro_1", "pressure", 40, bus="baro_bus"),
            ],
            {"name": "gps_bus_failure", "compromised": [], "failed": ["gps_bus"]},
        )

        self.assertEqual(result.function_scores["state_estimation"], 70)
        self.assertEqual(result.function_statuses["state_estimation"], "degraded")
        self.assertIn("state_estimation", result.functions_degraded)
        self.assertNotIn("state_estimation_lacks_bus_diversity", result.function_findings)
        self.assertNotIn("state_estimation_lost_under_bus_failure", result.function_findings)
        self.assertNotIn("state_estimation_bus_fallback_below_degraded_threshold", result.function_findings)
        self.assertEqual(result.failed_buses, ["gps_bus"])


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

    def test_python_direct_run_auto_generates_scenarios(self) -> None:
        results = Phase3FastAgent(
            network_model=self.model,
            phase1_result=self.p1,
            phase2_result=self.p2,
            strategy="max_security",
            timeout=30,
            extra_instance_facts=self.instance_facts,
            solver_config={"phase3_backend": "python"},
        ).run()
        self.assertGreater(len(results), 1)

    def test_asp_direct_run_auto_generates_scenarios(self) -> None:
        results = Phase3Agent(
            clingo_dir=CLINGO_DIR,
            testcase_lp="",
            phase1_result=self.p1,
            phase2_result=self.p2,
            network_model=self.model,
            strategy="max_security",
            timeout=30,
            extra_instance_facts=self.instance_facts,
            solver_config={"clingo_threads": 1},
        ).run()
        self.assertGreater(len(results), 1)

    def test_assume_all_cp_active_matches_asp(self) -> None:
        model = copy.deepcopy(self.model)
        model.system_caps["assume_all_cp_active"] = 1
        facts = ASPGenerator(model).generate()
        empty_p2 = Phase2Result(satisfiable=False)
        scenario = {"name": "baseline", "compromised": [], "failed": []}

        asp = Phase3Agent(
            clingo_dir=CLINGO_DIR,
            testcase_lp="",
            phase1_result=self.p1,
            phase2_result=empty_p2,
            network_model=model,
            strategy="max_security",
            timeout=30,
            extra_instance_facts=facts,
            solver_config={"clingo_threads": 1},
        ).run(model_scenarios=[scenario])[0]

        fast = Phase3FastAgent(
            network_model=model,
            phase1_result=self.p1,
            phase2_result=empty_p2,
            strategy="max_security",
            timeout=30,
            extra_instance_facts=facts,
            solver_config={"phase3_backend": "python"},
        ).run(model_scenarios=[scenario])[0]

        self.assertEqual(fast.active_ps_count, asp.active_ps_count)
        self.assertEqual(sorted(fast.ungoverned_peps), sorted(asp.ungoverned_peps))


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
