"""
Golden baseline comparison tests.

Fast path:
  - always checks the max_security strategy for tc9 and DARPA UAV
  - checks OpenTitan OT-A/OT-B/OT-C Phase 1 baselines

Slow path:
  - checks balanced and min_resources against the checked-in fixtures
  - enabled only when DSE_RUN_SLOW_GOLDEN=1 because min_resources can take
    on the order of an hour on tc9
"""
from __future__ import annotations

import json
import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLINGO_DIR = os.path.join(PROJECT_ROOT, "Clingo")
TESTCASE_LP = os.path.join(CLINGO_DIR, "tgt_system_tc9_inst.lp")
DARPA_LP = os.path.join(CLINGO_DIR, "tgt_system_darpa_uav_inst.lp")
FIXTURES_DIR = os.path.join(PROJECT_ROOT, "tests", "fixtures")

RUN_SLOW_GOLDEN = os.environ.get("DSE_RUN_SLOW_GOLDEN") == "1"
FAST_TIMEOUT = int(os.environ.get("DSE_GOLDEN_TIMEOUT", "60"))
SLOW_TIMEOUT = int(os.environ.get("DSE_SLOW_GOLDEN_TIMEOUT", "4800"))
FAST_STRATEGIES = ("max_security",)
SLOW_STRATEGIES = ("balanced", "min_resources")
DETERMINISTIC_CLINGO = {
    "clingo_threads": 1,
}
DETERMINISTIC_MATHOPT = {
    "phase1_backend": "cpsat",
    "ilp_solver": "cpsat",
    "cpsat_threads": 1,
}

sys.path.insert(0, PROJECT_ROOT)

from dse_tool.agents.phase1_mathopt_agent import Phase1MathOptAgent
from dse_tool.agents.phase1_agent import Phase1Agent
from dse_tool.agents.phase2_agent import Phase2Agent
from dse_tool.agents.phase3_agent import Phase3Agent, generate_scenarios
from dse_tool.core.asp_generator import (
    ASPGenerator,
    make_opentitan_network,
    make_pixhawk6x_uav_network,
    make_tc9_network,
)

_TC9_MODEL = make_tc9_network()
_TC9_FACTS = ASPGenerator(_TC9_MODEL).generate()
_TC9_SCENARIOS = generate_scenarios(_TC9_MODEL, full=True)
_PIXHAWK_MODEL = make_pixhawk6x_uav_network()
_PIXHAWK_FACTS = ASPGenerator(_PIXHAWK_MODEL).generate()
_PIXHAWK_SCENARIOS = generate_scenarios(_PIXHAWK_MODEL, full=True)


def _load_fixture(name: str) -> dict:
    with open(os.path.join(FIXTURES_DIR, name), encoding="utf-8") as handle:
        return json.load(handle)


def _run_tc9_pipeline(strategy: str, timeout: int):
    p1 = Phase1Agent(
        clingo_dir=CLINGO_DIR,
        testcase_lp=TESTCASE_LP,
        strategy=strategy,
        extra_instance_facts=_TC9_FACTS,
        timeout=timeout,
        solver_config=DETERMINISTIC_CLINGO,
    ).run()

    p2 = Phase2Agent(
        clingo_dir=CLINGO_DIR,
        testcase_lp=TESTCASE_LP,
        phase1_result=p1,
        strategy=strategy,
        extra_instance_facts=_TC9_FACTS,
        timeout=timeout,
        solver_config=DETERMINISTIC_CLINGO,
    ).run()

    p3 = Phase3Agent(
        clingo_dir=CLINGO_DIR,
        testcase_lp=TESTCASE_LP,
        phase1_result=p1,
        phase2_result=p2,
        strategy=strategy,
        timeout=timeout,
        full_scenarios=True,
        extra_instance_facts=_TC9_FACTS,
        solver_config=DETERMINISTIC_CLINGO,
    ).run(model_scenarios=_TC9_SCENARIOS)

    return p1, p2, p3


def _run_darpa_pipeline(strategy: str, timeout: int):
    p1 = Phase1Agent(
        clingo_dir=CLINGO_DIR,
        testcase_lp=DARPA_LP,
        strategy=strategy,
        timeout=timeout,
        solver_config=DETERMINISTIC_CLINGO,
    ).run()

    p2 = Phase2Agent(
        clingo_dir=CLINGO_DIR,
        testcase_lp=DARPA_LP,
        phase1_result=p1,
        strategy=strategy,
        timeout=timeout,
        solver_config=DETERMINISTIC_CLINGO,
    ).run()

    p3 = Phase3Agent(
        clingo_dir=CLINGO_DIR,
        testcase_lp=DARPA_LP,
        phase1_result=p1,
        phase2_result=p2,
        strategy=strategy,
        timeout=timeout,
        solver_config=DETERMINISTIC_CLINGO,
    ).run()

    return p1, p2, p3


def _run_opentitan_phase1(profile: str, timeout: int):
    model = make_opentitan_network(profile)
    p1 = Phase1MathOptAgent(
        network_model=model,
        strategy="max_security",
        timeout=timeout,
        solver_config=DETERMINISTIC_MATHOPT,
    ).run()
    return p1


def _run_pixhawk_pipeline(strategy: str, timeout: int):
    p1 = Phase1MathOptAgent(
        network_model=_PIXHAWK_MODEL,
        strategy=strategy,
        timeout=timeout,
        solver_config=DETERMINISTIC_MATHOPT,
    ).run()

    p2 = Phase2Agent(
        clingo_dir=CLINGO_DIR,
        testcase_lp="",
        phase1_result=p1,
        strategy=strategy,
        extra_instance_facts=_PIXHAWK_FACTS,
        timeout=timeout,
        solver_config=DETERMINISTIC_CLINGO,
    ).run()

    p3 = Phase3Agent(
        clingo_dir=CLINGO_DIR,
        testcase_lp="",
        phase1_result=p1,
        phase2_result=p2,
        strategy=strategy,
        timeout=timeout,
        full_scenarios=True,
        extra_instance_facts=_PIXHAWK_FACTS,
        solver_config=DETERMINISTIC_CLINGO,
    ).run(model_scenarios=_PIXHAWK_SCENARIOS)

    return p1, p2, p3


def _worst_case_risk_scaled(results) -> int:
    return max((r.total_risk_scaled for r in results if r.satisfiable), default=0)


class TestGoldenFixtureShape(unittest.TestCase):
    def test_tc9_fixture_has_all_three_strategies(self):
        fixture = _load_fixture("tc9_baseline.json")
        self.assertEqual(
            {"max_security", "min_resources", "balanced"},
            {key for key in fixture.keys() if key != "description"},
        )

    def test_darpa_fixture_has_all_three_strategies(self):
        fixture = _load_fixture("darpa_uav_baseline.json")
        self.assertEqual(
            {"max_security", "min_resources", "balanced"},
            {key for key in fixture.keys() if key != "description"},
        )

    def test_opentitan_fixture_has_all_three_profiles(self):
        fixture = _load_fixture("opentitan_phase1_baseline.json")
        self.assertEqual({"OT-A", "OT-B", "OT-C"}, {key for key in fixture.keys() if key != "description"})

    def test_pixhawk_fixture_has_all_three_strategies(self):
        fixture = _load_fixture("pixhawk6x_baseline.json")
        self.assertEqual(
            {"max_security", "min_resources", "balanced"},
            {key for key in fixture.keys() if key != "description"},
        )


class _GoldenAssertions:
    def assert_tc9_matches_fixture(self, strategy: str, expected: dict, actual):
        p1, p2, p3 = actual
        self.assertEqual(p1.satisfiable, expected["satisfiable"])
        self.assertEqual(p1.total_risk(), expected["total_risk"])
        self.assertEqual(p1.total_luts, expected["total_luts"])
        self.assertEqual(p1.total_power, expected["total_power"])
        self.assertEqual(p2.satisfiable, expected["phase2_satisfiable"])
        self.assertEqual(sorted(set(p2.placed_fws)), sorted(expected["placed_fws"]))
        self.assertEqual(sorted(set(p2.placed_ps)), sorted(expected["placed_ps"]))
        self.assertEqual(len(p3), expected["phase3_scenario_count"])
        self.assertEqual(_worst_case_risk_scaled(p3), expected["phase3_worst_case_risk_scaled"])

    def assert_darpa_matches_fixture(self, strategy: str, expected: dict, actual):
        p1, p2, p3 = actual
        self.assertEqual(p1.satisfiable, expected["satisfiable"])
        self.assertEqual(p1.total_risk(), expected["total_risk"])
        self.assertEqual(p1.total_luts, expected["total_luts"])
        self.assertEqual(p1.total_power, expected["total_power"])
        self.assertEqual(p2.satisfiable, expected["phase2_satisfiable"])
        self.assertEqual(sorted(set(p2.placed_fws)), sorted(expected["placed_fws"]))
        self.assertEqual(sorted(set(p2.placed_ps)), sorted(expected["placed_ps"]))
        self.assertEqual(len(p3), expected["phase3_scenario_count"])
        self.assertEqual(_worst_case_risk_scaled(p3), expected["phase3_worst_case_risk_scaled"])

    def assert_pixhawk_matches_fixture(self, strategy: str, expected: dict, actual):
        p1, p2, p3 = actual
        self.assertEqual(p1.satisfiable, expected["satisfiable"])
        self.assertEqual(p1.total_risk(), expected["total_risk"])
        self.assertEqual(p1.total_luts, expected["total_luts"])
        self.assertEqual(p1.total_power, expected["total_power"])
        self.assertEqual(p2.satisfiable, expected["phase2_satisfiable"])
        self.assertEqual(sorted(set(p2.placed_fws)), sorted(expected["placed_fws"]))
        self.assertEqual(sorted(set(p2.placed_ps)), sorted(expected["placed_ps"]))
        self.assertEqual(len(p3), expected["phase3_scenario_count"])
        self.assertEqual(_worst_case_risk_scaled(p3), expected["phase3_worst_case_risk_scaled"])


class TestTC9GoldenBaselineFast(unittest.TestCase, _GoldenAssertions):
    @classmethod
    def setUpClass(cls):
        cls.expected = _load_fixture("tc9_baseline.json")
        cls.actual = {
            strategy: _run_tc9_pipeline(strategy, FAST_TIMEOUT)
            for strategy in FAST_STRATEGIES
        }

    def test_fast_strategies_match(self):
        for strategy in FAST_STRATEGIES:
            with self.subTest(strategy=strategy):
                self.assert_tc9_matches_fixture(
                    strategy,
                    self.expected[strategy],
                    self.actual[strategy],
                )


@unittest.skipUnless(
    RUN_SLOW_GOLDEN,
    "Set DSE_RUN_SLOW_GOLDEN=1 to run balanced/min_resources golden baselines.",
)
class TestTC9GoldenBaselineSlow(unittest.TestCase, _GoldenAssertions):
    @classmethod
    def setUpClass(cls):
        cls.expected = _load_fixture("tc9_baseline.json")
        cls.actual = {
            strategy: _run_tc9_pipeline(strategy, SLOW_TIMEOUT)
            for strategy in SLOW_STRATEGIES
        }

    def test_slow_strategies_match(self):
        for strategy in SLOW_STRATEGIES:
            with self.subTest(strategy=strategy):
                self.assert_tc9_matches_fixture(
                    strategy,
                    self.expected[strategy],
                    self.actual[strategy],
                )


@unittest.skipUnless(
    os.path.isfile(DARPA_LP),
    "DARPA UAV instance file not present",
)
class TestDarpaUAVGoldenBaselineFast(unittest.TestCase, _GoldenAssertions):
    @classmethod
    def setUpClass(cls):
        cls.expected = _load_fixture("darpa_uav_baseline.json")
        cls.actual = {
            strategy: _run_darpa_pipeline(strategy, FAST_TIMEOUT)
            for strategy in FAST_STRATEGIES
        }

    def test_fast_strategies_match(self):
        for strategy in FAST_STRATEGIES:
            with self.subTest(strategy=strategy):
                self.assert_darpa_matches_fixture(
                    strategy,
                    self.expected[strategy],
                    self.actual[strategy],
                )


class TestOpenTitanPhase1GoldenBaselines(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = _load_fixture("opentitan_phase1_baseline.json")
        cls.actual = {
            profile: _run_opentitan_phase1(profile, FAST_TIMEOUT)
            for profile in ("OT-A", "OT-B", "OT-C")
        }

    def test_profiles_match(self):
        for profile in ("OT-A", "OT-B", "OT-C"):
            with self.subTest(profile=profile):
                expected = self.expected[profile]
                p1 = self.actual[profile]
                self.assertEqual(p1.satisfiable, expected["satisfiable"])
                self.assertEqual(p1.total_risk(), expected["total_risk"])
                self.assertEqual(p1.total_luts, expected["total_luts"])
                self.assertEqual(p1.total_power, expected["total_power"])


class TestPixhawk6XGoldenBaselineFast(unittest.TestCase, _GoldenAssertions):
    @classmethod
    def setUpClass(cls):
        cls.expected = _load_fixture("pixhawk6x_baseline.json")
        cls.actual = {
            strategy: _run_pixhawk_pipeline(strategy, FAST_TIMEOUT)
            for strategy in FAST_STRATEGIES
        }

    def test_fast_strategies_match(self):
        for strategy in FAST_STRATEGIES:
            with self.subTest(strategy=strategy):
                self.assert_pixhawk_matches_fixture(
                    strategy,
                    self.expected[strategy],
                    self.actual[strategy],
                )


@unittest.skipUnless(
    RUN_SLOW_GOLDEN,
    "Set DSE_RUN_SLOW_GOLDEN=1 to run balanced/min_resources Pixhawk golden baselines.",
)
class TestPixhawk6XGoldenBaselineSlow(unittest.TestCase, _GoldenAssertions):
    @classmethod
    def setUpClass(cls):
        cls.expected = _load_fixture("pixhawk6x_baseline.json")
        cls.actual = {
            strategy: _run_pixhawk_pipeline(strategy, SLOW_TIMEOUT)
            for strategy in SLOW_STRATEGIES
        }

    def test_slow_strategies_match(self):
        for strategy in SLOW_STRATEGIES:
            with self.subTest(strategy=strategy):
                self.assert_pixhawk_matches_fixture(
                    strategy,
                    self.expected[strategy],
                    self.actual[strategy],
                )


@unittest.skipUnless(
    os.path.isfile(DARPA_LP) and RUN_SLOW_GOLDEN,
    "Set DSE_RUN_SLOW_GOLDEN=1 to run balanced/min_resources DARPA golden baselines.",
)
class TestDarpaUAVGoldenBaselineSlow(unittest.TestCase, _GoldenAssertions):
    @classmethod
    def setUpClass(cls):
        cls.expected = _load_fixture("darpa_uav_baseline.json")
        cls.actual = {
            strategy: _run_darpa_pipeline(strategy, SLOW_TIMEOUT)
            for strategy in SLOW_STRATEGIES
        }

    def test_slow_strategies_match(self):
        for strategy in SLOW_STRATEGIES:
            with self.subTest(strategy=strategy):
                self.assert_darpa_matches_fixture(
                    strategy,
                    self.expected[strategy],
                    self.actual[strategy],
                )


if __name__ == "__main__":
    unittest.main()
