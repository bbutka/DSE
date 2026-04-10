"""
Backend selection and parity tests for Phase 1 in DSE_Core.
"""

from __future__ import annotations

import os
import queue
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLINGO_DIR = os.path.join(PROJECT_ROOT, "Clingo")

from dse_tool.core.asp_generator import (
    ASPGenerator,
    Asset,
    Component,
    NetworkModel,
    RedundancyGroup,
    make_tc9_network,
)
from dse_tool.core.solution_parser import Phase1Result, Phase2Result, ScenarioResult
from dse_tool.agents.phase1_mathopt_agent import Phase1MathOptAgent
from dse_tool.agents.phase1_agent import Phase1Agent
from dse_tool.agents.orchestrator import DSEOrchestrator
from ip_catalog.xilinx_ip_catalog import (
    EXPLOIT_FACTOR_MAP,
    EXPOSURE_VALUES,
    REALTIME_DETECTION_VALUES,
    get_calibrated_estimate,
)


class _FakeAtomArg:
    def __init__(self, value):
        self._value = value
        if isinstance(value, int):
            self.number = value

    def __str__(self):
        return str(self._value)


class _FakeAtom:
    def __init__(self, name, *args):
        self.name = name
        self.arguments = [_FakeAtomArg(arg) for arg in args]


def _sat_phase1(strategy: str = "max_security") -> Phase1Result:
    return Phase1Result(
        strategy=strategy,
        satisfiable=True,
        optimal=True,
        security={"c1": "zero_trust"},
        realtime={"c1": "runtime_attestation"},
        new_risk=[("c1", "c1r1", "read", 1)],
        security_risk=[("c1", "c1r1", "read", 1)],
        total_luts=100,
        total_ffs=100,
        total_power=10,
    )


def _unsat_phase1(strategy: str = "max_security") -> Phase1Result:
    return Phase1Result(strategy=strategy, satisfiable=False, optimal=False)


def _sat_phase2() -> Phase2Result:
    return Phase2Result(satisfiable=True, placed_fws=["pep_group"], placed_ps=["ps0"])


def _sat_phase3() -> list[ScenarioResult]:
    return [ScenarioResult(name="baseline", compromised=[], failed=[], satisfiable=True)]


def _write_minimal_phase1_catalog(filepath: str) -> Path:
    security = "no_security"
    realtime = "no_realtime"
    sec_est = get_calibrated_estimate(security)
    rt_est = get_calibrated_estimate(realtime)
    raw_score = int(EXPOSURE_VALUES[security]) * int(REALTIME_DETECTION_VALUES[realtime])
    normalized = ((raw_score - 25) * 1000) // 975
    denormalized = (normalized * 975) // 1000 + 250
    lines = [
        "% Minimal catalog for Phase 1 backend parity tests",
        f"security_feature({security}).",
        f"realtime_feature({realtime}).",
        f"power_cost({security}, byAsset, 0).",
        f"power_cost({security}, byComponent, {int(round(sec_est.power_mw))}).",
        f"power_cost({security}, base, 0).",
        f"power_cost({realtime}, base, {int(round(rt_est.power_mw))}).",
        f"exposure({security}, {EXPOSURE_VALUES[security]}).",
        f"realtime_detection({realtime}, {REALTIME_DETECTION_VALUES[realtime]}).",
        f"prob_lookup({security}, {realtime}, {raw_score}, {normalized}, {denormalized}).",
    ]
    for exploitability, factor in EXPLOIT_FACTOR_MAP.items():
        lines.append(f"exploit_factor_map({exploitability}, {factor}).")
    for lp_name, attr_name in [
        ("luts", "luts"),
        ("ffs", "ffs"),
        ("dsps", "dsps"),
        ("lutram", "lutrams"),
        ("bram", "brams"),
    ]:
        sec_value = getattr(sec_est, attr_name)
        rt_value = getattr(rt_est, attr_name)
        lines.extend(
            [
                f"{lp_name}({security}, byAsset, 0).",
                f"{lp_name}({security}, byComponent, {sec_value}).",
                f"{lp_name}({security}, base, 0).",
                f"{lp_name}({realtime}, base, {rt_value}).",
            ]
        )
    lines.extend(
        [
            f"bufg({security}, byAsset, 0).",
            f"bufg({security}, byComponent, 0).",
            f"bufg({security}, base, 0).",
            f"bufg({realtime}, base, 0).",
            f"latency_cost({security}, {sec_est.latency}).",
            f"latency_cost({realtime}, {rt_est.latency}).",
        ]
    )
    output_path = Path(filepath)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output_path


def _make_micro_phase1_model() -> NetworkModel:
    return NetworkModel(
        name="phase1_micro",
        components=[
            Component(
                name="sys_cpu",
                comp_type="processor",
                domain="low",
                impact_read=0,
                impact_write=0,
                latency_read=1000,
                latency_write=1000,
                is_master=True,
                is_receiver=False,
            ),
            Component(
                name="nav_a",
                comp_type="ip_core",
                domain="high",
                impact_read=5,
                impact_write=4,
                impact_avail=5,
                latency_read=0,
                latency_write=0,
                exploitability=3,
            ),
            Component(
                name="nav_b",
                comp_type="ip_core",
                domain="privileged",
                impact_read=4,
                impact_write=4,
                impact_avail=5,
                latency_read=0,
                latency_write=0,
                exploitability=4,
            ),
            Component(
                name="crypto",
                comp_type="ip_core",
                domain="high",
                impact_read=5,
                impact_write=5,
                latency_read=0,
                latency_write=0,
                exploitability=2,
            ),
        ],
        assets=[
            Asset("nav_a_reg", "nav_a", direction="bidirectional", impact_read=5, impact_write=4, impact_avail=5, latency_read=0, latency_write=0),
            Asset("nav_b_reg", "nav_b", direction="bidirectional", impact_read=4, impact_write=4, impact_avail=5, latency_read=0, latency_write=0),
            Asset("crypto_reg", "crypto", direction="bidirectional", impact_read=5, impact_write=5, latency_read=0, latency_write=0),
        ],
        links=[
            ("sys_cpu", "nav_a"),
            ("sys_cpu", "nav_b"),
            ("sys_cpu", "crypto"),
        ],
        redundancy_groups=[RedundancyGroup("g1", ["nav_a", "nav_b"])],
        system_caps={
            "max_power": 15000,
            "max_luts": 53200,
            "max_ffs": 106400,
            "max_dsps": 220,
            "max_lutram": 17400,
            "max_bufgs": 32,
            "max_bram": 140,
            "max_security_risk": 1000,
            "max_avail_risk": 1000,
            "redundancy_beta_pct": 10,
            "max_attack_depth": 5,
        },
    )


def _make_triple_redundant_phase1_model() -> NetworkModel:
    return NetworkModel(
        name="phase1_triple_redundant",
        components=[
            Component(
                name="sys_cpu",
                comp_type="processor",
                domain="low",
                impact_read=0,
                impact_write=0,
                latency_read=1000,
                latency_write=1000,
                is_master=True,
                is_receiver=False,
            ),
            Component(
                name="sensor_a",
                comp_type="ip_core",
                domain="high",
                impact_read=5,
                impact_write=4,
                impact_avail=5,
                latency_read=0,
                latency_write=0,
                exploitability=3,
            ),
            Component(
                name="sensor_b",
                comp_type="ip_core",
                domain="privileged",
                impact_read=4,
                impact_write=4,
                impact_avail=5,
                latency_read=0,
                latency_write=0,
                exploitability=4,
            ),
            Component(
                name="sensor_c",
                comp_type="ip_core",
                domain="high",
                impact_read=4,
                impact_write=5,
                impact_avail=5,
                latency_read=0,
                latency_write=0,
                exploitability=2,
            ),
        ],
        assets=[
            Asset("sensor_a_reg", "sensor_a", direction="bidirectional", impact_read=5, impact_write=4, impact_avail=5, latency_read=0, latency_write=0),
            Asset("sensor_b_reg", "sensor_b", direction="bidirectional", impact_read=4, impact_write=4, impact_avail=5, latency_read=0, latency_write=0),
            Asset("sensor_c_reg", "sensor_c", direction="bidirectional", impact_read=4, impact_write=5, impact_avail=5, latency_read=0, latency_write=0),
        ],
        links=[
            ("sys_cpu", "sensor_a"),
            ("sys_cpu", "sensor_b"),
            ("sys_cpu", "sensor_c"),
        ],
        redundancy_groups=[RedundancyGroup("g1", ["sensor_a", "sensor_b", "sensor_c"])],
        system_caps={
            "max_power": 15000,
            "max_luts": 53200,
            "max_ffs": 106400,
            "max_dsps": 220,
            "max_lutram": 17400,
            "max_bufgs": 32,
            "max_bram": 140,
            "max_security_risk": 1000,
            "max_avail_risk": 1000,
            "redundancy_beta_pct": 15,
            "max_attack_depth": 5,
        },
    )


class TestOrchestratorPhase1BackendSelection(unittest.TestCase):
    def _make_orchestrator(self, **kwargs) -> DSEOrchestrator:
        model = make_tc9_network()
        return DSEOrchestrator(
            network_model=model,
            clingo_files_dir=CLINGO_DIR,
            testcase_lp="",
            progress_queue=queue.Queue(),
            phase_timeout=60,
            **kwargs,
        )

    def test_default_backend_is_cpsat_mathopt(self):
        orch = self._make_orchestrator()
        facts = ASPGenerator(orch.network_model).generate()
        with patch("dse_tool.agents.orchestrator.Phase1MathOptAgent.run", return_value=_sat_phase1()) as mathopt_run, \
             patch("dse_tool.agents.orchestrator.Phase1Agent.run", side_effect=AssertionError("ASP fallback should not run")), \
             patch("dse_tool.agents.orchestrator.Phase2Agent.run", return_value=_sat_phase2()), \
             patch("dse_tool.agents.orchestrator.Phase3Agent.run", return_value=_sat_phase3()):
            sol = orch._run_strategy("max_security", facts)
        self.assertTrue(mathopt_run.called)
        self.assertTrue(sol.phase1.satisfiable)
        self.assertEqual(sol.phase1.security["c1"], "zero_trust")

    def test_explicit_asp_backend_skips_ilp(self):
        orch = self._make_orchestrator(solver_config={"phase1_backend": "asp"})
        facts = ASPGenerator(orch.network_model).generate()
        with patch("dse_tool.agents.orchestrator.Phase1MathOptAgent.run", side_effect=AssertionError("MathOpt should not run")), \
             patch("dse_tool.agents.orchestrator.Phase1Agent.run", return_value=_sat_phase1()) as asp_run, \
             patch("dse_tool.agents.orchestrator.Phase2Agent.run", return_value=_sat_phase2()), \
             patch("dse_tool.agents.orchestrator.Phase3Agent.run", return_value=_sat_phase3()):
            sol = orch._run_strategy("max_security", facts)
        self.assertTrue(asp_run.called)
        self.assertTrue(sol.phase1.satisfiable)

    def test_explicit_cbc_backend_runs_mathopt(self):
        orch = self._make_orchestrator(solver_config={"phase1_backend": "cbc"})
        facts = ASPGenerator(orch.network_model).generate()
        with patch("dse_tool.agents.orchestrator.Phase1MathOptAgent.run", return_value=_sat_phase1()) as mathopt_run, \
             patch("dse_tool.agents.orchestrator.Phase1Agent.run", side_effect=AssertionError("ASP should not run")), \
             patch("dse_tool.agents.orchestrator.Phase2Agent.run", return_value=_sat_phase2()), \
             patch("dse_tool.agents.orchestrator.Phase3Agent.run", return_value=_sat_phase3()):
            sol = orch._run_strategy("max_security", facts)
        self.assertTrue(mathopt_run.called)
        self.assertTrue(sol.phase1.satisfiable)


class TestPhase1AgentTimeoutReuse(unittest.TestCase):
    def test_timeout_with_atoms_returns_best_so_far_solution(self):
        atoms = [
            _FakeAtom("selected_security", "c1", "zero_trust"),
            _FakeAtom("selected_realtime", "c1", "runtime_attestation"),
            _FakeAtom("new_risk", "c1", "c1r1", "read", 7),
            _FakeAtom("security_risk", "c1", "c1r1", "read", 7),
            _FakeAtom("total_luts_used", 120),
            _FakeAtom("total_ffs_used", 80),
            _FakeAtom("total_power_used", 9),
        ]

        class _Runner:
            def solve(self, **_kwargs):
                return {
                    "status": "TIMEOUT",
                    "atoms": atoms,
                    "message": "Clingo timed out after 60s",
                }

        with patch("dse_tool.agents.phase1_agent.export_security_features_to_lp"), \
             patch.object(Phase1Agent, "_make_runner", return_value=_Runner()):
            result = Phase1Agent(
                clingo_dir=CLINGO_DIR,
                testcase_lp="",
                strategy="max_security",
                extra_instance_facts="component(c1).",
                timeout=60,
            ).run()

        self.assertTrue(result.satisfiable)
        self.assertFalse(result.optimal)
        self.assertEqual(result.security["c1"], "zero_trust")
        self.assertEqual(result.realtime["c1"], "runtime_attestation")
        self.assertEqual(result.total_luts, 120)
        self.assertEqual(result.risk_per_asset_action(), {("c1r1", "read"): 7})


class TestPhase1BackendIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import clingo  # noqa: F401
            cls.has_clingo = True
        except ImportError:
            cls.has_clingo = False
        try:
            import ortools  # noqa: F401
            cls.has_ortools = True
        except ImportError:
            cls.has_ortools = False
        try:
            import pulp  # noqa: F401
            cls.has_pulp = True
        except ImportError:
            cls.has_pulp = False
        cls.has_lp = os.path.isfile(os.path.join(CLINGO_DIR, "init_enc.lp"))

    def setUp(self):
        if not self.has_clingo or not self.has_lp or not self.has_pulp or not self.has_ortools:
            self.skipTest("clingo, OR-Tools, PuLP, or LP files not available")

    def _assert_micro_model_parity(self, strategy: str) -> None:
        model = _make_micro_phase1_model()
        facts = ASPGenerator(model).generate()
        ilp = Phase1MathOptAgent(model, strategy=strategy, timeout=20).run()
        with patch("dse_tool.agents.phase1_agent.export_security_features_to_lp", side_effect=_write_minimal_phase1_catalog):
            asp = Phase1Agent(
                clingo_dir=CLINGO_DIR,
                testcase_lp="",
                strategy=strategy,
                extra_instance_facts=facts,
                timeout=20,
            ).run()
        self.assertTrue(ilp.satisfiable)
        self.assertTrue(asp.satisfiable)
        self.assertEqual(ilp.risk_per_asset_action(), asp.risk_per_asset_action())
        self.assertEqual(ilp.max_risk_per_asset(), asp.max_risk_per_asset())
        self.assertEqual(ilp.total_risk(), asp.total_risk())

    def test_micro_model_max_security_matches_asp(self):
        self._assert_micro_model_parity("max_security")

    def test_micro_model_min_resources_matches_asp(self):
        self._assert_micro_model_parity("min_resources")

    def test_micro_model_balanced_matches_asp(self):
        self._assert_micro_model_parity("balanced")

    def test_triple_redundancy_micro_model_matches_asp(self):
        model = _make_triple_redundant_phase1_model()
        facts = ASPGenerator(model).generate()
        ilp = Phase1MathOptAgent(model, strategy="max_security", timeout=20).run()
        with patch("dse_tool.agents.phase1_agent.export_security_features_to_lp", side_effect=_write_minimal_phase1_catalog):
            asp = Phase1Agent(
                clingo_dir=CLINGO_DIR,
                testcase_lp="",
                strategy="max_security",
                extra_instance_facts=facts,
                timeout=20,
            ).run()
        self.assertTrue(ilp.satisfiable)
        self.assertTrue(asp.satisfiable)
        self.assertEqual(ilp.risk_per_asset_action(), asp.risk_per_asset_action())
        self.assertEqual(ilp.max_risk_per_asset(), asp.max_risk_per_asset())
        self.assertEqual(ilp.total_risk(), asp.total_risk())

    def test_tc9_full_pipeline_defaults_to_mathopt(self):
        model = make_tc9_network()
        q = queue.Queue()
        orch = DSEOrchestrator(
            network_model=model,
            clingo_files_dir=CLINGO_DIR,
            testcase_lp="",
            progress_queue=q,
            full_phase3=False,
            phase_timeout=60,
        )
        with patch("dse_tool.agents.orchestrator.Phase1MathOptAgent.run", return_value=_sat_phase1()), \
             patch("dse_tool.agents.orchestrator.Phase2Agent.run", return_value=_sat_phase2()), \
             patch("dse_tool.agents.orchestrator.Phase3FastAgent.run", return_value=_sat_phase3()):
            orch.run()
        self.assertTrue(orch.done)
        self.assertEqual(orch.error, "")
        self.assertEqual(len(orch.solutions), 3)
        self.assertTrue(all(sol.phase1 and sol.phase1.satisfiable for sol in orch.solutions))

