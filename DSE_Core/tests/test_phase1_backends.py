"""
Backend selection and parity tests for Phase 1 in DSE_Core.
"""

from __future__ import annotations

import os
import queue
import unittest
from unittest.mock import patch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLINGO_DIR = os.path.join(PROJECT_ROOT, "Clingo")

from dse_tool.core.asp_generator import ASPGenerator, make_reference_soc, make_tc9_network
from dse_tool.core.solution_parser import Phase1Result, Phase2Result, ScenarioResult
from dse_tool.agents.phase1_mathopt_agent import Phase1MathOptAgent
from dse_tool.agents.phase1_agent import Phase1Agent
from dse_tool.agents.orchestrator import DSEOrchestrator


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

    def test_cpsat_unsat_falls_back_to_asp(self):
        orch = self._make_orchestrator()
        facts = ASPGenerator(orch.network_model).generate()
        asp_phase1 = _sat_phase1()
        asp_phase1.security = {"c1": "dynamic_mac"}
        with patch("dse_tool.agents.orchestrator.Phase1MathOptAgent.run", return_value=_unsat_phase1()) as mathopt_run, \
             patch("dse_tool.agents.orchestrator.Phase1Agent.run", return_value=asp_phase1) as asp_run, \
             patch("dse_tool.agents.orchestrator.Phase2Agent.run", return_value=_sat_phase2()), \
             patch("dse_tool.agents.orchestrator.Phase3Agent.run", return_value=_sat_phase3()):
            sol = orch._run_strategy("max_security", facts)
        self.assertTrue(mathopt_run.called)
        self.assertTrue(asp_run.called)
        self.assertEqual(sol.phase1.security["c1"], "dynamic_mac")

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

    def test_tc9_max_security_asset_risk_matches_asp(self):
        model = make_tc9_network()
        facts = ASPGenerator(model).generate()
        ilp = Phase1MathOptAgent(model, strategy="max_security", timeout=60).run()
        asp = Phase1Agent(
            clingo_dir=CLINGO_DIR,
            testcase_lp="",
            strategy="max_security",
            extra_instance_facts=facts,
            timeout=60,
        ).run()
        self.assertTrue(ilp.satisfiable)
        self.assertTrue(asp.satisfiable)
        self.assertEqual(ilp.risk_per_asset_action(), asp.risk_per_asset_action())
        self.assertEqual(ilp.max_risk_per_asset(), asp.max_risk_per_asset())

    def test_tc9_min_resources_asset_risk_matches_asp(self):
        model = make_tc9_network()
        facts = ASPGenerator(model).generate()
        ilp = Phase1MathOptAgent(model, strategy="min_resources", timeout=60).run()
        asp = Phase1Agent(
            clingo_dir=CLINGO_DIR,
            testcase_lp="",
            strategy="min_resources",
            extra_instance_facts=facts,
            timeout=60,
        ).run()
        self.assertTrue(ilp.satisfiable)
        self.assertTrue(asp.satisfiable)
        self.assertEqual(ilp.risk_per_asset_action(), asp.risk_per_asset_action())
        self.assertEqual(ilp.max_risk_per_asset(), asp.max_risk_per_asset())

    def test_tc9_balanced_asset_risk_matches_asp(self):
        model = make_tc9_network()
        facts = ASPGenerator(model).generate()
        ilp = Phase1MathOptAgent(model, strategy="balanced", timeout=60).run()
        asp = Phase1Agent(
            clingo_dir=CLINGO_DIR,
            testcase_lp="",
            strategy="balanced",
            extra_instance_facts=facts,
            timeout=60,
        ).run()
        self.assertTrue(ilp.satisfiable)
        self.assertTrue(asp.satisfiable)
        self.assertEqual(ilp.risk_per_asset_action(), asp.risk_per_asset_action())
        self.assertEqual(ilp.max_risk_per_asset(), asp.max_risk_per_asset())

    def test_reference_soc_max_security_asset_risk_matches_asp(self):
        model = make_reference_soc()
        facts = ASPGenerator(model).generate()
        ilp = Phase1MathOptAgent(model, strategy="max_security", timeout=60).run()
        asp = Phase1Agent(
            clingo_dir=CLINGO_DIR,
            testcase_lp="",
            strategy="max_security",
            extra_instance_facts=facts,
            timeout=60,
        ).run()
        self.assertTrue(ilp.satisfiable)
        self.assertTrue(asp.satisfiable)
        self.assertEqual(ilp.risk_per_asset_action(), asp.risk_per_asset_action())
        self.assertEqual(ilp.max_risk_per_asset(), asp.max_risk_per_asset())

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
        orch.run()
        self.assertTrue(orch.done)
        self.assertEqual(orch.error, "")
        self.assertEqual(len(orch.solutions), 3)
        messages = []
        while not q.empty():
            _level, msg = q.get_nowait()
            messages.append(msg)
        self.assertTrue(
            any("/MATHOPT]" in msg for msg in messages),
            f"Expected ILP backend progress messages, got: {messages[:20]}",
        )

