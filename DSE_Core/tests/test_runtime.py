"""
Runtime test suite for RuntimeAgent, runtime dataclasses, and parsers.

Covers:
  - RuntimeScenario / RuntimeAdaptiveResult / JointPhase2RuntimeResult construction
  - SolutionParser.parse_runtime_adaptive() with known atom sets
  - SolutionParser.parse_runtime_joint() with known atom sets
  - RuntimeAgent.solve_adaptive() happy path (baseline scenario)
  - RuntimeAgent.solve_joint() happy path
  - joint.to_phase2_result() compatibility with Phase3Agent
  - SolutionRanker/comparison compatibility with runtime fields
  - Orchestrator with runtime flags
  - Golden baseline comparison against HOST26 oracle
"""
from __future__ import annotations

import json
import os
import queue
import sys
import unittest
from dataclasses import asdict
from importlib.util import find_spec
from unittest.mock import patch

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLINGO_DIR   = os.path.join(PROJECT_ROOT, "Clingo")
TESTCASE_LP  = os.path.join(CLINGO_DIR, "tgt_system_tc9_inst.lp")
FIXTURES_DIR = os.path.join(PROJECT_ROOT, "tests", "fixtures")
HAS_CLINGO = find_spec("clingo") is not None

sys.path.insert(0, PROJECT_ROOT)

from dse_tool.core.asp_generator import ASPGenerator, make_tc9_network, make_reference_soc
from dse_tool.core.solution_parser import (
    Phase1Result, Phase2Result, SolutionResult, ScenarioResult,
    RuntimeScenario, RuntimeAdaptiveResult, JointPhase2RuntimeResult,
    SolutionParser,
)
from dse_tool.core.solution_ranker import SolutionRanker
from dse_tool.core.comparison import generate_report_text
from dse_tool.agents.phase1_agent import Phase1Agent
from dse_tool.agents.phase2_agent import Phase2Agent
from dse_tool.agents.runtime_agent import RuntimeAgent, RUNTIME_SCENARIOS

# Pre-generate instance facts for all integration tests
_TC9_MODEL = make_tc9_network()
_TC9_FACTS = ASPGenerator(_TC9_MODEL).generate()
_CACHED_P1: Phase1Result | None = None
_CACHED_P2: Phase2Result | None = None
_CACHED_RT_ADAPTIVE: list[RuntimeAdaptiveResult] | None = None
_CACHED_RT_JOINT: JointPhase2RuntimeResult | None = None
_CACHED_RT_JOINT_ADAPTIVE: list[RuntimeAdaptiveResult] | None = None


# ═══════════════════════════════════════════════════════════════════════════
# 1. Dataclass Unit Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestRuntimeScenario(unittest.TestCase):
    def test_construction(self):
        sc = RuntimeScenario(
            name="test", observations=(("dma", "rate_spike", 1),),
            description="A test scenario"
        )
        self.assertEqual(sc.name, "test")
        self.assertEqual(len(sc.observations), 1)

    def test_frozen(self):
        sc = RuntimeScenario(name="x", observations=(), description="")
        with self.assertRaises(AttributeError):
            sc.name = "y"  # type: ignore


class TestRuntimeAdaptiveResult(unittest.TestCase):
    def test_defaults(self):
        r = RuntimeAdaptiveResult()
        self.assertEqual(r.current_mode, "unknown")
        self.assertEqual(r.placed_monitors, [])
        self.assertEqual(r.monitor_total_cost, 0)

    def test_fields_populated(self):
        sc = RuntimeScenario(name="test", observations=(), description="")
        r = RuntimeAdaptiveResult(
            scenario=sc,
            placed_monitors=["mon_a", "mon_b"],
            current_mode="attack_suspected",
            monitor_total_cost=200,
        )
        self.assertEqual(r.current_mode, "attack_suspected")
        self.assertEqual(len(r.placed_monitors), 2)


class TestJointPhase2RuntimeResult(unittest.TestCase):
    def test_defaults(self):
        j = JointPhase2RuntimeResult()
        self.assertFalse(j.satisfiable)
        self.assertEqual(j.placed_monitors, [])

    def test_to_phase2_result_fallback(self):
        """to_phase2_result() without cached parse produces valid Phase2Result."""
        j = JointPhase2RuntimeResult(
            placed_fws=["fw1"], placed_ps=["ps1"],
            total_zta_cost=100, satisfiable=True, optimal=True,
        )
        p2 = j.to_phase2_result()
        self.assertIsInstance(p2, Phase2Result)
        self.assertTrue(p2.satisfiable)
        self.assertEqual(p2.placed_fws, ["fw1"])
        self.assertEqual(p2.total_cost, 100)

    def test_as_runtime_facts_basic(self):
        j = JointPhase2RuntimeResult(
            placed_fws=["pep_group"], placed_ps=["ps0"],
            placed_monitors=["mon_ctrl"],
        )
        facts = j.as_runtime_facts()
        self.assertIn("deployed_pep(pep_group).", facts)
        self.assertIn("deployed_ps(ps0).", facts)
        self.assertIn("deployed_monitor(mon_ctrl).", facts)


# ═══════════════════════════════════════════════════════════════════════════
# 2. Parser Unit Tests (mock clingo.Symbol objects)
# ═══════════════════════════════════════════════════════════════════════════

class _MockArg:
    """Simulates a clingo.Symbol argument for parser testing."""
    def __init__(self, value):
        self._value = value
        if isinstance(value, int):
            self.number = value
    def __str__(self):
        return str(self._value)


class _MockSymbol:
    """Simulates a clingo.Symbol for parser testing."""
    def __init__(self, name: str, args: list):
        self.name = name
        self.arguments = [_MockArg(a) for a in args]


class TestParseRuntimeAdaptive(unittest.TestCase):
    def test_basic_parse(self):
        sc = RuntimeScenario(name="test", observations=(), description="")
        atoms = [
            _MockSymbol("place_monitor", ["mon_a"]),
            _MockSymbol("place_monitor", ["mon_b"]),
            _MockSymbol("covered", ["node1"]),
            _MockSymbol("monitor_total_cost", [300]),
            _MockSymbol("current_mode", ["attack_suspected"]),
            _MockSymbol("trust_state", ["dma", "low"]),
            _MockSymbol("anomaly_score", ["dma", 5]),
            _MockSymbol("mode_trigger", ["dma", "rate_spike"]),
            _MockSymbol("response_action", ["dma", "throttle"]),
            _MockSymbol("adaptive_deny", ["dma", "c8", "attack_suspected"]),
            _MockSymbol("effective_allow", ["cpu", "mem", "read"]),
        ]
        r = SolutionParser.parse_runtime_adaptive(atoms, sc)
        self.assertEqual(r.current_mode, "attack_suspected")
        self.assertIn("mon_a", r.placed_monitors)
        self.assertIn("mon_b", r.placed_monitors)
        self.assertEqual(r.monitor_total_cost, 300)
        self.assertEqual(r.trust_states["dma"], "low")
        self.assertEqual(r.anomaly_scores["dma"], 5)
        self.assertEqual(len(r.adaptive_denies), 1)
        self.assertEqual(len(r.effective_allows), 1)


class TestParseRuntimeJoint(unittest.TestCase):
    def test_basic_parse(self):
        atoms = [
            _MockSymbol("place_fw", ["pep_group"]),
            _MockSymbol("place_ps", ["ps0"]),
            _MockSymbol("place_monitor", ["mon_ctrl"]),
            _MockSymbol("total_cost", [500]),
            _MockSymbol("monitor_total_cost", [200]),
            _MockSymbol("total_joint_runtime_cost", [700]),
            _MockSymbol("response_readiness_score", [100]),
            _MockSymbol("detection_strength_score", [400]),
            _MockSymbol("observability_score", ["dma", 3]),
            _MockSymbol("detection_latency", ["dma", 2]),
            _MockSymbol("protected", ["cpu", "mem"]),
            _MockSymbol("final_allow", ["cpu", "mem", "read"]),
        ]
        j = SolutionParser.parse_runtime_joint(atoms)
        self.assertIn("pep_group", j.placed_fws)
        self.assertIn("ps0", j.placed_ps)
        self.assertIn("mon_ctrl", j.placed_monitors)
        self.assertEqual(j.monitor_total_cost, 200)
        self.assertEqual(j.total_joint_runtime_cost, 700)
        self.assertEqual(j.observability.get("dma"), 3)
        # to_phase2_result uses cached parse_phase2
        p2 = j.to_phase2_result()
        self.assertIn("pep_group", p2.placed_fws)
        self.assertIn(("cpu", "mem", "read"), p2.final_allows)
        # as_runtime_facts includes p2_allow
        facts = j.as_runtime_facts()
        self.assertIn("deployed_pep(pep_group).", facts)
        self.assertIn("p2_allow(cpu, mem, read).", facts)


# ═══════════════════════════════════════════════════════════════════════════
# 3. Integration Tests (require Clingo)
# ═══════════════════════════════════════════════════════════════════════════

def _run_phase1() -> Phase1Result:
    """Run Phase 1 for tc9 and return the result."""
    global _CACHED_P1
    if _CACHED_P1 is None:
        agent = Phase1Agent(
            clingo_dir=CLINGO_DIR,
            testcase_lp=TESTCASE_LP,
            strategy="max_security",
            extra_instance_facts=_TC9_FACTS,
            timeout=60,
            solver_config={"clingo_threads": 1},
        )
        _CACHED_P1 = agent.run()
    return _CACHED_P1


def _run_phase2(p1: Phase1Result) -> Phase2Result:
    """Run Phase 2 for tc9 and return the result."""
    global _CACHED_P2
    if _CACHED_P2 is None:
        agent = Phase2Agent(
            clingo_dir=CLINGO_DIR,
            testcase_lp=TESTCASE_LP,
            phase1_result=p1,
            strategy="max_security",
            extra_instance_facts=_TC9_FACTS,
            timeout=60,
            solver_config={"clingo_threads": 1},
        )
        _CACHED_P2 = agent.run()
    return _CACHED_P2


def _run_runtime_adaptive() -> list[RuntimeAdaptiveResult]:
    global _CACHED_RT_ADAPTIVE
    if _CACHED_RT_ADAPTIVE is None:
        rt = RuntimeAgent(
            clingo_dir=CLINGO_DIR,
            testcase_lp=TESTCASE_LP,
            extra_instance_facts=_TC9_FACTS,
            timeout=60,
            solver_config={"clingo_threads": 1},
        )
        _CACHED_RT_ADAPTIVE = rt.solve_adaptive(
            _run_phase1(),
            _run_phase2(_run_phase1()),
            scenarios=list(RUNTIME_SCENARIOS),
        )
    return _CACHED_RT_ADAPTIVE


def _run_runtime_joint() -> JointPhase2RuntimeResult:
    global _CACHED_RT_JOINT
    if _CACHED_RT_JOINT is None:
        rt = RuntimeAgent(
            clingo_dir=CLINGO_DIR,
            testcase_lp=TESTCASE_LP,
            extra_instance_facts=_TC9_FACTS,
            timeout=60,
            solver_config={"clingo_threads": 1},
        )
        _CACHED_RT_JOINT = rt.solve_joint(_run_phase1())
    return _CACHED_RT_JOINT


def _run_runtime_joint_adaptive() -> list[RuntimeAdaptiveResult]:
    global _CACHED_RT_JOINT_ADAPTIVE
    if _CACHED_RT_JOINT_ADAPTIVE is None:
        rt = RuntimeAgent(
            clingo_dir=CLINGO_DIR,
            testcase_lp=TESTCASE_LP,
            extra_instance_facts=_TC9_FACTS,
            timeout=60,
            solver_config={"clingo_threads": 1},
        )
        joint = _run_runtime_joint()
        _CACHED_RT_JOINT_ADAPTIVE = rt.solve_adaptive(
            _run_phase1(),
            joint.to_phase2_result(),
            scenarios=list(RUNTIME_SCENARIOS),
            extra_runtime_facts=joint.as_runtime_facts(),
        )
    return _CACHED_RT_JOINT_ADAPTIVE


@unittest.skipUnless(HAS_CLINGO, "clingo is required for runtime integration tests.")
class TestRuntimeAdaptiveIntegration(unittest.TestCase):
    """Integration tests for solve_adaptive (require clingo)."""

    @classmethod
    def setUpClass(cls):
        cls.p1 = _run_phase1()
        cls.p2 = _run_phase2(cls.p1)
        cls.results = _run_runtime_adaptive()

    def test_phase1_phase2_satisfiable(self):
        self.assertTrue(self.p1.satisfiable)
        self.assertTrue(self.p2.satisfiable)

    def test_baseline_scenario(self):
        baseline = self.results[0]
        self.assertEqual(baseline.current_mode, "normal")
        self.assertTrue(len(baseline.placed_monitors) > 0)

    def test_all_scenarios(self):
        self.assertEqual(len(self.results), 5)
        # Baseline should be normal
        self.assertEqual(self.results[0].current_mode, "normal")
        # dma_rate_spike should NOT be normal (mode transition)
        self.assertNotEqual(self.results[1].current_mode, "normal")

    def test_report_generation(self):
        report = RuntimeAgent.generate_runtime_report(self.p1, self.p2, self.results)
        self.assertIn("Runtime Adaptive Monitoring Summary", report)
        self.assertIn("baseline", report)


@unittest.skipUnless(HAS_CLINGO, "clingo is required for runtime integration tests.")
class TestRuntimeJointIntegration(unittest.TestCase):
    """Integration tests for solve_joint (require clingo)."""

    @classmethod
    def setUpClass(cls):
        cls.p1 = _run_phase1()
        cls.joint = _run_runtime_joint()
        cls.joint_adaptive = _run_runtime_joint_adaptive()

    def test_joint_satisfiable(self):
        joint = self.joint
        self.assertTrue(joint.satisfiable)
        self.assertTrue(len(joint.placed_monitors) > 0)
        self.assertTrue(len(joint.placed_fws) > 0)

    def test_joint_to_phase2_has_all_fields(self):
        """joint.to_phase2_result() must have full Phase2Result fields."""
        p2 = self.joint.to_phase2_result()
        self.assertTrue(p2.satisfiable)
        self.assertTrue(len(p2.placed_fws) > 0)
        self.assertTrue(len(p2.placed_ps) > 0)
        # These must be non-empty if joint includes zta_policy_enc.lp
        self.assertTrue(len(p2.final_allows) > 0, "final_allows empty — Phase 2 atom parity broken")

    def test_joint_as_runtime_facts_includes_p2_allow(self):
        """as_runtime_facts() must emit p2_allow for adaptive runtime."""
        facts = self.joint.as_runtime_facts()
        self.assertIn("deployed_pep(", facts)
        self.assertIn("deployed_ps(", facts)
        self.assertIn("deployed_monitor(", facts)
        self.assertIn("p2_allow(", facts)

    def test_joint_to_adaptive_pipeline(self):
        """Joint -> adaptive pipeline must succeed."""
        self.assertEqual(len(self.joint_adaptive), 5)
        self.assertEqual(self.joint_adaptive[0].current_mode, "normal")

    def test_joint_report_generation(self):
        report = RuntimeAgent.generate_joint_runtime_report(
            self.p1, self.joint, self.joint_adaptive
        )
        self.assertIn("Joint Policy + Runtime Synthesis Summary", report)


# ═══════════════════════════════════════════════════════════════════════════
# 4. Compatibility Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestRankerCompatibility(unittest.TestCase):
    """SolutionRanker must not break when runtime fields are present."""

    def test_ranker_with_runtime_results(self):
        sc = RuntimeScenario(name="test", observations=(), description="")
        runtime_r = RuntimeAdaptiveResult(scenario=sc, current_mode="normal")
        joint_r = JointPhase2RuntimeResult(satisfiable=True)

        sol = SolutionResult(
            strategy="max_security",
            label="Test",
            phase1=Phase1Result(satisfiable=True, optimal=True),
            phase2=Phase2Result(satisfiable=True),
            scenarios=[ScenarioResult(name="baseline", compromised=[], failed=[], satisfiable=True)],
            runtime_results=[runtime_r],
            joint_runtime=joint_r,
            complete=True,
        )
        ranker = SolutionRanker([sol], max_luts=50000, max_power=500)
        ranker.rank()  # must not raise


class TestComparisonCompatibility(unittest.TestCase):
    """Comparison engine must not break when runtime fields are present."""

    def test_generate_report_with_runtime_fields(self):
        sc = RuntimeScenario(name="test", observations=(), description="")
        runtime_r = RuntimeAdaptiveResult(scenario=sc, current_mode="normal")

        sol = SolutionResult(
            strategy="max_security",
            label="Test Solution",
            phase1=Phase1Result(satisfiable=True, optimal=True),
            phase2=Phase2Result(satisfiable=True),
            scenarios=[ScenarioResult(name="baseline", compromised=[], failed=[], satisfiable=True)],
            runtime_results=[runtime_r],
            complete=True,
        )
        report = generate_report_text(
            [sol], network_name="test", max_luts=50000, max_power=500,
        )
        self.assertIsInstance(report, str)


class TestGuiCompatibility(unittest.TestCase):
    """ResultsPanel must ignore runtime fields without crashing."""

    def test_results_panel_accepts_extended_solution_result(self):
        try:
            import tkinter as tk
        except Exception as exc:  # pragma: no cover - platform dependent
            self.skipTest(f"tkinter unavailable: {exc}")

        from dse_tool.gui.results_panel import ResultsPanel

        sc = RuntimeScenario(name="baseline", observations=(), description="")
        sol = SolutionResult(
            strategy="max_security",
            label="GUI Test",
            phase1=Phase1Result(
                satisfiable=True,
                optimal=True,
                total_luts=100,
                total_ffs=200,
                total_power=10,
            ),
            phase2=Phase2Result(
                satisfiable=True,
                placed_fws=["pep_group"],
                placed_ps=["ps0"],
            ),
            scenarios=[ScenarioResult(name="baseline", compromised=[], failed=[], satisfiable=True)],
            runtime_results=[RuntimeAdaptiveResult(scenario=sc, current_mode="normal")],
            joint_runtime=JointPhase2RuntimeResult(
                satisfiable=True,
                placed_fws=["pep_group"],
                placed_ps=["ps0"],
                placed_monitors=["mon_ctrl"],
            ),
            complete=True,
        )

        root = None
        panel = None
        try:
            root = tk.Tk()
            root.withdraw()
            panel = ResultsPanel(root)
            panel.set_results([sol])
            root.update_idletasks()
            self.assertIn("pep_group", getattr(panel, "_phase2_strategy_1").cget("text"))
            self.assertIn("baseline", getattr(panel, "_phase3_strategy_1").cget("text"))
            panel.clear()
        except tk.TclError as exc:  # pragma: no cover - display dependent
            self.skipTest(f"tkinter display unavailable: {exc}")
        finally:
            if root is not None:
                try:
                    if panel is not None:
                        panel.destroy()
                    for child in list(root.winfo_children()):
                        child.destroy()
                    root.update_idletasks()
                    root.update()
                except tk.TclError:
                    pass
                root.destroy()


# ═══════════════════════════════════════════════════════════════════════════
# 5. Golden Baseline Comparison
# ═══════════════════════════════════════════════════════════════════════════

@unittest.skipUnless(HAS_CLINGO, "clingo is required for runtime golden baselines.")
class TestRuntimeGoldenBaselines(unittest.TestCase):
    """
    Compare runtime outputs against HOST26 baselines, with explicit
    assertions for the known DSE_ADD-base divergences documented in the
    fixture.
    """

    @classmethod
    def setUpClass(cls):
        fixture_path = os.path.join(FIXTURES_DIR, "tc9_runtime_baseline.json")
        with open(fixture_path, encoding="utf-8") as f:
            cls.baselines = json.load(f)
        cls.p1 = _run_phase1()
        cls.p2 = _run_phase2(cls.p1)
        cls.adaptive_results = _run_runtime_adaptive()
        cls.joint = _run_runtime_joint()
        cls.joint_adaptive_results = _run_runtime_joint_adaptive()

    def test_adaptive_baseline_mode(self):
        expected = self.baselines["adaptive"]["scenarios"]

        self.assertEqual(self.adaptive_results[0].current_mode, expected["baseline"]["current_mode"])
        self.assertEqual(self.adaptive_results[1].current_mode, expected["dma_rate_spike"]["current_mode"])
        self.assertEqual(self.adaptive_results[3].current_mode, expected["c8_sequence_anomaly"]["current_mode"])

    def test_adaptive_monitor_placement(self):
        expected = self.baselines["adaptive"]["scenarios"]["baseline"]
        self.assertEqual(self.adaptive_results[0].placed_monitors, sorted(expected["placed_monitors"]))
        self.assertEqual(self.adaptive_results[0].monitor_total_cost, expected["monitor_total_cost"])

    def test_joint_matches_host26_on_shared_fields(self):
        expected = self.baselines["joint"]

        self.assertTrue(self.joint.satisfiable)
        self.assertEqual(self.joint.optimal, expected["optimal"])
        self.assertEqual(sorted(self.joint.placed_fws), sorted(expected["placed_fws"]))
        self.assertEqual(sorted(self.joint.placed_ps), sorted(expected["placed_ps"]))
        self.assertEqual(sorted(self.joint.placed_monitors), sorted(expected["placed_monitors"]))
        self.assertEqual(self.joint.total_zta_cost, expected["total_zta_cost"])
        self.assertEqual(self.joint.monitor_total_cost, expected["monitor_total_cost"])
        self.assertEqual(self.joint.total_joint_runtime_cost, expected["total_joint_runtime_cost"])
        self.assertEqual(self.joint.response_readiness_score, expected["response_readiness_score"])
        self.assertEqual(self.joint.weighted_detection_latency, expected["weighted_detection_latency"])
        self.assertEqual(self.joint.false_positive_cost, expected["false_positive_cost"])

    def test_joint_dse_add_base_divergence_is_explicit(self):
        expected = self.baselines["expected_dse_core_divergences"]["joint.detection_strength_score"]

        self.assertEqual(self.baselines["joint"]["detection_strength_score"], expected["host26"])
        self.assertEqual(self.joint.detection_strength_score, expected["dse_core_expected"])

    def test_joint_adaptive_modes_match_host26(self):
        expected = self.baselines["joint_adaptive"]["scenarios"]

        for result in self.joint_adaptive_results:
            with self.subTest(scenario=result.scenario.name):
                oracle = expected[result.scenario.name]
                self.assertEqual(result.current_mode, oracle["current_mode"])
                self.assertEqual(result.placed_monitors, sorted(oracle["placed_monitors"]))
                self.assertEqual(result.monitor_total_cost, oracle["monitor_total_cost"])

    def test_joint_adaptive_effective_allows_match_documented_fix(self):
        expected = self.baselines["expected_dse_core_divergences"]["joint_adaptive.effective_allows_count"]["dse_core_expected"]

        for result in self.joint_adaptive_results:
            with self.subTest(scenario=result.scenario.name):
                self.assertEqual(len(result.effective_allows), expected[result.scenario.name])


# ═══════════════════════════════════════════════════════════════════════════
# 6. Orchestrator Path Tests
# ═══════════════════════════════════════════════════════════════════════════

@unittest.skipUnless(HAS_CLINGO, "clingo is required for runtime orchestrator path tests.")
class TestOrchestratorRuntimePaths(unittest.TestCase):
    """Test orchestrator with runtime flags enabled."""

    def _run_single_strategy(self, **kwargs):
        from dse_tool.core.asp_generator import make_tc9_network
        from dse_tool.core.solution_ranker import SolutionRanker
        from dse_tool.core.comparison import generate_report_text
        from dse_tool.core.asp_generator import ASPGenerator
        from dse_tool.agents.orchestrator import DSEOrchestrator

        model = make_tc9_network()
        q = queue.Queue()
        orch = DSEOrchestrator(
            network_model=model,
            clingo_files_dir=CLINGO_DIR,
            testcase_lp=TESTCASE_LP,
            progress_queue=q,
            phase_timeout=60,
            **kwargs,
        )
        instance_facts = ASPGenerator(model).generate()
        cached_p1 = _run_phase1()
        cached_p2 = _run_phase2(cached_p1)
        cached_joint = _run_runtime_joint()
        runtime_results = (
            _run_runtime_joint_adaptive()
            if kwargs.get("run_joint_runtime")
            else _run_runtime_adaptive()
        )
        fake_phase3 = [ScenarioResult(name="baseline", compromised=[], failed=[], satisfiable=True)]

        with patch("dse_tool.agents.orchestrator.Phase1MathOptAgent.run", return_value=cached_p1), \
             patch("dse_tool.agents.orchestrator.Phase1Agent.run", return_value=cached_p1), \
             patch("dse_tool.agents.orchestrator.Phase2Agent.run", return_value=cached_p2), \
             patch("dse_tool.agents.orchestrator.RuntimeAgent.solve_joint", return_value=cached_joint), \
             patch("dse_tool.agents.orchestrator.RuntimeAgent.solve_adaptive", return_value=runtime_results), \
             patch("dse_tool.agents.orchestrator.Phase3Agent.run", return_value=fake_phase3):
            sol = orch._run_strategy("max_security", instance_facts)

        caps = model.system_caps
        SolutionRanker([sol], max_luts=caps.get("max_luts", 0), max_power=caps.get("max_power", 0)).rank()
        generate_report_text(
            [sol],
            network_name=model.name,
            max_luts=caps.get("max_luts", 0),
            max_power=caps.get("max_power", 0),
            max_ffs=caps.get("max_ffs", 0),
        )
        return sol

    def test_no_runtime_flags(self):
        """Default orchestrator: no runtime fields populated."""
        sol = self._run_single_strategy()
        self.assertEqual(sol.runtime_results, [])
        self.assertIsNone(sol.joint_runtime)

    def test_adaptive_runtime_flag(self):
        """Orchestrator with run_adaptive_runtime=True populates runtime_results."""
        sol = self._run_single_strategy(run_adaptive_runtime=True)
        self.assertTrue(sol.phase2 and sol.phase2.satisfiable)
        self.assertTrue(len(sol.runtime_results) > 0)

    def test_joint_runtime_flag(self):
        """Orchestrator with run_joint_runtime=True populates joint_runtime."""
        sol = self._run_single_strategy(run_joint_runtime=True)
        self.assertIsNotNone(sol.joint_runtime)
        self.assertTrue(sol.joint_runtime.satisfiable)
        self.assertTrue(len(sol.scenarios) > 0)


# ═══════════════════════════════════════════════════════════════════════════
# 7. Failure-Path Tests
# ═══════════════════════════════════════════════════════════════════════════

@unittest.skipUnless(HAS_CLINGO, "clingo is required for runtime failure-path tests.")
class TestSolveAdaptiveFailurePaths(unittest.TestCase):
    """Verify solve_adaptive() raises RuntimeError on impossible inputs."""

    @classmethod
    def setUpClass(cls):
        cls.p1 = _run_phase1()
        cls.p2 = _run_phase2(cls.p1)

    def test_unsat_raises_with_diagnostic(self):
        """Removing all candidate monitors should cause UNSAT with diagnostic."""
        # Inject facts that remove all candidate monitors (override budget to 0)
        poison = "system_capability(max_monitor_cost, 0)."
        rt = RuntimeAgent(
            clingo_dir=CLINGO_DIR, testcase_lp=TESTCASE_LP,
            extra_instance_facts=_TC9_FACTS + "\n" + poison, timeout=30,
        )
        baseline = RuntimeScenario(name="baseline", observations=(), description="")
        with self.assertRaises(RuntimeError) as ctx:
            rt.solve_adaptive(self.p1, self.p2, scenarios=[baseline])
        msg = str(ctx.exception)
        self.assertIn("UNSAT", msg)

    def test_non_tc9_topology_rejected_early(self):
        """RuntimeAgent should reject non-tc9 generated topologies before solve."""
        refsoc_facts = ASPGenerator(make_reference_soc()).generate()
        rt = RuntimeAgent(
            clingo_dir=CLINGO_DIR,
            testcase_lp=TESTCASE_LP,
            extra_instance_facts=refsoc_facts,
            timeout=30,
        )
        baseline = RuntimeScenario(name="baseline", observations=(), description="")
        with self.assertRaises(RuntimeError) as ctx:
            rt.solve_adaptive(self.p1, self.p2, scenarios=[baseline])
        self.assertIn("tc9-specific", str(ctx.exception))


class TestAttackDepthFacts(unittest.TestCase):
    """Phase 3 attack depth should be emitted as a configurable system capability."""

    def test_tc9_default_attack_depth_emitted(self):
        facts = ASPGenerator(make_tc9_network()).generate()
        self.assertIn("system_capability(max_attack_depth, 5).", facts)

    def test_reference_soc_attack_depth_emitted(self):
        facts = ASPGenerator(make_reference_soc()).generate()
        self.assertIn("system_capability(max_attack_depth, 8).", facts)


@unittest.skipUnless(HAS_CLINGO, "clingo is required for runtime joint tests.")
class TestSolveJointNeverRaises(unittest.TestCase):
    """Verify solve_joint() never raises — returns satisfiable=False."""

    @classmethod
    def setUpClass(cls):
        cls.p1 = _run_phase1()

    def test_impossible_joint_returns_unsat(self):
        """Zero FW budget should make joint UNSAT but not raise."""
        poison = (
            "system_capability(max_zta_cost, 0).\n"
            "system_capability(max_monitor_cost, 0).\n"
        )
        progress = queue.Queue()
        rt = RuntimeAgent(
            clingo_dir=CLINGO_DIR, testcase_lp=TESTCASE_LP,
            progress_queue=progress,
            extra_instance_facts=_TC9_FACTS + "\n" + poison, timeout=30,
        )
        result = rt.solve_joint(self.p1)  # must NOT raise
        self.assertIsInstance(result, JointPhase2RuntimeResult)
        self.assertFalse(result.satisfiable)
        messages = []
        while not progress.empty():
            _level, msg = progress.get_nowait()
            messages.append(msg)
        self.assertTrue(
            any("UNSAT" in msg or "ERROR" in msg or "TIMEOUT" in msg for msg in messages),
            f"No actionable diagnostic emitted. Messages: {messages}",
        )


# ═══════════════════════════════════════════════════════════════════════════
# 8. Phase 2 Parity Test
# ═══════════════════════════════════════════════════════════════════════════

@unittest.skipUnless(HAS_CLINGO, "clingo is required for Phase 2 parity tests.")
class TestPhase2Parity(unittest.TestCase):
    """Compare standalone Phase 2 vs joint.to_phase2_result() structural fields."""

    @classmethod
    def setUpClass(cls):
        cls.p1 = _run_phase1()
        cls.p2_standalone = _run_phase2(cls.p1)
        cls.joint = _run_runtime_joint()
        cls.p2_joint = cls.joint.to_phase2_result()

    def test_both_satisfiable(self):
        self.assertTrue(self.p2_standalone.satisfiable)
        self.assertTrue(self.p2_joint.satisfiable)

    def test_fws_match(self):
        """Joint and standalone should place the same firewalls."""
        self.assertEqual(
            sorted(set(self.p2_standalone.placed_fws)),
            sorted(set(self.p2_joint.placed_fws)),
        )

    def test_ps_overlap(self):
        """Joint places at least the same PS as standalone (may add more for monitors)."""
        standalone_ps = set(self.p2_standalone.placed_ps)
        joint_ps = set(self.p2_joint.placed_ps)
        self.assertTrue(
            standalone_ps.issubset(joint_ps),
            f"Standalone PS {standalone_ps} not subset of joint PS {joint_ps}"
        )

    def test_final_allows_nonempty(self):
        """Both must have non-empty final_allows."""
        self.assertTrue(len(self.p2_standalone.final_allows) > 0)
        self.assertTrue(len(self.p2_joint.final_allows) > 0)

    def test_to_phase2_result_idempotent(self):
        """Calling to_phase2_result() twice returns equal but distinct objects."""
        p2a = self.joint.to_phase2_result()
        p2b = self.joint.to_phase2_result()
        self.assertEqual(p2a.placed_fws, p2b.placed_fws)
        self.assertEqual(p2a.placed_ps, p2b.placed_ps)
        self.assertEqual(p2a.satisfiable, p2b.satisfiable)
        # Must be distinct objects (copy, not shared reference)
        self.assertIsNot(p2a, p2b)


# ═══════════════════════════════════════════════════════════════════════════
# 9. Additional Orchestrator Tests
# ═══════════════════════════════════════════════════════════════════════════

@unittest.skipUnless(HAS_CLINGO, "clingo is required for runtime orchestrator path tests.")
class TestOrchestratorBothFlags(unittest.TestCase):
    """Orchestrator with both joint and adaptive runtime flags."""

    def _run_single_strategy(self, **kwargs):
        from dse_tool.core.asp_generator import make_tc9_network
        from dse_tool.core.asp_generator import ASPGenerator
        from dse_tool.agents.orchestrator import DSEOrchestrator

        model = make_tc9_network()
        q = queue.Queue()
        orch = DSEOrchestrator(
            network_model=model,
            clingo_files_dir=CLINGO_DIR,
            testcase_lp=TESTCASE_LP,
            progress_queue=q,
            phase_timeout=60,
            **kwargs,
        )
        instance_facts = ASPGenerator(model).generate()
        cached_p1 = _run_phase1()
        cached_p2 = _run_phase2(cached_p1)
        cached_joint = _run_runtime_joint()
        fake_phase3 = [ScenarioResult(name="baseline", compromised=[], failed=[], satisfiable=True)]

        with patch("dse_tool.agents.orchestrator.Phase1MathOptAgent.run", return_value=cached_p1), \
             patch("dse_tool.agents.orchestrator.Phase1Agent.run", return_value=cached_p1), \
             patch("dse_tool.agents.orchestrator.Phase2Agent.run", return_value=cached_p2), \
             patch("dse_tool.agents.orchestrator.RuntimeAgent.solve_joint", return_value=cached_joint), \
             patch("dse_tool.agents.orchestrator.RuntimeAgent.solve_adaptive", return_value=_run_runtime_joint_adaptive()), \
             patch("dse_tool.agents.orchestrator.Phase3Agent.run", return_value=fake_phase3):
            return orch._run_strategy("max_security", instance_facts)

    def test_both_flags_true(self):
        """Joint + adaptive: joint replaces Phase 2, adaptive uses joint context."""
        sol = self._run_single_strategy(
            run_joint_runtime=True,
            run_adaptive_runtime=True,
        )
        self.assertIsNotNone(sol.joint_runtime)
        self.assertTrue(sol.joint_runtime.satisfiable, "No satisfiable joint solution")
        self.assertTrue(len(sol.runtime_results) > 0, "Adaptive results missing when both flags True")


# ═══════════════════════════════════════════════════════════════════════════
# 10. CLI Runner Smoke Test
# ═══════════════════════════════════════════════════════════════════════════

@unittest.skipUnless(HAS_CLINGO, "clingo is required for runtime CLI tests.")
class TestCLIRunner(unittest.TestCase):
    """Smoke test for run_runtime.py functions (not subprocess)."""

    def test_run_standard_completes(self):
        """run_standard() should complete without raising."""
        import run_runtime
        # Capture stdout, don't pollute test output
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            run_runtime.run_standard(timeout=60)
        output = buf.getvalue()
        self.assertIn("Runtime Adaptive Monitoring Summary", output)

    def test_run_joint_completes(self):
        """run_joint() should complete without raising."""
        import run_runtime
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            run_runtime.run_joint(timeout=60)
        output = buf.getvalue()
        self.assertIn("Joint Policy + Runtime Synthesis Summary", output)


if __name__ == "__main__":
    unittest.main()
