from __future__ import annotations

import unittest

from tc9_runtime_joint import solve_joint_phase2_runtime, solve_joint_runtime_pipeline
from runClingo_tc9 import phase1_optimise


class Tc9RuntimeJointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.p1 = phase1_optimise()
        cls.joint = solve_joint_phase2_runtime(cls.p1)
        _p1, _joint, runtime_results = solve_joint_runtime_pipeline()
        cls.runtime_results = {result.scenario.name: result for result in runtime_results}

    def test_joint_phase2_places_control_plane_monitors(self) -> None:
        self.assertEqual(self.joint.placed_fws, ["pep_group", "pep_standalone"])
        self.assertEqual(self.joint.placed_ps, ["ps0", "ps1"])
        self.assertIn("mon_c8",   self.joint.placed_monitors)
        self.assertIn("mon_ctrl", self.joint.placed_monitors)
        self.assertIn("mon_noc0", self.joint.placed_monitors)
        self.assertIn("mon_noc1", self.joint.placed_monitors)

    def test_joint_cost_includes_monitor_cost(self) -> None:
        self.assertEqual(
            self.joint.total_joint_runtime_cost,
            self.joint.total_zta_cost + self.joint.monitor_total_cost,
        )
        self.assertGreater(self.joint.response_readiness_score, 0)
        self.assertGreater(self.joint.detection_strength_score, 0)
        self.assertGreater(self.joint.weighted_detection_latency, 0)
        self.assertGreater(self.joint.false_positive_cost, 0)
        self.assertIn("c8", self.joint.detection_latency)

    def test_joint_runtime_still_reaches_confirmed_on_policy_tamper(self) -> None:
        result = self.runtime_results["ps0_policy_tamper"]
        self.assertEqual(result.current_mode, "attack_confirmed")
        self.assertIn(("lockdown_pep", "pep_group"), result.response_actions)


if __name__ == "__main__":
    unittest.main()
