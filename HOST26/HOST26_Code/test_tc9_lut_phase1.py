from __future__ import annotations

import unittest
from pathlib import Path

from tc9_lut_phase1 import _load_pair_log_facts, phase1_lut


BASE_DIR = Path(__file__).resolve().parent


class Tc9LutPhase1Tests(unittest.TestCase):
    def test_pair_log_facts_loaded(self) -> None:
        facts = _load_pair_log_facts(BASE_DIR)
        self.assertEqual(facts[("zero_trust", "no_logging")].prob_scaled, 179487)
        self.assertEqual(facts[("mac", "no_logging")].log_weight, 13287444)

    def test_phase1_lut_matches_expected_selection(self) -> None:
        selection = phase1_lut(BASE_DIR)
        self.assertEqual(selection.precise_math.total_risk, 515)
        self.assertEqual(selection.approx_frontier_size, 1)
        self.assertEqual(selection.phase1.security["c1"], "zero_trust")
        self.assertEqual(selection.phase1.logging["c7"], "zero_trust_logger")
        self.assertEqual(selection.member_prob_scaled["c5"], 76923)


if __name__ == "__main__":
    unittest.main()
