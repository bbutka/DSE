import unittest

import runClingo_tc9_precise as precise_runner
from tc9_precise_math import compute_precise_phase1_math, load_tc9_math_facts


class Tc9PreciseMathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.facts = load_tc9_math_facts(precise_runner.legacy.BASE_DIR)

    def test_fixed_selection_exact_risk_matches_expected_rows(self) -> None:
        security = {
            "c1": "mac",
            "c2": "mac",
            "c3": "mac",
            "c4": "mac",
            "c5": "zero_trust",
            "c6": "zero_trust",
            "c7": "zero_trust",
            "c8": "mac",
        }
        logging = {
            "c1": "some_logging",
            "c2": "some_logging",
            "c3": "some_logging",
            "c4": "some_logging",
            "c5": "no_logging",
            "c6": "some_logging",
            "c7": "some_logging",
            "c8": "no_logging",
        }

        result = compute_precise_phase1_math(self.facts, security, logging)

        self.assertEqual(result.total_risk, 2688)
        self.assertEqual(result.rounded_risk["c1r1"], {"read": 113, "write": 566})
        self.assertEqual(result.rounded_risk["c2r1"], {"read": 566, "write": 227})
        self.assertEqual(result.rounded_risk["c3r1"], {"read": 340, "write": 340})
        self.assertEqual(result.rounded_risk["c4r1"], {"read": 340, "write": 453})
        self.assertEqual(result.rounded_risk["c5r1"], {"read": 453, "write": 113})
        self.assertGreater(result.combined_prob_norm[1], 0)
        self.assertGreater(result.new_prob_denormalized["c1"], 0)

    def test_precise_phase1_runner_selects_expected_best_frontier_candidate(self) -> None:
        selection = precise_runner.phase1_precise()
        p1 = selection.phase1

        self.assertEqual(selection.approx_frontier_size, 40)
        self.assertEqual(selection.approx_opt_cost, (530,))
        self.assertEqual(p1.total_risk(), 2688)
        self.assertEqual(p1.security["c5"], "zero_trust")
        self.assertEqual(p1.logging["c1"], "some_logging")
        self.assertEqual(p1.total_luts, 7808)
        self.assertEqual(p1.total_ffs, 6962)
        self.assertEqual(p1.total_dsps, 22)
        self.assertEqual(p1.total_lutram, 203)
        self.assertEqual(p1.total_bram, 10)
        self.assertEqual(p1.total_power, 106)

    def test_phase2_optimal_returns_proven_min_cost_solution(self) -> None:
        selection = precise_runner.phase1_precise()
        p2 = precise_runner.phase2_optimal(selection.phase1)

        self.assertTrue(p2.satisfiable)
        self.assertEqual(sorted(p2.placed_fws), ["pep_group", "pep_standalone"])
        self.assertEqual(sorted(p2.placed_ps), ["ps0"])
        self.assertEqual(p2.total_cost, 450)


if __name__ == "__main__":
    unittest.main()
