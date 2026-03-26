import unittest
from pathlib import Path

from tc9_cpsat_phase1 import benchmark_against_precise_helper, solve_cpsat_phase1


BASE_DIR = Path(__file__).resolve().parent


class Tc9CpSatPhase1Tests(unittest.TestCase):
    def test_cpsat_selection_is_stable(self) -> None:
        selection = solve_cpsat_phase1(BASE_DIR)

        self.assertTrue(selection.optimal)
        self.assertEqual(selection.precise_math.total_risk, 525)
        self.assertEqual(selection.exact_frontier_size, 1)
        self.assertFalse(selection.exact_frontier_truncated)
        self.assertEqual(
            selection.security,
            {
                "c1": "zero_trust",
                "c2": "zero_trust",
                "c3": "zero_trust",
                "c4": "zero_trust",
                "c5": "zero_trust",
                "c6": "zero_trust",
                "c7": "zero_trust",
                "c8": "mac",
            },
        )
        self.assertEqual(
            selection.logging,
            {
                "c1": "no_logging",
                "c2": "no_logging",
                "c3": "no_logging",
                "c4": "no_logging",
                "c5": "some_logging",
                "c6": "some_logging",
                "c7": "some_logging",
                "c8": "no_logging",
            },
        )
        self.assertEqual(selection.resources, {"luts": 13670, "ffs": 21382, "dsps": 66, "lutram": 1413, "bram": 62, "power": 254})

    def test_cpsat_beats_precise_helper_reference(self) -> None:
        benchmark = benchmark_against_precise_helper(BASE_DIR)

        self.assertEqual(benchmark.precise_selection.precise_math.total_risk, 2688)
        self.assertEqual(benchmark.cpsat_selection.precise_math.total_risk, 525)
        self.assertLess(benchmark.cpsat_selection.precise_math.total_risk, benchmark.precise_selection.precise_math.total_risk)
        self.assertNotEqual(benchmark.precise_selection.phase1.security, benchmark.cpsat_selection.security)
        self.assertEqual(len(benchmark.path_rows), 8)


if __name__ == "__main__":
    unittest.main()
