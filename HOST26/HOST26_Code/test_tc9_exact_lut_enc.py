from __future__ import annotations

import unittest
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
LUT_PATH = BASE_DIR / "Clingo" / "tc9_combined_prob_norm_size5_lut.lp"


class Tc9ExactLutEncodingTests(unittest.TestCase):
    def test_lookup_contains_original_tc9_input_tuple(self) -> None:
        text = LUT_PATH.read_text(encoding="utf-8")
        self.assertIn("combined_prob_norm_size5_lut(589,589,384,589,589,462160).", text)

    def test_lookup_contains_low_risk_tuple(self) -> None:
        text = LUT_PATH.read_text(encoding="utf-8")
        self.assertIn("combined_prob_norm_size5_lut(179,179,179,179,76,780).", text)


if __name__ == "__main__":
    unittest.main()
