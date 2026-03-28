from __future__ import annotations

import unittest

from export_tc9_phase1_minizinc import build_tc9_phase1_dzn


class ExportTc9MiniZincTest(unittest.TestCase):
    def test_generated_dzn_contains_core_parameters(self) -> None:
        text = build_tc9_phase1_dzn().text
        self.assertIn("n_components = 8;", text)
        self.assertIn('component_name = ["c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8"];', text)
        self.assertIn('security_name = ["zero_trust", "mac", "dynamic_mac"];', text)
        self.assertIn('logging_name = ["zero_trust_logger", "some_logging", "no_logging"];', text)
        self.assertIn("n_groups = 1;", text)
        self.assertIn("group_size = [5];", text)
        self.assertIn("max_asset_risk = 500;", text)
        self.assertIn("max_luts = 53200;", text)


if __name__ == "__main__":
    unittest.main()
