from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ip_catalog.xilinx_ip_catalog import export_security_features_to_lp


class VivadoCatalogExportTest(unittest.TestCase):
    def test_export_writes_vivado_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "security_features_inst.lp"
            export_security_features_to_lp(out)
            text = out.read_text(encoding="utf-8")

        self.assertIn("luts(mac, byComponent, 650).", text)
        self.assertIn("ffs(dynamic_mac, byComponent, 680).", text)
        self.assertIn("lutram(zero_trust, byComponent, 64).", text)
        self.assertIn("bram(zero_trust_logger, base, 2).", text)
        self.assertIn("power_cost(some_logging, base, 4).", text)
        self.assertIn("latency_cost(zero_trust, 3).", text)
        self.assertIn("latency_cost(mac, 4).", text)


if __name__ == "__main__":
    unittest.main()
