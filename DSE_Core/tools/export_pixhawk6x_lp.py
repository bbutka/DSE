"""Export generated Pixhawk 6X ASP facts to reference .lp files.

These files are for reproducibility, documentation, and direct Clingo
inspection. The integrated pipeline still generates facts dynamically from the
Python `NetworkModel` factories.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dse_tool.core.asp_generator import (  # noqa: E402
    ASPGenerator,
    make_pixhawk6x_dual_ps_network,
    make_pixhawk6x_platform,
    make_pixhawk6x_uav_network,
)


CLINGO_DIR = PROJECT_ROOT / "Clingo"


def _write_export(filename: str, title: str, facts: str) -> Path:
    path = CLINGO_DIR / filename
    header = [
        f"% {title}",
        "%",
        "% Generated from the Python NetworkModel factory for reproducibility and",
        "% direct Clingo inspection. The integrated DSE_Core pipeline continues to",
        "% generate instance facts dynamically at runtime.",
        "",
    ]
    path.write_text("\n".join(header) + facts.strip() + "\n", encoding="utf-8")
    return path


def main() -> None:
    platform = make_pixhawk6x_platform()
    uav = make_pixhawk6x_uav_network()
    uav_dual_ps = make_pixhawk6x_dual_ps_network()

    platform_facts = ASPGenerator(platform).generate()
    uav_facts = ASPGenerator(uav).generate()
    uav_dual_ps_facts = ASPGenerator(uav_dual_ps).generate()

    exported = [
        _write_export(
            "tgt_system_pixhawk6x_platform_inst.lp",
            "Pixhawk 6X platform generated instance facts",
            platform_facts,
        ),
        _write_export(
            "tgt_system_pixhawk6x_uav_inst.lp",
            "Pixhawk 6X UAV generated instance facts",
            uav_facts,
        ),
        _write_export(
            "tgt_system_pixhawk6x_uav_dual_ps_inst.lp",
            "Pixhawk 6X UAV dual-PS generated instance facts",
            uav_dual_ps_facts,
        ),
    ]

    for path in exported:
        print(path)


if __name__ == "__main__":
    main()
