"""
Regenerate checked-in Phase 1 golden baseline fixtures.

By default this refreshes the fast-path entries that are exercised in CI:
- tc9 max_security
- DARPA UAV max_security
- OpenTitan OT-A/OT-B/OT-C
- Pixhawk 6X UAV max_security

Pass ``--slow`` to also refresh the balanced/min_resources entries for the
tc9, DARPA UAV, and Pixhawk fixtures. Those paths can take substantially longer.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tests import test_golden_baselines as baselines


FIXTURES_DIR = Path(baselines.FIXTURES_DIR)
GENERATED_BY = "tools/regenerate_phase1_golden_fixtures.py"
RISK_UNITS = "milli"


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _update_strategy_fixture(
    filename: str,
    runner,
    strategies: tuple[str, ...],
    timeout: int,
) -> None:
    path = FIXTURES_DIR / filename
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["risk_units"] = RISK_UNITS
    payload["generated_by"] = GENERATED_BY
    for strategy in strategies:
        p1, p2, p3 = runner(strategy, timeout)
        payload[strategy] = {
            "satisfiable": p1.satisfiable,
            "total_risk": p1.total_risk(),
            "total_luts": p1.total_luts,
            "total_power": p1.total_power,
            "phase2_satisfiable": p2.satisfiable,
            "placed_fws": sorted(set(p2.placed_fws)),
            "placed_ps": sorted(set(p2.placed_ps)),
            "phase3_scenario_count": len(p3),
            "phase3_worst_case_risk_scaled": baselines._worst_case_risk_scaled(p3),
        }
    _write_json(path, payload)


def _update_opentitan_fixture(timeout: int) -> None:
    path = FIXTURES_DIR / "opentitan_phase1_baseline.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["risk_units"] = RISK_UNITS
    payload["generated_by"] = GENERATED_BY
    for profile in ("OT-A", "OT-B", "OT-C"):
        p1 = baselines._run_opentitan_phase1(profile, timeout)
        payload[profile] = {
            "satisfiable": p1.satisfiable,
            "total_risk": p1.total_risk(),
            "total_luts": p1.total_luts,
            "total_power": p1.total_power,
        }
    _write_json(path, payload)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--slow",
        action="store_true",
        help="also refresh balanced/min_resources entries for tc9, DARPA UAV, and Pixhawk",
    )
    args = parser.parse_args()

    fast_only = baselines.FAST_STRATEGIES
    all_strategies = baselines.FAST_STRATEGIES + baselines.SLOW_STRATEGIES
    strategy_set = all_strategies if args.slow else fast_only
    timeout = baselines.SLOW_TIMEOUT if args.slow else baselines.FAST_TIMEOUT

    _update_strategy_fixture("tc9_baseline.json", baselines._run_tc9_pipeline, strategy_set, timeout)
    _update_strategy_fixture("darpa_uav_baseline.json", baselines._run_darpa_pipeline, strategy_set, timeout)
    _update_opentitan_fixture(timeout)
    _update_strategy_fixture("pixhawk6x_baseline.json", baselines._run_pixhawk_pipeline, strategy_set, timeout)


if __name__ == "__main__":
    main()
