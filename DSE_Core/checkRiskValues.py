"""Standalone sanity-check script for the current Phase 1 risk model.

This mirrors the active exposure/realtime/exploitability formulas used by the
integrated DSE_Core flow. It is intended for quick manual spot checks only.
"""

from __future__ import annotations

from ip_catalog.xilinx_ip_catalog import (
    EXPLOIT_FACTOR_MAP,
    EXPOSURE_VALUES,
    REALTIME_DETECTION_VALUES,
)


MU = 25
OMEGA = 1000

REDUNDANT_GROUPS = [
    ("c1", "c2", "c3", "c4", "c5"),
]

ASSET_IMPACTS = {
    "c1": {"max_read_impact": 1, "max_write_impact": 5},
    "c2": {"max_read_impact": 5, "max_write_impact": 2},
    "c3": {"max_read_impact": 3, "max_write_impact": 3},
    "c4": {"max_read_impact": 3, "max_write_impact": 4},
    "c5": {"max_read_impact": 4, "max_write_impact": 1},
    "c6": {"max_read_impact": 5, "max_write_impact": 3},
    "c7": {"max_read_impact": 1, "max_write_impact": 2},
    "c8": {"max_read_impact": 2, "max_write_impact": 4},
}

SECURITY_FEATURES = {component: "zero_trust" for component in ASSET_IMPACTS}
REALTIME_FEATURES = {component: "runtime_attestation" for component in ASSET_IMPACTS}
EXPLOITABILITY = {component: 3 for component in ASSET_IMPACTS}


def trunc_div(numerator: int, denominator: int) -> int:
    quotient = abs(numerator) // abs(denominator)
    if (numerator < 0) ^ (denominator < 0):
        return -quotient
    return quotient


def standalone_risk(component: str, impact: int) -> int:
    exposure = int(EXPOSURE_VALUES[SECURITY_FEATURES[component]])
    realtime = int(REALTIME_DETECTION_VALUES[REALTIME_FEATURES[component]])
    exploit_factor = int(EXPLOIT_FACTOR_MAP[EXPLOITABILITY.get(component, 3)])
    return trunc_div(impact * exposure * realtime * exploit_factor, 100)


def normalized_component_prob(component: str) -> int:
    exposure = int(EXPOSURE_VALUES[SECURITY_FEATURES[component]])
    realtime = int(REALTIME_DETECTION_VALUES[REALTIME_FEATURES[component]])
    original_prob = exposure * realtime
    return trunc_div((original_prob - MU) * 1000, OMEGA - MU)


def group_denorm_prob(group: tuple[str, ...]) -> int:
    partial = None
    for component in group:
        normalized = normalized_component_prob(component)
        if partial is None:
            partial = normalized
        else:
            partial = trunc_div(partial * normalized, 1000)
    if partial is None:
        return 0
    return trunc_div(partial * (OMEGA - MU), 1000) + MU * 10


def redundant_risk(component: str, impact: int, denorm_prob: int) -> int:
    exploit_factor = int(EXPLOIT_FACTOR_MAP[EXPLOITABILITY.get(component, 3)])
    return trunc_div(impact * denorm_prob * exploit_factor, 1000)


def main() -> None:
    grouped = {component for group in REDUNDANT_GROUPS for component in group}

    print("CURRENT PHASE 1 RISK MODEL CHECK")
    print("=" * 60)
    print("Standalone formula: Impact * Exposure * Detection * ExploitFactor / 100")
    print("Redundant formula:  Impact * denorm_combined_prob * ExploitFactor / 1000")
    print()

    for group in REDUNDANT_GROUPS:
        denorm = group_denorm_prob(group)
        print(f"Redundant group {group}: denorm_combined_prob = {denorm}")
    print()

    for component, impacts in ASSET_IMPACTS.items():
        read_impact = impacts.get("max_read_impact", 0)
        write_impact = impacts.get("max_write_impact", 0)
        if component in grouped:
            group = next(group for group in REDUNDANT_GROUPS if component in group)
            denorm = group_denorm_prob(group)
            read_risk = redundant_risk(component, read_impact, denorm)
            write_risk = redundant_risk(component, write_impact, denorm)
            mode = "redundant"
        else:
            read_risk = standalone_risk(component, read_impact)
            write_risk = standalone_risk(component, write_impact)
            mode = "standalone"

        exploitability = EXPLOITABILITY.get(component, 3)
        print(f"Component: {component} ({mode})")
        print(f"  security   = {SECURITY_FEATURES[component]}")
        print(f"  realtime   = {REALTIME_FEATURES[component]}")
        print(f"  exploit    = {exploitability} -> factor {EXPLOIT_FACTOR_MAP[exploitability]}")
        print(f"  read risk  = {read_risk}")
        print(f"  write risk = {write_risk}")
        print()


if __name__ == "__main__":
    main()
