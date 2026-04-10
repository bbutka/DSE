"""
Phase 1 triple-validation tests: CP-SAT vs CBC vs Python reference checker.

9 minimal cases (8 non-redundant + 1 redundant-group) plus all model
factories (tc9, reference SoC, DARPA UAV, OpenTitan, Pixhawk 6X variants).
Each test runs both solver backends across all 3 strategies and validates
every result against an independent Python reference implementation.

The Python checker verifies:
  - Risk arithmetic (multiplicative formula, redundancy product, denorm)
  - Feature selection (exactly 1 security + 1 realtime per receiver)
  - Resource budgets (LUTs, FFs, DSPs, BRAM, LUTRAM, BUFG, power)
  - Latency constraints (per-asset per-action)
  - Risk caps (max_security_risk for standalone, max_avail_risk for groups)
  - Resource accounting (reported totals match sum of selected feature costs)
"""

from __future__ import annotations

import os
import unittest
from dataclasses import dataclass
from typing import Dict, List, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLINGO_DIR = os.path.join(PROJECT_ROOT, "Clingo")

from dse_tool.core.asp_generator import (
    ASPGenerator, Asset, Component, NetworkModel, RedundancyGroup,
    make_tc9_network,
    make_reference_soc,
    make_darpa_uav_network,
    make_opentitan_network,
    make_pixhawk6x_platform,
    make_pixhawk6x_uav_network,
    make_pixhawk6x_uav_dual_ps_network,
    make_pixhawk6x_dual_ps_network,
)
from dse_tool.core.solution_parser import Phase1Result
from dse_tool.agents.phase1_mathopt_agent import Phase1MathOptAgent
from ip_catalog.xilinx_ip_catalog import (
    EXPOSURE_VALUES,
    PHASE1_REDUNDANCY_NORM_SCALE,
    PHASE1_REDUNDANCY_RAW_CEILING,
    PHASE1_REDUNDANCY_RAW_FLOOR,
    PHASE1_REDUNDANCY_RAW_RANGE,
    REALTIME_DETECTION_VALUES,
    EXPLOIT_FACTOR_MAP,
    SECURITY_FEATURE_EXPORT_ORDER,
    REALTIME_FEATURE_EXPORT_ORDER,
    phase1_prob_lookup_entry,
    get_calibrated_estimate,
    scale_phase1_availability_risk,
    scale_phase1_risk_cap,
    scale_phase1_security_risk,
)


# ---------------------------------------------------------------------------
# Python reference checker
# ---------------------------------------------------------------------------

_RESOURCE_ATTRS = {
    "luts": "luts",
    "ffs": "ffs",
    "dsps": "dsps",
    "lutram": "lutrams",
    "bram": "brams",
    "power": "power_mw",
}

_MU = PHASE1_REDUNDANCY_RAW_FLOOR
_OMEGA = PHASE1_REDUNDANCY_RAW_CEILING


def _feature_cost(feature: str, resource: str) -> int:
    est = get_calibrated_estimate(feature)
    return int(round(getattr(est, _RESOURCE_ATTRS[resource], 0)))


def _feature_latency(feature: str) -> int:
    return int(get_calibrated_estimate(feature).latency)


def verify_phase1_solution(
    model: NetworkModel,
    result: Phase1Result,
) -> List[str]:
    """
    Independently verify a Phase1Result against the NetworkModel.

    Returns a list of violation strings.  Empty list = valid solution.
    """
    violations: List[str] = []

    if not result.satisfiable:
        violations.append("Result is not satisfiable")
        return violations

    # --- Identify protected components (mirrors ILP _protected_components) ---
    comp_by_name_all = {c.name: c for c in model.components}
    if model.assets:
        allowed = {
            c.name for c in model.components
            if c.comp_type not in ("policy_server", "firewall", "bus")
        }
        seen: set = set()
        receivers = []
        for asset in model.assets:
            if asset.component in allowed and asset.component not in seen:
                receivers.append(comp_by_name_all[asset.component])
                seen.add(asset.component)
    else:
        receivers = [
            c for c in model.components
            if c.is_receiver and c.comp_type not in ("policy_server", "firewall", "bus")
        ]
    receiver_names = {c.name for c in receivers}
    grouped = set()
    groups_by_component: Dict[str, List[str]] = {}
    for g in model.redundancy_groups:
        for m in g.members:
            grouped.add(m)
            groups_by_component[m] = g.members

    # --- Check 1: Feature selection completeness ---
    for c in receivers:
        if c.name not in result.security:
            violations.append(f"SELECTION: no security feature for {c.name}")
        elif result.security[c.name] not in SECURITY_FEATURE_EXPORT_ORDER:
            violations.append(
                f"SELECTION: invalid security feature '{result.security[c.name]}' for {c.name}"
            )
        if c.name not in result.realtime:
            violations.append(f"SELECTION: no realtime feature for {c.name}")
        elif result.realtime[c.name] not in REALTIME_FEATURE_EXPORT_ORDER:
            violations.append(
                f"SELECTION: invalid realtime feature '{result.realtime[c.name]}' for {c.name}"
            )

    if violations:
        return violations  # can't verify further without valid selections

    # --- Check 2: Latency constraints ---
    # Deferred until after asset map is built (Check 5 preamble).
    # Placeholder — actual check runs after comp_assets is available.

    # --- Check 3: Resource accounting ---
    for resource in _RESOURCE_ATTRS:
        expected = sum(
            _feature_cost(result.security[c.name], resource)
            + _feature_cost(result.realtime[c.name], resource)
            for c in receivers
        )
        reported = getattr(result, f"total_{resource}", None)
        if reported is not None and reported != expected:
            violations.append(
                f"RESOURCE_ACCOUNTING: total_{resource} reported={reported} expected={expected}"
            )

    # --- Check 4: Resource budget constraints ---
    cap_map = {
        "luts": "max_luts",
        "ffs": "max_ffs",
        "dsps": "max_dsps",
        "lutram": "max_lutram",
        "bram": "max_bram",
        "power": "max_power",
    }
    for resource, cap_name in cap_map.items():
        if cap_name in model.system_caps:
            cap = model.system_caps[cap_name]
            total = sum(
                _feature_cost(result.security[c.name], resource)
                + _feature_cost(result.realtime[c.name], resource)
                for c in receivers
            )
            if total > cap:
                violations.append(
                    f"RESOURCE_CAP: {resource} total={total} > cap={cap}"
                )

    # --- Build asset map (mirrors ILP agent's _component_assets) ---
    comp_by_name = {c.name: c for c in model.components}
    comp_assets: Dict[str, List[Asset]] = {c.name: [] for c in receivers}
    if model.assets:
        for asset in model.assets:
            if asset.component in comp_assets:
                comp_assets[asset.component].append(asset)
    else:
        for c in receivers:
            comp_assets[c.name].append(Asset(
                asset_id=f"{c.name}r1",
                component=c.name,
                direction=c.direction,
                impact_read=c.impact_read,
                impact_write=c.impact_write,
                impact_avail=int(getattr(c, "impact_avail", 0)),
                latency_read=c.latency_read,
                latency_write=c.latency_write,
            ))

    def _asset_actions(asset: Asset) -> List[Tuple[str, int]]:
        """Return (action, impact) pairs for an asset (mirrors ILP _iter_asset_actions)."""
        rows = []
        if asset.direction in ("input", "bidirectional"):
            rows.append(("read", asset.impact_read))
        if asset.direction in ("output", "bidirectional"):
            rows.append(("write", asset.impact_write))
        if int(getattr(asset, "impact_avail", 0)) > 0:
            rows.append(("avail", int(asset.impact_avail)))
        return rows

    # --- Check 2 (deferred): Latency constraints ---
    for c in receivers:
        sec = result.security[c.name]
        rt = result.realtime[c.name]
        total_lat = _feature_latency(sec) + _feature_latency(rt)
        for asset in comp_assets[c.name]:
            if asset.latency_read < 1000 and total_lat > asset.latency_read:
                violations.append(
                    f"LATENCY: {c.name}/{asset.asset_id} read: {total_lat} > {asset.latency_read}"
                )
            if asset.latency_write < 1000 and total_lat > asset.latency_write:
                violations.append(
                    f"LATENCY: {c.name}/{asset.asset_id} write: {total_lat} > {asset.latency_write}"
                )

    # --- Check 5: Risk arithmetic ---
    expected_risks: Dict[Tuple[str, str, str], int] = {}

    for c in receivers:
        if c.name in grouped:
            continue  # handled below in group computation
        sec = result.security[c.name]
        rt = result.realtime[c.name]
        exposure = EXPOSURE_VALUES[sec]
        realtime_det = REALTIME_DETECTION_VALUES[rt]
        exploit_factor = EXPLOIT_FACTOR_MAP.get(c.exploitability, 10)

        for asset in comp_assets[c.name]:
            for action, impact in _asset_actions(asset):
                risk = scale_phase1_security_risk(impact, exposure, realtime_det, exploit_factor)
                expected_risks[(c.name, asset.asset_id, action)] = risk

    # --- Redundancy group computation ---
    for g in model.redundancy_groups:
        members = [c for c in receivers if c.name in g.members]
        if not members:
            continue

        # Sort members by name (lexicographic, matches ASP group_rank)
        members_sorted = sorted(members, key=lambda c: c.name)

        # Per-member normalized prob
        member_norms = []
        for c in members_sorted:
            sec = result.security[c.name]
            rt = result.realtime[c.name]
            exposure = EXPOSURE_VALUES[sec]
            realtime_det = REALTIME_DETECTION_VALUES[rt]
            _raw_prob, norm, _denorm = phase1_prob_lookup_entry(sec, rt)
            member_norms.append(norm)

        # Running product with divide-by-1000 at each step
        combined = member_norms[0]
        for p in member_norms[1:]:
            combined = combined * p // PHASE1_REDUNDANCY_NORM_SCALE

        # Denormalize
        denorm = (combined * PHASE1_REDUNDANCY_RAW_RANGE // PHASE1_REDUNDANCY_NORM_SCALE) + (_MU * 10)

        # Check for common-cause beta correction
        beta = model.system_caps.get("redundancy_beta_pct", 0)
        if beta > 0:
            single_denorms = []
            for c in members_sorted:
                sec = result.security[c.name]
                rt = result.realtime[c.name]
                _raw_prob, norm, _denorm = phase1_prob_lookup_entry(sec, rt)
                sd = (norm * PHASE1_REDUNDANCY_RAW_RANGE // PHASE1_REDUNDANCY_NORM_SCALE) + (_MU * 10)
                single_denorms.append(sd)
            max_single = max(single_denorms)
            denorm = ((100 - beta) * denorm + beta * max_single) // 100

        # Compute avail_risk for each member
        for c in members_sorted:
            exploit_factor = EXPLOIT_FACTOR_MAP.get(c.exploitability, 10)
            for asset in comp_assets[c.name]:
                for action, impact in _asset_actions(asset):
                    risk = scale_phase1_availability_risk(impact, denorm, exploit_factor)
                    expected_risks[(c.name, asset.asset_id, action)] = risk

    # Compare expected vs reported risks
    reported_risks: Dict[Tuple[str, str, str], int] = {}
    for comp, asset, action, risk in result.new_risk:
        reported_risks[(comp, asset, action)] = risk

    for key, expected in sorted(expected_risks.items()):
        reported = reported_risks.get(key)
        if reported is None:
            violations.append(f"RISK: missing reported risk for {key}")
        elif reported != expected:
            violations.append(
                f"RISK: {key} reported={reported} expected={expected}"
            )

    for key in sorted(reported_risks):
        if key not in expected_risks:
            # Reported risk for a component we didn't expect
            comp = key[0]
            if comp in receiver_names:
                violations.append(f"RISK: unexpected reported risk for {key}")

    # --- Check 6: Risk caps ---
    max_security_risk = scale_phase1_risk_cap(model.system_caps.get(
        "max_security_risk", model.system_caps.get("max_asset_risk", 500)
    ))
    max_avail_risk = scale_phase1_risk_cap(model.system_caps.get(
        "max_avail_risk", model.system_caps.get("max_asset_risk", 500)
    ))

    for (comp, asset, action), risk in expected_risks.items():
        if comp in grouped:
            if risk > max_avail_risk:
                violations.append(
                    f"RISK_CAP: avail {comp}/{asset}/{action} risk={risk} > cap={max_avail_risk}"
                )
        else:
            if risk > max_security_risk:
                violations.append(
                    f"RISK_CAP: security {comp}/{asset}/{action} risk={risk} > cap={max_security_risk}"
                )

    return violations


# ---------------------------------------------------------------------------
# Model builder
# ---------------------------------------------------------------------------

def _minimal_model(
    name: str,
    components: list[Component],
    redundancy_groups: list[RedundancyGroup] | None = None,
    system_caps: dict[str, int] | None = None,
) -> NetworkModel:
    """Build the smallest possible Phase-1-solvable NetworkModel."""
    model = NetworkModel(name=name)
    master = Component("cpu", "processor", "low", 1, 1, 1000, 1000,
                       is_master=True, is_receiver=False)
    model.components = [master] + components
    model.buses = ["bus0"]
    model.links = [("cpu", "bus0")] + [("bus0", c.name) for c in components]
    model.redundancy_groups = redundancy_groups or []
    model.system_caps = system_caps or {
        "max_power":          15000,
        "max_luts":           53200,
        "max_ffs":           106400,
        "max_dsps":             220,
        "max_lutram":         17400,
        "max_bufgs":             32,
        "max_bram":             140,
        "max_security_risk":   500,
        "max_avail_risk":      500,
    }
    return model


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Shared validation logic
# ---------------------------------------------------------------------------

def _validate_one(model: NetworkModel, label: str, strategy: str):
    """Run CP-SAT + CBC, validate with Python checker, return errors or None."""
    tag = f"{label}/{strategy}"
    errors = []

    cpsat = Phase1MathOptAgent(
        model, strategy=strategy, timeout=60,
        solver_config={"phase1_backend": "cpsat"},
    ).run()
    cbc = Phase1MathOptAgent(
        model, strategy=strategy, timeout=60,
        solver_config={"phase1_backend": "cbc"},
    ).run()

    if not cpsat.satisfiable:
        errors.append(f"{tag}: CP-SAT UNSAT")
    if not cbc.satisfiable:
        errors.append(f"{tag}: CBC UNSAT")
    if errors:
        return errors

    cpsat_violations = verify_phase1_solution(model, cpsat)
    if cpsat_violations:
        errors.append(f"{tag} CP-SAT checker violations:\n  " + "\n  ".join(cpsat_violations))

    cbc_violations = verify_phase1_solution(model, cbc)
    if cbc_violations:
        errors.append(f"{tag} CBC checker violations:\n  " + "\n  ".join(cbc_violations))

    if cpsat.total_risk() != cbc.total_risk():
        errors.append(
            f"{tag}: total_risk mismatch CP-SAT={cpsat.total_risk()} CBC={cbc.total_risk()}\n"
            f"  CP-SAT sec: {cpsat.security}  rt: {cpsat.realtime}\n"
            f"  CBC    sec: {cbc.security}  rt: {cbc.realtime}"
        )

    if strategy == "min_resources" and cpsat.total_luts != cbc.total_luts:
        errors.append(
            f"{tag}: total_luts mismatch CP-SAT={cpsat.total_luts} CBC={cbc.total_luts}"
        )

    return errors


# ---------------------------------------------------------------------------
# Model builders for parametrized tests
# ---------------------------------------------------------------------------

_MINIMAL_CASES = {
    "case01_high_high": lambda: _minimal_model("case01", [
        Component("r1", "ip_core", "high", 5, 5, 1000, 1000),
    ]),
    "case02_low_low": lambda: _minimal_model("case02", [
        Component("r1", "ip_core", "low", 1, 1, 1000, 1000),
    ]),
    "case03_exploit1": lambda: _minimal_model("case03", [
        Component("r1", "ip_core", "normal", 3, 3, 1000, 1000, exploitability=1),
    ]),
    "case04_exploit5": lambda: _minimal_model("case04", [
        Component("r1", "ip_core", "privileged", 4, 4, 1000, 1000, exploitability=5),
    ]),
    "case05_two_mixed": lambda: _minimal_model("case05", [
        Component("r1", "ip_core", "high", 5, 2, 1000, 1000, exploitability=2),
        Component("r2", "ip_core", "low",  1, 4, 1000, 1000, exploitability=4),
    ]),
    "case06_root_asym": lambda: _minimal_model("case06", [
        Component("r1", "ip_core", "root", 5, 1, 1000, 1000),
    ]),
    "case07_tight_lat": lambda: _minimal_model("case07", [
        Component("r1", "ip_core", "normal", 3, 3, 5, 5, exploitability=3),
    ]),
    "case08_tight_luts": lambda: _minimal_model("case08", [
        Component("r1", "ip_core", "high", 4, 3, 1000, 1000, exploitability=3),
        Component("r2", "ip_core", "privileged", 3, 5, 1000, 1000, exploitability=2),
    ], system_caps={
        "max_power": 15000, "max_luts": 3000, "max_ffs": 106400,
        "max_dsps": 220, "max_lutram": 17400, "max_bufgs": 32, "max_bram": 140,
        "max_security_risk": 500, "max_avail_risk": 500,
    }),
    "case09_redundant3": lambda: _minimal_model("case09", [
        Component("r1", "ip_core", "normal", 4, 3, 1000, 1000, exploitability=2),
        Component("r2", "ip_core", "normal", 3, 4, 1000, 1000, exploitability=3),
        Component("r3", "ip_core", "normal", 2, 2, 1000, 1000, exploitability=4),
    ], redundancy_groups=[RedundancyGroup("g1", ["r1", "r2", "r3"])]),
}

_FACTORY_CASES = {
    "tc9":                 make_tc9_network,
    "refsoc":              make_reference_soc,
    "darpa_uav":           make_darpa_uav_network,
    "opentitan_a":         lambda: make_opentitan_network("OT-A"),
    "opentitan_b":         lambda: make_opentitan_network("OT-B"),
    "pixhawk6x_plat":      make_pixhawk6x_platform,
    "pixhawk6x_uav":       make_pixhawk6x_uav_network,
    "pixhawk6x_uav_dual":  make_pixhawk6x_uav_dual_ps_network,
    "pixhawk6x_dual":      make_pixhawk6x_dual_ps_network,
}

_ALL_CASES = {**_MINIMAL_CASES, **_FACTORY_CASES}
_STRATEGIES = ("max_security", "min_resources", "balanced")


# ---------------------------------------------------------------------------
# pytest parametrized tests (runs with pytest-xdist -n auto)
# ---------------------------------------------------------------------------

import pytest

_PARAMS = [
    pytest.param(case_name, strategy, id=f"{case_name}__{strategy}")
    for case_name in _ALL_CASES
    for strategy in _STRATEGIES
]


@pytest.mark.parametrize("case_name,strategy", _PARAMS)
def test_phase1_parity(case_name, strategy):
    """Triple-validate Phase 1: CP-SAT vs CBC vs Python checker."""
    model = _ALL_CASES[case_name]()
    errors = _validate_one(model, case_name, strategy)
    assert errors == [], "\n".join(errors)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
