"""
CP-SAT vs ASP/clingo benchmark for the ICCAD 2026 paper.

Solves the same Phase 1 security-feature synthesis problem using
Google OR-Tools CP-SAT, then compares against clingo on the ICCAD
benchmark instances and constraint profiles.

The formulation matches the maintained ICCAD benchmark model:
  - Multiplicative per-asset cyber risk: Impact * Vulnerability * Logging / 10
  - Scoped feature costs with one-time base, per-component, and per-asset terms
  - Shared security/logging base costs charged once when a feature is used
  - Minimise total risk (sum of per-asset risk over all component/asset/action)
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ortools.sat.python import cp_model


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class FeatureCatalog:
    security_features: list[str] = field(default_factory=list)
    logging_features: list[str] = field(default_factory=list)
    # resource_costs[resource][feature][tier] = int
    resource_costs: dict[str, dict[str, dict[str, int]]] = field(default_factory=dict)
    vulnerability: dict[str, int] = field(default_factory=dict)
    logging_score: dict[str, int] = field(default_factory=dict)
    latency_cost: dict[str, int] = field(default_factory=dict)
    security_protect_val: dict[str, int] = field(default_factory=dict)
    log_protect_val: dict[str, int] = field(default_factory=dict)


@dataclass
class TestCase:
    name: str
    components: list[str] = field(default_factory=list)
    # assets: list of (component, asset_name, action)
    assets: list[tuple[str, str, str]] = field(default_factory=list)
    # impact: (asset_name, action) -> int
    impact: dict[tuple[str, str], int] = field(default_factory=dict)
    # allowable_latency: (asset_name, action) -> int
    allowable_latency: dict[tuple[str, str], int] = field(default_factory=dict)
    # redundant_group: group_id -> [components]
    redundant_groups: dict[str, list[str]] = field(default_factory=dict)
    # domain: component -> "high" | "low"
    domain: dict[str, str] = field(default_factory=dict)


@dataclass
class Profile:
    name: str
    capabilities: dict[str, int] = field(default_factory=dict)


@dataclass
class SolveResult:
    testcase: str
    profile: str
    solver: str
    time_s: float
    objective: int
    satisfiable: bool
    optimal: bool
    security: dict[str, str] = field(default_factory=dict)
    logging: dict[str, str] = field(default_factory=dict)
    luts: int = 0
    ffs: int = 0
    power: int = 0
    bram: int = 0


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
CLINGO_DIR = BASE_DIR / "Clingo"
TESTCASE_DIR = BASE_DIR / "testCases"

RESOURCES = ("luts", "ffs", "dsps", "lutram", "bram", "bufg")
RESOURCE_LP_NAMES = {
    "luts": "luts", "ffs": "ffs", "dsps": "dsps",
    "lutram": "lutram", "bram": "bram", "bufg": "bufg",
}


def parse_catalog(path: Path) -> FeatureCatalog:
    cat = FeatureCatalog()
    for res in RESOURCES:
        cat.resource_costs[res] = {}
    cat.resource_costs["power"] = {}
    text = path.read_text(encoding="utf-8")

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("%"):
            continue

        m = re.match(r"security_feature\((\w+)\)\.", line)
        if m:
            cat.security_features.append(m.group(1))
            continue

        m = re.match(r"logging_feature\((\w+)\)\.", line)
        if m:
            cat.logging_features.append(m.group(1))
            continue

        m = re.match(r"(power_cost|luts|ffs|dsps|lutram|bram|bufg)\((\w+),\s*(\w+),\s*(-?\d+)\)\.", line)
        if m:
            res_name = "power" if m.group(1) == "power_cost" else m.group(1)
            feature, tier, value = m.group(2), m.group(3), int(m.group(4))
            cat.resource_costs[res_name].setdefault(feature, {})[tier] = value
            continue

        m = re.match(r"vulnerability\((\w+),\s*(-?\d+)\)\.", line)
        if m:
            cat.vulnerability[m.group(1)] = int(m.group(2))
            continue

        m = re.match(r"logging\((\w+),\s*(-?\d+)\)\.", line)
        if m:
            cat.logging_score[m.group(1)] = int(m.group(2))
            continue

        m = re.match(r"latency_cost\((\w+),\s*(-?\d+)\)\.", line)
        if m:
            cat.latency_cost[m.group(1)] = int(m.group(2))
            continue

        m = re.match(r"security_protect_val\((\w+),\s*(-?\d+)\)\.", line)
        if m:
            cat.security_protect_val[m.group(1)] = int(m.group(2))
            continue

        m = re.match(r"log_protect_val\((\w+),\s*(-?\d+)\)\.", line)
        if m:
            cat.log_protect_val[m.group(1)] = int(m.group(2))
            continue

    return cat


def parse_testcase(path: Path) -> TestCase:
    tc = TestCase(name=path.stem)
    text = path.read_text(encoding="utf-8")

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("%"):
            continue

        # component(c1; c2; c3).  or  component(c1).
        m = re.match(r"component\(([^)]+)\)\.", line)
        if m:
            parts = m.group(1).split(";")
            for p in parts:
                p = p.strip()
                if p:
                    tc.components.append(p)
            continue

        m = re.match(r"asset\((\w+),\s*(\w+),\s*(\w+)\)\.", line)
        if m:
            tc.assets.append((m.group(1), m.group(2), m.group(3)))
            continue

        m = re.match(r"impact\((\w+),\s*(\w+),\s*(-?\d+)\)\.", line)
        if m:
            tc.impact[(m.group(1), m.group(2))] = int(m.group(3))
            continue

        m = re.match(r"allowable_latency\((\w+),\s*(\w+),\s*(-?\d+)\)\.", line)
        if m:
            tc.allowable_latency[(m.group(1), m.group(2))] = int(m.group(3))
            continue

        m = re.match(r"redundant_group\((\w+),\s*(\w+)\)\.", line)
        if m:
            gid, comp = m.group(1), m.group(2)
            tc.redundant_groups.setdefault(gid, []).append(comp)
            continue

        m = re.match(r"domain\((\w+),\s*(\w+)\)\.", line)
        if m:
            tc.domain[m.group(1)] = m.group(2)
            continue

    return tc


def parse_profile(path: Path) -> Profile:
    prof = Profile(name=path.stem)
    text = path.read_text(encoding="utf-8")
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"system_capability\((\w+),\s*(-?\d+)\)\.", line)
        if m:
            prof.capabilities[m.group(1)] = int(m.group(2))
    return prof


# ---------------------------------------------------------------------------
# CP-SAT solver
# ---------------------------------------------------------------------------

# Constants matching the ASP encoding
MU = 25
OMEGA = 1000


def _pair_index(sec_idx: int, log_idx: int, n_log: int) -> int:
    return sec_idx * n_log + log_idx


def solve_cpsat(
    tc: TestCase, profile: Profile, catalog: FeatureCatalog
) -> SolveResult:
    model = cp_model.CpModel()
    n_sec = len(catalog.security_features)
    n_log = len(catalog.logging_features)
    n_pairs = n_sec * n_log

    def _cost(res: str, feature: str, tier: str) -> int:
        return catalog.resource_costs.get(res, {}).get(feature, {}).get(tier, 0)

    # Compute asset count per component (distinct asset names, matching ASP)
    comp_asset_count: dict[str, int] = {}
    for comp in tc.components:
        comp_asset_count[comp] = len(
            {a for c, a, _ in tc.assets if c == comp}
        )

    # Pre-compute shared pair tables for risk and feature names
    pair_sec = []
    pair_log = []
    pair_vl = []  # V * L product for each (sec, log) pair

    for si, sec in enumerate(catalog.security_features):
        for li, log in enumerate(catalog.logging_features):
            pair_sec.append(sec)
            pair_log.append(log)
            v = catalog.vulnerability.get(sec, 0)
            l = catalog.logging_score.get(log, 0)
            pair_vl.append(v * l)

    # Per-component pair resource tables (sec.byComponent + sec.byAsset * n_assets)
    # Logging costs are handled as one-time base costs below, NOT per-component.
    ALL_RES = ("luts", "ffs", "dsps", "lutram", "bram", "bufg", "power")

    # Decision variables: one pair index per component
    pair_vars: dict[str, cp_model.IntVar] = {}
    for comp in tc.components:
        pair_vars[comp] = model.new_int_var(0, n_pairs - 1, f"pair_{comp}")

    # Per-component resource lookup variables
    comp_res: dict[str, dict[str, cp_model.IntVar]] = {r: {} for r in ALL_RES}
    comp_vl: dict[str, cp_model.IntVar] = {}  # V*L product per component

    # Which security feature index each component uses (for base cost tracking)
    comp_sec_idx: dict[str, cp_model.IntVar] = {}
    comp_log_idx: dict[str, cp_model.IntVar] = {}

    for comp in tc.components:
        pv = pair_vars[comp]
        n_assets = comp_asset_count.get(comp, 1)

        # Security feature index = pair_index // n_log
        comp_sec_idx[comp] = model.new_int_var(0, n_sec - 1, f"si_{comp}")
        model.add_division_equality(comp_sec_idx[comp], pv, n_log)
        # Logging feature index = pair_index % n_log
        comp_log_idx[comp] = model.new_int_var(0, n_log - 1, f"li_{comp}")
        model.add_modulo_equality(comp_log_idx[comp], pv, n_log)

        # Build per-component resource pair tables
        # Per-component cost = sec.byComponent + sec.byAsset * n_assets
        for res in ALL_RES:
            res_key = "power" if res == "power" else res
            pair_res_vals = []
            for si, sec in enumerate(catalog.security_features):
                by_comp = _cost(res_key, sec, "byComponent")
                by_asset = _cost(res_key, sec, "byAsset")
                comp_cost = by_comp + by_asset * n_assets
                for li, log in enumerate(catalog.logging_features):
                    pair_res_vals.append(comp_cost)

            lo = min(pair_res_vals)
            hi = max(pair_res_vals)
            v = model.new_int_var(lo, hi, f"{res}_{comp}")
            model.add_element(pv, pair_res_vals, v)
            comp_res[res][comp] = v

        # V*L product lookup
        comp_vl[comp] = model.new_int_var(min(pair_vl), max(pair_vl), f"vl_{comp}")
        model.add_element(pv, pair_vl, comp_vl[comp])

    # --- Feature-used boolean indicators (for one-time base costs) ---
    sec_used: dict[int, cp_model.IntVar] = {}
    for si in range(n_sec):
        sec_used[si] = model.new_bool_var(f"sec_used_{si}")
        # sec_used[si] == 1 iff any component uses security feature si
        indicators = []
        for comp in tc.components:
            b = model.new_bool_var(f"sec_{si}_at_{comp}")
            model.add(comp_sec_idx[comp] == si).only_enforce_if(b)
            model.add(comp_sec_idx[comp] != si).only_enforce_if(b.negated())
            indicators.append(b)
        model.add_max_equality(sec_used[si], indicators)

    log_used: dict[int, cp_model.IntVar] = {}
    for li in range(n_log):
        log_used[li] = model.new_bool_var(f"log_used_{li}")
        indicators = []
        for comp in tc.components:
            b = model.new_bool_var(f"log_{li}_at_{comp}")
            model.add(comp_log_idx[comp] == li).only_enforce_if(b)
            model.add(comp_log_idx[comp] != li).only_enforce_if(b.negated())
            indicators.append(b)
        model.add_max_equality(log_used[li], indicators)

    # --- Resource constraints (per-component sum + one-time base costs) ---
    caps = profile.capabilities
    for res in ALL_RES:
        res_key = "power" if res == "power" else res
        cap_key = f"max_{res}" if res != "power" else "max_power"
        if cap_key not in caps and (res == "bufg" and "max_bufgs" in caps):
            cap_key = "max_bufgs"
        if cap_key not in caps:
            continue

        # Sum of per-component costs
        comp_sum = sum(comp_res[res][c] for c in tc.components)

        # One-time security base costs
        sec_base_terms = []
        for si, sec in enumerate(catalog.security_features):
            base_val = _cost(res_key, sec, "base")
            if base_val != 0:
                sec_base_terms.append(base_val * sec_used[si])

        # One-time logging base costs
        log_base_terms = []
        for li, log in enumerate(catalog.logging_features):
            base_val = _cost(res_key, log, "base")
            if base_val != 0:
                log_base_terms.append(base_val * log_used[li])

        total = comp_sum + sum(sec_base_terms) + sum(log_base_terms)
        model.add(total <= caps[cap_key])

    # Risk cap (ASP uses MAX of all declared caps)
    risk_caps = [v for k, v in caps.items() if k == "max_asset_risk"]
    effective_risk_cap = max(risk_caps) if risk_caps else 999999

    # --- Latency constraints (security-feature only; logging excluded) ---
    # For each asset with an allowable_latency, the selected security
    # feature's latency_cost must not exceed the cap.
    # Build a per-security-feature latency table.
    sec_latency = [catalog.latency_cost.get(sec, 0) for sec in catalog.security_features]
    for comp, asset_name, action in tc.assets:
        cap = tc.allowable_latency.get((asset_name, action))
        if cap is None:
            continue
        # comp_sec_idx[comp] indexes into catalog.security_features
        lat_var = model.new_int_var(0, max(sec_latency), f"lat_{comp}_{asset_name}_{action}")
        model.add_element(comp_sec_idx[comp], sec_latency, lat_var)
        model.add(lat_var <= cap)

    # --- Redundancy-aware risk (matching ASP opt_redundancy_generic_enc.lp) ---
    # Non-group: risk = Impact * V * L / 10
    # Group:     normalise V*L to [0,1000], multiply across group members,
    #            denormalise, then risk = Impact * denorm / 100
    # Parameters must match ASP: mu=25, omega=1000.

    max_vl = max(pair_vl)

    # Identify which components are in redundancy groups
    in_group: set[str] = set()
    for members in tc.redundant_groups.values():
        for m in members:
            in_group.add(m)

    # --- Normalised probability for group members only: (V*L - MU)*1000 / (OMEGA - MU) ---
    # Only needed for components in redundancy groups; non-group risk uses V*L directly.
    comp_norm: dict[str, cp_model.IntVar] = {}
    for comp in in_group:
        # V*L ranges from mu (25) up to omega (1000) for meaningful features,
        # but can go below mu; ASP integer division handles negative values via
        # truncation.  Mirror that here with unclamped bounds.
        lo_num = (min(pair_vl) - MU) * 1000
        hi_num = (max(pair_vl) - MU) * 1000
        numerator = model.new_int_var(
            lo_num, hi_num, f"norm_num_{comp}",
        )
        model.add(numerator == (comp_vl[comp] - MU) * 1000)
        # ASP integer division truncates toward zero; CP-SAT division_equality
        # does the same.  Allow negative norms (they only arise for V*L < mu).
        norm_lo = lo_num // (OMEGA - MU) if lo_num >= 0 else -((-lo_num + OMEGA - MU - 1) // (OMEGA - MU))
        norm = model.new_int_var(norm_lo, 1000, f"norm_{comp}")
        model.add_division_equality(norm, numerator, OMEGA - MU)
        comp_norm[comp] = norm

    # --- Combined normalised probability for each redundancy group ---
    # Recursive partial product: partial[1] = norm[rank1],
    #   partial[k] = partial[k-1] * norm[rank_k] / 1000
    group_combined: dict[str, cp_model.IntVar] = {}  # group_id -> combined norm
    for gid, members in tc.redundant_groups.items():
        ranked = sorted(members)  # lexicographic, matching ASP C2 < C
        if len(ranked) == 1:
            group_combined[gid] = comp_norm[ranked[0]]
            continue
        prev = comp_norm[ranked[0]]
        for k in range(1, len(ranked)):
            # Intermediate products can be negative (when norms are negative)
            prod_k = model.new_int_var(-1000 * 1000, 1000 * 1000, f"gprod_{gid}_{k}")
            model.add_multiplication_equality(prod_k, [prev, comp_norm[ranked[k]]])
            next_var = model.new_int_var(-1000, 1000, f"gpart_{gid}_{k}")
            model.add_division_equality(next_var, prod_k, 1000)
            prev = next_var
        group_combined[gid] = prev

    # Map combined back to each member
    comp_combined: dict[str, cp_model.IntVar] = {}
    for gid, members in tc.redundant_groups.items():
        for m in members:
            comp_combined[m] = group_combined[gid]

    # --- Denormalized probability for group members ---
    # denorm = (combined * (OMEGA - MU) / 1000) + MU * 10
    comp_denorm: dict[str, cp_model.IntVar] = {}
    for comp in in_group:
        # prod_d = combined * (OMEGA - MU); combined can be negative
        prod_d = model.new_int_var(-1000 * (OMEGA - MU), 1000 * (OMEGA - MU), f"dprod_{comp}")
        model.add(prod_d == comp_combined[comp] * (OMEGA - MU))
        scaled = model.new_int_var(-(OMEGA - MU), (OMEGA - MU), f"dscale_{comp}")
        model.add_division_equality(scaled, prod_d, 1000)
        # denorm = scaled + MU * 10
        denorm = model.new_int_var(-(OMEGA - MU) + MU * 10, (OMEGA - MU) + MU * 10, f"denorm_{comp}")
        model.add(denorm == scaled + MU * 10)
        comp_denorm[comp] = denorm

    # --- Per-asset risk ---
    risk_vars: list[cp_model.IntVar] = []
    for comp, asset_name, action in tc.assets:
        imp = tc.impact.get((asset_name, action), 0)
        if comp in in_group:
            # Group risk: Imp * denorm / 100
            rprod = model.new_int_var(0, imp * OMEGA * 10, f"rprod_{comp}_{asset_name}_{action}")
            model.add(rprod == imp * comp_denorm[comp])
            risk = model.new_int_var(0, imp * OMEGA * 10 // 100 + 1, f"risk_{comp}_{asset_name}_{action}")
            model.add_division_equality(risk, rprod, 100)
        else:
            # Non-group risk: Imp * V * L / 10
            rprod = model.new_int_var(0, imp * max_vl, f"rprod_{comp}_{asset_name}_{action}")
            model.add(rprod == imp * comp_vl[comp])
            risk = model.new_int_var(0, imp * max_vl // 10 + 1, f"risk_{comp}_{asset_name}_{action}")
            model.add_division_equality(risk, rprod, 10)

        model.add(risk <= effective_risk_cap)
        risk_vars.append(risk)

    # Objective: minimise total risk
    model.minimize(sum(risk_vars))

    # Solve
    solver = cp_model.CpSolver()
    solver.parameters.max_time_in_seconds = 120
    solver.parameters.num_workers = 1  # single-threaded for fair comparison

    t0 = time.perf_counter()
    status = solver.solve(model)
    t1 = time.perf_counter()

    result = SolveResult(
        testcase=tc.name,
        profile=profile.name,
        solver="CP-SAT",
        time_s=round(t1 - t0, 3),
        objective=0,
        satisfiable=False,
        optimal=False,
    )

    if status in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        result.satisfiable = True
        result.optimal = (status == cp_model.OPTIMAL)
        result.objective = int(solver.objective_value)

        for comp in tc.components:
            idx = solver.value(pair_vars[comp])
            result.security[comp] = pair_sec[idx]
            result.logging[comp] = pair_log[idx]

        # Total resources = per-component sum + one-time base costs
        for res_name, attr in [("luts", "luts"), ("ffs", "ffs"),
                               ("power", "power"), ("bram", "bram")]:
            res_key = "power" if res_name == "power" else res_name
            comp_total = sum(solver.value(comp_res[res_name][c]) for c in tc.components)
            base_total = 0
            for si, sec in enumerate(catalog.security_features):
                if solver.value(sec_used[si]):
                    base_total += _cost(res_key, sec, "base")
            for li, log in enumerate(catalog.logging_features):
                if solver.value(log_used[li]):
                    base_total += _cost(res_key, log, "base")
            setattr(result, attr, comp_total + base_total)

    return result


# ---------------------------------------------------------------------------
# Gurobi ILP solver
# ---------------------------------------------------------------------------

def solve_gurobi(
    tc: TestCase, profile: Profile, catalog: FeatureCatalog
) -> SolveResult:
    import gurobipy as gp
    from gurobipy import GRB

    n_sec = len(catalog.security_features)
    n_log = len(catalog.logging_features)

    def _cost(res: str, feature: str, tier: str) -> int:
        return catalog.resource_costs.get(res, {}).get(feature, {}).get(tier, 0)

    caps = profile.capabilities
    risk_caps = [v for k, v in caps.items() if k == "max_asset_risk"]
    effective_risk_cap = max(risk_caps) if risk_caps else 999999

    # Component assets
    comp_assets: dict[str, list[tuple[str, str]]] = {}
    for c, a, op in tc.assets:
        comp_assets.setdefault(c, []).append((a, op))
    n_assets = {c: len({a for a, _ in comp_assets.get(c, [])}) for c in tc.components}

    # Precompute feature pair properties
    MU, OMEGA = 25, 1000
    pairs = []  # list of (sec, log, V, L, VL, latency)
    for si, sec in enumerate(catalog.security_features):
        for li, log in enumerate(catalog.logging_features):
            v = catalog.vulnerability.get(sec, 0)
            l = catalog.logging_score.get(log, 0)
            lat = catalog.latency_cost.get(sec, 0)
            pairs.append((sec, log, v, l, v * l, lat))

    model = gp.Model("iccad_ilp")
    model.setParam("OutputFlag", 0)
    model.setParam("TimeLimit", 120)
    model.setParam("Threads", 1)

    # Determine feasible pairs per component (latency + risk cap)
    feasible: dict[str, list[int]] = {}
    for c in tc.components:
        feasible[c] = []
        for p, (sec, log, v, l, vl, lat) in enumerate(pairs):
            ok = True
            for a, op in comp_assets.get(c, []):
                cap = tc.allowable_latency.get((a, op))
                if cap is not None and lat > cap:
                    ok = False; break
                imp = tc.impact.get((a, op), 0)
                if imp * vl // 10 > effective_risk_cap:
                    ok = False; break
            if ok:
                feasible[c].append(p)

    # Decision variables: x[c,p] = 1 if component c uses pair p (feasible only)
    x = {}
    for c in tc.components:
        for p in feasible[c]:
            x[c, p] = model.addVar(vtype=GRB.BINARY, name=f"x_{c}_{p}")

    # Exactly one pair per component
    for c in tc.components:
        model.addConstr(sum(x[c, p] for p in feasible[c]) == 1)

    # Feature-used indicators for base costs
    sec_used = {}
    for si, sec in enumerate(catalog.security_features):
        sec_used[si] = model.addVar(vtype=GRB.BINARY, name=f"su_{si}")
        for c in tc.components:
            for p in feasible[c]:
                if p // n_log == si:
                    model.addConstr(sec_used[si] >= x[c, p])

    log_used = {}
    for li, log in enumerate(catalog.logging_features):
        log_used[li] = model.addVar(vtype=GRB.BINARY, name=f"lu_{li}")
        for c in tc.components:
            for p in feasible[c]:
                if p % n_log == li:
                    model.addConstr(log_used[li] >= x[c, p])

    # Resource constraints
    ALL_RES = ("luts", "ffs", "dsps", "lutram", "bram", "bufg", "power")
    for res in ALL_RES:
        res_key = "power" if res == "power" else res
        cap_key = f"max_{res}" if res != "power" else "max_power"
        if cap_key not in caps and (res == "bufg" and "max_bufgs" in caps):
            cap_key = "max_bufgs"
        if cap_key not in caps:
            continue

        # Per-component costs
        comp_sum = gp.LinExpr()
        for c in tc.components:
            na = n_assets.get(c, 1)
            for p in feasible[c]:
                sec = pairs[p][0]
                comp_cost = _cost(res_key, sec, "byComponent") + _cost(res_key, sec, "byAsset") * na
                if comp_cost != 0:
                    comp_sum += comp_cost * x[c, p]

        # Base costs
        base_sum = gp.LinExpr()
        for si, sec in enumerate(catalog.security_features):
            bv = _cost(res_key, sec, "base")
            if bv != 0:
                base_sum += bv * sec_used[si]
        for li, log in enumerate(catalog.logging_features):
            bv = _cost(res_key, log, "base")
            if bv != 0:
                base_sum += bv * log_used[li]

        model.addConstr(comp_sum + base_sum <= caps[cap_key])

    # Objective: minimize total risk (non-group: I*V*L/10, group: redundancy-aware)
    # For ILP, precompute group risk via lookup tables
    in_group = set()
    for members in tc.redundant_groups.values():
        for m in members:
            in_group.add(m)

    # Precompute group denorm lookup: for each group, enumerate all possible
    # member pair assignments and compute denormalized risk
    from itertools import product as iterproduct

    # Precompute group denorm for feasible combos only
    group_denorm_table: dict[str, dict[tuple, int]] = {}
    for gid, members in tc.redundant_groups.items():
        ranked = sorted(members)
        member_feasible = [feasible[m] for m in ranked]
        table = {}
        for combo in iterproduct(*member_feasible):
            norms = []
            for p in combo:
                vl = pairs[p][4]
                norms.append((vl - MU) * 1000 // (OMEGA - MU))
            combined = norms[0]
            for i in range(1, len(norms)):
                combined = combined * norms[i] // 1000
            denorm = combined * (OMEGA - MU) // 1000 + MU * 10
            table[combo] = denorm
        group_denorm_table[gid] = table

    obj = gp.LinExpr()

    # Non-group risk
    for c in tc.components:
        if c in in_group:
            continue
        for p in feasible[c]:
            vl = pairs[p][4]
            for a, op in comp_assets.get(c, []):
                imp = tc.impact.get((a, op), 0)
                risk = imp * vl // 10
                if risk != 0:
                    obj += risk * x[c, p]

    # Group risk via feasible combo variables
    for gid, members in tc.redundant_groups.items():
        ranked = sorted(members)
        table = group_denorm_table[gid]
        member_feasible = [feasible[m] for m in ranked]

        combo_vars = {}
        for combo in iterproduct(*member_feasible):
            denorm = table[combo]
            group_risk = 0
            for i, m in enumerate(ranked):
                for a, op in comp_assets.get(m, []):
                    imp = tc.impact.get((a, op), 0)
                    group_risk += imp * denorm // 100
            if group_risk == 0:
                continue
            cname = f"gc_{gid}_{'_'.join(str(c) for c in combo)}"
            y = model.addVar(vtype=GRB.BINARY, name=cname)
            for i, m in enumerate(ranked):
                model.addConstr(y <= x[m, combo[i]])
            combo_vars[combo] = (y, group_risk)

        # Exactly one combo must be active
        model.addConstr(
            sum(y for y, _ in combo_vars.values()) == 1,
            name=f"one_combo_{gid}")

        for combo, (y, gr) in combo_vars.items():
            obj += gr * y

    model.setObjective(obj, GRB.MINIMIZE)

    t0 = time.perf_counter()
    model.optimize()
    t1 = time.perf_counter()

    result = SolveResult(
        testcase=tc.name, profile=profile.name, solver="ILP/Gurobi",
        time_s=round(t1 - t0, 3), objective=0, satisfiable=False, optimal=False,
    )

    if model.status in (GRB.OPTIMAL, GRB.SUBOPTIMAL):
        result.satisfiable = True
        result.optimal = (model.status == GRB.OPTIMAL)
        result.objective = int(round(model.objVal))

        for c in tc.components:
            for p in feasible[c]:
                if x[c, p].X > 0.5:
                    result.security[c] = pairs[p][0]
                    result.logging[c] = pairs[p][1]
                    break

        # Resource totals
        for res_name, attr in [("luts", "luts"), ("ffs", "ffs"),
                               ("power", "power"), ("bram", "bram")]:
            res_key = "power" if res_name == "power" else res_name
            total = 0
            for c in tc.components:
                na = n_assets.get(c, 1)
                for p in feasible[c]:
                    if x[c, p].X > 0.5:
                        total += _cost(res_key, pairs[p][0], "byComponent") + \
                                 _cost(res_key, pairs[p][0], "byAsset") * na
            for si, sec in enumerate(catalog.security_features):
                if sec_used[si].X > 0.5:
                    total += _cost(res_key, sec, "base")
            for li, log in enumerate(catalog.logging_features):
                if log_used[li].X > 0.5:
                    total += _cost(res_key, log, "base")
            setattr(result, attr, total)

    return result


# ---------------------------------------------------------------------------
# Clingo solver (Python API for fair timing)
# ---------------------------------------------------------------------------

def solve_clingo(
    tc: TestCase, profile: Profile, catalog_path: Path,
    testcase_path: Path, profile_path: Path,
    timeout: float = 120.0,
) -> SolveResult:
    import clingo

    lp_files = [
        str(CLINGO_DIR / "init_enc.lp"),
        str(catalog_path),
        str(CLINGO_DIR / "opt_redundancy_generic_enc.lp"),
        str(CLINGO_DIR / "opt_resource_enc.lp"),
        str(CLINGO_DIR / "opt_power_enc.lp"),
        str(CLINGO_DIR / "opt_latency_enc.lp"),
        str(CLINGO_DIR / "bridge_enc.lp"),
        str(testcase_path),
        str(profile_path),
    ]

    result = SolveResult(
        testcase=tc.name,
        profile=profile.name,
        solver="ASP/clingo",
        time_s=0.0,
        objective=0,
        satisfiable=False,
        optimal=False,
    )

    last_model_atoms: list = []
    last_cost: list[int] = []

    def on_model(model: clingo.Model) -> None:
        nonlocal last_model_atoms, last_cost
        last_model_atoms = list(model.symbols(shown=True))
        last_cost = list(model.cost)

    ctl = clingo.Control(["--opt-mode=opt", "0"])
    for f in lp_files:
        ctl.load(f)
    ctl.ground([("base", [])])

    t0 = time.perf_counter()
    with ctl.solve(on_model=on_model, async_=True) as handle:
        finished = handle.wait(timeout)
        if not finished:
            handle.cancel()
    t1 = time.perf_counter()
    result.time_s = round(t1 - t0, 3)

    if last_cost:
        result.satisfiable = True
        result.optimal = finished
        result.objective = last_cost[0]

        for sym in last_model_atoms:
            name = sym.name
            args = sym.arguments
            if name == "selected_security" and len(args) == 2:
                result.security[str(args[0])] = str(args[1])
            elif name == "selected_logging" and len(args) == 2:
                result.logging[str(args[0])] = str(args[1])
            elif name == "total_luts_used" and len(args) == 1:
                result.luts = args[0].number
            elif name == "total_ffs_used" and len(args) == 1:
                result.ffs = args[0].number
            elif name == "total_power_used" and len(args) == 1:
                result.power = args[0].number
            elif name == "total_bram_used" and len(args) == 1:
                result.bram = args[0].number

    return result


# ---------------------------------------------------------------------------
# Main benchmark
# ---------------------------------------------------------------------------

VALID_TESTCASES = [
    "testCase1_inst", "testCase2_inst", "testCase3_inst", "testCase5_inst",
    "testCase6_inst", "testCase7_inst", "testCase8_inst", "testCase9_inst",
    "testCaseOT_inst",  # testCaseOT40_inst available but not in paper scope
]

DEFAULT_PROFILES = [
    ("A", "tgt_system_inst1.lp"),
    ("B", "tgt_system_inst2.lp"),
    ("C", "tgt_system_inst3.lp"),
]

# OpenTitan uses different profiles (Kintex-7 410T target)
OT_PROFILES = [
    ("OT-A", "tgt_system_inst_ot1.lp"),
    ("OT-B", "tgt_system_inst_ot2.lp"),
    ("OT-C", "tgt_system_inst_ot3.lp"),
]

OT40_PROFILES = [
    ("OT40-A", "tgt_system_inst_ot40_1.lp"),
    ("OT40-B", "tgt_system_inst_ot40_2.lp"),
]

TESTCASE_PROFILES: dict[str, list[tuple[str, str]]] = {
    "testCaseOT_inst": OT_PROFILES,
    "testCaseOT40_inst": OT40_PROFILES,
}


def _save_json(json_data: list[dict], out_path: Path) -> None:
    """Write current results to JSON incrementally."""
    out_path.write_text(json.dumps(json_data, indent=2), encoding="utf-8")


def main() -> None:
    catalog_path = CLINGO_DIR / "security_features_inst.lp"
    catalog = parse_catalog(catalog_path)

    results: list[tuple[SolveResult, SolveResult]] = []
    json_data: list[dict] = []
    out_path = Path(__file__).parent / "iccad_cpsat_comparison.json"

    for tc_name in VALID_TESTCASES:
        tc_path = TESTCASE_DIR / f"{tc_name}.lp"
        tc = parse_testcase(tc_path)

        profiles = TESTCASE_PROFILES.get(tc_name, DEFAULT_PROFILES)
        for prof_label, prof_file in profiles:
            prof_path = CLINGO_DIR / prof_file
            profile = parse_profile(prof_path)

            print(f"  {tc_name} / Profile {prof_label} ...", end=" ", flush=True)

            # CP-SAT
            cpsat_result = solve_cpsat(tc, profile, catalog)

            # Clingo — skip for large instances (ASP cannot prove
            # optimality within timeout at 20+ components)
            ASP_COMPONENT_LIMIT = 10
            skip_asp = len(tc.components) > ASP_COMPONENT_LIMIT

            if skip_asp:
                clingo_result = SolveResult(
                    testcase=tc_name, profile=prof_label, solver="ASP/clingo",
                    time_s=0, objective=0, satisfiable=False, optimal=False,
                )
                print(
                    f"CP-SAT={cpsat_result.objective} ({cpsat_result.time_s}s)  "
                    f"clingo=skipped (>{ASP_COMPONENT_LIMIT} components)"
                )
            else:
                clingo_result = solve_clingo(
                    tc, profile, catalog_path, tc_path, prof_path
                )
                match = (
                    cpsat_result.objective == clingo_result.objective
                    and cpsat_result.satisfiable == clingo_result.satisfiable
                )
                marker = "OK" if match else "MISMATCH"
                print(
                    f"CP-SAT={cpsat_result.objective} ({cpsat_result.time_s}s)  "
                    f"clingo={clingo_result.objective} ({clingo_result.time_s}s)  "
                    f"[{marker}]"
                )

            results.append((cpsat_result, clingo_result))

            # --- Incremental JSON save after each case ---
            entry = {
                "testcase": tc_name,
                "profile": prof_label,
                "cpsat_objective": cpsat_result.objective,
                "cpsat_time_s": cpsat_result.time_s,
                "cpsat_luts": cpsat_result.luts,
                "cpsat_ffs": cpsat_result.ffs,
                "cpsat_power": cpsat_result.power,
                "cpsat_security": cpsat_result.security,
                "cpsat_logging": cpsat_result.logging,
            }
            if skip_asp:
                entry["asp_skipped"] = True
                entry["asp_skip_reason"] = f">{ASP_COMPONENT_LIMIT} components"
            else:
                entry["asp_objective"] = clingo_result.objective
                entry["asp_time_s"] = clingo_result.time_s
                entry["asp_luts"] = clingo_result.luts
                entry["asp_ffs"] = clingo_result.ffs
                entry["asp_power"] = clingo_result.power
                entry["asp_security"] = clingo_result.security
                entry["asp_logging"] = clingo_result.logging
                entry["objective_match"] = cpsat_result.objective == clingo_result.objective
            json_data.append(entry)
            _save_json(json_data, out_path)
            print(f"    [{len(json_data)} results saved to JSON]", flush=True)

    # --- Report ---
    print()
    print("=" * 100)
    print(f"{'Case':<18} {'Prof':>4}  {'ASP obj':>7} {'ASP (s)':>8}  "
          f"{'CPSAT obj':>9} {'CPSAT (s)':>9}  {'Match':>5}  ASP mix / CPSAT mix")
    print("-" * 100)

    for cpsat_r, clingo_r in results:
        prof_label = {
            "tgt_system_inst1": "A", "tgt_system_inst2": "B", "tgt_system_inst3": "C",
            "tgt_system_inst_ot1": "OT-A", "tgt_system_inst_ot2": "OT-B", "tgt_system_inst_ot3": "OT-C",
            "tgt_system_inst_ot40_1": "OT40-A", "tgt_system_inst_ot40_2": "OT40-B",
        }.get(cpsat_r.profile, cpsat_r.profile)
        match = "YES" if cpsat_r.objective == clingo_r.objective else "NO"

        def _mix(r: SolveResult) -> str:
            if not r.security:
                return "UNSAT"
            sec_counts: dict[str, int] = {}
            for s in r.security.values():
                sec_counts[s] = sec_counts.get(s, 0) + 1
            log_counts: dict[str, int] = {}
            for l in r.logging.values():
                log_counts[l] = log_counts.get(l, 0) + 1
            sec_str = "+".join(f"{v}{k[:3]}" for k, v in sorted(sec_counts.items()))
            log_str = "+".join(f"{v}{k[:3]}" for k, v in sorted(log_counts.items()))
            return f"{sec_str} | {log_str}"

        print(
            f"{clingo_r.testcase:<18} {prof_label:>4}  "
            f"{clingo_r.objective:>7} {clingo_r.time_s:>8.3f}  "
            f"{cpsat_r.objective:>9} {cpsat_r.time_s:>9.3f}  "
            f"{match:>5}  {_mix(clingo_r)} / {_mix(cpsat_r)}"
        )

    print("=" * 100)

    # Summary stats
    asp_times = [c.time_s for _, c in results if c.satisfiable]
    cpsat_times = [c.time_s for c, _ in results if c.satisfiable]
    matches = sum(1 for c, a in results if c.objective == a.objective)

    print(f"\nTotal runs: {len(results)}")
    print(f"Objective matches: {matches}/{len(results)}")
    print(f"ASP/clingo  mean time: {sum(asp_times)/len(asp_times):.3f}s  "
          f"(min={min(asp_times):.3f}s, max={max(asp_times):.3f}s)")
    print(f"CP-SAT      mean time: {sum(cpsat_times)/len(cpsat_times):.3f}s  "
          f"(min={min(cpsat_times):.3f}s, max={max(cpsat_times):.3f}s)")

    # Final save (json_data already written incrementally)
    _save_json(json_data, out_path)
    print(f"\nFinal results saved to {out_path} ({len(json_data)} entries)")


if __name__ == "__main__":
    print("ICCAD 2026 — CP-SAT vs ASP/clingo Phase 1 Benchmark")
    print("=" * 100)
    main()
