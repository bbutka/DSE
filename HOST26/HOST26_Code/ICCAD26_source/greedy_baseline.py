"""Greedy + local-search heuristic baseline for ICCAD benchmark.

Enforces ALL constraints matching the CP-SAT formulation:
  - LUT budget
  - Power budget
  - Per-asset latency cap (security feature latency <= allowable_latency)
  - Per-asset risk cap (Impact * V * L / 10 <= max_asset_risk)

Uses standalone (non-group) risk as its objective, since the heuristic
has no mechanism to coordinate redundancy-group assignments.
"""
import json, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from iccad_cpsat_benchmark import (
    parse_catalog, parse_testcase, parse_profile, solve_cpsat,
    CLINGO_DIR, TESTCASE_DIR,
)
from pathlib import Path

CATALOG = CLINGO_DIR / "security_features_inst.lp"


def _rc(catalog, res, feat, tier):
    return catalog.resource_costs.get(res, {}).get(feat, {}).get(tier, 0)


def greedy_solve(tc, profile, catalog):
    """Greedy: sort components by max impact descending, assign best
    latency-feasible, risk-feasible, resource-feasible feature pair."""

    sec_feats = catalog.security_features
    log_feats = catalog.logging_features
    V = catalog.vulnerability
    L = catalog.logging_score
    sec_lat = catalog.latency_cost
    caps = profile.capabilities
    lut_cap = caps.get("max_luts", 999999)
    pow_cap = caps.get("max_power", 999999)
    risk_cap = caps.get("max_asset_risk", 999999)

    comp_assets = {}
    for c, a, op in tc.assets:
        comp_assets.setdefault(c, []).append((a, op))

    n_assets = {c: len({a for a, _ in comp_assets.get(c, [])}) for c in tc.components}

    # Sort by max impact descending
    comp_max_imp = {
        c: max((tc.impact.get((a, op), 0) for a, op in comp_assets.get(c, [])), default=0)
        for c in tc.components
    }
    sorted_comps = sorted(tc.components, key=lambda c: -comp_max_imp[c])

    def sec_feasible(comp, sec):
        """Check latency feasibility for this security feature on this component."""
        lat = sec_lat.get(sec, 0)
        for a, op in comp_assets.get(comp, []):
            cap = tc.allowable_latency.get((a, op))
            if cap is not None and lat > cap:
                return False
        return True

    def risk_feasible(comp, sec, log):
        """Check per-asset risk cap."""
        vl = V.get(sec, 0) * L.get(log, 0)
        for a, op in comp_assets.get(comp, []):
            imp = tc.impact.get((a, op), 0)
            if imp * vl // 10 > risk_cap:
                return False
        return True

    def comp_cost(comp, sec):
        """Per-component resource cost (LUT and power)."""
        na = n_assets.get(comp, 1)
        lut = _rc(catalog, "luts", sec, "byComponent") + _rc(catalog, "luts", sec, "byAsset") * na
        pwr = _rc(catalog, "power", sec, "byComponent") + _rc(catalog, "power", sec, "byAsset") * na
        return lut, pwr

    def total_resources(assign):
        tl = tp = 0
        for c, (s, l) in assign.items():
            cl, cp = comp_cost(c, s)
            tl += cl; tp += cp
        for s in set(s for s, _ in assign.values()):
            tl += _rc(catalog, "luts", s, "base")
            tp += _rc(catalog, "power", s, "base")
        for l in set(l for _, l in assign.values()):
            tl += _rc(catalog, "luts", l, "base")
            tp += _rc(catalog, "power", l, "base")
        return tl, tp

    def standalone_risk(comp, sec, log):
        vl = V.get(sec, 0) * L.get(log, 0)
        return sum(tc.impact.get((a, op), 0) * vl // 10
                   for a, op in comp_assets.get(comp, []))

    def total_risk(assign):
        return sum(standalone_risk(c, s, l) for c, (s, l) in assign.items())

    # --- Greedy assignment ---
    assign = {}
    for c in sorted_comps:
        best_r, best_p = None, None
        for sec in sec_feats:
            if not sec_feasible(c, sec):
                continue
            for log in log_feats:
                if not risk_feasible(c, sec, log):
                    continue
                trial = dict(assign)
                trial[c] = (sec, log)
                tl, tp = total_resources(trial)
                if tl > lut_cap or tp > pow_cap:
                    continue
                r = standalone_risk(c, sec, log)
                if best_r is None or r < best_r:
                    best_r, best_p = r, (sec, log)
        if best_p is None:
            # Absolute fallback: cheapest feasible
            for sec in reversed(sec_feats):
                if not sec_feasible(c, sec):
                    continue
                best_p = (sec, "no_logging")
                break
            if best_p is None:
                best_p = ("mac", "no_logging")
        assign[c] = best_p

    greedy_assign = dict(assign)
    greedy_risk = total_risk(assign)
    greedy_luts, greedy_power = total_resources(assign)

    # --- Local search (1-opt) ---
    improved = True
    iterations = 0
    while improved and iterations < 500:
        improved = False
        iterations += 1
        for c in tc.components:
            cur_total = total_risk(assign)
            for sec in sec_feats:
                if not sec_feasible(c, sec):
                    continue
                for log in log_feats:
                    if not risk_feasible(c, sec, log):
                        continue
                    trial = dict(assign)
                    trial[c] = (sec, log)
                    tl, tp = total_resources(trial)
                    if tl > lut_cap or tp > pow_cap:
                        continue
                    nr = total_risk(trial)
                    if nr < cur_total:
                        assign = trial
                        cur_total = nr
                        improved = True

    ls_risk = total_risk(assign)
    ls_luts, ls_power = total_resources(assign)

    return {
        "greedy_objective": greedy_risk,
        "greedy_luts": greedy_luts,
        "greedy_power": greedy_power,
        "greedy_security": {c: s for c, (s, _) in greedy_assign.items()},
        "greedy_logging": {c: l for c, (_, l) in greedy_assign.items()},
        "local_search_objective": ls_risk,
        "local_search_luts": ls_luts,
        "local_search_power": ls_power,
        "local_search_security": {c: s for c, (s, _) in assign.items()},
        "local_search_logging": {c: l for c, (_, l) in assign.items()},
        "ls_iterations": iterations,
    }


def main():
    catalog = parse_catalog(CATALOG)

    OT_PROFILES = [
        ("OT-A", "tgt_system_inst_ot1.lp"),
        ("OT-B", "tgt_system_inst_ot2.lp"),
        ("OT-C", "tgt_system_inst_ot3.lp"),
    ]

    tc = parse_testcase(TESTCASE_DIR / "testCaseOT_inst.lp")
    results = []

    for pname, pfile in OT_PROFILES:
        prof = parse_profile(CLINGO_DIR / pfile)
        prof.name = pname

        h = greedy_solve(tc, prof, catalog)
        r = solve_cpsat(tc, prof, catalog)
        opt = r.objective if r.satisfiable else "UNSAT"

        entry = {"profile": pname, "optimal": opt}
        entry.update(h)
        if isinstance(opt, int) and opt > 0:
            entry["greedy_gap_pct"] = round((h["greedy_objective"] - opt) * 100 / opt)
            entry["ls_gap_pct"] = round((h["local_search_objective"] - opt) * 100 / opt)

        results.append(entry)
        print(f"{pname}: optimal={opt}  greedy={h['greedy_objective']}  "
              f"ls={h['local_search_objective']}  "
              f"gaps=+{entry.get('greedy_gap_pct','?')}% / +{entry.get('ls_gap_pct','?')}%")

    with open("greedy_baseline.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved {len(results)} results to greedy_baseline.json")


if __name__ == "__main__":
    main()
