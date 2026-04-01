"""
runClingo_darpa_uav.py  — DARPA CASE UAV Zero Trust SoC DSE Runner
===================================================================
Three-phase solver for the DARPA CASE UAV surveillance system
translated from AADL to SoC interconnect model.

Phase 1 — Security DSE optimisation
Phase 2 — ZTA policy synthesis
Phase 3 — Resilience scenarios (auto-generated from topology)

Output: console + resilience_summary_darpa_uav.txt
"""

import os, sys, copy, time
import clingo
from dataclasses import dataclass, field

# Force UTF-8 output on Windows and ensure unbuffered
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def log(msg: str):
    """Print with immediate flush so progress is visible."""
    print(msg, flush=True)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
CLINGO_DIR = os.path.join(BASE_DIR, "Clingo")

def lp(name): return os.path.join(CLINGO_DIR, name)

# DARPA UAV uses a single instance file (no separate testCase file)
UAV_INST = lp("tgt_system_darpa_uav_inst.lp")

PHASE1_FILES = [
    UAV_INST,
    lp("security_features_inst.lp"),
    lp("init_enc.lp"),
    lp("opt_redundancy_generic_enc.lp"),
    lp("opt_latency_enc.lp"),
    lp("opt_power_enc.lp"),
    lp("opt_resource_enc.lp"),
    lp("bridge_enc.lp"),
]

PHASE2_FILES = [UAV_INST, lp("zta_policy_enc.lp")]
PHASE3_FILES = [UAV_INST, lp("resilience_enc.lp")]

AMP_DENOM = 10

# Components — all receivers
COMPONENTS = {
    "radio_drv", "fpln", "wpm", "cam_mgr", "wifi_drv",
    "uart_drv", "nfzdb", "attest_gate", "geofence", "fpln_filt", "swu"
}
MASTERS = {"mc", "fc", "gs"}
BUSES = {"bus_rf", "bus_mc", "bus_uart", "bus_wifi"}
SAFETY_CRITICAL = {"fc", "geofence", "fpln_filt", "uart_drv"}
CAND_FWS = {"pep_mc"}
CAND_PS = {"ps_mc", "ps_uart"}

# ---------------------------------------------------------------------------
# Scenarios (auto-generated from topology)
# ---------------------------------------------------------------------------
SCENARIOS = [
    # Baseline
    {"name": "baseline",                "compromised": [],                  "failed": []},

    # Single master compromises
    {"name": "mc_compromise",           "compromised": ["mc"],              "failed": []},
    {"name": "fc_compromise",           "compromised": ["fc"],              "failed": []},
    {"name": "gs_compromise",           "compromised": ["gs"],              "failed": []},

    # High-exploitability component compromises
    {"name": "radio_drv_compromise",    "compromised": ["radio_drv"],       "failed": []},
    {"name": "wifi_drv_compromise",     "compromised": ["wifi_drv"],        "failed": []},
    {"name": "swu_compromise",          "compromised": ["swu"],            "failed": []},

    # Safety-critical component compromises
    {"name": "geofence_compromise",     "compromised": ["geofence"],        "failed": []},
    {"name": "fpln_filt_compromise",    "compromised": ["fpln_filt"],       "failed": []},
    {"name": "uart_drv_compromise",     "compromised": ["uart_drv"],        "failed": []},

    # Bus failures
    {"name": "bus_rf_failure",          "compromised": [],                  "failed": ["bus_rf"]},
    {"name": "bus_mc_failure",          "compromised": [],                  "failed": ["bus_mc"]},
    {"name": "bus_uart_failure",        "compromised": [],                  "failed": ["bus_uart"]},
    {"name": "bus_wifi_failure",        "compromised": [],                  "failed": ["bus_wifi"]},

    # Component failures (safety-critical)
    {"name": "fc_failure",              "compromised": [],                  "failed": ["fc"]},
    {"name": "geofence_failure",        "compromised": [],                  "failed": ["geofence"]},
    {"name": "uart_drv_failure",        "compromised": [],                  "failed": ["uart_drv"]},

    # Control plane
    {"name": "ps_mc_compromise",        "compromised": ["ps_mc"],           "failed": []},
    {"name": "ps_uart_compromise",      "compromised": ["ps_uart"],         "failed": []},
    {"name": "pep_mc_bypass",           "compromised": ["pep_mc"],          "failed": []},
    {"name": "all_ps_failure",          "compromised": [],                  "failed": ["ps_mc", "ps_uart"]},

    # Combined: bridge compromise + bus failure
    {"name": "radio_drv_comp_bus_mc_fail", "compromised": ["radio_drv"],   "failed": ["bus_mc"]},
    {"name": "mc_comp_bus_uart_fail",   "compromised": ["mc"],              "failed": ["bus_uart"]},

    # GS compromise: attacker controls ground station, attacks through radio bridge
    {"name": "gs_radio_chain",          "compromised": ["gs", "radio_drv"], "failed": []},
]

# ---------------------------------------------------------------------------
# Data containers (same as TC9 runner)
# ---------------------------------------------------------------------------

@dataclass
class Phase1Result:
    security:     dict = field(default_factory=dict)
    logging:      dict = field(default_factory=dict)
    new_risk:     list = field(default_factory=list)
    total_luts:   int  = 0
    total_ffs:    int  = 0
    total_dsps:   int  = 0
    total_lutram: int  = 0
    total_bram:   int  = 0
    total_power:  int  = 0
    optimal:      bool = False

    def max_risk_per_asset(self) -> dict:
        result = {}
        for _c, asset, _a, risk in self.new_risk:
            result[asset] = max(result.get(asset, 0), risk)
        return result

    def total_risk(self) -> int:
        return sum(self.max_risk_per_asset().values())

    def as_p1_facts(self, extra: str = "") -> str:
        lines = []
        for comp, feat in self.security.items():
            lines.append(f"p1_security({comp}, {feat}).")
        for comp, feat in self.logging.items():
            lines.append(f"p1_logging({comp}, {feat}).")
        for asset, risk in self.max_risk_per_asset().items():
            lines.append(f"p1_risk({asset}, {risk}).")
        if extra:
            lines.append(extra)
        return "\n".join(lines)


@dataclass
class Phase2Result:
    placed_fws:              list = field(default_factory=list)
    placed_ps:               list = field(default_factory=list)
    final_allows:            list = field(default_factory=list)
    final_denies:            list = field(default_factory=list)
    asset_policies:          list = field(default_factory=list)
    role_allows:             list = field(default_factory=list)
    isolated:                list = field(default_factory=list)
    protected:               list = field(default_factory=list)
    governs_ip:              list = field(default_factory=list)
    excess_privileges:       list = field(default_factory=list)
    missing_privileges:      list = field(default_factory=list)
    policy_tightness:        dict = field(default_factory=dict)
    over_privileged:         list = field(default_factory=list)
    role_excess:             list = field(default_factory=list)
    operational_excess:      list = field(default_factory=list)
    trust_gap_rot:           list = field(default_factory=list)
    trust_gap_sboot:         list = field(default_factory=list)
    trust_gap_attest:        list = field(default_factory=list)
    unattested_access:       list = field(default_factory=list)
    unsigned_ps:             list = field(default_factory=list)
    trust_gap_keys:          list = field(default_factory=list)
    trust_levels:            dict = field(default_factory=dict)
    unexplained_exceptions:  list = field(default_factory=list)
    critical_exceptions:     list = field(default_factory=list)
    total_cost:              int  = 0
    satisfiable:             bool = False
    optimal:                 bool = False

    def as_phase3_facts(self) -> str:
        lines = []
        for fw in sorted(set(self.placed_fws)):
            lines.append(f"deployed_pep({fw}).")
        for ps in sorted(set(self.placed_ps)):
            lines.append(f"deployed_ps({ps}).")
        for master, ip, op in sorted(set(self.final_allows)):
            lines.append(f"p2_allow({master}, {ip}, {op}).")
        return "\n".join(lines)


@dataclass
class ScenarioResult:
    name:              str
    compromised:       list
    failed:            list
    scenario_risks:    dict = field(default_factory=dict)
    total_risk_scaled: int  = 0
    blast_radii:       dict = field(default_factory=dict)
    eff_blast_radii:   dict = field(default_factory=dict)
    unavailable:       list = field(default_factory=list)
    cut_off:           list = field(default_factory=list)
    services_ok:       list = field(default_factory=list)
    services_degraded: list = field(default_factory=list)
    services_unavail:  list = field(default_factory=list)
    service_counts:    dict = field(default_factory=dict)
    active_ps_count:   int  = 2
    ungoverned_peps:   list = field(default_factory=list)
    cp_degraded:       bool = False
    cp_stale:          bool = False
    cp_compromised:    bool = False
    peps_bypassed:     list = field(default_factory=list)
    ps_compromised:    list = field(default_factory=list)
    direct_exp:        list = field(default_factory=list)
    cross_exp:         list = field(default_factory=list)
    unmediated_exp:    list = field(default_factory=list)
    attack_paths:      list = field(default_factory=list)
    escalation_paths:  list = field(default_factory=list)
    cap_available:     list = field(default_factory=list)
    cap_degraded:      list = field(default_factory=list)
    cap_lost:          list = field(default_factory=list)
    satisfiable:       bool = False

    @property
    def total_risk(self) -> float:
        return self.total_risk_scaled / AMP_DENOM


# ---------------------------------------------------------------------------
# Phase 1
# ---------------------------------------------------------------------------

STRATEGY_EXTRA = {
    "max_security": "",
    "min_resources": (
        "% min_resources strategy: add secondary LUT objective\n"
        "#minimize { LUTs@2, total : total_luts_used(LUTs) }.\n"
    ),
    "balanced": (
        "% balanced strategy: explicit total-risk objective plus LUT tie-break\n"
        "total_risk_sum(R) :- R = #sum { Risk, C, Asset, Action : new_risk(C, Asset, Action, Risk) }.\n"
        "#show total_risk_sum/1.\n"
        "#minimize { R@2 : total_risk_sum(R) }.\n"
        "#minimize { L@1 : total_luts_used(L) }.\n"
    ),
}


def phase1_optimise(strategy: str = "max_security") -> Phase1Result:
    t0 = time.time()
    log(f"[Phase 1] [{strategy}] Loading LP files...")
    from ip_catalog.xilinx_ip_catalog import export_security_features_to_lp
    export_security_features_to_lp(lp("security_features_inst.lp"))

    SOLVE_TIMEOUT = 60  # seconds; uses best model found if not proven optimal
    ctl = clingo.Control(["-n", "1", "--opt-mode=optN", "--warn=none"])
    for f in PHASE1_FILES:
        log(f"  Loading {os.path.basename(f)}")
        ctl.load(f)
    extra = STRATEGY_EXTRA.get(strategy, "")
    if extra:
        ctl.add("strategy", [], extra)

    log(f"[Phase 1] [{strategy}] Grounding... ({time.time()-t0:.1f}s)")
    ctl.ground([("base", [])] + ([("strategy", [])] if extra else []))
    log(f"[Phase 1] [{strategy}] Grounding done ({time.time()-t0:.1f}s). "
        f"Solving (timeout={SOLVE_TIMEOUT}s)...")

    result, last_model = Phase1Result(), []
    model_count = [0]

    def on_model(model):
        nonlocal last_model
        model_count[0] += 1
        last_model     = list(model.symbols(shown=True))
        result.optimal = model.optimality_proven
        # Report intermediate models
        cost = model.cost
        log(f"  [Phase 1] Model #{model_count[0]}  cost={cost}  "
            f"optimal_proven={model.optimality_proven}  ({time.time()-t0:.1f}s)")

    with ctl.solve(on_model=on_model, async_=True) as handle:
        finished = handle.wait(SOLVE_TIMEOUT)
        if not finished:
            log(f"  [Phase 1] Timeout ({SOLVE_TIMEOUT}s) — interrupting, using best model found")
            handle.cancel()
        sr = handle.get()

    timed_out = not finished
    result.optimal = sr.satisfiable and not timed_out and result.optimal

    if sr.unsatisfiable:
        raise RuntimeError("Phase 1 UNSAT — check resource/risk budgets")
    if timed_out and not last_model:
        raise RuntimeError("Phase 1 timed out before finding any model")

    for sym in last_model:
        n, a = sym.name, sym.arguments
        if n == "selected_security" and len(a) == 2 and str(a[0]) in COMPONENTS:
            result.security[str(a[0])] = str(a[1])
        elif n == "selected_logging"  and len(a) == 2 and str(a[0]) in COMPONENTS:
            result.logging[str(a[0])]  = str(a[1])
        elif n == "new_risk"          and len(a) == 4:
            result.new_risk.append((str(a[0]), str(a[1]), str(a[2]), a[3].number))
        elif n == "total_luts_used"   and len(a) == 1: result.total_luts   = a[0].number
        elif n == "total_ffs_used"    and len(a) == 1: result.total_ffs    = a[0].number
        elif n == "total_dsps_used"   and len(a) == 1: result.total_dsps   = a[0].number
        elif n == "total_lutram_used" and len(a) == 1: result.total_lutram = a[0].number
        elif n == "total_bram_used"   and len(a) == 1: result.total_bram   = a[0].number
        elif n == "total_power_used"  and len(a) == 1: result.total_power  = a[0].number

    proven = "PROVEN" if result.optimal else "BEST-FOUND (timeout)"
    log(f"[Phase 1] [{strategy}] DONE in {time.time()-t0:.1f}s — "
        f"{proven}  Risk={result.total_risk()}  "
        f"LUTs={result.total_luts}/53200 ({100*result.total_luts//53200}%)")
    for comp in sorted(result.security):
        log(f"  {comp:<14} sec={result.security[comp]:<16} log={result.logging.get(comp, '?')}")
    return result


# ---------------------------------------------------------------------------
# Phase 2
# ---------------------------------------------------------------------------

def phase2_zta(p1: Phase1Result) -> Phase2Result:
    t0 = time.time()
    log("[Phase 2] Loading ZTA policy encoding...")
    ctl = clingo.Control(["-n", "1", "--opt-mode=optN", "--warn=none"])
    for f in PHASE2_FILES:
        log(f"  Loading {os.path.basename(f)}")
        ctl.load(f)
    ctl.add("p1", [], p1.as_p1_facts())
    log(f"[Phase 2] Grounding... ({time.time()-t0:.1f}s)")
    ctl.ground([("base", []), ("p1", [])])
    log(f"[Phase 2] Grounding done ({time.time()-t0:.1f}s). Solving...")

    result, last_model = Phase2Result(), []
    model_count = [0]

    def on_model(model):
        nonlocal last_model
        model_count[0] += 1
        last_model = list(model.symbols(shown=True))
        result.optimal = model.optimality_proven
        log(f"  [Phase 2] Model #{model_count[0]}  cost={model.cost}  "
            f"optimal_proven={model.optimality_proven}  ({time.time()-t0:.1f}s)")

    sr = ctl.solve(on_model=on_model)
    result.satisfiable = not sr.unsatisfiable

    if sr.unsatisfiable:
        log(f"[Phase 2] WARNING: UNSAT ({time.time()-t0:.1f}s) — attempting diagnosis...")
        _diagnose_phase2_unsat(p1)
        return result

    result.optimal = result.satisfiable and not sr.unknown and result.optimal

    for sym in last_model:
        n, a = sym.name, sym.arguments
        if   n == "place_fw"           and len(a)==1: result.placed_fws.append(str(a[0]))
        elif n == "place_ps"           and len(a)==1: result.placed_ps.append(str(a[0]))
        elif n == "final_allow"        and len(a)==3: result.final_allows.append((str(a[0]),str(a[1]),str(a[2])))
        elif n == "final_deny"         and len(a)==3: result.final_denies.append((str(a[0]),str(a[1]),str(a[2])))
        elif n == "asset_policy"       and len(a)==4: result.asset_policies.append((str(a[0]),str(a[1]),str(a[2]),str(a[3])))
        elif n == "role_allow"         and len(a)==4: result.role_allows.append((str(a[0]),str(a[1]),str(a[2]),str(a[3])))
        elif n == "isolated"           and len(a)==2: result.isolated.append((str(a[0]),str(a[1])))
        elif n == "protected"          and len(a)==2: result.protected.append((str(a[0]),str(a[1])))
        elif n == "governs_ip"         and len(a)==2: result.governs_ip.append((str(a[0]),str(a[1])))
        elif n == "excess_privilege"   and len(a)==3: result.excess_privileges.append((str(a[0]),str(a[1]),str(a[2])))
        elif n == "missing_privilege"  and len(a)==3: result.missing_privileges.append((str(a[0]),str(a[1]),str(a[2])))
        elif n == "policy_tightness"   and len(a)==2: result.policy_tightness[str(a[0])] = a[1].number
        elif n == "over_privileged"    and len(a)==1: result.over_privileged.append(str(a[0]))
        elif n == "role_excess"        and len(a)==3: result.role_excess.append((str(a[0]),str(a[1]),str(a[2])))
        elif n == "operational_excess" and len(a)==3: result.operational_excess.append((str(a[0]),str(a[1]),str(a[2])))
        elif n == "trust_gap_rot"      and len(a)==1: result.trust_gap_rot.append(str(a[0]))
        elif n == "trust_gap_sboot"    and len(a)==1: result.trust_gap_sboot.append(str(a[0]))
        elif n == "trust_gap_attest"   and len(a)==1: result.trust_gap_attest.append(str(a[0]))
        elif n == "unattested_privileged_access" and len(a)==2: result.unattested_access.append((str(a[0]),str(a[1])))
        elif n == "unsigned_ps"        and len(a)==1: result.unsigned_ps.append(str(a[0]))
        elif n == "trust_gap_keys"     and len(a)==1: result.trust_gap_keys.append(str(a[0]))
        elif n == "trust_level"        and len(a)==2: result.trust_levels[str(a[0])] = str(a[1])
        elif n == "unexplained_exception" and len(a)==3: result.unexplained_exceptions.append((str(a[0]),str(a[1]),str(a[2])))
        elif n == "critical_exception" and len(a)==5: result.critical_exceptions.append(tuple(str(x) for x in a))
        elif n == "total_zta_cost"     and len(a)==1: result.total_cost = a[0].number

    log(f"[Phase 2] DONE in {time.time()-t0:.1f}s — Optimal={result.optimal}  "
        f"FWs={result.placed_fws}  PS={result.placed_ps}  cost={result.total_cost}  "
        f"excess_privileges={len(result.excess_privileges)}")
    return result


def _diagnose_phase2_unsat(p1: Phase1Result):
    """Try relaxing constraints to find UNSAT cause."""
    log("  DIAG: Testing constraint relaxations...")
    # Test 1: relax critical-IP constraint
    ctl = clingo.Control(["-n", "1", "--warn=none"])
    for f in PHASE2_FILES:
        ctl.load(f)
    facts = p1.as_p1_facts()
    facts += "\n#const relax_critical = 1."
    ctl.add("p1", [], facts)
    ctl.ground([("base", []), ("p1", [])])
    sr = ctl.solve()
    if not sr.unsatisfiable:
        log("  DIAG: Relaxing critical-IP constraint makes SAT")
        log("  -> Some critical IPs lack an on-path firewall")
    else:
        log("  DIAG: Still UNSAT after relaxing critical-IP constraint")
    # Test 2: relax mode constraints
    ctl2 = clingo.Control(["-n", "1", "--warn=none"])
    for f in PHASE2_FILES:
        ctl2.load(f)
    facts2 = p1.as_p1_facts()
    facts2 += "\n#const relax_modes = 1."
    ctl2.add("p1", [], facts2)
    ctl2.ground([("base", []), ("p1", [])])
    sr2 = ctl2.solve()
    if not sr2.unsatisfiable:
        log("  DIAG: Relaxing mode constraints makes SAT")
    else:
        log("  DIAG: Still UNSAT after relaxing mode constraints")


# ---------------------------------------------------------------------------
# Phase 3
# ---------------------------------------------------------------------------

def phase3_scenario(sc: dict, p1: Phase1Result, p2: Phase2Result) -> ScenarioResult:
    ctl = clingo.Control(["-n", "1", "--warn=none"])
    for f in PHASE3_FILES:
        ctl.load(f)

    facts = p1.as_p1_facts()
    if p2.satisfiable:
        p2_facts = p2.as_phase3_facts()
        if p2_facts:
            facts += "\n" + p2_facts
    for node in sc["compromised"]:
        facts += f"\ncompromised({node})."
    for node in sc["failed"]:
        facts += f"\nfailed({node})."
    ctl.add("scenario", [], facts)
    ctl.ground([("base", []), ("scenario", [])])

    res = ScenarioResult(name=sc["name"],
                         compromised=sc["compromised"],
                         failed=sc["failed"])
    found = []
    def on_model(m): found.extend(m.symbols(shown=True))
    sr = ctl.solve(on_model=on_model)
    res.satisfiable = not sr.unsatisfiable

    for sym in found:
        n, a = sym.name, sym.arguments
        if   n == "scenario_asset_risk"  and len(a)==2: res.scenario_risks[str(a[0])] = a[1].number
        elif n == "scenario_total_risk"  and len(a)==1: res.total_risk_scaled = a[0].number
        elif n == "blast_radius"         and len(a)==2: res.blast_radii[str(a[0])] = a[1].number
        elif n == "effective_blast_radius" and len(a)==2: res.eff_blast_radii[str(a[0])] = a[1].number
        elif n == "asset_unavailable"    and len(a)==1: res.unavailable.append(str(a[0]))
        elif n == "node_cut_off"         and len(a)==1: res.cut_off.append(str(a[0]))
        elif n == "service_ok"           and len(a)==1: res.services_ok.append(str(a[0]))
        elif n == "service_degraded"     and len(a)==1: res.services_degraded.append(str(a[0]))
        elif n == "service_unavailable"  and len(a)==1: res.services_unavail.append(str(a[0]))
        elif n == "service_live_count"   and len(a)==2: res.service_counts[str(a[0])] = a[1].number
        elif n == "active_ps_count"      and len(a)==1: res.active_ps_count = a[0].number
        elif n == "ungoverned_pep"       and len(a)==1: res.ungoverned_peps.append(str(a[0]))
        elif n == "ungovernerd_pep"      and len(a)==1: res.ungoverned_peps.append(str(a[0]))
        elif n == "control_plane_degraded"  and len(a)==0: res.cp_degraded   = True
        elif n == "stale_policy_active"     and len(a)==0: res.cp_stale      = True
        elif n == "control_plane_compromised" and len(a)==0: res.cp_compromised = True
        elif n == "pep_bypassed"         and len(a)==1: res.peps_bypassed.append(str(a[0]))
        elif n == "ps_compromised"       and len(a)==1: res.ps_compromised.append(str(a[0]))
        elif n == "direct_exposure"      and len(a)==3: res.direct_exp.append((str(a[0]),str(a[1])))
        elif n == "indirect_exposure_cross" and len(a)==3: res.cross_exp.append((str(a[0]),str(a[1])))
        elif n == "unmediated_exposure"  and len(a)==3: res.unmediated_exp.append((str(a[0]),str(a[1])))
        elif n == "attack_reaches_critical" and len(a)==3:
            res.attack_paths.append((str(a[0]), str(a[1]), a[2].number))
        elif n == "escalation_path"      and len(a)==4:
            res.escalation_paths.append((str(a[0]), str(a[1]), str(a[2]), str(a[3])))
        elif n == "capability_available" and len(a)==1: res.cap_available.append(str(a[0]))
        elif n == "capability_degraded"  and len(a)==1: res.cap_degraded.append(str(a[0]))
        elif n == "capability_lost"      and len(a)==1: res.cap_lost.append(str(a[0]))

    return res


def phase3_all(p1: Phase1Result, p2: Phase2Result) -> list:
    t0 = time.time()
    total = len(SCENARIOS)
    log(f"[Phase 3] Running {total} scenarios...")
    results = []
    for i, sc in enumerate(SCENARIOS, 1):
        r = phase3_scenario(sc, p1, p2)
        cp_tag = " [CP-COMP]" if r.cp_compromised else (" [CP-DEG]" if r.cp_degraded else "")
        cap_tag = ""
        if r.cap_lost:
            cap_tag = f" LOST:{','.join(r.cap_lost)}"
        tag = f"risk={r.total_risk:.1f}{cp_tag}{cap_tag}" if r.satisfiable else "UNSAT"
        log(f"  [{i}/{total}] {sc['name']:<35} {tag}")
        results.append(r)
    log(f"[Phase 3] DONE — {total} scenarios in {time.time()-t0:.1f}s")
    return results


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
SEP  = "=" * 78
SEP2 = "-" * 78

def _sec(title): return f"\n{SEP}\n  {title}\n{SEP}"
def _sub(title): return f"\n  --- {title} ---"


def generate_report(p1: Phase1Result, p2: Phase2Result,
                    scenarios: list) -> str:
    L = []
    baseline  = next((r for r in scenarios if r.name == "baseline"), None)
    base_risk = baseline.total_risk if baseline and baseline.satisfiable else 1.0

    # ── HEADER ──
    L.append(SEP)
    L.append("  DARPA CASE UAV — Zero Trust SoC Security DSE Assessment")
    L.append("  11 components | 3 masters | 4 buses | 0 redundancy groups")
    L.append("  4 safety-critical | PYNQ-Z2 target")
    L.append(SEP)

    # ── PHASE 1 ──
    L.append(_sec("A. PHASE 1 — OPTIMAL SECURITY FEATURE ASSIGNMENT"))
    L.append(f"  Optimality proven: {p1.optimal}")
    L.append(f"  Total base risk: {p1.total_risk()}")
    L.append("")
    L.append(f"  {'Component':<14} {'Domain':<12} {'Security':<16} {'Logging':<20} {'Exploit'}")
    L.append(f"  {'-'*14} {'-'*12} {'-'*16} {'-'*20} {'-'*8}")

    domain_map = {
        "radio_drv": "low", "fpln": "normal", "wpm": "normal",
        "cam_mgr": "normal", "wifi_drv": "untrusted", "uart_drv": "normal",
        "nfzdb": "high", "attest_gate": "root", "geofence": "high",
        "fpln_filt": "high", "swu": "privileged"
    }
    exploit_map = {
        "radio_drv": 5, "fpln": 3, "wpm": 3, "cam_mgr": 3, "wifi_drv": 5,
        "uart_drv": 3, "nfzdb": 2, "attest_gate": 1, "geofence": 1,
        "fpln_filt": 1, "swu": 4
    }
    for comp in sorted(COMPONENTS):
        sec = p1.security.get(comp, "?")
        log = p1.logging.get(comp, "?")
        dom = domain_map.get(comp, "?")
        exp = exploit_map.get(comp, "?")
        L.append(f"  {comp:<14} {dom:<12} {sec:<16} {log:<20} {exp}")

    L.append("")
    L.append("  Resource usage (PYNQ-Z2):")
    L.append(f"    LUTs   {p1.total_luts:>6} / 53200  ({100*p1.total_luts//53200}%)")
    L.append(f"    FFs    {p1.total_ffs:>6} / 106400  ({100*p1.total_ffs//106400}%)")
    L.append(f"    DSPs   {p1.total_dsps:>6} / 220")
    L.append(f"    LUTRAM {p1.total_lutram:>6} / 17400")
    L.append(f"    BRAM   {p1.total_bram:>6} / 140")
    L.append(f"    Power  {p1.total_power:>6} mW / 15000 mW  ({100*p1.total_power//15000}%)")

    L.append("")
    L.append("  Per-asset risk:")
    L.append(f"  {'Component':<14} {'Asset':<16} {'Read':>6} {'Write':>6} {'Avail':>6} {'Max':>6}")
    L.append(f"  {'-'*14} {'-'*16} {'-'*6} {'-'*6} {'-'*6} {'-'*6}")
    risk_by_comp = {}
    for comp, asset, action, risk in sorted(p1.new_risk):
        if comp not in risk_by_comp:
            risk_by_comp[comp] = {}
        risk_by_comp[comp][action] = (asset, risk)
    for comp in sorted(risk_by_comp.keys()):
        d = risk_by_comp[comp]
        asset_name = list(d.values())[0][0] if d else "?"
        r = d.get("read", ("", 0))[1]
        w = d.get("write", ("", 0))[1]
        av = d.get("avail", ("", 0))[1]
        mx = max(r, w, av)
        L.append(f"  {comp:<14} {asset_name:<16} {r:>6} {w:>6} {av:>6} {mx:>6}")

    # ── PHASE 2 ──
    L.append(_sec("B. PHASE 2 — ZTA POLICY SYNTHESIS"))
    if not p2.satisfiable:
        L.append("  WARNING: ZTA policy synthesis UNSATISFIABLE.")
        L.append("  Phase 3 will proceed without ZTA overlay.")
    else:
        L.append(f"  Total ZTA hardware cost: {p2.total_cost}")
        L.append(f"  Firewalls placed   : {', '.join(sorted(p2.placed_fws))}")
        L.append(f"  Policy servers     : {', '.join(sorted(p2.placed_ps))}")
        L.append("")

        L.append(_sub("B1. Least-Privilege Analysis"))
        L.append(f"  Excess privileges: {len(p2.excess_privileges)}")
        for master in sorted(set(m for m, _, _ in p2.excess_privileges)):
            tightness = p2.policy_tightness.get(master, 0)
            excess = [(c, op) for m, c, op in p2.excess_privileges if m == master]
            L.append(f"  {master}: tightness {tightness}%"
                     f"  {'[OVER-PRIVILEGED]' if master in p2.over_privileged else ''}")
            for c, op in sorted(set(excess)):
                L.append(f"    Excess: {master} -> {c} ({op})")
        if p2.missing_privileges:
            L.append("  Missing privileges:")
            for m, c, op in sorted(p2.missing_privileges):
                L.append(f"    MISSING: {m} -> {c} ({op})")

        L.append(_sub("B2. Trust Anchor Assessment"))
        L.append(f"  No hardware RoT  : {sorted(p2.trust_gap_rot)}")
        L.append(f"  No secure boot   : {sorted(p2.trust_gap_sboot)}")
        L.append(f"  No attestation   : {sorted(p2.trust_gap_attest)}")
        L.append(f"  Unsigned PS      : {sorted(p2.unsigned_ps)}")
        L.append(f"  No key storage   : {sorted(p2.trust_gap_keys)}")
        if p2.unattested_access:
            L.append("  Unattested masters accessing high-domain IPs:")
            for m, c in sorted(set(p2.unattested_access)):
                L.append(f"    {m} -> {c}")

        L.append(_sub("B3. Mode-Aware Policy"))
        by_mode = {}
        for ip, mode in p2.isolated:
            by_mode.setdefault(mode, []).append(ip)
        for mode in ["attack_suspected", "attack_confirmed"]:
            ips = sorted(by_mode.get(mode, []))
            L.append(f"  {mode:<22}: {len(ips)} IPs isolated")

        L.append(_sub("B4. Policy Exceptions"))
        if p2.critical_exceptions:
            L.append("  Critical exceptions:")
            for ex in p2.critical_exceptions:
                L.append(f"    {ex}")
        if p2.unexplained_exceptions:
            L.append("  Unexplained exceptions:")
            for ex in p2.unexplained_exceptions:
                L.append(f"    {ex}")
        else:
            L.append("  All exceptions have declared access_need.")

    # ── PHASE 3 ──
    L.append(_sec("C. PHASE 3 — RESILIENCE UNDER FAULT/COMPROMISE"))
    L.append(f"  Baseline total risk: {base_risk:.1f}")
    L.append(f"  Total scenarios: {len(scenarios)}")
    L.append("")
    L.append(f"  {'Scenario':<35} {'Risk':>8} {'vs Base':>8} {'CP':>5} {'Svcs OK/Deg/Una':>16} {'Caps Lost'}")
    L.append(f"  {'-'*35} {'-'*8} {'-'*8} {'-'*5} {'-'*16} {'-'*20}")

    for r in scenarios:
        if not r.satisfiable:
            L.append(f"  {r.name:<35} UNSAT")
            continue
        ratio    = r.total_risk / base_risk if base_risk > 0 else 0
        cp_flag  = "COMP" if r.cp_compromised else ("DEG" if r.cp_degraded else ("STL" if r.cp_stale else "ok"))
        svc_str  = f"{len(r.services_ok)}/{len(r.services_degraded)}/{len(r.services_unavail)}"
        cap_str  = ",".join(r.cap_lost) if r.cap_lost else "-"
        L.append(f"  {r.name:<35} {r.total_risk:>8.1f} {ratio:>7.2f}x {cp_flag:>5}  {svc_str:>16} {cap_str}")

    # Worst scenarios
    sat_scens = [r for r in scenarios if r.satisfiable and r.name != "baseline"]
    if sat_scens:
        worst = max(sat_scens, key=lambda r: r.total_risk)
        ratio_str = f"{worst.total_risk/base_risk:.2f}x" if base_risk > 0 else "N/A"
        L.append(f"\n  Worst scenario: {worst.name} ({worst.total_risk:.1f}, {ratio_str})")

    # Attack paths summary
    all_attack_paths = set()
    all_escalation = set()
    for r in scenarios:
        for ap in r.attack_paths:
            all_attack_paths.add(ap)
        for ep in r.escalation_paths:
            all_escalation.add(ep)
    if all_attack_paths:
        L.append(_sub("C1. Attack Paths to Critical Components"))
        for source, target, depth in sorted(all_attack_paths):
            L.append(f"  {source} -> {target} (depth {depth})")
    if all_escalation:
        L.append(_sub("C2. Trust Escalation Paths"))
        for source, target, src_dom, tgt_dom in sorted(all_escalation):
            L.append(f"  {source} ({src_dom}) -> {target} ({tgt_dom})")

    # Capability assessment summary
    L.append(_sub("C3. Capability Impact Summary"))
    cap_loss_count = {}
    for r in scenarios:
        if r.satisfiable:
            for cap in r.cap_lost:
                cap_loss_count[cap] = cap_loss_count.get(cap, 0) + 1
    if cap_loss_count:
        L.append(f"  {'Capability':<25} {'# Scenarios Lost'}")
        for cap, count in sorted(cap_loss_count.items(), key=lambda x: -x[1]):
            L.append(f"  {cap:<25} {count}")
    else:
        L.append("  No capabilities lost in any scenario.")

    # Service availability
    L.append(_sub("C4. Service Single Points of Failure"))
    svc_unavail_count = {}
    for r in scenarios:
        if r.satisfiable:
            for svc in r.services_unavail:
                svc_unavail_count[svc] = svc_unavail_count.get(svc, 0) + 1
    if svc_unavail_count:
        for svc, count in sorted(svc_unavail_count.items(), key=lambda x: -x[1]):
            L.append(f"  {svc:<30} unavailable in {count} scenarios")

    # ── SUMMARY ──
    L.append(_sec("D. SUMMARY — KEY FINDINGS"))
    L.append(f"""
  1. Architecture: 11 receivers, 3 masters, 4 buses, 0 redundancy groups.
     All services are SINGLE-STRING — no quorum redundancy.
     Every component failure directly degrades at least one service.

  2. Risk profile: Total base risk = {p1.total_risk()}.
     LUT utilization = {100*p1.total_luts//53200}% ({p1.total_luts}/53200).

  3. Trust domains: 6-level model (untrusted → root).
     CakeML-verified components (attest_gate, geofence, fpln_filt) at
     high/root trust with exploitability=1.

  4. Safety-critical components: fc, geofence, fpln_filt, uart_drv.
     All on single-string service chains.

  5. Bridge risk: radio_drv bridges untrusted GS RF bus into MC internal bus.
     Exploitability=5, write impact=5. Primary attack vector.

  6. WiFi maintenance interface: wifi_drv (untrusted, exploit=5) provides
     firmware update path. Must be physically isolated or ZTA-gated
     during operational flight.
""")
    if p2.satisfiable:
        L.append(f"  7. ZTA overlay: {len(p2.placed_fws)} FW(s), {len(p2.placed_ps)} PS(s), "
                 f"cost={p2.total_cost}.")
        L.append(f"     Excess privileges: {len(p2.excess_privileges)}.")
        L.append(f"     Trust gaps: {len(p2.trust_gap_rot)} no-RoT, "
                 f"{len(p2.trust_gap_sboot)} no-SB, "
                 f"{len(p2.trust_gap_attest)} unattested masters.")

    L.append("")
    L.append(SEP)
    return "\n".join(L)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    t_start = time.time()
    log(SEP)
    log("  DARPA CASE UAV — ZTA SoC DSE Runner (3-strategy)")
    log(SEP)

    strategies = ["max_security", "min_resources", "balanced"]
    all_results = {}

    for si, strategy in enumerate(strategies, 1):
        log(f"\n{'='*60}")
        log(f"  STRATEGY {si}/{len(strategies)}: {strategy}")
        log(f"{'='*60}")

        try:
            p1 = phase1_optimise(strategy)
        except RuntimeError as e:
            log(f"FATAL: {e}")
            all_results[strategy] = {"error": str(e)}
            continue

        p2 = phase2_zta(p1)
        scenarios = phase3_all(p1, p2)

        all_results[strategy] = {
            "p1": p1, "p2": p2, "scenarios": scenarios
        }
        log(f"[{strategy}] Strategy complete ({time.time()-t_start:.1f}s total)")

    # Generate consolidated report
    log(f"\nGenerating consolidated report...")
    report = generate_consolidated_report(all_results)
    log("\n" + report)

    out_path = os.path.join(BASE_DIR, "resilience_summary_darpa_uav.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report)
    log(f"\nReport written to: {out_path}")
    log(f"Total runtime: {time.time()-t_start:.1f}s")


def generate_consolidated_report(all_results: dict) -> str:
    L = []
    L.append(SEP)
    L.append("  DARPA CASE UAV — Zero Trust SoC DSE Assessment")
    L.append("  11 components | 3 masters | 4 buses | 0 redundancy groups")
    L.append("  4 safety-critical | 3 strategies | PYNQ-Z2 target")
    L.append(SEP)

    # Strategy comparison table
    L.append(_sec("STRATEGY COMPARISON"))
    L.append(f"\n  {'Metric':<30} {'max_security':>14} {'min_resources':>14} {'balanced':>14}")
    L.append(f"  {'-'*30} {'-'*14} {'-'*14} {'-'*14}")

    for metric_name, getter in [
        ("Total risk", lambda r: str(r["p1"].total_risk())),
        ("LUTs used", lambda r: str(r["p1"].total_luts)),
        ("LUT %", lambda r: f"{100*r['p1'].total_luts//53200}%"),
        ("FFs used", lambda r: str(r["p1"].total_ffs)),
        ("Power (mW)", lambda r: str(r["p1"].total_power)),
        ("Optimal", lambda r: str(r["p1"].optimal)),
        ("P2 SAT", lambda r: str(r["p2"].satisfiable)),
        ("FWs placed", lambda r: str(len(r["p2"].placed_fws)) if r["p2"].satisfiable else "N/A"),
        ("PSs placed", lambda r: str(len(r["p2"].placed_ps)) if r["p2"].satisfiable else "N/A"),
        ("Excess privs", lambda r: str(len(r["p2"].excess_privileges)) if r["p2"].satisfiable else "N/A"),
        ("Trust gaps (no RoT)", lambda r: str(len(r["p2"].trust_gap_rot)) if r["p2"].satisfiable else "N/A"),
    ]:
        vals = []
        for strat in ["max_security", "min_resources", "balanced"]:
            res = all_results.get(strat, {})
            if "error" in res:
                vals.append("ERROR")
            else:
                try:
                    vals.append(getter(res))
                except Exception:
                    vals.append("N/A")
        L.append(f"  {metric_name:<30} {vals[0]:>14} {vals[1]:>14} {vals[2]:>14}")

    # Detailed per-strategy reports
    for strat in ["max_security", "min_resources", "balanced"]:
        res = all_results.get(strat, {})
        if "error" in res:
            L.append(f"\n  STRATEGY {strat}: ERROR — {res['error']}")
            continue

        p1 = res["p1"]
        p2 = res["p2"]
        scenarios = res["scenarios"]

        L.append(_sec(f"STRATEGY: {strat}"))
        report = generate_report(p1, p2, scenarios)
        L.append(report)

    return "\n".join(L)


if __name__ == "__main__":
    main()
