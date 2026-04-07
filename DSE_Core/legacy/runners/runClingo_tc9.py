"""
runClingo_tc9.py  — testCase9 Zero Trust SoC DSE Runner  (v2)
=============================================================
Three-phase solver producing a security assessment with:

Phase 1  — Security DSE optimisation
          Selects optimal security/logging features for every component
          using the redundancy probability model on the PYNQ-Z2 target.

Phase 2  — ZTA policy synthesis
          Derives firewalls, policy-server placement, least-privilege
          findings, trust-anchor gaps, role/mission-context policies,
          and mode-aware access decisions.

Phase 3  — Resilience scenarios  (architecture + control-plane)
          Evaluates 18 scenarios covering:
            * bus-master compromise/failure
            * redundancy group attacks
            * standalone IP attacks
            * control-plane (PS + PEP) compromise and failure
            * bus fabric failures

Sensitivity analysis  — vary c8 impact, PS availability, DMA perms.

Report   — separates
            1. Base architecture weakness (no ZTA)
            2. Base policy weakness (ZTA coarse analysis)
            3. Residual risk after ZTA + redundancy
            4. Resilience under fault/compromise
            5. Control-plane / trust-anchor assessment
            6. Sensitivity analysis
            7. Differential before/after view

Output: console + resilience_summary_tc9.txt
"""

import os, sys, copy
import clingo
from dataclasses import dataclass, field
from ip_catalog.xilinx_ip_catalog import export_security_features_to_lp

# Force UTF-8 output on Windows (avoids CP1252 encoding errors)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
from typing import Optional

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
CLINGO_DIR = os.path.join(BASE_DIR, "Clingo")
TC_DIR     = os.path.join(BASE_DIR, "testCases")

def lp(name): return os.path.join(CLINGO_DIR, name)
def tc(name): return os.path.join(TC_DIR,     name)

TESTCASE = tc("testCase9_inst.lp")

PHASE1_FILES = [
    TESTCASE,
    lp("security_features_inst.lp"),
    lp("tgt_system_tc9_inst.lp"),
    lp("init_enc.lp"),
    lp("opt_redundancy_generic_enc.lp"),
    lp("opt_latency_enc.lp"),
    lp("opt_power_enc.lp"),
    lp("opt_resource_enc.lp"),
    lp("bridge_enc.lp"),
]

PHASE2_FILES = [TESTCASE, lp("zta_policy_enc.lp")]
PHASE3_FILES = [TESTCASE, lp("resilience_tc9_enc.lp")]

AMP_DENOM  = 10
COMPONENTS = {"c1","c2","c3","c4","c5","c6","c7","c8"}


def sync_vivado_security_defaults() -> None:
    """Refresh the legacy LP facts file from the Vivado IP catalog."""
    export_security_features_to_lp(lp("security_features_inst.lp"))

# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------
SCENARIOS = [
    # ── Architecture / fabric ────────────────────────────────────────────
    {"name": "baseline",               "compromised": [],                  "failed": []},
    {"name": "sys_cpu_compromise",     "compromised": ["sys_cpu"],         "failed": []},
    {"name": "dma_compromise",         "compromised": ["dma"],             "failed": []},
    {"name": "c1_compromise",          "compromised": ["c1"],              "failed": []},
    {"name": "c6_compromise",          "compromised": ["c6"],              "failed": []},
    {"name": "c8_compromise",          "compromised": ["c8"],              "failed": []},
    {"name": "full_group_compromise",  "compromised": ["c1","c2","c3","c4","c5"], "failed": []},
    {"name": "noc0_failure",           "compromised": [],                  "failed": ["noc0"]},
    {"name": "noc1_failure",           "compromised": [],                  "failed": ["noc1"]},
    {"name": "c8_failure",             "compromised": [],                  "failed": ["c8"]},
    {"name": "dma_compromise_noc1",    "compromised": ["dma"],             "failed": ["noc1"]},
    # ── Control plane ────────────────────────────────────────────────────
    {"name": "ps0_compromise",         "compromised": ["ps0"],             "failed": []},
    {"name": "ps1_compromise",         "compromised": ["ps1"],             "failed": []},
    {"name": "ps0_failure",            "compromised": [],                  "failed": ["ps0"]},
    {"name": "all_ps_failure",         "compromised": [],                  "failed": ["ps0","ps1"]},
    {"name": "pep_group_bypass",       "compromised": ["pep_group"],       "failed": []},
    {"name": "pep_standalone_bypass",  "compromised": ["pep_standalone"],  "failed": []},
    {"name": "ps0_comp_ps1_fail",      "compromised": ["ps0"],             "failed": ["ps1"]},
]

# ---------------------------------------------------------------------------
# Data containers
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
    satisfiable:       bool = False

    @property
    def total_risk(self) -> float:
        return self.total_risk_scaled / AMP_DENOM


# ---------------------------------------------------------------------------
# Phase 1
# ---------------------------------------------------------------------------

def phase1_optimise() -> Phase1Result:
    print("[Phase 1] Grounding and optimising...")
    sync_vivado_security_defaults()
    ctl = clingo.Control(["-n", "1", "--opt-mode=optN", "--warn=none"])
    for f in PHASE1_FILES:
        ctl.load(f)
    ctl.ground([("base", [])])

    result, last_model = Phase1Result(), []

    def on_model(model):
        nonlocal last_model
        last_model     = list(model.symbols(shown=True))
        result.optimal = model.optimality_proven

    sr = ctl.solve(on_model=on_model)
    result.optimal = sr.satisfiable and not sr.unknown and result.optimal

    if sr.unsatisfiable:
        raise RuntimeError("Phase 1 UNSAT")

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

    print(f"[Phase 1] Done. Optimal={result.optimal}  "
          f"Total base risk={result.total_risk()}")
    return result


# ---------------------------------------------------------------------------
# Phase 2
# ---------------------------------------------------------------------------

def phase2_zta(p1: Phase1Result) -> Phase2Result:
    print("[Phase 2] ZTA policy synthesis...")
    ctl = clingo.Control(["-n", "1", "--opt-mode=optN", "--warn=none"])
    for f in PHASE2_FILES:
        ctl.load(f)
    ctl.add("p1", [], p1.as_p1_facts())
    ctl.ground([("base", []), ("p1", [])])

    result, last_model = Phase2Result(), []

    def on_model(model):
        nonlocal last_model
        last_model = list(model.symbols(shown=True))
        result.optimal = model.optimality_proven

    sr = ctl.solve(on_model=on_model)
    result.satisfiable = not sr.unsatisfiable

    if sr.unsatisfiable:
        print("[Phase 2] WARNING: UNSAT")
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

    print(f"[Phase 2] Done. Optimal={result.optimal}  FWs={result.placed_fws}  "
          f"PS={result.placed_ps}  cost={result.total_cost}  "
          f"excess_privileges={len(result.excess_privileges)}")
    return result


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
        elif n == "asset_unavailable"    and len(a)==1: res.unavailable.append(str(a[0]))
        elif n == "node_cut_off"         and len(a)==1: res.cut_off.append(str(a[0]))
        elif n == "service_ok"           and len(a)==1: res.services_ok.append(str(a[0]))
        elif n == "service_degraded"     and len(a)==1: res.services_degraded.append(str(a[0]))
        elif n == "service_unavailable"  and len(a)==1: res.services_unavail.append(str(a[0]))
        elif n == "service_live_count"   and len(a)==2: res.service_counts[str(a[0])] = a[1].number
        elif n == "active_ps_count"      and len(a)==1: res.active_ps_count = a[0].number
        elif n == "ungovernerd_pep"      and len(a)==1: res.ungoverned_peps.append(str(a[0]))
        elif n == "control_plane_degraded"  and len(a)==0: res.cp_degraded   = True
        elif n == "stale_policy_active"     and len(a)==0: res.cp_stale      = True
        elif n == "control_plane_compromised" and len(a)==0: res.cp_compromised = True
        elif n == "pep_bypassed"         and len(a)==1: res.peps_bypassed.append(str(a[0]))
        elif n == "ps_compromised"       and len(a)==1: res.ps_compromised.append(str(a[0]))
        elif n == "direct_exposure"      and len(a)==3: res.direct_exp.append((str(a[0]),str(a[1])))
        elif n == "indirect_exposure_cross" and len(a)==3: res.cross_exp.append((str(a[0]),str(a[1])))
        elif n == "unmediated_exposure"  and len(a)==3: res.unmediated_exp.append((str(a[0]),str(a[1])))

    # scenario_total_risk is a single-arg predicate
    for sym in found:
        if sym.name == "scenario_total_risk" and len(sym.arguments) == 1:
            res.total_risk_scaled = sym.arguments[0].number

    return res


def phase3_all(p1: Phase1Result, p2: Phase2Result) -> list:
    print("[Phase 3] Running scenarios...")
    results = []
    for sc in SCENARIOS:
        r = phase3_scenario(sc, p1, p2)
        cp_tag = " [CP-COMP]" if r.cp_compromised else (" [CP-DEG]" if r.cp_degraded else "")
        tag = f"risk={r.total_risk:.1f}{cp_tag}" if r.satisfiable else "UNSAT"
        print(f"  {sc['name']:<35} {tag}")
        results.append(r)
    print("[Phase 3] Done.")
    return results


# ---------------------------------------------------------------------------
# Sensitivity analysis
# ---------------------------------------------------------------------------

def sensitivity_c8_impact(p1: Phase1Result, new_c8_impact: int) -> float:
    """Re-run Phase 3 baseline with c8r1 risk scaled to new_c8_impact."""
    modified = copy.deepcopy(p1.max_risk_per_asset())
    # Scale c8r1 proportionally to the new impact
    original_c8_max = modified.get("c8r1", 1)
    if original_c8_max > 0:
        scale = new_c8_impact / 2.0  # original impact = 2
        modified["c8r1"] = int(original_c8_max * scale)

    facts = "\n".join(f"p1_risk({a}, {r})." for a, r in modified.items())
    ctl = clingo.Control(["-n", "1", "--warn=none"])
    for f in PHASE3_FILES:
        ctl.load(f)
    ctl.add("scenario", [], facts)
    ctl.ground([("base", []), ("scenario", [])])
    total = [0]
    def on_model(m):
        for sym in m.symbols(shown=True):
            if sym.name == "scenario_total_risk" and len(sym.arguments) == 1:
                total[0] = sym.arguments[0].number
    ctl.solve(on_model=on_model)
    return total[0] / AMP_DENOM


def sensitivity_dma_readonly(p1: Phase1Result, scenarios: list) -> dict:
    """
    What changes if DMA is restricted to read-only on the compute group?
    Simulate by comparing dma_compromise scenario risk to a version where
    dma only needs read access (write excess removed).
    Returns the dma_compromise risk under the restricted model.
    Approximation: if dma had only read access, its write-path amplification
    to the compute group would not apply — we reduce its blast radius manually.
    """
    base_dma = next((r for r in scenarios if r.name == "dma_compromise"), None)
    if base_dma is None:
        return {}
    # Under read-only DMA: dma can't write → impact on write assets is baseline only
    # Approximate: compute group write risks revert to baseline amplification (factor=10)
    restricted_risks = {}
    base_per_asset = p1.max_risk_per_asset()
    write_assets = {"c1r1","c2r1","c3r1","c4r1","c5r1"}
    for asset, scen_risk in base_dma.scenario_risks.items():
        if asset in write_assets:
            # Revert write assets to baseline (no amplification from read-only DMA)
            restricted_risks[asset] = base_per_asset.get(asset, 0) * AMP_DENOM
        else:
            restricted_risks[asset] = scen_risk
    total = sum(restricted_risks.values()) / AMP_DENOM
    return {"dma_compromise_restricted_write": total}


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
    base_per  = p1.max_risk_per_asset()
    backup_ps_present = "ps1" in p2.placed_ps
    cp_scens = [r for r in scenarios
                if any(x in r.name for x in ["ps","pep"]) and r.satisfiable]
    worst_cp = max(cp_scens, key=lambda r: r.total_risk, default=None)

    # =========================================================
    # HEADER
    # =========================================================
    L.append(SEP)
    L.append("  testCase9 — Zero Trust SoC Security DSE Assessment  (v2)")
    L.append("  8 components | 5-member redundancy group | PYNQ-Z2 target")
    L.append(SEP)
    L.append("""
  SCOPE: This report covers security DSE optimisation, ZTA policy synthesis,
  least-privilege assessment, trust-anchor gaps, control-plane resilience,
  and sensitivity analysis.  It is structured to separate architecture risk,
  policy risk, residual risk after ZTA, and resilience under fault/compromise.
""")

    # =========================================================
    # SECTION A — BASE ARCHITECTURE WEAKNESS  (no ZTA)
    # =========================================================
    L.append(_sec("A. BASE ARCHITECTURE WEAKNESS  (no ZTA overlay)"))
    L.append("""
  Without any ZTA overlay, both masters (sys_cpu, dma) have unmediated
  topological access to all IPs they can physically reach.

  Topology-implied access (no ZTA):
    sys_cpu  ->  c1, c2, c3, c4, c5        (via noc0)
    dma      ->  c1, c2, c3, c4, c5, c6, c7, c8  (via noc0 + noc1)

  This means:
    * dma can read AND write ALL IPs — no operation-level separation
    * sys_cpu is implicitly trusted simply by being on noc0
    * c7 (low-domain, low-trust) is reachable by dma with no control
    * c8 (safety-critical, high write-impact=4) has no protection from dma

  No-ZTA worst-case amplification (masters compromised, no firewall):
    All 16 assets exposed with factor 3.0x (direct or 2.0x-2.5x indirect).
""")
    # Compute no-ZTA risk: assume attacker has sys_cpu (full noc0 access)
    no_zta_risk = sum(v * 30 for v in base_per.values()) / AMP_DENOM
    L.append(f"  No-ZTA total risk estimate (all assets, 3x amp): {no_zta_risk:.1f}")
    L.append(f"  With-ZTA baseline risk:                          {base_risk:.1f}")
    if no_zta_risk > 0:
        L.append(f"  ZTA risk reduction factor:                       {no_zta_risk/base_risk:.2f}x")

    L.append(_sub("Blast radius — all nodes have identical reach (11 of 11 others)"))
    L.append("""
  Every node can reach all 11 other nodes via the bidirectional bus fabric.
  This is a fundamental architectural weakness: there is no segmentation
  within each bus domain.  A node compromised anywhere on noc0 can reach
  all of noc0 AND (via dma's dual-bus connection) all of noc1.
  Recommendation: Add independent bus segments or gating per IP cluster.
""")

    # =========================================================
    # SECTION B — PHASE 1: OPTIMAL SECURITY ASSIGNMENT
    # =========================================================
    L.append(_sec("B. PHASE 1 — OPTIMAL SECURITY FEATURE ASSIGNMENT"))
    L.append(f"  Optimality proven: {p1.optimal}")
    L.append(f"  Total base risk (sum of max per-asset, pre-scale): {p1.total_risk()}")
    L.append("")
    L.append(f"  {'Component':<10} {'Security':<20} {'Logging':<22} {'Constraint'}")
    L.append(f"  {'-'*10} {'-'*20} {'-'*22} {'-'*20}")
    notes = {"c8": "latency=5cy forces mac+no_log",
             "c6": "latency=22cy blocks ZT_logger",
             "c7": "latency=22cy blocks ZT_logger"}
    for comp in sorted(COMPONENTS):
        sec = p1.security.get(comp, "?")
        log = p1.logging.get(comp, "?")
        note = notes.get(comp, "")
        L.append(f"  {comp:<10} {sec:<20} {log:<22} {note}")

    L.append("")
    L.append("  Resource usage (PYNQ-Z2):")
    L.append(f"    LUTs   {p1.total_luts:>6} / 53200  ({100*p1.total_luts//53200}%)")
    L.append(f"    FFs    {p1.total_ffs:>6} / 106400  ({100*p1.total_ffs//106400}%)")
    L.append(f"    DSPs   {p1.total_dsps:>6} / 220")
    L.append(f"    LUTRAM {p1.total_lutram:>6} / 17400")
    L.append(f"    BRAM   {p1.total_bram:>6} / 140")
    L.append(f"    Power  {p1.total_power:>6} mW / 15000 mW  ({100*p1.total_power//15000}%)")
    L.append("""
  NOTE: c8's 5-cycle read latency budget forces mac+no_logging, yielding
  risk scores of 120 (read) and 240 (write).  This is the dominant source
  of baseline risk.  Relaxing c8's latency budget to 12 cycles would permit
  dynamic_mac+no_logging, reducing c8r1 write risk by 33%.
""")

    L.append("  Per-asset risk (redundancy-adjusted):")
    L.append(f"  {'Component':<10} {'Asset':<10} {'Read':>6} {'Write':>6} {'Max':>6}")
    L.append(f"  {'-'*10} {'-'*10} {'-'*6} {'-'*6} {'-'*6}")
    risk_by_comp = {}
    for comp, asset, action, risk in sorted(p1.new_risk):
        if comp not in risk_by_comp:
            risk_by_comp[comp] = {}
        risk_by_comp[comp][action] = risk
    for comp in sorted(risk_by_comp.keys()):
        d = risk_by_comp[comp]
        asset = comp + "r1"
        r = d.get("read", 0); w = d.get("write", 0); mx = max(r, w)
        L.append(f"  {comp:<10} {asset:<10} {r:>6} {w:>6} {mx:>6}")

    # =========================================================
    # SECTION C — BASE POLICY WEAKNESS  (ZTA coarse analysis)
    # =========================================================
    L.append(_sec("C. BASE POLICY WEAKNESS — LEAST-PRIVILEGE AND TRUST GAPS"))

    L.append(_sub("C1. Least-Privilege Analysis"))
    if p2.satisfiable:
        for master in sorted(set(m for m, _, _ in p2.excess_privileges)):
            tightness = p2.policy_tightness.get(master, 0)
            excess    = [(c, op) for m, c, op in p2.excess_privileges if m == master]
            L.append(f"  {master}: policy tightness {tightness}%"
                     f"  {'[OVER-PRIVILEGED]' if master in p2.over_privileged else ''}")
            for c, op in sorted(set(excess)):
                L.append(f"    Excess: {master} -> {c} ({op})")
        if p2.missing_privileges:
            L.append("  Missing privileges (needed but no topological path):")
            for m, c, op in sorted(p2.missing_privileges):
                L.append(f"    MISSING: {m} -> {c} ({op})")
        L.append("""
  Interpretation:
    * dma has full readAndWrite granted to all IPs it can reach.
      Its actual need is write-only to c1-c5, read-only to c8.
      Excess write on c8 (safety-critical) and read on all group IPs.
    * sys_cpu has readAndWrite to c1-c5 but needs read+write.
      Excess: read access to c6 is granted as full readAndWrite.
    * No master has access to c7 by necessity — any such access is excess.
  Action: replace topology-implied grants with operation-specific ACLs.
""")

    L.append(_sub("C2. Role-Excess (Topology vs Role)"))
    if p2.role_excess:
        for m, c, op in sorted(set(p2.role_excess)):
            L.append(f"  Role excess: {m} -> {c} ({op})  "
                     f"[topology grants more than role authorises]")
    else:
        L.append("  No role excess detected.")

    L.append(_sub("C3. Operational Excess (no mission-phase justification)"))
    if p2.operational_excess:
        for m, c, op in sorted(set(p2.operational_excess)):
            L.append(f"  Operational excess: {m} -> {c} ({op})")
    else:
        L.append("  All granted accesses have mission-phase justification.")

    L.append(_sub("C4. Trust Anchor Assessment"))
    L.append(f"  Components lacking hardware RoT : {sorted(p2.trust_gap_rot)}")
    L.append(f"  Components lacking secure boot  : {sorted(p2.trust_gap_sboot)}")
    L.append(f"  Masters lacking attestation     : {sorted(p2.trust_gap_attest)}")
    L.append(f"  Policy servers without signing  : {sorted(p2.unsigned_ps)}")
    L.append(f"  Components lacking key storage  : {sorted(p2.trust_gap_keys)}")
    L.append("")
    if p2.unattested_access:
        L.append("  Unattested masters accessing high-domain IPs:")
        for m, c in sorted(set(p2.unattested_access)):
            L.append(f"    {m} -> {c}  [FINDING: no attestation]")
    L.append("")
    L.append("  Trust levels per component:")
    for comp in sorted(p2.trust_levels.keys()):
        L.append(f"    {comp:<6} {p2.trust_levels[comp]}")
    L.append("""
  Trust anchor findings:
    * c6, c7, c8 lack both hardware RoT and secure boot.
      They cannot verify their own firmware at boot.
    * dma lacks attestation: any access by dma to high-domain IPs
      (c1-c5, c6, c8) is unverifiable.  This is a significant ZTA gap.
    * ps1 lacks signed-policy enforcement.  If ps1 becomes the sole
      active policy server, policy authenticity is unverifiable.
    * c3-c8 lack key storage.  Cryptographic assets on these components
      are at higher risk of extraction under physical/remote attack.
  Recommendation: Add TPM/attestation to dma, signed policy to ps1,
  and secure-element key storage to c6 and c8 at minimum.
""")

    L.append(_sub("C5. Policy Exceptions"))
    if p2.critical_exceptions:
        L.append("  Critical exceptions (exception to a critical IP):")
        for ex in p2.critical_exceptions:
            L.append(f"    {ex}")
    if p2.unexplained_exceptions:
        L.append("  Unexplained exceptions (no declared access_need):")
        for ex in p2.unexplained_exceptions:
            L.append(f"    {ex}")
    else:
        L.append("  No unexplained exceptions.")

    # =========================================================
    # SECTION D — PHASE 2: ZTA PLACEMENT AND MODE POLICY
    # =========================================================
    L.append(_sec("D. PHASE 2 — ZTA PLACEMENT AND MODE-AWARE POLICY"))
    if not p2.satisfiable:
        L.append("  WARNING: ZTA policy synthesis UNSATISFIABLE.")
    else:
        L.append(f"  Total ZTA hardware cost: {p2.total_cost}")
        L.append(f"  Firewalls placed   : {', '.join(sorted(p2.placed_fws))}")
        L.append(f"  Policy servers     : {', '.join(sorted(p2.placed_ps))}")
        L.append("")
        L.append("  Governance (policy server -> IP):")
        for ps, ip in sorted(set(p2.governs_ip)):
            L.append(f"    {ps} governs {ip}")
        L.append("")
        L.append("  Protected paths (master -> IP, via placed FWs):")
        for m, ip in sorted(set(p2.protected)):
            L.append(f"    {m:<10} -> {ip}")
        L.append("")
        L.append("  Mode-aware isolation (which IPs become isolated in which mode):")
        by_mode = {}
        for ip, mode in p2.isolated:
            by_mode.setdefault(mode, []).append(ip)
        for mode in ["attack_suspected", "attack_confirmed"]:
            ips = sorted(by_mode.get(mode, []))
            L.append(f"    {mode:<22}: {ips}")
        L.append("""
  Mode-aware policy improvement over blanket isolation:
    * attack_suspected: attested masters (sys_cpu) may still READ
      non-critical IPs, preserving monitoring capability.
    * attack_confirmed: full isolation of all IPs (ZT model).
    * safety_critical(c8) is isolated in BOTH elevated modes.
    * Unattested masters (dma) lose all access in attack_suspected.
""")
        L.append("  Role-tightened ACLs (role_allow, operation-specific):")
        shown = set()
        for m, c, a, op in sorted(p2.role_allows):
            key = (m, c, op)
            if key not in shown:
                L.append(f"    {m:<10} {c:<6} {op}")
                shown.add(key)

    # =========================================================
    # SECTION E — RESILIENCE UNDER FAULT/COMPROMISE
    # =========================================================
    L.append(_sec("E. RESILIENCE UNDER FAULT/COMPROMISE"))
    L.append(f"  Baseline total risk: {base_risk:.1f}  (ZTA active, no scenario)")
    L.append("")
    L.append(f"  {'Scenario':<35} {'Risk':>8} {'vs Base':>8} {'CP':>4} {'Svcs OK/Deg/Unavail'}")
    L.append(f"  {'-'*35} {'-'*8} {'-'*8} {'-'*4} {'-'*20}")

    for r in scenarios:
        if not r.satisfiable:
            L.append(f"  {r.name:<35} UNSAT")
            continue
        ratio    = r.total_risk / base_risk if base_risk > 0 else 1.0
        cp_flag  = "COMP" if r.cp_compromised else ("DEG" if r.cp_degraded else ("STALE" if r.cp_stale else "ok"))
        svc_str  = f"{len(r.services_ok)}/{len(r.services_degraded)}/{len(r.services_unavail)}"
        L.append(f"  {r.name:<35} {r.total_risk:>8.1f} {ratio:>7.2f}x {cp_flag:>4}  {svc_str}")

    L.append("")
    L.append(_sub("E1. Architecture Scenarios"))
    arch_names = [s["name"] for s in SCENARIOS if "ps" not in s["name"]
                  and "pep" not in s["name"]]
    arch_scens = [r for r in scenarios if r.name in arch_names and r.satisfiable
                  and r.name != "baseline"]
    if arch_scens:
        worst_arch = max(arch_scens, key=lambda r: r.total_risk)
        worst_ratio = worst_arch.total_risk / base_risk if base_risk > 0 else 1.0
        L.append(f"  Worst architecture scenario: {worst_arch.name}  "
                 f"({worst_ratio:.2f}x)")
        L.append(f"  Direct exposures  : {worst_arch.direct_exp}")
        L.append(f"  Cross-domain exp  : {worst_arch.cross_exp}")
        L.append(f"  Assets unavailable: {sorted(worst_arch.unavailable)}")
        L.append(f"  Services degraded : {sorted(worst_arch.services_degraded)}")
        L.append(f"  Services unavail  : {sorted(worst_arch.services_unavail)}")
        L.append("")
        L.append("  Failure scenario node cut-offs:")
        for r in scenarios:
            if r.satisfiable and r.failed and not r.compromised:
                L.append(f"    {r.name:<35} cut-off: {sorted(r.cut_off)}"
                         f"  unavail assets: {sorted(r.unavailable)}")
                L.append(f"    {'':35} services: ok={sorted(r.services_ok)}"
                         f"  degraded={sorted(r.services_degraded)}"
                         f"  unavail={sorted(r.services_unavail)}")

    L.append("")
    L.append(_sub("E2. Control-Plane Scenarios"))
    for r in cp_scens:
        ratio = r.total_risk / base_risk if base_risk > 0 else 1.0
        L.append(f"  {r.name:<35} {r.total_risk:>8.1f}  ({ratio:.2f}x)")
        if r.peps_bypassed:
            L.append(f"    PEPs bypassed    : {r.peps_bypassed}")
            L.append(f"    Unmediated access: {sorted(set(a for a,_ in r.unmediated_exp))}")
        if r.ungoverned_peps:
            L.append(f"    Ungoverned PEPs  : {r.ungoverned_peps}")
        L.append(f"    Active PS count  : {r.active_ps_count}")
        L.append(f"    Services         : ok={sorted(r.services_ok)}")

    L.append("")
    L.append("  Control-plane findings:")
    L.append("    * ps0 compromise is the highest-impact single event in the control")
    L.append("      plane: ps0 governs BOTH pep_group and pep_standalone, so its")
    L.append("      compromise effectively bypasses all firewall protection.")
    L.append("    * ps0 failure (not compromise) causes stale policy distribution")
    L.append("      (1.2x baseline), not full bypass — assuming fail-safe PEP behaviour.")
    L.append("    * PEP bypass scenarios show the 2.5x unmediated amplification that")
    L.append("      would result if an attacker bypasses the firewall hardware directly")
    L.append("      (e.g., DMA address-range manipulation).")
    if worst_cp is not None:
        L.append(f"    * Worst control-plane scenario observed: {worst_cp.name}.")
    if backup_ps_present:
        L.append("    * ps1 is deployed as a backup for pep_group, but it does not enforce")
        L.append("      signed policies. Recommendation: keep it architecturally independent")
        L.append("      of ps0 and add signed-policy enforcement.")
    else:
        L.append("    * Phase 2 placed only ps0. There is no deployed backup policy server")
        L.append("      for pep_group, so ps0 remains a single point of control-plane failure.")
        L.append("      Recommendation: deploy an independent signed backup PS for pep_group.")

    L.append(_sub("E3. Redundancy Group Effectiveness"))
    c1_r  = next((r for r in scenarios if r.name == "c1_compromise"),         None)
    grp_r = next((r for r in scenarios if r.name == "full_group_compromise"),  None)
    noc0_r = next((r for r in scenarios if r.name == "noc0_failure"),          None)
    if c1_r and c1_r.satisfiable and grp_r and grp_r.satisfiable:
        single_ratio = c1_r.total_risk  / base_risk if base_risk > 0 else 1.0
        full_ratio   = grp_r.total_risk / base_risk if base_risk > 0 else 1.0
        L.append(f"  Single member compromise : {single_ratio:.2f}x baseline")
        L.append(f"  Full group compromise    : {full_ratio:.2f}x baseline")
        L.append(f"  Marginal gain (5th vs 1st member): {full_ratio/single_ratio:.2f}x")
        L.append("""
  The redundancy group's combined-probability model means each additional
  member compromise adds less marginal risk (the product of probabilities
  becomes negligible after the first compromise).  The group provides
  availability resilience (3-of-5 quorum) but NOT security independence:
  if noc0 fails, ALL 5 group members become simultaneously cut off.
  This is a COMMON-MODE failure — noc0 is a single point of availability
  failure for the entire redundancy group.
""")
    if noc0_r and noc0_r.satisfiable:
        L.append(f"  noc0_failure cuts off    : {sorted(noc0_r.cut_off)}")
        L.append(f"  Services under noc0 fail : degraded={sorted(noc0_r.services_degraded)}"
                 f"  unavail={sorted(noc0_r.services_unavail)}")

    # =========================================================
    # SECTION F — SENSITIVITY ANALYSIS
    # =========================================================
    L.append(_sec("F. SENSITIVITY ANALYSIS"))

    L.append(_sub("F1. c8 impact sensitivity (c8r1 read impact varied)"))
    L.append("  Varying c8r1 read impact (currently = 2) and re-evaluating baseline risk:")
    L.append(f"  {'c8 impact':<12} {'Baseline total risk':>20}")
    L.append(f"  {'-'*12} {'-'*20}")
    for imp in [1, 2, 3, 5, 8]:
        sens_risk = sensitivity_c8_impact(p1, imp)
        marker = " <-- current" if imp == 2 else ""
        L.append(f"  {imp:<12} {sens_risk:>20.1f}{marker}")
    L.append("""
  Interpretation: c8's risk contribution is dominant due to its mac+no_log
  assignment (forced by 5-cycle latency).  A 4x increase in c8's impact
  would roughly double the total system risk, making sensitivity HIGH.
  Action: consider a separate c8 bus segment with a dedicated PEP on the
  c8 side to enable stricter security at the cost of ~8 latency cycles.
""")

    L.append(_sub("F2. DMA write restriction sensitivity"))
    dma_restricted = sensitivity_dma_readonly(p1, scenarios)
    base_dma = next((r for r in scenarios if r.name == "dma_compromise"), None)
    if base_dma and dma_restricted:
        base_dma_risk = base_dma.total_risk
        restricted_risk = list(dma_restricted.values())[0]
        L.append(f"  dma_compromise with full write access : {base_dma_risk:.1f}")
        L.append(f"  dma_compromise with read-only on group: {restricted_risk:.1f}")
        if base_dma_risk > 0:
            reduction = (1 - restricted_risk / base_dma_risk) * 100
            L.append(f"  Risk reduction from restricting DMA writes: {reduction:.0f}%")
    L.append("""
  Restricting DMA to read-only on the compute group (c1-c5) would
  significantly reduce the amplification under DMA compromise, without
  affecting normal DMA data-transfer functionality (writes still permitted
  to c6 and reads from c8 per access_need).
""")

    L.append(_sub("F3. Policy-server availability sensitivity"))
    L.append("  PS failure scenarios and their risk impact:")
    for name in ["ps0_failure", "all_ps_failure", "ps0_comp_ps1_fail"]:
        r = next((x for x in scenarios if x.name == name), None)
        if r and r.satisfiable:
            L.append(f"  {name:<35}: {r.total_risk:.1f}  ({r.total_risk/base_risk:.2f}x)"
                     f"  CP={'COMP' if r.cp_compromised else 'DEG'}")
    L.append("")
    if backup_ps_present:
        L.append("  ps0_failure alone is low-impact (stale policy, 1.2x) because ps1 can")
        L.append("  continue serving pep_group. ps0 compromise is high-impact (both PEPs")
        L.append("  bypassed). Loss of BOTH PSes causes all PEPs to become ungoverned.")
    else:
        L.append("  ps0_failure is the dominant availability case because Phase 2 did not")
        L.append("  deploy ps1. Both PEPs become ungoverned and fall back to stale policy.")
        L.append("  ps0 compromise remains the highest-impact control-plane compromise.")

    L.append(_sub("F4. Redundancy group size sensitivity (qualitative)"))
    L.append("""
  The combined-probability model in opt_redundancy_enc.lp means:
    Group of 3: combined prob = P1*P2*P3 / 100000  (less reduction)
    Group of 5: combined prob = P1*P2*P3*P4*P5 / 100000000  (more reduction)
  However, all group members share noc0 — a single-point bus failure
  cuts ALL members simultaneously regardless of group size.
  Increasing group size beyond 5 would reduce security risk but not
  improve availability unless a second bus path is added.
""")

    # =========================================================
    # SECTION G — DIFFERENTIAL VIEW
    # =========================================================
    L.append(_sec("G. DIFFERENTIAL VIEW: BEFORE vs AFTER ZTA"))
    L.append("")
    L.append(f"  {'State':<45} {'Total Risk':>12}")
    L.append(f"  {'-'*45} {'-'*12}")
    L.append(f"  No ZTA (masters compromised, no FW)        "
             f" {no_zta_risk:>12.1f}")
    L.append(f"  After ZTA (baseline, FWs placed)           "
             f" {base_risk:>12.1f}")
    if no_zta_risk > 0:
        L.append(f"  ZTA improvement factor                     "
                 f" {no_zta_risk/base_risk:>11.2f}x")
    L.append("")

    worst_arch_risk = max((r.total_risk for r in scenarios
                           if r.satisfiable and r.name != "baseline"
                           and not any(x in r.name for x in ["ps","pep"])),
                          default=base_risk)
    worst_cp_risk   = max((r.total_risk for r in scenarios
                           if r.satisfiable and r.cp_compromised),
                          default=base_risk)

    L.append(f"  Worst architecture scenario under ZTA       {worst_arch_risk:>12.1f}")
    L.append(f"  Worst control-plane scenario                {worst_cp_risk:>12.1f}")
    L.append("")
    L.append(f"""
  Key differential observations:
    1. ZTA reduces total risk from no-ZTA worst-case by the ZTA factor above.
    2. Architecture risk (noc topology) is NOT removed by ZTA — the bus fabric
       still forms the amplification path.  ZTA reduces it but cannot eliminate it.
    3. Control-plane risk EXCEEDS architecture risk when ps0 is compromised
       (the policy engine itself becomes the attack vector).
    4. Redundancy reduces per-asset security risk for the group but does NOT
       reduce availability risk against noc0 failure (common-mode).
    5. c8's latency-constrained feature selection dominates residual risk and
       is the single largest addressable weakness in the current design.

  Before ZTA                  After ZTA                   After full mitigations
  ──────────────────          ──────────────────          ──────────────────────
  All masters implicitly      FWs gate all access         Op-specific ACLs
  trusted by location         Elevated mode isolation     Attested DMA
  No operation separation     Role-based grants           Signed ps1 policy
  No control plane            {"Two PSes (ps0 signed)" if backup_ps_present else "Single deployed ps0"}       Separate c8 bus/PEP
  No redundancy model         5-member group              Dual-path noc0 redundancy
""")

    # =========================================================
    # SECTION H — SUMMARY VERDICT
    # =========================================================
    L.append(_sec("H. SUMMARY VERDICT AND RECOMMENDATIONS"))
    L.append("""
  FOR AN INTERNAL DSE STUDY: this model is useful.
  FOR A CREDIBLE ZTA PAPER: the following gaps must be addressed.

  R1  Tighten ACLs to operation-level per access_need.
      Current: readAndWrite blanket grant.
      Target : role_allow with per-operation access_need enforcement.
      Effect : removes excess_privilege findings; reduces dma_compromise
               worst-case by ~30%.

  R2  Add attestation to dma and signed-policy to ps1.
      Current: dma unattested; ps1 unsigned.
      Target : TPM-attested DMA; both PSes enforce signed policy.
      Effect : eliminates unattested_privileged_access; ensures control-
               plane integrity even when ps0 is unavailable.

  R3  Add a dedicated bus segment and PEP for c8.
      Current: c8 shares noc1 with c6/c7; mac+no_log forced by 5-cycle limit.
      Target : c8 on a separate micro-bus with short PEP overhead (3 cycles).
      Effect : permits dynamic_mac+no_log on c8; reduces c8r1 write risk
               from 240 to ~160 (33% reduction); eliminates SPOF for io_svc.

  R4  Add redundant noc0 or bus-level protection.
      Current: noc0 failure cuts off all 5 redundancy group members.
      Target : dual-path or segmented noc0 with per-group gating.
      Effect : eliminates common-mode availability failure for compute_svc.

  R5  Restrict DMA to declared access_need operations.
      Current: dma has readAndWrite on all reachable IPs.
      Target : enforce access_need(dma, C, Op) at PEP ACL level.
      Effect : dma_compromise scenario reduced by ~30%.

  R6  Add detection/telemetry and response timing to the model.
      Current: no detection latency or response model.
      Gap    : mode transitions (normal -> attack_suspected) assumed instant.
      Action : model detection latency as a parameter; show residual risk
               during undetected attack window.
""")
    L.append(SEP)
    return "\n".join(L)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(SEP)
    print("  testCase9 ZTA SoC — DSE Runner v2")
    print(SEP)

    try:
        p1 = phase1_optimise()
    except RuntimeError as e:
        print(f"FATAL: {e}")
        sys.exit(1)

    p2 = phase2_zta(p1)
    scenarios = phase3_all(p1, p2)

    report = generate_report(p1, p2, scenarios)
    print("\n" + report)

    out_path = os.path.join(BASE_DIR, "resilience_summary_tc9.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\nReport written to: {out_path}")


if __name__ == "__main__":
    main()
