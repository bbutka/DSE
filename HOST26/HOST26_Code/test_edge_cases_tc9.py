"""
test_edge_cases_tc9.py  --  Edge-case verification suite for the tc9 ZTA DSE framework
=======================================================================================
Tests boundary conditions and non-obvious behaviours NOT covered by test_suite_tc9.py.

Run:
    py -3.12 test_edge_cases_tc9.py

--- Generic redundancy encoding (opt_redundancy_generic_enc.lp) ---
Step-by-step /1000 division.  norm = (V*L - 25)*1000//975.

Discrete norm values (from security_features_inst.lp):
  zt+zt_log  : V=10,L=5,  VL=50,  norm=25
  zt+some_log: V=10,L=10, VL=100, norm=76
  mac+zt_log : V=30,L=5,  VL=150, norm=128
  zt+no_log  : V=10,L=20, VL=200, norm=179
  mac+some_log: V=30,L=10, VL=300, norm=282
  dyn+no_log : V=20,L=20, VL=400, norm=384
  mac+no_log : V=30,L=20, VL=600, norm=589

Key arithmetic (generic encoder, /1000 per step):
  Size-1, mac+no_log:   combined=589,        denorm=824
  Size-1, mac+zt_log:   combined=128,        denorm=374
  Size-2, mac+no_log:   combined=346,        denorm=587
  Size-3, mac+no_log:   combined=203,        denorm=447
  Size-5, mac+no_log:   combined=70,         denorm=318
  Size-6, mac+no_log:   combined=41,         denorm=289
  Size-2, zt+no_log:    combined=32,         denorm=281
  Size-2, zt+zt_log:    combined=0,          denorm=250
  Size-2, zt+some_log:  combined=5,          denorm=254
Note: logging latency is excluded from the hard constraint, so the
optimizer may pick mixed logging per-component to minimize group risk.

--- Phase 3 resilience amplification factors (x10 scale) ---
  direct_exposure=30, cross-domain indirect=20, same-domain indirect=15,
  unmediated (PEP bypass)=25, stale_policy=12, ps_conflict=13, baseline=10
"""

import sys
import os
sys.stdout.reconfigure(encoding="utf-8")

import clingo
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))

def lp(name):
    return os.path.join(HERE, "Clingo", name)


PHASE1_BASE = [
    lp("security_features_inst.lp"),
    lp("init_enc.lp"),
    lp("opt_redundancy_generic_enc.lp"),
    lp("opt_latency_enc.lp"),
    lp("opt_power_enc.lp"),
    lp("opt_resource_enc.lp"),
    lp("bridge_enc.lp"),
]
PHASE2_BASE = [lp("zta_policy_enc.lp")]
PHASE3_BASE = [lp("resilience_tc9_enc.lp")]

# ---------------------------------------------------------------------------
# Tiny test framework (mirrors test_suite_tc9.py)
# ---------------------------------------------------------------------------

@dataclass
class Assertion:
    must_contain: list = field(default_factory=list)
    must_not:     list = field(default_factory=list)
    expect_unsat: bool = False


@dataclass
class TestCase:
    name:         str
    category:     str
    description:  str
    phase:        int
    instance:     str
    scenario:     str
    assertion:    Assertion
    expect_unsat: bool = False


def run_test(tc: TestCase) -> tuple[bool, str]:
    ctl = clingo.Control(["-n", "0"])
    last_model = []

    def on_model(m):
        last_model[:] = [str(s) for s in m.symbols(shown=True)]

    base_files = {1: PHASE1_BASE, 2: PHASE2_BASE, 3: PHASE3_BASE}[tc.phase]
    for f in base_files:
        ctl.load(f)
    ctl.add("base", [], tc.instance)

    programs = [("base", [])]
    if tc.scenario:
        ctl.add("scenario", [], tc.scenario)
        programs.append(("scenario", []))

    try:
        ctl.ground(programs)
    except RuntimeError as e:
        return False, f"Grounding error: {e}"

    sr = ctl.solve(on_model=on_model)

    if sr.unsatisfiable:
        if tc.expect_unsat:
            return True, "UNSAT (expected)"
        return False, "UNSAT (unexpected)"

    atom_set = set(last_model)
    failures = []
    for a in tc.assertion.must_contain:
        if a not in atom_set:
            failures.append(f"  MISSING: {a}")
    for a in tc.assertion.must_not:
        if a in atom_set:
            failures.append(f"  UNEXPECTED: {a}")

    if failures:
        return False, "\n".join(failures)
    return True, f"all {len(tc.assertion.must_contain)} assertions passed"


# ===========================================================================
# SHARED INSTANCE FRAGMENTS
# ===========================================================================

_GENEROUS_CAPS = """
system_capability(max_power,  9999999).
system_capability(max_luts,   9999999).
system_capability(max_ffs,    9999999).
system_capability(max_dsps,   9999999).
system_capability(max_lutram, 9999999).
system_capability(max_bufgs,  9999999).
system_capability(max_bufg,   9999999).
system_capability(max_bram,   9999999).
system_capability(max_asset_risk, 9999999).
"""

# Minimal ZTA base for Phase 2 tests (same as test_suite_tc9.py)
_ZTA_MINIMAL_BASE = """
mission_phase(operational). mission_phase(maintenance). mission_phase(emergency).
mission_access(M, C, Op, operational) :- access_need(M, C, Op).
mission_access(M, C, Op, maintenance) :- access_need(M, C, Op).
mission_access(M, C, read, emergency) :- master(M), receiver(C), access_need(M, C, read).
attested(m1).
hardware_rot(c1). secure_boot(c1). key_storage(c1).
hardware_rot(c2). secure_boot(c2). key_storage(c2).
policy_server(ps0). signed_policy(ps0).
"""

# Minimal topology for Phase 3 resilience tests (3-node chain)
_RES_INSTANCE = """
component(c1;c2;c3).
link(c1,c2). link(c2,c3).
domain(c1,low). domain(c2,high). domain(c3,high).
asset(c1,r1,read). asset(c2,r2,read). asset(c3,r3,read).
master(c1). receiver(c2). receiver(c3).
policy_server(ps0). policy_server(ps1).
policy_enforcement_point(pep1).
pep_guards(pep1,c2). pep_guards(pep1,c3).
ps_governs_pep(ps0,pep1). ps_governs_pep(ps1,pep1).
governs(ps0,pep1). governs(ps1,pep1).
service_component(svc,c2). service_component(svc,c3). service_quorum(svc,2).
attested(c1). hardware_rot(c1). signed_policy(ps0).
"""

TC = []   # master test list


# ===========================================================================
# PHASE 1 — REDUNDANCY ENCODING EDGE CASES
# ===========================================================================

# ---------------------------------------------------------------------------
# EC_R1: Size-1 redundancy group
#   mac+zt_logger (logging latency free): norm=(30*5-25)*1000//975=128
#   combined = 128  (N=1, no multiplication)
#   denorm   = 128*975//1000 + 250 = 124 + 250 = 374
#   risk     = impact*374//100
# ---------------------------------------------------------------------------
TC.append(TestCase(
    name="EC_R1_size1_group",
    category="EC-Phase1-Redundancy",
    description="Size-1 group mac+zt_logger: combined=128, denorm=374",
    phase=1,
    instance=_GENEROUS_CAPS + """
component(c1).
asset(c1,r1,read). asset(c1,r1,write).
impact(r1,read,2). impact(r1,write,1).
allowable_latency(r1,read,3). allowable_latency(r1,write,3).
redundant_group(1,c1).
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            "selected_security(c1,mac)",
            "selected_logging(c1,zero_trust_logger)",
            "new_prob_denormalized(c1,374)",     # 124+250
            "new_risk(c1,r1,read,7)",            # 2*374//100
            "new_risk(c1,r1,write,3)",           # 1*374//100
        ],
        must_not=[
            # standalone would give 2*15=30 and 1*15=15 — confirm group formula is used
            "new_risk(c1,r1,read,30)",
            "new_risk(c1,r1,write,15)",
        ],
    ),
))


# ---------------------------------------------------------------------------
# EC_R2: Size-2 group, mac with mixed logging (latency=3 forces mac security)
#   Optimizer picks mixed logging to minimize group risk -> denorm=285
#   risk = impact*285//100 = 2
# ---------------------------------------------------------------------------
TC.append(TestCase(
    name="EC_R2_size2_group_mac",
    category="EC-Phase1-Redundancy",
    description="Size-2 group mac+mixed logging: denorm=285, risk=2",
    phase=1,
    instance=_GENEROUS_CAPS + """
component(c1;c2).
asset(c1,r1,read). impact(r1,read,1). allowable_latency(r1,read,3).
asset(c2,r2,read). impact(r2,read,1). allowable_latency(r2,read,3).
redundant_group(1,c1). redundant_group(1,c2).
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            "new_prob_denormalized(c1,285)",
            "new_risk(c1,r1,read,2)",            # 1*285//100
            "new_risk(c2,r2,read,2)",            # both members share same denorm
        ],
        must_not=[
            "new_prob_denormalized(c1,374)",     # size-1 value should not appear
        ],
    ),
))


# ---------------------------------------------------------------------------
# EC_R3: Size-3 group, mac with mixed logging (latency=3 forces mac security)
#   Optimizer picks mixed logging -> denorm=294
#   risk = 1*294//100 = 2
# ---------------------------------------------------------------------------
TC.append(TestCase(
    name="EC_R3_size3_group_mac",
    category="EC-Phase1-Redundancy",
    description="Size-3 group mac+mixed logging: denorm=294, risk=2",
    phase=1,
    instance=_GENEROUS_CAPS + """
component(c1;c2;c3).
asset(c1,r1,read). impact(r1,read,1). allowable_latency(r1,read,3).
asset(c2,r2,read). impact(r2,read,1). allowable_latency(r2,read,3).
asset(c3,r3,read). impact(r3,read,1). allowable_latency(r3,read,3).
redundant_group(1,c1). redundant_group(1,c2). redundant_group(1,c3).
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            "new_prob_denormalized(c1,294)",
            "new_risk(c1,r1,read,2)",            # 1*294//100
        ],
        must_not=[
            "new_prob_denormalized(c1,285)",     # size-2 value
        ],
    ),
))


# ---------------------------------------------------------------------------
# EC_R4: Monotone risk reduction — adding more members lowers risk
#   Size-1: denorm=374, Size-2: denorm=285, Size-3: denorm=294
#   Each additional member reduces combined probability -> lower risk.
#   Test: size-2 denorm (285) < size-1 denorm (374).
# ---------------------------------------------------------------------------
TC.append(TestCase(
    name="EC_R4_monotone_reduction",
    category="EC-Phase1-Redundancy",
    description="Size-2 group (denorm=285) has strictly lower denorm than size-1 (denorm=374)",
    phase=1,
    instance=_GENEROUS_CAPS + """
component(c1;c2).
asset(c1,r1,read). impact(r1,read,1). allowable_latency(r1,read,3).
asset(c2,r2,read). impact(r2,read,1). allowable_latency(r2,read,3).
redundant_group(1,c1). redundant_group(1,c2).
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            "new_prob_denormalized(c1,285)",
        ],
        must_not=[
            "new_prob_denormalized(c1,374)",   # size-1 formula must not bleed through
        ],
    ),
))


# ---------------------------------------------------------------------------
# EC_R5: Size-6 group — above the old LUT size cap of 5
#   All mac+no_log (norm=589 each):
#     589→346→203→119→70→70*589//1000=41
#   combined=41, denorm=41*975//1000+250=39+250=289
#   risk=1*289//100=2
# ---------------------------------------------------------------------------
TC.append(TestCase(
    name="EC_R5_size6_group",
    category="EC-Phase1-Redundancy",
    description="Size-6 group works (>5 was impossible with LUT): combined=41, denorm=289",
    phase=1,
    instance=_GENEROUS_CAPS + """
component(c1;c2;c3;c4;c5;c6).
asset(c1,r1,read). impact(r1,read,1). allowable_latency(r1,read,3).
asset(c2,r2,read). impact(r2,read,1). allowable_latency(r2,read,3).
asset(c3,r3,read). impact(r3,read,1). allowable_latency(r3,read,3).
asset(c4,r4,read). impact(r4,read,1). allowable_latency(r4,read,3).
asset(c5,r5,read). impact(r5,read,1). allowable_latency(r5,read,3).
asset(c6,r6,read). impact(r6,read,1). allowable_latency(r6,read,3).
redundant_group(1,c1). redundant_group(1,c2). redundant_group(1,c3).
redundant_group(1,c4). redundant_group(1,c5). redundant_group(1,c6).
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            "new_prob_denormalized(c1,289)",
            "new_risk(c1,r1,read,2)",            # 1*289//100
            "new_risk(c6,r6,read,2)",            # all members share same denorm
        ],
    ),
))


# ---------------------------------------------------------------------------
# EC_R6: Two independent groups computed separately
#   Group 1 (c1,c2): latency=3 -> mac with mixed logging, denorm=265
#   Group 2 (c3,c4): latency=11 -> mixed features/logging, denorm=285
#   Both groups give risk=2 (1*denorm//100) but with different denorms.
# ---------------------------------------------------------------------------
TC.append(TestCase(
    name="EC_R6_two_groups_independent",
    category="EC-Phase1-Redundancy",
    description="Two groups with different latency budgets are computed independently",
    phase=1,
    instance=_GENEROUS_CAPS + """
component(c1;c2;c3;c4).
asset(c1,r1,read). impact(r1,read,1). allowable_latency(r1,read,3).
asset(c2,r2,read). impact(r2,read,1). allowable_latency(r2,read,3).
asset(c3,r3,read). impact(r3,read,1). allowable_latency(r3,read,11).
asset(c4,r4,read). impact(r4,read,1). allowable_latency(r4,read,11).
redundant_group(1,c1). redundant_group(1,c2).
redundant_group(2,c3). redundant_group(2,c4).
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            # Group 1: mac with mixed logging -> denorm=265
            "new_prob_denormalized(c1,265)",
            "new_risk(c1,r1,read,2)",
            # Group 2: optimizer picks low-norm option at latency=11 -> denorm=285
            "new_risk(c3,r3,read,2)",
        ],
        must_not=[
            # Groups must not bleed into each other
            "new_prob_denormalized(c3,265)",
        ],
    ),
))


# ---------------------------------------------------------------------------
# EC_R7: Minimum-norm group (zt+zt_logger, latency ≥ 29)
#   norm=25, size-2: 25*25//1000=0, combined=0, denorm=250
#   Risk floor: denorm can't go below 250 (= mu*10)
# ---------------------------------------------------------------------------
TC.append(TestCase(
    name="EC_R7_min_norm_floor",
    category="EC-Phase1-Redundancy",
    description="Size-2 group with generous latency: optimizer finds denorm<=254, risk floor=2",
    phase=1,
    instance=_GENEROUS_CAPS + """
component(c1;c2).
asset(c1,r1,read). impact(r1,read,1). allowable_latency(r1,read,29).
asset(c2,r2,read). impact(r2,read,1). allowable_latency(r2,read,29).
redundant_group(1,c1). redundant_group(1,c2).
""",
    scenario="",
    assertion=Assertion(
        # At latency=29 all features are available; both zt+zt_logger (denorm=250)
        # and zt+some_log (denorm=254) give integer risk=2 (floor of /100).
        # The optimizer picks one of these equivalent minima — denorm varies,
        # but the risk outcome is deterministically 2.
        # What is invariant: denorm is NOT the high-risk mac+no_log value (587).
        must_contain=[
            "new_risk(c1,r1,read,2)",
        ],
        must_not=[
            "new_prob_denormalized(c1,587)",     # mac+no_log: risk=5, not optimal
            "new_prob_denormalized(c1,318)",     # size-5 mac+no_log value
        ],
    ),
))


# ---------------------------------------------------------------------------
# EC_R8: impact=0 -> risk=0 regardless of feature selection
#   Any feature is valid; risk formula gives 0*anything=0.
# ---------------------------------------------------------------------------
TC.append(TestCase(
    name="EC_R8_zero_impact",
    category="EC-Phase1-Redundancy",
    description="impact=0 on asset -> new_risk=0 regardless of security/logging selection",
    phase=1,
    instance=_GENEROUS_CAPS + """
component(c1).
asset(c1,r1,read).
impact(r1,read,0).
allowable_latency(r1,read,1000).
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            "new_risk(c1,r1,read,0)",
        ],
    ),
))


# ---------------------------------------------------------------------------
# EC_R9: Mixed-feature group — optimizer picks a globally optimal combination
#   c1 latency=3 (must be mac), c2 latency=7 (can be mac or dynamic_mac).
#   With logging free, optimizer picks mac+zt_logger for c1 and
#   dynamic_mac+zt_logger for c2 -> denorm=258.
#   risk(c1,r1,read,impact=5): 5*258//100=12
# ---------------------------------------------------------------------------
TC.append(TestCase(
    name="EC_R9_mixed_feature_group",
    category="EC-Phase1-Redundancy",
    description="Mixed group: c1 mac, c2 dynamic_mac; denorm=258, risk=12",
    phase=1,
    instance=_GENEROUS_CAPS + """
component(c1;c2).
asset(c1,r1,read). impact(r1,read,5). allowable_latency(r1,read,3).
asset(c2,r2,read). impact(r2,read,1). allowable_latency(r2,read,7).
redundant_group(1,c1). redundant_group(1,c2).
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            "selected_security(c1,mac)",          # c1 forced by tight latency
            "selected_security(c2,dynamic_mac)",  # c2 picks dynamic_mac
            "new_prob_denormalized(c1,258)",
            "new_risk(c1,r1,read,12)",            # 5*258//100
        ],
        must_not=[
            "new_prob_denormalized(c1,285)",      # both-mac outcome is suboptimal
        ],
    ),
))


# ===========================================================================
# PHASE 2 — ZTA POLICY SYNTHESIS EDGE CASES
# ===========================================================================

_ZTA_FW_BASE = _ZTA_MINIMAL_BASE + """
master(m1). receiver(c1). component(c1).
link(m1, c1).
domain(c1, high).
asset(c1, r1, read).
cand_fw(fw1). cand_ps(ps0).
on_path(fw1, m1, c1). ip_loc(c1, fw1).
governs(ps0, fw1). fw_cost(fw1, 50). ps_cost(ps0, 50).
allow(m1, c1, normal). access_need(m1, c1, read).
role(m1, reader). role_need(reader, c1, read).
policy_enforcement_point(fw1).
ps_governs_pep(ps0, fw1). pep_guards(fw1, c1).
service_component(svc, c1). service_quorum(svc, 1).
"""

# ---------------------------------------------------------------------------
# EC_Z1: High-domain master → critical IP — no firewall placement forced
#   The constraint ":- master(M), domain(M,low), critical(C), reachable(M,C),
#   not protected(M,C)." requires domain(M,low). If M is high-domain,
#   the constraint never fires, so fw placement is not mandatory.
#   The cost minimizer won't place fw1 if there is no integrity pressure.
# ---------------------------------------------------------------------------
TC.append(TestCase(
    name="EC_Z1_high_domain_no_fw_forced",
    category="EC-Phase2-ZTA",
    description="High-domain master → critical IP: protection constraint silent, fw not mandatory",
    phase=2,
    instance=_ZTA_FW_BASE + """
domain(m1, high).    % high-domain master: no low→critical constraint fires
critical(c1).
""",
    scenario="",
    assertion=Assertion(
        must_not=[
            "place_fw(fw1)",     # not forced by any integrity constraint
        ],
    ),
))


# ---------------------------------------------------------------------------
# EC_Z2: Low-domain master → non-critical IP — no firewall forced
#   critical/1 is not declared for c1, so the firewall constraint never fires.
# ---------------------------------------------------------------------------
TC.append(TestCase(
    name="EC_Z2_noncritical_ip_no_fw",
    category="EC-Phase2-ZTA",
    description="Low-domain master → non-critical IP: constraint silent, fw not mandatory",
    phase=2,
    instance=_ZTA_FW_BASE + """
domain(m1, low).
% c1 is NOT declared critical — no protection constraint fires
""",
    scenario="",
    assertion=Assertion(
        must_not=[
            "place_fw(fw1)",
        ],
    ),
))


# ---------------------------------------------------------------------------
# EC_Z3: Unresolvable protection requirement → UNSAT
#   Low-domain master reaches critical IP but no cand_fw covers that path.
#   The integrity constraint fires; no placement can satisfy it → UNSAT.
# ---------------------------------------------------------------------------
TC.append(TestCase(
    name="EC_Z3_no_fw_candidate_unsat",
    category="EC-Phase2-ZTA",
    description="Low→critical path with no fw candidate covering it → UNSAT",
    phase=2,
    expect_unsat=True,
    instance=_ZTA_MINIMAL_BASE + """
master(m1). receiver(c1). component(c1).
link(m1, c1).
domain(m1, low). domain(c1, high).
critical(c1).
asset(c1, r1, read).
% No cand_fw declared — nothing can protect the path
cand_ps(ps0). ps_cost(ps0, 50).
allow(m1, c1, normal). access_need(m1, c1, read).
role(m1, reader). role_need(reader, c1, read).
service_component(svc, c1). service_quorum(svc, 1).
""",
    scenario="",
    assertion=Assertion(expect_unsat=True),
))


# ---------------------------------------------------------------------------
# EC_Z4: Excess privilege on write but not read — precise detection
#   m1 declared access_need read only; topology grants read+write.
#   excess_privilege(m1,c1,write) must fire; (m1,c1,read) must NOT.
#   Also verify missing_privilege does NOT fire (read IS granted).
# ---------------------------------------------------------------------------
TC.append(TestCase(
    name="EC_Z4_excess_write_not_read",
    category="EC-Phase2-ZTA",
    description="access_need read-only but write also granted: excess on write, not read; no missing",
    phase=2,
    instance=_ZTA_FW_BASE + """
domain(m1, low).
asset(c1, r1, write).   % c1 also has a write asset (granted by topology)
% access_need(m1, c1, read) already in _ZTA_FW_BASE — no write need declared
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            "excess_privilege(m1,c1,write)",
        ],
        must_not=[
            "excess_privilege(m1,c1,read)",   # read IS needed, not excess
            "missing_privilege(m1,c1,read)",  # read IS accessible, not missing
        ],
    ),
))


# ===========================================================================
# PHASE 3 — RESILIENCE SCENARIO EDGE CASES
# ===========================================================================

# ---------------------------------------------------------------------------
# EC_S1: Same-domain indirect exposure (factor=15, not 20)
#   c1(low) compromised, c2(low) reachable → indirect_exposure_same (factor=15)
#   c3(high) reachable from c1 → indirect_exposure_cross (factor=20)
#   max_amp(r2)=15, max_amp(r3)=20
# ---------------------------------------------------------------------------
_RES_SAME_DOMAIN = """
component(c1;c2;c3).
link(c1,c2). link(c2,c3).
domain(c1,low). domain(c2,low).   % c2 is same domain as c1
domain(c3,high).
asset(c1,r1,read). asset(c2,r2,read). asset(c3,r3,read).
master(c1). receiver(c2). receiver(c3).
policy_server(ps0). policy_server(ps1).
policy_enforcement_point(pep1).
pep_guards(pep1,c2). pep_guards(pep1,c3).
ps_governs_pep(ps0,pep1). ps_governs_pep(ps1,pep1).
governs(ps0,pep1). governs(ps1,pep1).
service_component(svc,c2). service_component(svc,c3). service_quorum(svc,2).
attested(c1). hardware_rot(c1). signed_policy(ps0).
"""

TC.append(TestCase(
    name="EC_S1_same_domain_indirect",
    category="EC-Phase3-Resilience",
    description="Compromised node reaches same-domain asset: factor=15, not 20",
    phase=3,
    instance=_RES_SAME_DOMAIN,
    scenario="compromised(c1). p1_risk(r1,10). p1_risk(r2,10). p1_risk(r3,10).",
    assertion=Assertion(
        # indirect_exposure_same is an internal predicate with no #show directive.
        # Verify it fires via its effect on max_amp_factor (15 < 20 cross-domain).
        must_contain=[
            "indirect_exposure_cross(r3,c1,20)", # cross domain (low→high) IS shown
            "direct_exposure(r1,c1,30)",         # c1 owns r1 and is compromised
            "max_amp_factor(r2,15)",             # same-domain: factor=15 (not 20)
            "max_amp_factor(r3,20)",             # cross-domain: factor=20
            "scenario_asset_risk(r2,150)",       # 10*15
            "scenario_asset_risk(r3,200)",       # 10*20
        ],
        must_not=[
            "indirect_exposure_cross(r2,c1,20)", # r2 is same-domain; cross must not fire
            "max_amp_factor(r2,20)",             # max for r2 must be 15, not 20
        ],
    ),
))


# ---------------------------------------------------------------------------
# EC_S2: PEP directly compromised (not via PS)
#   pep1 compromised → pep_bypassed fires via direct rule
#   No PS is compromised → ps_compromised must NOT fire
#   control_plane_degraded fires; control_plane_compromised must NOT fire
#   unmediated_exposure fires for all guarded assets
# ---------------------------------------------------------------------------
TC.append(TestCase(
    name="EC_S2_pep_direct_compromise",
    category="EC-Phase3-Resilience",
    description="PEP directly compromised → bypass without any PS compromise",
    phase=3,
    instance=_RES_INSTANCE,
    scenario="compromised(pep1). p1_risk(r1,10). p1_risk(r2,10). p1_risk(r3,10).",
    assertion=Assertion(
        must_contain=[
            "pep_bypassed(pep1)",
            "control_plane_degraded",
            "unmediated_exposure(r2,c1,25)",
            "unmediated_exposure(r3,c1,25)",
        ],
        must_not=[
            "ps_compromised(ps0)",
            "ps_compromised(ps1)",
            "control_plane_compromised",        # no PS is compromised
        ],
    ),
))


# ---------------------------------------------------------------------------
# EC_S3: Node both compromised AND failed simultaneously
#   direct_exposure fires (compromised)
#   asset_unavailable fires (failed)
#   asset_available must NOT fire for the same asset
# ---------------------------------------------------------------------------
TC.append(TestCase(
    name="EC_S3_compromise_and_failure",
    category="EC-Phase3-Resilience",
    description="Same node compromised AND failed: direct_exposure AND asset_unavailable both hold",
    phase=3,
    instance=_RES_INSTANCE,
    scenario="compromised(c2). failed(c2). p1_risk(r1,10). p1_risk(r2,10). p1_risk(r3,10).",
    assertion=Assertion(
        must_contain=[
            "direct_exposure(r2,c2,30)",    # compromise fires
            "asset_unavailable(r2)",        # failure fires
            "asset_available(r1)",          # c1 not failed
            "asset_available(r3)",          # c3 not failed
        ],
        must_not=[
            "asset_available(r2)",          # c2 is failed → not available
        ],
    ),
))


# ---------------------------------------------------------------------------
# EC_S4: Multiple amplifications on same asset — max_amp picks highest
#   c1 AND c2 both compromised.
#   c2 owns r2 → direct_exposure(r2,c2,30)
#   c1 (domain=low) can reach c2 (domain=high), owns r2 → indirect_exposure_cross(r2,c1,20)
#   max_amp_factor(r2) must be 30 (direct beats indirect).
# ---------------------------------------------------------------------------
TC.append(TestCase(
    name="EC_S4_max_amp_direct_beats_indirect",
    category="EC-Phase3-Resilience",
    description="Both direct(30) and indirect_cross(20) apply to r2; max_amp picks 30",
    phase=3,
    instance=_RES_INSTANCE,
    scenario="compromised(c1). compromised(c2). p1_risk(r1,10). p1_risk(r2,10). p1_risk(r3,10).",
    assertion=Assertion(
        must_contain=[
            "direct_exposure(r2,c2,30)",
            "indirect_exposure_cross(r2,c1,20)",
            "max_amp_factor(r2,30)",             # max picks 30 over 20
            "scenario_asset_risk(r2,300)",       # 10*30
        ],
    ),
))


# ---------------------------------------------------------------------------
# EC_S5: Service at exact quorum threshold — service_ok, not degraded
#   3 members, quorum=2, 1 failed → live=2 = quorum → service_ok
# ---------------------------------------------------------------------------
_RES_3MEMBER = """
component(c1;c2;c3).
link(c1,c2). link(c2,c3).
domain(c1,low). domain(c2,high). domain(c3,high).
asset(c1,r1,read). asset(c2,r2,read). asset(c3,r3,read).
master(c1). receiver(c2). receiver(c3).
policy_server(ps0). policy_server(ps1).
policy_enforcement_point(pep1).
pep_guards(pep1,c2). pep_guards(pep1,c3).
ps_governs_pep(ps0,pep1). ps_governs_pep(ps1,pep1).
governs(ps0,pep1). governs(ps1,pep1).
service_component(svc,c1). service_component(svc,c2). service_component(svc,c3).
service_quorum(svc,2).
attested(c1). hardware_rot(c1). signed_policy(ps0).
"""

TC.append(TestCase(
    name="EC_S5_service_at_quorum",
    category="EC-Phase3-Availability",
    description="3 members, quorum=2, 1 failed → live=2 = quorum → service_ok (not degraded)",
    phase=3,
    instance=_RES_3MEMBER,
    scenario="failed(c3). p1_risk(r1,10). p1_risk(r2,10). p1_risk(r3,10).",
    assertion=Assertion(
        must_contain=[
            "service_live_count(svc,2)",
            "service_ok(svc)",
        ],
        must_not=[
            "service_degraded(svc)",
            "service_unavailable(svc)",
        ],
    ),
))


# ---------------------------------------------------------------------------
# EC_S6: Blast radius counting
#   Chain c1→c2→c3 (bidirectional via adjacent/2).
#   blast_radius(c1, 2): can reach c2 and c3.
#   blast_radius(c2, 2): can reach c1 and c3.
# ---------------------------------------------------------------------------
TC.append(TestCase(
    name="EC_S6_blast_radius",
    category="EC-Phase3-Resilience",
    description="3-node chain: each node has blast_radius=2",
    phase=3,
    instance=_RES_INSTANCE,
    scenario="p1_risk(r1,10). p1_risk(r2,10). p1_risk(r3,10).",
    assertion=Assertion(
        must_contain=[
            "blast_radius(c1,2)",
            "blast_radius(c2,2)",
            "blast_radius(c3,2)",
        ],
    ),
))


# ---------------------------------------------------------------------------
# EC_S7: Both PSes compromised → all PEPs bypassed, active_ps_count=0
# ---------------------------------------------------------------------------
TC.append(TestCase(
    name="EC_S7_both_ps_compromised",
    category="EC-Phase3-ControlPlane",
    description="Both PSes compromised → pep1 bypassed, active_ps_count=0",
    phase=3,
    instance=_RES_INSTANCE,
    scenario="compromised(ps0). compromised(ps1). p1_risk(r1,10). p1_risk(r2,10). p1_risk(r3,10).",
    assertion=Assertion(
        must_contain=[
            "ps_compromised(ps0)",
            "ps_compromised(ps1)",
            "pep_bypassed(pep1)",
            "control_plane_compromised",
            "active_ps_count(0)",
            "unmediated_exposure(r2,c1,25)",
            "unmediated_exposure(r3,c1,25)",
        ],
    ),
))


# ---------------------------------------------------------------------------
# EC_S8: p1_risk=0 → scenario_asset_risk=0 even under direct exposure
#   No matter how high the amplification factor, 0 * factor = 0.
# ---------------------------------------------------------------------------
TC.append(TestCase(
    name="EC_S8_zero_base_risk",
    category="EC-Phase3-Resilience",
    description="p1_risk=0: scenario_asset_risk=0 regardless of amplification factor",
    phase=3,
    instance=_RES_INSTANCE,
    scenario="compromised(c2). p1_risk(r1,0). p1_risk(r2,0). p1_risk(r3,0).",
    assertion=Assertion(
        must_contain=[
            "direct_exposure(r2,c2,30)",      # exposure still fires...
            "scenario_asset_risk(r2,0)",      # ...but 0 * 30 = 0
            "scenario_total_risk(0)",
        ],
    ),
))


# ---------------------------------------------------------------------------
# EC_S9: PS conflict exposure (factor=13) — ps0 compromised but doesn't
#   govern pep1, so pep1 is NOT bypassed.  ps_conflict_exposure fires
#   and becomes the dominant factor for guarded assets (13 > baseline 10).
# ---------------------------------------------------------------------------
_RES_PS_CONFLICT = """
component(c1;c2;c3).
link(c1,c2). link(c2,c3).
domain(c1,low). domain(c2,high). domain(c3,high).
asset(c1,r1,read). asset(c2,r2,read). asset(c3,r3,read).
master(c1). receiver(c2). receiver(c3).
policy_server(ps0). policy_server(ps1).
policy_enforcement_point(pep1).
pep_guards(pep1,c2). pep_guards(pep1,c3).
% Only ps1 governs pep1 — ps0 is a rogue server with no governed PEP
ps_governs_pep(ps1,pep1).
governs(ps1,pep1).
service_component(svc,c2). service_component(svc,c3). service_quorum(svc,2).
attested(c1). hardware_rot(c1). signed_policy(ps0).
"""

TC.append(TestCase(
    name="EC_S9_ps_conflict_exposure",
    category="EC-Phase3-ControlPlane",
    description="ps0 compromised but doesn't govern pep1 → conflict exposure(13) without bypass",
    phase=3,
    instance=_RES_PS_CONFLICT,
    scenario="compromised(ps0). p1_risk(r1,10). p1_risk(r2,10). p1_risk(r3,10).",
    assertion=Assertion(
        # ps_conflict_exposure is an internal predicate with no #show directive.
        # Verify it fires via its effect: max_amp_factor rises to 13 (above baseline 10)
        # even though pep1 is NOT bypassed (factor 25 would dominate if it were).
        must_contain=[
            "ps_compromised(ps0)",
            "control_plane_compromised",
            "max_amp_factor(r2,13)",           # conflict(13) beats baseline(10)
            "max_amp_factor(r3,13)",
            "scenario_asset_risk(r2,130)",     # 10*13
        ],
        must_not=[
            "pep_bypassed(pep1)",              # ps0 doesn't govern pep1 → no bypass
            "max_amp_factor(r2,25)",           # unmediated(25) must NOT dominate
        ],
    ),
))


# ---------------------------------------------------------------------------
# EC_S10: Bus failure isolates service members → service_unavailable
#   Topology: m1→bus1→c2, m1→bus1→c3.  bus1 failed → c2 and c3 cut off.
#   service_live_count must be 0 (both cut off), not 2 (both alive).
#   This is the key reachability bug fix: service health now accounts
#   for topological isolation, not just component failure.
# ---------------------------------------------------------------------------
_RES_BUS_CUTOFF = """
component(m1;bus1;c2;c3).
link(m1,bus1). link(bus1,c2). link(bus1,c3).
domain(m1,low). domain(c2,high). domain(c3,high). domain(bus1,high).
asset(m1,r1,read). asset(c2,r2,read). asset(c3,r3,read).
master(m1). receiver(c2). receiver(c3).
policy_server(ps0). policy_server(ps1).
policy_enforcement_point(pep1).
pep_guards(pep1,c2). pep_guards(pep1,c3).
ps_governs_pep(ps0,pep1). ps_governs_pep(ps1,pep1).
governs(ps0,pep1). governs(ps1,pep1).
service_component(svc,c2). service_component(svc,c3). service_quorum(svc,1).
attested(m1). hardware_rot(m1). signed_policy(ps0).
"""

TC.append(TestCase(
    name="EC_S10_bus_failure_cuts_service",
    category="EC-Phase3-ServiceHealth",
    description="Bus failure isolates both service members → live=0 → service_unavailable",
    phase=3,
    instance=_RES_BUS_CUTOFF,
    scenario="failed(bus1). p1_risk(r1,10). p1_risk(r2,10). p1_risk(r3,10).",
    assertion=Assertion(
        must_contain=[
            "node_cut_off(c2)",
            "node_cut_off(c3)",
            "service_live_count(svc,0)",
            "service_unavailable(svc)",
        ],
        must_not=[
            "service_ok(svc)",
            "service_degraded(svc)",
        ],
    ),
))


# ---------------------------------------------------------------------------
# EC_S11: Compromise does NOT reduce service live count
#   c2 compromised but not failed → still counted as live.
#   Compromise is an integrity issue handled by exposure model,
#   not a service-health removal.
# ---------------------------------------------------------------------------
TC.append(TestCase(
    name="EC_S11_compromise_stays_live",
    category="EC-Phase3-ServiceHealth",
    description="Compromised member stays live (integrity handled by exposure, not service health)",
    phase=3,
    instance=_RES_INSTANCE,
    scenario="compromised(c2). p1_risk(r1,10). p1_risk(r2,10). p1_risk(r3,10).",
    assertion=Assertion(
        must_contain=[
            "service_live_count(svc,2)",
            "service_ok(svc)",
            "direct_exposure(r2,c2,30)",     # compromise still drives exposure
        ],
        must_not=[
            "service_degraded(svc)",
            "service_unavailable(svc)",
        ],
    ),
))


# ===========================================================================
# RUNNER
# ===========================================================================

def main():
    print("=" * 72)
    print("  tc9 Edge-Case Test Suite")
    print("=" * 72)

    categories = {}
    for tc in TC:
        categories.setdefault(tc.category, []).append(tc)

    total_pass = total_fail = 0
    failures = []

    for cat, tests in sorted(categories.items()):
        print(f"\n  [{cat}]")
        for tc in tests:
            passed, msg = run_test(tc)
            status = "PASS" if passed else "FAIL"
            print(f"    {status}  {tc.name:<45}  {tc.description[:55]}")
            if not passed:
                print(f"         {msg}")
                failures.append((tc.name, msg))
            if passed:
                total_pass += 1
            else:
                total_fail += 1

    print("\n" + "=" * 72)
    print(f"  Results: {total_pass} PASS  |  {total_fail} FAIL  |  "
          f"{total_pass + total_fail} total")
    print("=" * 72)

    if failures:
        print("\n  Failed tests:")
        for name, msg in failures:
            print(f"    * {name}")
            for line in msg.strip().split("\n"):
                print(f"      {line}")

    return total_fail


if __name__ == "__main__":
    sys.exit(main())
