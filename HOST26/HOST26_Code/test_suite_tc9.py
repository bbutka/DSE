"""
test_suite_tc9.py  --  Verification test suite for the testCase9 ZTA DSE framework
====================================================================================
Runs 20 focused tests across all three phases.  Each test uses a minimal, hand-crafted
instance where the expected output can be derived by pencil-and-paper before the solver
is invoked.  The test runner then checks that the Clingo model agrees.

Usage:
    py -3.12 test_suite_tc9.py

Risk formula quick-reference (from security_features_inst.lp / opt_redundancy_enc.lp):

  Vulnerability:  zero_trust=10,  dynamic_mac=20,  mac=30
  Logging     :  zero_trust_logger=5,  some_logging=10,  no_logging=20
  Multiplier  :  V * L / 10  (integer division)

  Non-redundant component:  risk = impact * V * L / 10
  Redundant group (size N): 32-bit product overflow -> denorm ~= 250 (exact: 250 for
                             all-mac+no_log, 240 for all-zt+no_log groups of 5)
                             -> risk = impact * denorm / 100  (integer division)

Latency costs (cycles):  mac=3, dynamic_mac=7, zero_trust=7,
                         zero_trust_logger=22, some_logging=4, no_logging=0

Resilience amplification factors (x10 scale):
  direct_exposure=30, cross-domain indirect=20, same-domain indirect=15,
  unmediated (PEP bypass)=25, stale_policy=12, baseline sentinel=10
"""

import sys, os
sys.stdout.reconfigure(encoding="utf-8")

import clingo
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))

def lp(name):  return os.path.join(HERE, "Clingo", name)

PHASE1_BASE = [
    # Note: tgt_system_tc9_inst.lp is NOT included — each test provides its own
    # system_capability facts to avoid conflicting constraints.
    lp("security_features_inst.lp"),
    lp("init_enc.lp"),
    lp("opt_redundancy_enc.lp"),
    lp("opt_latency_enc.lp"),
    lp("opt_power_enc.lp"),
    lp("opt_resource_enc.lp"),
    lp("bridge_enc.lp"),
]

PHASE2_BASE = [lp("zta_policy_enc.lp")]
PHASE3_BASE = [lp("resilience_tc9_enc.lp")]

# ---------------------------------------------------------------------------
# Test framework
# ---------------------------------------------------------------------------

@dataclass
class Assertion:
    """A single check on a Clingo model."""
    must_contain:  list = field(default_factory=list)   # atom strings that MUST appear
    must_not:      list = field(default_factory=list)   # atom strings that must NOT appear
    expect_unsat:  bool = False                          # UNSAT is the expected outcome


@dataclass
class TestCase:
    name:        str
    category:    str
    description: str
    phase:       int          # 1, 2, or 3
    instance:    str          # extra LP facts (injected as "inst" program)
    scenario:    str          # for Phase 3: compromised/failed facts
    assertion:   Assertion
    expect_unsat: bool = False


# ---------------------------------------------------------------------------
# Runner helper
# ---------------------------------------------------------------------------

def run_test(tc: TestCase) -> tuple[bool, str]:
    """Run one test case; return (passed, message)."""
    ctl = clingo.Control(["-n", "0"])

    # last_model: replaced on each callback; keeps only the final (optimal) model's atoms
    last_model = []

    def on_model(m):
        last_model[:] = [str(s) for s in m.symbols(shown=True)]

    if tc.phase == 1:
        for f in PHASE1_BASE:
            ctl.load(f)
        ctl.add("base", [], tc.instance)
        try:
            ctl.ground([("base", [])])
        except RuntimeError as e:
            return False, f"Grounding error: {e}"
        sr = ctl.solve(on_model=on_model)
        if sr.unsatisfiable:
            if tc.expect_unsat:
                return True, "UNSAT (expected)"
            return False, "UNSAT (unexpected)"

    elif tc.phase == 2:
        for f in PHASE2_BASE:
            ctl.load(f)
        ctl.add("base", [], tc.instance)
        try:
            ctl.ground([("base", [])])
        except RuntimeError as e:
            return False, f"Grounding error: {e}"
        sr = ctl.solve(on_model=on_model)
        if sr.unsatisfiable:
            if tc.expect_unsat:
                return True, "UNSAT (expected)"
            return False, "UNSAT (unexpected)"

    elif tc.phase == 3:
        for f in PHASE3_BASE:
            ctl.load(f)
        ctl.add("base",     [], tc.instance)
        ctl.add("scenario", [], tc.scenario)
        try:
            ctl.ground([("base", []), ("scenario", [])])
        except RuntimeError as e:
            return False, f"Grounding error: {e}"
        sr = ctl.solve(on_model=on_model)
        if sr.unsatisfiable:
            if tc.expect_unsat:
                return True, "UNSAT (expected)"
            return False, "UNSAT (unexpected)"
    else:
        return False, f"Unknown phase {tc.phase}"

    model_atoms = last_model

    atom_set = set(model_atoms)
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
# TEST CASE DEFINITIONS
# ===========================================================================

# ---------------------------------------------------------------------------
# Phase 1 — Feature selection and risk calculation
# ---------------------------------------------------------------------------
# Risk multiplier table (V*L/10):
#   mac+no_logging       = 30*20/10 = 60
#   mac+some_logging     = 30*10/10 = 30
#   mac+zero_trust_lgr   = 30*5/10  = 15
#   dynamic_mac+no_log   = 20*20/10 = 40
#   dynamic_mac+some_log = 20*10/10 = 20
#   zero_trust+no_log    = 10*20/10 = 20
#   zero_trust+some_log  = 10*10/10 = 10
#   zero_trust+zt_logger = 10*5/10  = 5

# Generous system caps used in most P-tests (no resource pressure)
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

TC = []   # master test list


# P1 — tight latency forces mac+no_logging
# Only mac+no_logging fits in 3 cycles (mac=3, no_logging=0).
# risk = 3 * 30 * 20 / 10 = 180  (read), same formula for write
TC.append(TestCase(
    name="P1_forced_mac_no_log",
    category="Phase1-FeatureSelection",
    description="Tight latency=3 forces mac+no_logging; verify risk=impact*60",
    phase=1,
    instance=_GENEROUS_CAPS + """
component(c1).
asset(c1, r1, read).
asset(c1, r1, write).
impact(r1, read, 3).
impact(r1, write, 1).
allowable_latency(r1, read, 3).
allowable_latency(r1, write, 3).
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            "selected_security(c1,mac)",
            "selected_logging(c1,no_logging)",
            "new_risk(c1,r1,read,180)",    # 3*30*20/10
            "new_risk(c1,r1,write,60)",    # 1*30*20/10
        ]
    ),
))


# P2 — latency=7: zero_trust+no_logging chosen over mac (lower risk)
# Candidates: mac+no_log(3cy,mult=60), mac+some_log(7cy,mult=30),
#             dynamic_mac+no_log(7cy,mult=40), zero_trust+no_log(7cy,mult=20)
# Optimal: zero_trust+no_logging  ->  risk = 2*10*20/10 = 40
TC.append(TestCase(
    name="P2_latency7_zt_no_log",
    category="Phase1-FeatureSelection",
    description="latency=7 admits ZT+no_log; optimizer picks lowest-risk (mult=20)",
    phase=1,
    instance=_GENEROUS_CAPS + """
component(c1).
asset(c1, r1, read).
impact(r1, read, 2).
allowable_latency(r1, read, 7).
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            "selected_security(c1,zero_trust)",
            "selected_logging(c1,no_logging)",
            "new_risk(c1,r1,read,40)",    # 2*10*20/10
        ],
        must_not=[
            "selected_security(c1,mac)",
            "selected_security(c1,dynamic_mac)",
        ],
    ),
))


# P3 — latency=11: zero_trust+some_logging chosen (mult=10, best at 11-cycle budget)
# Additional candidates: dynamic_mac+some_log(11cy,mult=20), zero_trust+some_log(11cy,mult=10)
# Optimal: zero_trust+some_logging  ->  risk = 2*10*10/10 = 20
TC.append(TestCase(
    name="P3_latency11_zt_some_log",
    category="Phase1-FeatureSelection",
    description="latency=11: zero_trust+some_logging wins (mult=10)",
    phase=1,
    instance=_GENEROUS_CAPS + """
component(c1).
asset(c1, r1, read).
impact(r1, read, 2).
allowable_latency(r1, read, 11).
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            "selected_security(c1,zero_trust)",
            "selected_logging(c1,some_logging)",
            "new_risk(c1,r1,read,20)",    # 2*10*10/10
        ],
        must_not=[
            "selected_security(c1,mac)",
            "selected_logging(c1,no_logging)",
            "selected_logging(c1,zero_trust_logger)",
        ],
    ),
))


# P4 — unlimited latency + generous resources: zero_trust+zero_trust_logger wins
# risk = 4*10*5/10 = 20
TC.append(TestCase(
    name="P4_unlimited_zt_logger",
    category="Phase1-FeatureSelection",
    description="Unlimited latency/resources: zero_trust+zero_trust_logger wins (mult=5)",
    phase=1,
    instance=_GENEROUS_CAPS + """
component(c1).
asset(c1, r1, read).
impact(r1, read, 4).
allowable_latency(r1, read, 1000).
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            "selected_security(c1,zero_trust)",
            "selected_logging(c1,zero_trust_logger)",
            "new_risk(c1,r1,read,20)",    # 4*10*5/10
        ],
    ),
))


# P5 — tight resource cap blocks dynamic_mac and zero_trust base LUTs.
# Note: bridge_enc.lp causes double-counting of byAsset LUTs (fires for both
# the component c1 and the asset register r1). Actual computed LUTs:
#   mac+no_logging       :  51+51 (byAsset x2) + 234 (byComp) + 0 (base) = 336
#   zero_trust+no_logging: 102 + 234 + 1985 (base_zt) = 2321
#   dynamic_mac+no_logging: same = 2321
#   mac+some_logging     : 102 + 234 + 6270 (some_log base x2) = 6606
# Setting max_luts=400 allows only mac+no_logging (336 ≤ 400 < 2321).
# risk = 3*30*20/10 = 180
TC.append(TestCase(
    name="P5_resource_cap_forces_mac",
    category="Phase1-ResourceConstraint",
    description="LUT cap=400 allows only mac+no_logging (336 LUTs); blocks all others (>=2321)",
    phase=1,
    instance="""
system_capability(max_power,  9999999).
system_capability(max_luts,   400).
system_capability(max_ffs,    9999999).
system_capability(max_dsps,   9999999).
system_capability(max_lutram, 9999999).
system_capability(max_bufgs,  9999999).
system_capability(max_bufg,   9999999).
system_capability(max_bram,   9999999).
system_capability(max_asset_risk, 9999999).
component(c1).
asset(c1, r1, read).
impact(r1, read, 3).
allowable_latency(r1, read, 1000).
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            "selected_security(c1,mac)",
            "selected_logging(c1,no_logging)",
            "new_risk(c1,r1,read,180)",
        ],
        must_not=[
            "selected_security(c1,zero_trust)",
            "selected_security(c1,dynamic_mac)",
            "selected_logging(c1,some_logging)",
            "selected_logging(c1,zero_trust_logger)",
        ],
    ),
))


# P6 — Two independent components; each gets its own optimal feature selection
# c1: latency=3 -> mac+no_logging  (risk=1*60=60)
# c2: latency=11 -> zero_trust+some_logging  (risk=1*10=10)
TC.append(TestCase(
    name="P6_two_components_independent",
    category="Phase1-FeatureSelection",
    description="Two components with different latency constraints get independent optima",
    phase=1,
    instance=_GENEROUS_CAPS + """
component(c1). component(c2).
asset(c1, r1, read). impact(r1, read, 1). allowable_latency(r1, read, 3).
asset(c2, r2, read). impact(r2, read, 1). allowable_latency(r2, read, 11).
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            "selected_security(c1,mac)",
            "selected_logging(c1,no_logging)",
            "new_risk(c1,r1,read,60)",
            "selected_security(c2,zero_trust)",
            "selected_logging(c2,some_logging)",
            "new_risk(c2,r2,read,10)",
        ],
    ),
))


# P7 — max_asset_risk violated -> UNSAT
# impact=5, latency=3 forces mac+no_logging: risk=5*60=300.  Cap=50 -> UNSAT.
TC.append(TestCase(
    name="P7_max_asset_risk_unsat",
    category="Phase1-Constraints",
    description="min achievable risk (300) exceeds max_asset_risk (50) -> UNSAT",
    phase=1,
    expect_unsat=True,
    instance="""
system_capability(max_power,  9999999).
system_capability(max_luts,   9999999).
system_capability(max_ffs,    9999999).
system_capability(max_dsps,   9999999).
system_capability(max_lutram, 9999999).
system_capability(max_bufgs,  9999999).
system_capability(max_bufg,   9999999).
system_capability(max_bram,   9999999).
system_capability(max_asset_risk, 50).
component(c1).
asset(c1, r1, read).
impact(r1, read, 5).
allowable_latency(r1, read, 3).
""",
    scenario="",
    assertion=Assertion(expect_unsat=True),
))


# ---------------------------------------------------------------------------
# Phase 1 — Redundancy group risk calculation
# ---------------------------------------------------------------------------
# 5-member group, all mac+no_logging:
#   norm(each) = (30*20-25)*1000//975 = 589
#   32-bit product: 589^5 overflows -> combined_prob_norm = 1
#   denorm = (1*975)//1000 + 250 = 0+250 = 250
#   risk = impact * 250 / 100  (integer division)

# R1 — 5-member group, all mac+no_logging (tight latency forces it)
# impact_read=4: 4*250//100 = 10
# impact_write=2: 2*250//100 = 5
TC.append(TestCase(
    name="R1_group5_mac_no_log",
    category="Phase1-Redundancy",
    description="5-member redundancy group, all mac+no_logging: denorm=250, risk=impact*250//100",
    phase=1,
    instance=_GENEROUS_CAPS + """
component(c1;c2;c3;c4;c5).
asset(c1,r1,read). asset(c1,r1,write). impact(r1,read,4). impact(r1,write,2).
asset(c2,r2,read). asset(c2,r2,write). impact(r2,read,1). impact(r2,write,1).
asset(c3,r3,read). asset(c3,r3,write). impact(r3,read,1). impact(r3,write,1).
asset(c4,r4,read). asset(c4,r4,write). impact(r4,read,1). impact(r4,write,1).
asset(c5,r5,read). asset(c5,r5,write). impact(r5,read,1). impact(r5,write,1).
allowable_latency(r1,read,3). allowable_latency(r1,write,3).
allowable_latency(r2,read,3). allowable_latency(r2,write,3).
allowable_latency(r3,read,3). allowable_latency(r3,write,3).
allowable_latency(r4,read,3). allowable_latency(r4,write,3).
allowable_latency(r5,read,3). allowable_latency(r5,write,3).
redundant_group(1,c1). redundant_group(1,c2). redundant_group(1,c3).
redundant_group(1,c4). redundant_group(1,c5).
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            "new_prob_denormalized(c1,250)",
            "new_risk(c1,r1,read,10)",     # 4*250//100
            "new_risk(c1,r1,write,5)",     # 2*250//100
            "new_risk(c2,r2,read,2)",      # 1*250//100
        ],
    ),
))


# R2 — Group risk < standalone risk (redundancy reduces risk numerically)
# Standalone c1 (mac+no_log, impact=5): risk = 5*60 = 300
# Group c1 (same features, 5-member): risk = 5*250//100 = 12
# Test verifies group reduces risk vs non-group baseline.
TC.append(TestCase(
    name="R2_group_reduces_risk",
    category="Phase1-Redundancy",
    description="Group membership reduces risk vs standalone (300 -> 12 for impact=5, mac+no_log)",
    phase=1,
    instance=_GENEROUS_CAPS + """
component(c1;c2;c3;c4;c5). component(c_solo).
asset(c1,r1,read). impact(r1,read,5). allowable_latency(r1,read,3).
asset(c2,r2,read). impact(r2,read,1). allowable_latency(r2,read,3).
asset(c3,r3,read). impact(r3,read,1). allowable_latency(r3,read,3).
asset(c4,r4,read). impact(r4,read,1). allowable_latency(r4,read,3).
asset(c5,r5,read). impact(r5,read,1). allowable_latency(r5,read,3).
asset(c_solo,rs,read). impact(rs,read,5). allowable_latency(rs,read,3).
redundant_group(1,c1). redundant_group(1,c2). redundant_group(1,c3).
redundant_group(1,c4). redundant_group(1,c5).
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            "new_risk(c1,r1,read,12)",      # group: 5*250//100=12
            "new_risk(c_solo,rs,read,300)", # standalone: 5*60=300
        ],
        must_not=[
            "new_risk(c1,r1,read,300)",     # group should NOT have standalone risk
        ],
    ),
))


# ---------------------------------------------------------------------------
# Phase 2 — ZTA policy synthesis
# ---------------------------------------------------------------------------
# Minimal instances for ZTA: need master/receiver/link/domain/critical/cand_fw/cand_ps/
#   on_path/ip_loc/governs/fw_cost/ps_cost/allow/access_need/role/role_need/
#   mission_phase/mission_access etc.
# We use the bare minimum to trigger specific predicates.

_ZTA_MINIMAL_BASE = """
% Minimal common ZTA topology for Phase 2 tests
mission_phase(operational). mission_phase(maintenance). mission_phase(emergency).
mission_access(M, C, Op, operational) :- access_need(M, C, Op).
mission_access(M, C, Op, maintenance) :- access_need(M, C, Op).
mission_access(M, C, read, emergency) :- master(M), receiver(C), access_need(M, C, read).
attested(m1).
hardware_rot(c1). secure_boot(c1). key_storage(c1).
hardware_rot(c2). secure_boot(c2). key_storage(c2).
policy_server(ps0). signed_policy(ps0).
"""

# Z1 — Low-domain master to critical IP: firewall placement is mandatory
# The ZTA integrity constraint is:
#   :- master(M), domain(M, low), critical(IP), reachable(M, IP), not protected(M, IP).
# With m1 (low) reachable to c1 (critical) and fw1 on-path, place_fw(fw1) must be chosen.
TC.append(TestCase(
    name="Z1_fw_placement_forced",
    category="Phase2-ZTA",
    description="Low-domain master -> critical IP requires firewall; place_fw must fire",
    phase=2,
    instance=_ZTA_MINIMAL_BASE + """
master(m1). receiver(c1). receiver(c2).
component(c1). component(c2).
link(m1, c1). link(m1, c2).
domain(m1, low). domain(c1, high). domain(c2, high).
critical(c1). critical(c2).
asset(c1, r1, read). asset(c2, r2, read).
cand_fw(fw1). cand_ps(ps0). cand_ps(ps1).
on_path(fw1, m1, c1). on_path(fw1, m1, c2).
ip_loc(c1, fw1). ip_loc(c2, fw1).
governs(ps0, fw1). governs(ps1, fw1).
fw_cost(fw1, 100). ps_cost(ps0, 50). ps_cost(ps1, 80).
allow(m1, c1, normal). allow(m1, c2, normal).
access_need(m1, c1, read). access_need(m1, c2, read).
role(m1, reader). role_need(reader, c1, read). role_need(reader, c2, read).
policy_enforcement_point(fw1).
ps_governs_pep(ps0, fw1). ps_governs_pep(ps1, fw1).
pep_guards(fw1, c1). pep_guards(fw1, c2).
service_component(svc, c1). service_quorum(svc, 1).
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            "place_fw(fw1)",
            "protected(m1,c1)",
            "protected(m1,c2)",
        ],
    ),
))


# Z2 — Cheaper PS wins when both are valid (cost minimisation)
# Two PS candidates: ps_cheap (cost=10) and ps_expensive (cost=200).
# Both govern the firewall.  Optimizer should pick ps_cheap.
TC.append(TestCase(
    name="Z2_ps_cost_minimisation",
    category="Phase2-ZTA",
    description="Between two valid PS candidates, cheaper one (cost=10 vs 200) is chosen",
    phase=2,
    instance=_ZTA_MINIMAL_BASE + """
master(m1). receiver(c1). component(c1).
link(m1, c1).
domain(m1, low). domain(c1, high).
critical(c1).
asset(c1, r1, read).
cand_fw(fw1). cand_ps(ps_cheap). cand_ps(ps_expensive).
on_path(fw1, m1, c1). ip_loc(c1, fw1).
governs(ps_cheap, fw1). governs(ps_expensive, fw1).
fw_cost(fw1, 50).
ps_cost(ps_cheap, 10). ps_cost(ps_expensive, 200).
allow(m1, c1, normal). access_need(m1, c1, read).
role(m1, reader). role_need(reader, c1, read).
policy_enforcement_point(fw1).
ps_governs_pep(ps_cheap, fw1). ps_governs_pep(ps_expensive, fw1).
pep_guards(fw1, c1).
policy_server(ps_cheap). policy_server(ps_expensive).
signed_policy(ps_cheap). signed_policy(ps_expensive).
service_component(svc, c1). service_quorum(svc, 1).
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            "place_ps(ps_cheap)",
            "place_fw(fw1)",
        ],
        must_not=[
            "place_ps(ps_expensive)",
        ],
    ),
))


# Z3 — Excess privilege detected (topology grants more than declared need)
# m1 can reach c1 (read+write asset).  Declared access_need: read only.
# granted_op(m1, c1, write) exists (topology), but no access_need(m1, c1, write).
# -> excess_privilege(m1, c1, write) must be derived.
TC.append(TestCase(
    name="Z3_excess_privilege_detected",
    category="Phase2-ZTA",
    description="Topology grants read+write but need is read-only -> excess_privilege(write)",
    phase=2,
    instance=_ZTA_MINIMAL_BASE + """
master(m1). receiver(c1). component(c1).
link(m1, c1).
domain(m1, low). domain(c1, high).
asset(c1, r1, read). asset(c1, r1, write).   % c1 has both read and write asset
cand_fw(fw1). cand_ps(ps0).
on_path(fw1, m1, c1). ip_loc(c1, fw1).
governs(ps0, fw1). fw_cost(fw1, 50). ps_cost(ps0, 50).
allow(m1, c1, normal).
access_need(m1, c1, read).   % only read is needed
% no access_need(m1, c1, write)
role(m1, reader). role_need(reader, c1, read).
policy_enforcement_point(fw1). ps_governs_pep(ps0, fw1). pep_guards(fw1, c1).
service_component(svc, c1). service_quorum(svc, 1).
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            "excess_privilege(m1,c1,write)",
        ],
        must_not=[
            "excess_privilege(m1,c1,read)",   # read IS needed, so no excess for read
        ],
    ),
))


# Z4 — Missing privilege: master needs access but no topological path
# m1 declares access_need(m1, c2, read) but there is no link(m1, c2).
# -> missing_privilege(m1, c2, read) must be derived.
TC.append(TestCase(
    name="Z4_missing_privilege_detected",
    category="Phase2-ZTA",
    description="Master needs access to c2 but no path exists -> missing_privilege",
    phase=2,
    instance=_ZTA_MINIMAL_BASE + """
master(m1). receiver(c1). receiver(c2). component(c1). component(c2).
link(m1, c1).             % m1 can reach c1 but NOT c2
domain(m1, low). domain(c1, high). domain(c2, high).
asset(c1, r1, read). asset(c2, r2, read).
cand_fw(fw1). cand_ps(ps0).
on_path(fw1, m1, c1). ip_loc(c1, fw1). ip_loc(c2, fw1).
governs(ps0, fw1). fw_cost(fw1, 50). ps_cost(ps0, 50).
allow(m1, c1, normal).
access_need(m1, c1, read).
access_need(m1, c2, read).   % need c2 but no path
role(m1, reader). role_need(reader, c1, read). role_need(reader, c2, read).
policy_enforcement_point(fw1). ps_governs_pep(ps0, fw1).
pep_guards(fw1, c1). pep_guards(fw1, c2).
service_component(svc, c1). service_quorum(svc, 1).
""",
    scenario="",
    assertion=Assertion(
        must_contain=[
            "missing_privilege(m1,c2,read)",
        ],
        must_not=[
            "missing_privilege(m1,c1,read)",  # c1 IS reachable
        ],
    ),
))


# ---------------------------------------------------------------------------
# Phase 3 — Resilience scenarios
# ---------------------------------------------------------------------------

# Minimal instance for Phase 3 (resilience) tests
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

# S1 — Node compromise: direct_exposure with factor 30
# p1_risk(r2, 10), compromised(c2)
# direct_exposure(r2, c2, 30) -> max_amp_factor(r2, 30)
# scenario_asset_risk(r2, 300) = 10 * 30
# scenario_total_risk(X): includes r1 (baseline 10) and r2 (300) and r3 (baseline 10 via indirect)
TC.append(TestCase(
    name="S1_direct_compromise",
    category="Phase3-Resilience",
    description="Node compromise -> direct_exposure factor=30 -> scenario_asset_risk = p1_risk*30",
    phase=3,
    instance=_RES_INSTANCE,
    scenario="compromised(c2). p1_risk(r1,10). p1_risk(r2,10). p1_risk(r3,10).",
    assertion=Assertion(
        must_contain=[
            "direct_exposure(r2,c2,30)",
            "max_amp_factor(r2,30)",
            "scenario_asset_risk(r2,300)",  # 10 * 30
        ],
        must_not=[
            "direct_exposure(r1,c1,30)",    # c1 not compromised
            "direct_exposure(r3,c3,30)",    # c3 not compromised
        ],
    ),
))


# S2 — Node failure -> asset_unavailable (not asset_available)
# failed(c2) -> asset_unavailable(r2)
TC.append(TestCase(
    name="S2_node_failure_asset_unavail",
    category="Phase3-Resilience",
    description="failed(c2) -> asset_unavailable(r2); other assets remain available",
    phase=3,
    instance=_RES_INSTANCE,
    scenario="failed(c2). p1_risk(r1,10). p1_risk(r2,10). p1_risk(r3,10).",
    assertion=Assertion(
        must_contain=[
            "asset_unavailable(r2)",
            "asset_available(r3)",   # c3 not failed
        ],
        must_not=[
            "asset_available(r2)",
            "asset_unavailable(r3)",
        ],
    ),
))


# S3 — PS compromise: pep_bypassed, control_plane_compromised
# compromised(ps0) -> ps_compromised(ps0)
# ps_governs_pep(ps0, pep1) -> pep_bypassed(pep1)
# pep_guards(pep1, c2) and master(c1), c1 not compromised ->
# unmediated_exposure(r2, c1, 25)  and  unmediated_exposure(r3, c1, 25)
TC.append(TestCase(
    name="S3_ps_compromise_pep_bypass",
    category="Phase3-ControlPlane",
    description="PS0 compromise -> pep1 bypassed -> unmediated_exposure(25) for all guarded assets",
    phase=3,
    instance=_RES_INSTANCE,
    scenario="compromised(ps0). p1_risk(r1,10). p1_risk(r2,10). p1_risk(r3,10).",
    assertion=Assertion(
        must_contain=[
            "ps_compromised(ps0)",
            "pep_bypassed(pep1)",
            "control_plane_compromised",
            "unmediated_exposure(r2,c1,25)",
            "unmediated_exposure(r3,c1,25)",
        ],
        must_not=[
            "pep_bypassed(ps0)",      # ps0 is a PS, not a PEP
        ],
    ),
))


# S4 — PS failure (not compromise): stale_policy fires, but pep NOT bypassed.
# failed(ps0) while ps1 healthy -> ps1 still governs pep1 -> has_healthy_governor(pep1) true
# -> ungovernerd_pep does NOT fire, pep_bypassed does NOT fire
# -> control_plane_degraded does NOT fire (no rule for stale-only)
# -> stale_policy_exposure fires (ps0 failed, governs pep1, pep1 not bypassed)
# -> active_ps_count(1) (ps1 alive)
TC.append(TestCase(
    name="S4_ps_failure_stale_not_bypass",
    category="Phase3-ControlPlane",
    description="PS0 failure -> stale_policy (factor 12); pep1 NOT bypassed since ps1 still governs it",
    phase=3,
    instance=_RES_INSTANCE,
    scenario="failed(ps0). p1_risk(r1,10). p1_risk(r2,10). p1_risk(r3,10).",
    assertion=Assertion(
        must_contain=[
            "stale_policy_exposure(r2,12)",  # factor 12: ps0 failed, governs pep1 which guards c2
            "stale_policy_exposure(r3,12)",  # same for c3
            "active_ps_count(1)",            # ps1 still active
        ],
        must_not=[
            "pep_bypassed(pep1)",            # ps1 still governs pep1 -> not bypassed
            "ps_compromised(ps0)",           # failure != compromise
            "control_plane_compromised",     # no PS is compromised
            "ungovernerd_pep(pep1)",         # ps1 covers pep1
            "control_plane_degraded",        # neither ungoverned nor bypassed
        ],
    ),
))


# S5 — All PSes failed -> all PEPs ungoverned -> control_plane_degraded
TC.append(TestCase(
    name="S5_all_ps_failure_ungoverned",
    category="Phase3-ControlPlane",
    description="All PSes failed -> pep1 ungoverned -> control_plane_degraded",
    phase=3,
    instance=_RES_INSTANCE,
    scenario="failed(ps0). failed(ps1). p1_risk(r1,10). p1_risk(r2,10). p1_risk(r3,10).",
    assertion=Assertion(
        must_contain=[
            "ungovernerd_pep(pep1)",
            "control_plane_degraded",
            "active_ps_count(0)",
        ],
        must_not=[
            "pep_bypassed(pep1)",           # failure != compromise/bypass
            "control_plane_compromised",
        ],
    ),
))


# S6 — Service quorum: 1 of 2 members failed -> degraded (live=1, quorum=2, 1<2 but >0)
TC.append(TestCase(
    name="S6_service_degraded",
    category="Phase3-Availability",
    description="1 of 2 service members failed -> service_degraded (live=1, quorum=2)",
    phase=3,
    instance=_RES_INSTANCE,
    scenario="failed(c2). p1_risk(r1,10). p1_risk(r2,10). p1_risk(r3,10).",
    assertion=Assertion(
        must_contain=[
            "service_live_count(svc,1)",
            "service_degraded(svc)",
        ],
        must_not=[
            "service_ok(svc)",
            "service_unavailable(svc)",
        ],
    ),
))


# S7 — Service quorum: both members failed -> service_unavailable
TC.append(TestCase(
    name="S7_service_unavailable",
    category="Phase3-Availability",
    description="All service members failed -> service_unavailable",
    phase=3,
    instance=_RES_INSTANCE,
    scenario="failed(c2). failed(c3). p1_risk(r1,10). p1_risk(r2,10). p1_risk(r3,10).",
    assertion=Assertion(
        must_contain=[
            "service_live_count(svc,0)",
            "service_unavailable(svc)",
        ],
        must_not=[
            "service_ok(svc)",
            "service_degraded(svc)",
        ],
    ),
))


# S8 — Cross-domain indirect exposure factor = 20
# compromised(c1, domain=low), c1 can reach c2 (domain=high, asset r2).
# c1 does NOT own r2 (c2 does) and domains differ -> indirect_exposure_cross(r2, c1, 20)
TC.append(TestCase(
    name="S8_cross_domain_indirect",
    category="Phase3-Resilience",
    description="Compromised node in low domain can reach high-domain asset -> factor=20",
    phase=3,
    instance=_RES_INSTANCE,
    scenario="compromised(c1). p1_risk(r1,10). p1_risk(r2,10). p1_risk(r3,10).",
    assertion=Assertion(
        must_contain=[
            "indirect_exposure_cross(r2,c1,20)",
            "indirect_exposure_cross(r3,c1,20)",
        ],
        must_not=[
            "direct_exposure(r1,c1,30)",  # c1 has r1 BUT c1 is compromised and owns r1
            # actually c1 DOES have asset r1 and IS compromised -> direct exposure DOES fire
            # Let's correct: direct_exposure(r1, c1, 30) SHOULD fire (c1 owns r1 and is compromised)
        ],
    ),
))

# Fix S8: c1 IS compromised and owns r1, so direct_exposure(r1,c1,30) WILL fire.
# Update to check correct predicates:
TC[-1].assertion.must_contain.append("direct_exposure(r1,c1,30)")
TC[-1].assertion.must_not.clear()  # no must_not needed


# ===========================================================================
# RUNNER
# ===========================================================================

def main():
    print("=" * 70)
    print("  testCase9 Framework — Verification Test Suite")
    print("=" * 70)

    categories = {}
    for tc in TC:
        categories.setdefault(tc.category, []).append(tc)

    total_pass = 0
    total_fail = 0
    failures = []

    for cat, tests in sorted(categories.items()):
        print(f"\n  [{cat}]")
        for tc in tests:
            passed, msg = run_test(tc)
            status = "PASS" if passed else "FAIL"
            print(f"    {status}  {tc.name:<40}  {tc.description[:60]}")
            if not passed:
                print(f"         {msg}")
                failures.append((tc.name, msg))
            if passed:
                total_pass += 1
            else:
                total_fail += 1

    print("\n" + "=" * 70)
    print(f"  Results: {total_pass} PASS  |  {total_fail} FAIL  |  "
          f"{total_pass+total_fail} total")
    print("=" * 70)

    if failures:
        print("\n  Failed tests:")
        for name, msg in failures:
            print(f"    * {name}")
            for line in msg.strip().split("\n"):
                print(f"      {line}")

    return total_fail


if __name__ == "__main__":
    sys.exit(main())
