"""
solution_parser.py
==================
Parses raw clingo atom lists (from ClingoRunner) into structured Python
dataclasses matching the Phase 1, 2, and 3 result schemas used by the
existing runClingo_tc9.py analysis pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any

import clingo

AMP_DENOM = 10  # risk is scaled by 10 in the ASP encodings


# ---------------------------------------------------------------------------
# Phase 1 result
# ---------------------------------------------------------------------------

@dataclass
class Phase1Result:
    """Structured output of the Phase 1 security DSE optimisation."""
    security:     Dict[str, str]  = field(default_factory=dict)
    logging:      Dict[str, str]  = field(default_factory=dict)
    new_risk:     List[Tuple]     = field(default_factory=list)
    total_luts:   int = 0
    total_ffs:    int = 0
    total_dsps:   int = 0
    total_lutram: int = 0
    total_bram:   int = 0
    total_power:  int = 0
    optimal:      bool = False
    satisfiable:  bool = False
    strategy:     str  = "unknown"

    def max_risk_per_asset(self) -> Dict[str, int]:
        """Return max risk value per asset across read/write operations."""
        result: Dict[str, int] = {}
        for _c, asset, _op, risk in self.new_risk:
            result[asset] = max(result.get(asset, 0), risk)
        return result

    def total_risk(self) -> int:
        """Sum of max risk values across all assets."""
        return sum(self.max_risk_per_asset().values())

    def as_p1_facts(self, extra: str = "") -> str:
        """Serialise as ASP facts for injection into Phase 2/3."""
        lines: List[str] = []
        for comp, feat in self.security.items():
            lines.append(f"p1_security({comp}, {feat}).")
        for comp, feat in self.logging.items():
            lines.append(f"p1_logging({comp}, {feat}).")
        for asset, risk in self.max_risk_per_asset().items():
            lines.append(f"p1_risk({asset}, {risk}).")
        if extra:
            lines.append(extra)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Phase 2 result
# ---------------------------------------------------------------------------

@dataclass
class Phase2Result:
    """Structured output of the Phase 2 ZTA policy synthesis."""
    placed_fws:             List[str]              = field(default_factory=list)
    placed_ps:              List[str]              = field(default_factory=list)
    final_allows:           List[Tuple[str,str,str]] = field(default_factory=list)
    final_denies:           List[Tuple[str,str,str]] = field(default_factory=list)
    asset_policies:         List[Tuple]            = field(default_factory=list)
    role_allows:            List[Tuple]            = field(default_factory=list)
    isolated:               List[Tuple[str,str]]   = field(default_factory=list)
    protected:              List[Tuple[str,str]]   = field(default_factory=list)
    governs_ip:             List[Tuple[str,str]]   = field(default_factory=list)
    excess_privileges:      List[Tuple]            = field(default_factory=list)
    missing_privileges:     List[Tuple]            = field(default_factory=list)
    policy_tightness:       Dict[str, int]         = field(default_factory=dict)
    over_privileged:        List[str]              = field(default_factory=list)
    role_excess:            List[Tuple]            = field(default_factory=list)
    operational_excess:     List[Tuple]            = field(default_factory=list)
    trust_gap_rot:          List[str]              = field(default_factory=list)
    trust_gap_sboot:        List[str]              = field(default_factory=list)
    trust_gap_attest:       List[str]              = field(default_factory=list)
    unattested_access:      List[Tuple[str,str]]   = field(default_factory=list)
    unsigned_ps:            List[str]              = field(default_factory=list)
    trust_gap_keys:         List[str]              = field(default_factory=list)
    trust_levels:           Dict[str, str]         = field(default_factory=dict)
    unexplained_exceptions: List[Tuple]            = field(default_factory=list)
    critical_exceptions:    List[Tuple]            = field(default_factory=list)
    total_cost:             int  = 0
    satisfiable:            bool = False
    optimal:                bool = False
    unsat_reason:           str  = ""

    def as_phase3_facts(self) -> str:
        """Serialise as ASP facts for injection into Phase 3."""
        lines: List[str] = []
        for fw in sorted(set(self.placed_fws)):
            lines.append(f"deployed_pep({fw}).")
        for ps in sorted(set(self.placed_ps)):
            lines.append(f"deployed_ps({ps}).")
        for master, ip, op in sorted(set(self.final_allows)):
            lines.append(f"p2_allow({master}, {ip}, {op}).")
        return "\n".join(lines)

    def avg_policy_tightness(self) -> float:
        """Return average policy tightness score across all masters (0-100)."""
        if not self.policy_tightness:
            return 0.0
        return sum(self.policy_tightness.values()) / len(self.policy_tightness)


# ---------------------------------------------------------------------------
# Phase 3 scenario result
# ---------------------------------------------------------------------------

@dataclass
class ScenarioResult:
    """Structured output of a single Phase 3 resilience scenario."""
    name:              str
    compromised:       List[str]
    failed:            List[str]
    scenario_risks:    Dict[str, int]  = field(default_factory=dict)
    total_risk_scaled: int             = 0
    blast_radii:       Dict[str, int]  = field(default_factory=dict)
    unavailable:       List[str]       = field(default_factory=list)
    cut_off:           List[str]       = field(default_factory=list)
    services_ok:       List[str]       = field(default_factory=list)
    services_degraded: List[str]       = field(default_factory=list)
    services_unavail:  List[str]       = field(default_factory=list)
    service_counts:    Dict[str, int]  = field(default_factory=dict)
    active_ps_count:   int             = 2
    ungoverned_peps:   List[str]       = field(default_factory=list)
    cp_degraded:       bool            = False
    cp_stale:          bool            = False
    cp_compromised:    bool            = False
    peps_bypassed:     List[str]       = field(default_factory=list)
    ps_compromised:    List[str]       = field(default_factory=list)
    direct_exp:        List[Tuple]     = field(default_factory=list)
    cross_exp:         List[Tuple]     = field(default_factory=list)
    unmediated_exp:    List[Tuple]     = field(default_factory=list)
    satisfiable:       bool            = False

    @property
    def total_risk(self) -> float:
        """Risk value in the same units as Phase 1 (divided by AMP_DENOM)."""
        return self.total_risk_scaled / AMP_DENOM

    @property
    def max_blast_radius(self) -> int:
        """Maximum blast radius across all components in this scenario."""
        return max(self.blast_radii.values(), default=0)


# ---------------------------------------------------------------------------
# Combined solution result
# ---------------------------------------------------------------------------

@dataclass
class SolutionResult:
    """
    Aggregates Phase 1, 2, and 3 results for one strategy variant.

    This is the object handed to the GUI solution viewer and comparison engine.
    """
    strategy:   str = "unknown"
    label:      str = ""
    phase1:     Optional[Phase1Result]     = None
    phase2:     Optional[Phase2Result]     = None
    scenarios:  List[ScenarioResult]       = field(default_factory=list)
    error:      str                        = ""
    complete:   bool                       = False

    # Pre-computed display metrics (populated by solution_ranker)
    security_score:   float = 0.0
    resource_score:   float = 0.0
    power_score:      float = 0.0
    latency_score:    float = 0.0
    resilience_score: float = 0.0
    policy_score:     float = 0.0

    def avg_blast_radius(self) -> float:
        """Average max blast radius across all scenarios."""
        if not self.scenarios:
            return 0.0
        vals = [s.max_blast_radius for s in self.scenarios if s.satisfiable]
        return sum(vals) / len(vals) if vals else 0.0

    def worst_scenario(self) -> Optional[ScenarioResult]:
        """Return the scenario with the highest total risk."""
        sat = [s for s in self.scenarios if s.satisfiable]
        return max(sat, key=lambda s: s.total_risk, default=None)

    def latency_violations(self) -> int:
        """Placeholder: count latency violations from Phase 1 atoms."""
        # The existing ASP encodings enforce latency as hard constraints;
        # if SAT then 0 violations by definition.
        return 0 if (self.phase1 and self.phase1.satisfiable) else 1


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class SolutionParser:
    """
    Parses raw clingo atom lists into Phase1Result / Phase2Result /
    ScenarioResult objects.
    """

    COMPONENTS = {
        "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8",
        "sys_cpu", "dma",
    }

    # ------------------------------------------------------------------
    # Phase 1
    # ------------------------------------------------------------------

    @staticmethod
    def parse_phase1(
        atoms: List[clingo.Symbol],
        strategy: str = "unknown",
    ) -> Phase1Result:
        """
        Parse Phase 1 atom list into a Phase1Result.

        Parameters
        ----------
        atoms : list[clingo.Symbol]
            Atoms from ClingoRunner.solve()["atoms"].
        strategy : str
            The strategy name for labelling.
        """
        import re as _re
        # Regex: asset-register names look like <compname>r<digit> (e.g. c1r1, c2r2)
        # We only want component-level selections (c1, c2, ..., sys_cpu, dma)
        _asset_pat = _re.compile(r'^.+r\d+$')

        r = Phase1Result(strategy=strategy, satisfiable=True)
        for sym in atoms:
            n, a = sym.name, sym.arguments
            if n == "selected_security" and len(a) == 2:
                comp_name = str(a[0])
                if not _asset_pat.match(comp_name):   # skip asset-level entries
                    r.security[comp_name] = str(a[1])
            elif n == "selected_logging" and len(a) == 2:
                comp_name = str(a[0])
                if not _asset_pat.match(comp_name):   # skip asset-level entries
                    r.logging[comp_name] = str(a[1])
            elif n == "new_risk" and len(a) == 4:
                r.new_risk.append((
                    str(a[0]), str(a[1]), str(a[2]), a[3].number
                ))
            elif n == "total_luts_used"   and len(a) == 1:
                r.total_luts   = a[0].number
            elif n == "total_ffs_used"    and len(a) == 1:
                r.total_ffs    = a[0].number
            elif n == "total_dsps_used"   and len(a) == 1:
                r.total_dsps   = a[0].number
            elif n == "total_lutram_used" and len(a) == 1:
                r.total_lutram = a[0].number
            elif n == "total_bram_used"   and len(a) == 1:
                r.total_bram   = a[0].number
            elif n == "total_power_used"  and len(a) == 1:
                r.total_power  = a[0].number
        return r

    # ------------------------------------------------------------------
    # Phase 2
    # ------------------------------------------------------------------

    @staticmethod
    def parse_phase2(atoms: List[clingo.Symbol]) -> Phase2Result:
        """Parse Phase 2 atom list into a Phase2Result."""
        r = Phase2Result(satisfiable=True)
        for sym in atoms:
            n, a = sym.name, sym.arguments
            if   n == "place_fw"           and len(a) == 1:
                r.placed_fws.append(str(a[0]))
            elif n == "place_ps"           and len(a) == 1:
                r.placed_ps.append(str(a[0]))
            elif n == "final_allow"        and len(a) == 3:
                r.final_allows.append((str(a[0]), str(a[1]), str(a[2])))
            elif n == "final_deny"         and len(a) == 3:
                r.final_denies.append((str(a[0]), str(a[1]), str(a[2])))
            elif n == "asset_policy"       and len(a) == 4:
                r.asset_policies.append(tuple(str(x) for x in a))
            elif n == "role_allow"         and len(a) == 4:
                r.role_allows.append(tuple(str(x) for x in a))
            elif n == "isolated"           and len(a) == 2:
                r.isolated.append((str(a[0]), str(a[1])))
            elif n == "protected"          and len(a) == 2:
                r.protected.append((str(a[0]), str(a[1])))
            elif n == "governs_ip"         and len(a) == 2:
                r.governs_ip.append((str(a[0]), str(a[1])))
            elif n == "excess_privilege"   and len(a) == 3:
                r.excess_privileges.append(tuple(str(x) for x in a))
            elif n == "missing_privilege"  and len(a) == 3:
                r.missing_privileges.append(tuple(str(x) for x in a))
            elif n == "policy_tightness"   and len(a) == 2:
                r.policy_tightness[str(a[0])] = a[1].number
            elif n == "over_privileged"    and len(a) == 1:
                r.over_privileged.append(str(a[0]))
            elif n == "role_excess"        and len(a) == 3:
                r.role_excess.append(tuple(str(x) for x in a))
            elif n == "operational_excess" and len(a) == 3:
                r.operational_excess.append(tuple(str(x) for x in a))
            elif n == "trust_gap_rot"      and len(a) == 1:
                r.trust_gap_rot.append(str(a[0]))
            elif n == "trust_gap_sboot"    and len(a) == 1:
                r.trust_gap_sboot.append(str(a[0]))
            elif n == "trust_gap_attest"   and len(a) == 1:
                r.trust_gap_attest.append(str(a[0]))
            elif n == "unattested_privileged_access" and len(a) == 2:
                r.unattested_access.append((str(a[0]), str(a[1])))
            elif n == "unsigned_ps"        and len(a) == 1:
                r.unsigned_ps.append(str(a[0]))
            elif n == "trust_gap_keys"     and len(a) == 1:
                r.trust_gap_keys.append(str(a[0]))
            elif n == "trust_level"        and len(a) == 2:
                r.trust_levels[str(a[0])] = str(a[1])
            elif n == "unexplained_exception" and len(a) == 3:
                r.unexplained_exceptions.append(tuple(str(x) for x in a))
            elif n == "critical_exception" and len(a) == 5:
                r.critical_exceptions.append(tuple(str(x) for x in a))
            elif n == "total_zta_cost"     and len(a) == 1:
                r.total_cost = a[0].number
        return r

    # ------------------------------------------------------------------
    # Phase 3
    # ------------------------------------------------------------------

    @staticmethod
    def parse_scenario(
        atoms: List[clingo.Symbol],
        scenario_def: Dict[str, Any],
    ) -> ScenarioResult:
        """
        Parse a single Phase 3 scenario atom list.

        Parameters
        ----------
        atoms : list[clingo.Symbol]
        scenario_def : dict with "name", "compromised", "failed" keys.
        """
        res = ScenarioResult(
            name=scenario_def["name"],
            compromised=scenario_def.get("compromised", []),
            failed=scenario_def.get("failed", []),
            satisfiable=True,
        )
        for sym in atoms:
            n, a = sym.name, sym.arguments
            if   n == "scenario_asset_risk"  and len(a) == 2:
                res.scenario_risks[str(a[0])] = a[1].number
            elif n == "scenario_total_risk"  and len(a) == 1:
                res.total_risk_scaled = a[0].number
            elif n == "blast_radius"         and len(a) == 2:
                res.blast_radii[str(a[0])] = a[1].number
            elif n == "asset_unavailable"    and len(a) == 1:
                res.unavailable.append(str(a[0]))
            elif n == "node_cut_off"         and len(a) == 1:
                res.cut_off.append(str(a[0]))
            elif n == "service_ok"           and len(a) == 1:
                res.services_ok.append(str(a[0]))
            elif n == "service_degraded"     and len(a) == 1:
                res.services_degraded.append(str(a[0]))
            elif n == "service_unavailable"  and len(a) == 1:
                res.services_unavail.append(str(a[0]))
            elif n == "service_live_count"   and len(a) == 2:
                res.service_counts[str(a[0])] = a[1].number
            elif n == "active_ps_count"      and len(a) == 1:
                res.active_ps_count = a[0].number
            elif n == "ungovernerd_pep"      and len(a) == 1:
                res.ungoverned_peps.append(str(a[0]))
            elif n == "control_plane_degraded"   and len(a) == 0:
                res.cp_degraded    = True
            elif n == "stale_policy_active"      and len(a) == 0:
                res.cp_stale       = True
            elif n == "control_plane_compromised" and len(a) == 0:
                res.cp_compromised = True
            elif n == "pep_bypassed"         and len(a) == 1:
                res.peps_bypassed.append(str(a[0]))
            elif n == "ps_compromised"       and len(a) == 1:
                res.ps_compromised.append(str(a[0]))
            elif n == "direct_exposure"      and len(a) == 3:
                res.direct_exp.append((str(a[0]), str(a[1])))
            elif n == "indirect_exposure_cross" and len(a) == 3:
                res.cross_exp.append((str(a[0]), str(a[1])))
            elif n == "unmediated_exposure"  and len(a) == 3:
                res.unmediated_exp.append((str(a[0]), str(a[1])))
        return res
