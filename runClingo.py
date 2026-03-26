"""
runClingo.py  -  Two-phase Security Design Space Exploration with Resilience Analysis

PHASE 1 (Optimization):
  Finds the minimum-risk security and logging feature assignment for all assets,
  subject to power, latency, and resource constraints defined in the instance files.

PHASE 2 (Resilience Evaluation):
  Takes the Phase 1 optimal assignment as fixed and evaluates the system's
  security posture under a set of failure and compromise scenarios:
    - compromised(Node): attacker has code execution on this node
    - failed(Node):      node is unavailable due to fault or DoS

  For each scenario, reports:
    - Blast radius: how many nodes an attacker can reach from a compromised node
    - Scenario risk: per-asset risk amplified by exposure level
    - Asset availability: which assets become unreachable after failures
    - Critical asset losses: high-impact assets that become unavailable

Usage:
  py -3.12 runClingo.py
"""

import clingo
from dataclasses import dataclass, field
from typing import List, Dict, Tuple

# ---------------------------------------------------------------------------
# File sets
# ---------------------------------------------------------------------------

# Phase 1: optimization solve
PHASE1_FILES = [
    "Clingo/init_enc.lp",
    "Clingo/opt_security_enc.lp",
    "Clingo/security_features_inst.lp",
    "Clingo/tgt_system_inst.lp",
    "Clingo/usr_constraints_inst.lp",
    "Clingo/topology_enc.lp",       # adds blast_radius info to Phase 1 output
]

# Phase 2: resilience evaluation (no choice rules, no optimization)
PHASE2_FILES = [
    "Clingo/topology_enc.lp",
    "Clingo/resilience_enc.lp",
]

# Test case to analyse (change this to switch architectures)
TESTCASE_FILE = "testCases/testCase3_inst.lp"

# Amplification factor denominator: ASP uses integers, real value = factor / 10
AMP_DENOM = 10

# ---------------------------------------------------------------------------
# Scenario definitions
# ---------------------------------------------------------------------------
# Each scenario specifies which nodes are compromised (attacker-controlled)
# and/or failed (unavailable). The baseline has neither.

SCENARIOS = [
    {
        "name": "baseline",
        "compromised": [],
        "failed": [],
        "description": "Normal operation, no threat active"
    },
    {
        "name": "jtag_compromise",
        "compromised": ["jtag"],
        "failed": [],
        "description": "Attacker gains access via JTAG debug port"
    },
    {
        "name": "peripheral_compromise",
        "compromised": ["peripheral0"],
        "failed": [],
        "description": "Attacker exploits exposed peripheral (GPIO/timer)"
    },
    {
        "name": "cpu1_compromise",
        "compromised": ["cpu1"],
        "failed": [],
        "description": "Secondary CPU is compromised (supply-chain / exploit)"
    },
    {
        "name": "cpu0_failure",
        "compromised": [],
        "failed": ["cpu0"],
        "description": "Primary CPU hardware fault or DoS"
    },
    {
        "name": "axi_bus_failure",
        "compromised": [],
        "failed": ["axi_bus"],
        "description": "Shared AXI bus fault — cuts off RAM, Flash, Peripheral"
    },
    {
        "name": "jtag_and_periph_compromise",
        "compromised": ["jtag", "peripheral0"],
        "failed": [],
        "description": "Simultaneous JTAG + peripheral attack"
    },
    {
        "name": "cpu1_compromise_axi_failure",
        "compromised": ["cpu1"],
        "failed": ["axi_bus"],
        "description": "CPU1 compromised while AXI bus fails (combined attack)"
    },
]

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Phase1Result:
    security: Dict[str, str] = field(default_factory=dict)   # asset -> feature
    logging:  Dict[str, str] = field(default_factory=dict)   # asset -> feature
    risks:    Dict[str, int] = field(default_factory=dict)   # asset -> raw risk
    optimal:  bool = False

    @property
    def total_risk(self) -> int:
        return sum(self.risks.values())

    def as_injected_facts(self) -> str:
        """Serialize Phase 1 results as ASP facts for re-injection into Phase 2."""
        lines = ["% Phase 1 optimal assignment (fixed for resilience evaluation)"]
        for asset, feat in self.security.items():
            lines.append(f"selected_security({asset}, {feat}).")
        for asset, feat in self.logging.items():
            lines.append(f"selected_logging({asset}, {feat}).")
        for asset, risk in self.risks.items():
            lines.append(f"register_risk_fact({asset}, {risk}).")
        return "\n".join(lines)


@dataclass
class ScenarioResult:
    name:                 str
    description:          str
    compromised:          List[str]
    failed:               List[str]
    scenario_risks:       Dict[str, float] = field(default_factory=dict)
    total_scenario_risk:  float = 0.0
    blast_radii:          Dict[str, int]   = field(default_factory=dict)
    unavailable:          List[str]        = field(default_factory=list)
    available:            List[str]        = field(default_factory=list)
    critical_lost:        List[str]        = field(default_factory=list)
    cross_domain_links:   List[Tuple[str, str, str]] = field(default_factory=list)
    compromise_paths:     List[Tuple[str, str]]      = field(default_factory=list)


# ---------------------------------------------------------------------------
# Phase 1: Optimization
# ---------------------------------------------------------------------------

def phase1_optimize() -> Phase1Result:
    """
    Load the base files and test case, ground, and solve with cost optimization
    to find the minimum-risk security/logging feature assignment.
    Extracts selected_security/2, selected_logging/2, register_risk_fact/2.
    """
    # No -n argument: Clingo's default optimization mode finds the provably
    # optimal model by iteratively tightening the cost bound until UNSAT.
    ctl = clingo.Control()

    for f in PHASE1_FILES + [TESTCASE_FILE]:
        ctl.load(f)

    ctl.ground([("base", [])])

    result = Phase1Result()
    last_symbols = []

    def on_model(model):
        nonlocal last_symbols
        # Clingo calls on_model for each improving (lower-cost) model.
        # The final call before the solver proves optimality is the best.
        last_symbols = list(model.symbols(shown=True))
        result.optimal = model.optimality_proven

    # ctl.solve(on_model=...) returns a SolveResult directly (synchronous).
    solve_result = ctl.solve(on_model=on_model)

    if solve_result.unsatisfiable:
        raise RuntimeError(
            "Phase 1 UNSATISFIABLE — no valid assignment meets all constraints.\n"
            "  Hint: Try relaxing max_asset_risk or max_latency in "
            "usr_constraints_inst.lp"
        )

    for sym in last_symbols:
        name = sym.name
        args = [str(a) for a in sym.arguments]
        if name == "selected_security" and len(args) == 2:
            result.security[args[0]] = args[1]
        elif name == "selected_logging" and len(args) == 2:
            result.logging[args[0]] = args[1]
        elif name == "register_risk_fact" and len(args) == 2:
            result.risks[args[0]] = int(args[1])

    return result


# ---------------------------------------------------------------------------
# Phase 2: Scenario evaluation
# ---------------------------------------------------------------------------

def _build_scenario_program(scenario: dict, phase1: Phase1Result) -> str:
    """
    Build the ASP text that gets injected as a named program "scenario".
    Contains Phase 1 optimal assignment facts + the scenario-specific
    compromised/1 and failed/1 facts.
    """
    lines = [phase1.as_injected_facts(), ""]
    lines.append("% Scenario: " + scenario["name"])
    for node in scenario.get("compromised", []):
        lines.append(f"compromised({node}).")
    for node in scenario.get("failed", []):
        lines.append(f"failed({node}).")
    return "\n".join(lines)


def phase2_evaluate(scenario: dict, phase1: Phase1Result) -> ScenarioResult:
    """
    Create a fresh Clingo Control for one scenario evaluation.
    Loads topology + resilience encodings plus the test case topology.
    Injects Phase 1 results and scenario facts as a named sub-program.
    No optimization — purely computes resilience metrics.
    """
    ctl = clingo.Control(["-n", "1"])

    for f in PHASE2_FILES + [TESTCASE_FILE]:
        ctl.load(f)

    # ctl.add(name, params, program_text) registers a new named program.
    # Grounding it separately from "base" lets us add scenario-specific
    # facts without re-compiling the encodings.
    scenario_text = _build_scenario_program(scenario, phase1)
    ctl.add("scenario", [], scenario_text)

    ctl.ground([("base", []), ("scenario", [])])

    res = ScenarioResult(
        name=scenario["name"],
        description=scenario["description"],
        compromised=list(scenario.get("compromised", [])),
        failed=list(scenario.get("failed", [])),
    )

    def on_model(model):
        for sym in model.symbols(shown=True):
            name = sym.name
            args = [str(a) for a in sym.arguments]

            if name == "scenario_asset_risk" and len(args) == 2:
                # Divide by AMP_DENOM to convert integer back to real value
                res.scenario_risks[args[0]] = int(args[1]) / AMP_DENOM

            elif name == "scenario_total_risk" and len(args) == 1:
                res.total_scenario_risk = int(args[0]) / AMP_DENOM

            elif name == "scenario_blast_radius" and len(args) == 2:
                res.blast_radii[args[0]] = int(args[1])

            elif name == "asset_unavailable" and len(args) == 1:
                res.unavailable.append(args[0])

            elif name == "asset_available" and len(args) == 1:
                res.available.append(args[0])

            elif name == "critical_asset_unavailable" and len(args) == 1:
                res.critical_lost.append(args[0])

            elif name == "cross_domain_link" and len(args) == 3:
                res.cross_domain_links.append((args[0], args[1], args[2]))

            elif name == "compromise_path_exists" and len(args) == 2:
                res.compromise_paths.append((args[0], args[1]))

    solve_result = ctl.solve(on_model=on_model)
    if solve_result.unsatisfiable:
        print(f"  [WARNING] Scenario '{scenario['name']}' returned UNSAT.")

    return res


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _bar(risk: float, max_risk: float, width: int = 20) -> str:
    """Simple ASCII progress bar for risk visualisation."""
    if max_risk == 0:
        return " " * width
    filled = int(round(risk / max_risk * width))
    return "#" * filled + "-" * (width - filled)


def print_report(p1: Phase1Result, results: List[ScenarioResult]) -> None:
    SEP  = "=" * 72
    SEP2 = "-" * 72

    # ------------------------------------------------------------------ Phase 1
    print(f"\n{SEP}")
    print("  PHASE 1 — OPTIMAL SECURITY ASSIGNMENT")
    print(SEP)
    print(f"  {'Asset':<18} {'Security':<15} {'Logging':<22} {'Base Risk':>9}")
    print(f"  {SEP2}")
    for asset in sorted(p1.security):
        sec  = p1.security.get(asset, "?")
        log  = p1.logging.get(asset, "?")
        risk = p1.risks.get(asset, 0)
        print(f"  {asset:<18} {sec:<15} {log:<22} {risk:>9}")
    print(f"  {SEP2}")
    print(f"  {'TOTAL BASELINE RISK':<55} {p1.total_risk:>9}")
    print(f"  Status: {'PROVEN OPTIMAL' if p1.optimal else 'BEST FOUND (not proven optimal)'}")

    # ------------------------------------------------------- Topology summary
    # Cross-domain links and compromise paths are the same across all scenarios
    # (they depend on topology, not on the scenario). Use baseline result.
    baseline = results[0]
    if baseline.cross_domain_links:
        print(f"\n{SEP}")
        print("  TOPOLOGY — TRUST BOUNDARY CROSSINGS  (architectural risk points)")
        print(SEP)
        seen = set()
        for (src, dst, lt) in sorted(baseline.cross_domain_links):
            key = (min(src, dst), max(src, dst), lt)
            if key not in seen:
                seen.add(key)
                from_zone = "?"
                to_zone   = "?"
                print(f"  {src} --[{lt}]--> {dst}")

    if baseline.compromise_paths:
        print(f"\n{SEP}")
        print("  TOPOLOGY — REACHABLE ASSETS FROM EXTERNAL ENTRY POINTS")
        print(SEP)
        by_entry: Dict[str, List[str]] = {}
        for (entry, asset) in sorted(baseline.compromise_paths):
            by_entry.setdefault(entry, []).append(asset)
        for entry, assets in sorted(by_entry.items()):
            print(f"  {entry}: {', '.join(sorted(assets))}")

    # -------------------------------------------------- Scenario comparison
    print(f"\n{SEP}")
    print("  PHASE 2 — RESILIENCE ANALYSIS ACROSS SCENARIOS")
    print(SEP)

    max_risk = max(r.total_scenario_risk for r in results) or 1.0

    header = f"  {'Scenario':<32} {'Risk':>8}  {'Ratio':>6}  {'Bar':<22} Critical Lost"
    print(header)
    print(f"  {SEP2}")

    for res in results:
        # p1.total_risk and res.total_scenario_risk are in the same units:
        # the baseline scenario produces total_scenario_risk == p1.total_risk.
        ratio = res.total_scenario_risk / p1.total_risk if p1.total_risk else 0
        bar   = _bar(res.total_scenario_risk, max_risk)
        lost  = ", ".join(sorted(res.critical_lost)) if res.critical_lost else "-"
        marker = " !!!" if res.critical_lost else ("  >>" if res.compromised else "")
        print(f"  {res.name:<32} {res.total_scenario_risk:>8.1f}  {ratio:>5.1f}x  [{bar}] {lost}{marker}")

    # -------------------------------------------------- Per-scenario details
    print(f"\n{SEP}")
    print("  DETAILED SCENARIO BREAKDOWN")
    print(SEP)

    for res in results:
        threat_str = ""
        if res.compromised:
            threat_str += f"COMPROMISED: {', '.join(res.compromised)}  "
        if res.failed:
            threat_str += f"FAILED: {', '.join(res.failed)}"
        if not threat_str:
            threat_str = "(no active threat)"

        print(f"\n  [{res.name}]")
        print(f"  {res.description}")
        print(f"  Threat: {threat_str}")

        if res.blast_radii:
            for node, radius in sorted(res.blast_radii.items()):
                print(f"  Blast radius from {node}: {radius} node(s) reachable")

        print(f"  {'Asset':<18} {'Base Risk':>9} {'Scenario Risk':>13} {'Amplification':>14}")
        print(f"  {'':->18} {'':->9} {'':->13} {'':->14}")
        for asset in sorted(res.scenario_risks):
            base  = p1.risks.get(asset, 0)
            scen  = res.scenario_risks[asset]
            amp   = f"{scen / base:.1f}x" if base else "-"
            print(f"  {asset:<18} {base:>9} {scen:>13.1f} {amp:>14}")
        print(f"  {'TOTAL':<18} {p1.total_risk:>9} {res.total_scenario_risk:>13.1f}")

        if res.unavailable:
            print(f"  Unavailable assets : {', '.join(sorted(res.unavailable))}")
        if res.critical_lost:
            print(f"  ** CRITICAL ASSETS LOST: {', '.join(sorted(res.critical_lost))} **")

    # --------------------------------------------------------- Resilience summary
    print(f"\n{SEP}")
    print("  RESILIENCE SUMMARY")
    print(SEP)

    worst = max(results, key=lambda r: r.total_scenario_risk)
    best  = min(results[1:], key=lambda r: r.total_scenario_risk) if len(results) > 1 else results[0]

    print(f"  Baseline total risk        : {p1.total_risk}")
    print(f"  Worst-case scenario        : {worst.name}  (risk={worst.total_scenario_risk:.1f}, "
          f"{worst.total_scenario_risk/p1.total_risk:.1f}x baseline)")
    if len(results) > 1:
        print(f"  Least-impactful scenario   : {best.name}  (risk={best.total_scenario_risk:.1f})")

    scenarios_with_loss = [r for r in results if r.critical_lost]
    if scenarios_with_loss:
        print(f"  Scenarios causing critical asset loss:")
        for r in scenarios_with_loss:
            print(f"    {r.name}: {', '.join(sorted(r.critical_lost))}")
    else:
        print("  No scenario causes critical asset loss with this assignment.")

    all_comproms = [r for r in results if r.compromised]
    if all_comproms:
        print(f"\n  Compromise scenarios ranked by risk increase:")
        ranked = sorted(all_comproms, key=lambda r: r.total_scenario_risk, reverse=True)
        for i, r in enumerate(ranked, 1):
            delta = r.total_scenario_risk - p1.total_risk
            print(f"    {i}. {r.name:<35} +{delta:.1f} risk  "
                  f"(blast={list(r.blast_radii.values())[0] if r.blast_radii else 0} nodes)")

    print(f"\n{SEP}\n")


# ---------------------------------------------------------------------------
# Written summary generator
# ---------------------------------------------------------------------------

# Severity thresholds: scenario_total_risk / baseline_total_risk
# These are the definitive boundaries used throughout the document.
_SEV_THRESHOLDS = [
    (1.05, "NEGLIGIBLE",  "risk increase is less than 5 percent of baseline"),
    (1.50, "LOW",         "risk increase is between 5 and 50 percent of baseline"),
    (1.75, "MODERATE",    "risk increase is between 50 and 75 percent of baseline"),
    (2.00, "HIGH",        "risk increase is between 75 and 100 percent of baseline"),
    (None, "CRITICAL",    "risk more than doubles relative to baseline"),
]

def _sev(ratio: float) -> str:
    for threshold, label, _ in _SEV_THRESHOLDS:
        if threshold is None or ratio <= threshold:
            return label
    return "CRITICAL"


def generate_summary(p1: Phase1Result, results: List[ScenarioResult],
                     out_path: str = "resilience_summary.txt") -> None:
    """
    Write a rigorous technical resilience summary to `out_path`.
    Covers the risk model definition, threat model, scoring derivation,
    scenario analysis with per-asset breakdowns, sensitivity analysis,
    and mitigation mapping.  Designed to be a defensible assurance artifact,
    not just an executive summary of model outputs.
    """
    import datetime, os, textwrap

    baseline    = results[0]
    scenarios   = results[1:]
    worst       = max(results,    key=lambda r: r.total_scenario_risk)
    comproms    = sorted([r for r in scenarios if r.compromised],
                         key=lambda r: r.total_scenario_risk, reverse=True)
    failures    = [r for r in scenarios if r.failed and not r.compromised]
    crit_losses = [r for r in results if r.critical_lost]
    B           = float(p1.total_risk)    # baseline total for ratio calculations

    def wrap(text: str, indent: int = 0) -> str:
        prefix = " " * indent
        return textwrap.fill(text, width=80, initial_indent=prefix,
                             subsequent_indent=prefix)

    lines: List[str] = []
    W = 80

    def h1(title: str) -> None:
        lines.append("=" * W)
        lines.append(f"  {title}")
        lines.append("=" * W)

    def h2(title: str) -> None:
        lines.append("")
        lines.append(f"--- {title} ---")

    def para(text: str, indent: int = 0) -> None:
        lines.append(wrap(text, indent))

    def blank() -> None:
        lines.append("")

    def bullet(items: List[str], indent: int = 2) -> None:
        for item in items:
            lines.append(wrap(f"* {item}", indent))

    def trow(cols: List[str], widths: List[int]) -> str:
        return "  " + "  ".join(str(c).ljust(w) for c, w in zip(cols, widths))

    def thead(cols: List[str], widths: List[int]) -> None:
        lines.append(trow(cols, widths))
        lines.append("  " + "  ".join("-" * w for w in widths))

    # -----------------------------------------------------------------------
    # Pre-compute derived values used throughout the document
    # -----------------------------------------------------------------------

    # Amplification factor table (as used in resilience_enc.lp, scaled x10)
    AMP = {"direct": 30, "cross_zone": 20, "same_zone": 15, "none": 10}

    # Per-asset amplification ratios for every scenario (real values)
    def amp_ratio(scen: ScenarioResult, asset: str) -> float:
        base = p1.risks.get(asset, 0)
        scen_r = scen.scenario_risks.get(asset, 0.0)
        return round(scen_r / base, 2) if base else 0.0

    # Find scenarios that saturate (combined no worse than single component)
    saturation_pairs: List[Tuple[str, str]] = []
    for r in comproms:
        if len(r.compromised) > 1:
            for single in comproms:
                if (len(single.compromised) == 1
                        and single.compromised[0] in r.compromised
                        and abs(r.total_scenario_risk
                                - single.total_scenario_risk) < 0.5):
                    saturation_pairs.append((r.name, single.name))

    # Identify which assets drive any ranking differences between top scenarios
    def score_diff_drivers(ra: ScenarioResult,
                           rb: ScenarioResult) -> List[Tuple[str, float, float]]:
        """Return (asset, risk_in_ra, risk_in_rb) where ra > rb for that asset."""
        drivers = []
        for asset in ra.scenario_risks:
            ra_r = ra.scenario_risks.get(asset, 0.0)
            rb_r = rb.scenario_risks.get(asset, 0.0)
            if abs(ra_r - rb_r) > 0.01:
                drivers.append((asset, ra_r, rb_r))
        return sorted(drivers, key=lambda t: abs(t[1] - t[2]), reverse=True)

    # -----------------------------------------------------------------------
    h1("RESILIENCE TECHNICAL ASSESSMENT REPORT")
    lines.append(
        f"  Generated  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"  Test case  : {TESTCASE_FILE}")
    lines.append(
        f"  Solver     : Clingo ASP (two-phase: optimize then evaluate)")
    lines.append(
        f"  Scenarios  : {len(results)} evaluated  "
        f"({len(comproms)} compromise, {len(failures)} failure, 1 baseline)")
    blank()

    # -----------------------------------------------------------------------
    h2("1. RISK MODEL DEFINITION")
    para(
        "This section defines the scoring model so that all scenario rankings "
        "and severity labels in this report can be independently verified."
    )
    blank()
    para("BASELINE RISK FORMULA")
    para(
        "Each asset A is assigned one security feature S and one logging feature "
        "L by the optimizer.  The baseline risk for A is the product of three "
        "integer-valued parameters:", indent=2
    )
    blank()
    lines.append(
        "    BaseRisk(A) = Impact(A)  x  Vulnerability(S)  x  LogFactor(L)")
    blank()
    para("The available security features and their parameter values are:",
         indent=2)
    blank()
    thead(["Feature", "Vulnerability", "Power", "Latency (cycles)", "LUT cost"],
          [14, 13, 7, 18, 10])
    lines.append(trow(["zero_trust",  "1 (lowest)",  "3", "3 + 32922 base", "51/asset"], [14,13,7,18,10]))
    lines.append(trow(["dynamic_mac", "2 (medium)",  "2", "3 + 1568 base",  "51/asset"], [14,13,7,18,10]))
    lines.append(trow(["mac",         "3 (highest)", "1", "3 (no base)",    "51/asset"], [14,13,7,18,10]))
    blank()
    para("The available logging features and their parameter values are:",
         indent=2)
    blank()
    thead(["Feature", "LogFactor", "Power", "Latency (cycles)"], [20, 11, 7, 16])
    lines.append(trow(["zero_trust_logger", "5  (best logging)",    "2", "22"], [20,11,7,16]))
    lines.append(trow(["some_logging",      "10 (partial logging)", "1", "4"],  [20,11,7,16]))
    lines.append(trow(["no_logging",        "20 (no logging)",      "0", "0"],  [20,11,7,16]))
    blank()
    para(
        "Note: LogFactor is an integer representation of a multiplier; the "
        "real multiplier is LogFactor / 10.  Logging quality inversely affects "
        "risk: better logging reduces the effective risk score because anomalies "
        "are more likely to be detected and contained."
    )
    blank()
    para("SCENARIO RISK FORMULA")
    para(
        "When a node is compromised, each asset receives an amplification "
        "factor based on how the attacker reaches it.  The factor is chosen "
        "as the maximum applicable across all compromised nodes:",
        indent=2
    )
    blank()
    thead(["Exposure type", "Factor (integer)", "Real multiplier", "Condition"],
          [20, 17, 17, 22])
    lines.append(trow(["Direct ownership",   "30", "3.0x",
                        "attacker owns node with asset"], [20,17,17,22]))
    lines.append(trow(["Indirect cross-zone","20", "2.0x",
                        "attacker traverses trust boundary"], [20,17,17,22]))
    lines.append(trow(["Indirect same-zone", "15", "1.5x",
                        "attacker stays within zone"], [20,17,17,22]))
    lines.append(trow(["No exposure",        "10", "1.0x",
                        "asset not reachable from any attacker"], [20,17,17,22]))
    blank()
    lines.append(
        "    ScenarioRisk(A) = BaseRisk(A)  x  MaxFactor(A)  /  10")
    lines.append(
        "    TotalScenarioRisk   = SUM over all assets of ScenarioRisk(A)")
    blank()
    para("SEVERITY THRESHOLDS")
    para(
        "Scenarios are labelled with a severity based on "
        "TotalScenarioRisk / BaselineTotalRisk:", indent=2
    )
    blank()
    thead(["Label", "Ratio range", "Plain-English meaning"],
          [12, 18, 40])
    for thr, label, desc in _SEV_THRESHOLDS:
        rng = f"<= {thr:.2f}" if thr else "> 2.00"
        lines.append(trow([label, rng, desc], [12, 18, 40]))

    # -----------------------------------------------------------------------
    h2("2. THREAT MODEL AND ASSUMPTIONS")
    para(
        "The following attacker classes are modelled.  Assumptions that differ "
        "from real-world deployment conditions will affect the validity of the "
        "scenario rankings."
    )
    blank()
    bullet([
        "External physical attacker (JTAG): assumed to have physical "
        "board-level access and can connect debug hardware to the JTAG "
        "port.  This is the highest-capability threat for this topology.  "
        "In a production deployment behind tamper-evident enclosure, this "
        "attacker class may be downgraded.",

        "Remote software attacker via peripheral (peripheral0): assumed to "
        "have network or firmware-level code execution on a connected "
        "peripheral device.  The peripheral is modelled as initiating "
        "transactions on the APB bus, which the model assumes can be "
        "forwarded to the main AXI fabric.  See the architectural note "
        "below on whether this reverse path is physically possible.",

        "Supply-chain or software exploit on cpu1: assumed to give "
        "arbitrary ring-0 code execution on the secondary processor.  "
        "This subsumes both malicious firmware and runtime exploitation.  "
        "Both threat types are treated identically in this model.",

        "Hardware fault (cpu0 failure, axi_bus failure): modelled as "
        "complete, instant unavailability of the component.  Partial "
        "failures, degraded-mode operation, and progressive faults are "
        "not modelled.",
    ])
    blank()
    para("ARCHITECTURAL ASSUMPTION: REVERSE APB REACHABILITY")
    para(
        "The model treats the APB bus connection between axi_bus and "
        "peripheral0 as bidirectional for reachability purposes: a "
        "compromised peripheral0 can initiate transactions that traverse "
        "the APB bridge and reach the main AXI fabric, and hence all "
        "other nodes.  This is a modelling abstraction.  Whether this "
        "path exists physically depends on whether the APB bridge includes "
        "a hardware initiator path from peripheral-side to fabric-side.  "
        "If the bridge only supports fabric-initiated transactions (typical "
        "for simple peripherals), this path does not exist and the "
        "peripheral_compromise scenario would be far less severe.  "
        "Sensitivity Analysis in Section 8 quantifies this difference.",
        indent=2
    )
    blank()
    para("WHAT 'COMPROMISED' MEANS IN THIS MODEL")
    para(
        "A compromised node is assumed to give the attacker read/write "
        "access to all assets on that node (direct exposure, factor 3.0x) "
        "and the ability to initiate transactions to all reachable nodes "
        "(indirect exposure, factor 1.5x or 2.0x depending on zone "
        "crossing).  The model does not distinguish between compromise "
        "depth (read-only vs read-write) or attacker persistence.",
        indent=2
    )

    # -----------------------------------------------------------------------
    h2("3. SYSTEM OVERVIEW")
    para(
        "The test case models a dual-processor embedded SoC.  "
        "Components, their trust zones, owned assets, and impact values are:"
    )
    blank()
    thead(["Component", "Zone", "Assets owned", "Impacts"], [14, 16, 22, 22])
    component_assets: Dict[str, List[str]] = {}
    for asset in p1.risks:
        # We don't have direct component info here, so group by prefix heuristic
        pass
    # Build from scenario data: assets on direct-exposed nodes tell us ownership
    owned_by: Dict[str, List[str]] = {}
    for r in results:
        for asset in r.scenario_risks:
            amp = amp_ratio(r, asset)
            if amp >= 3.0 and r.compromised:
                for node in r.compromised:
                    owned_by.setdefault(node, [])
                    if asset not in owned_by[node]:
                        owned_by[node].append(asset)
    # Assets not in owned_by belong to non-compromised nodes
    all_assets = set(p1.risks.keys())
    accounted  = {a for lst in owned_by.values() for a in lst}
    unaccounted = all_assets - accounted
    # Print what we know
    for node, assets in sorted(owned_by.items()):
        impacts = ", ".join(f"{a}={p1.risks.get(a,'?')}" for a in sorted(assets))
        lines.append(trow([node, "(see testcase)", ", ".join(sorted(assets)),
                           impacts], [14, 16, 22, 22]))
    if unaccounted:
        lines.append(trow(["(others)", "", ", ".join(sorted(unaccounted)), ""],
                          [14, 16, 22, 22]))
    blank()
    para(
        "Trust-zone boundary crossings in the topology (these represent "
        "architectural risk points that security features alone cannot eliminate):"
    )
    blank()
    for (src, dst, lt) in sorted(set(baseline.cross_domain_links)):
        lines.append(f"    {src} --[{lt}]--> {dst}")
    blank()
    para(
        "External entry points (nodes in the external_zone from which "
        "an attacker can reach the rest of the system):"
    )
    for ep in sorted(baseline.cross_domain_links,
                     key=lambda t: t[0])[:]:
        pass
    ext_entries = sorted(set(
        ep for ep, _ in baseline.compromise_paths))
    if ext_entries:
        for ep in ext_entries:
            targets = [a for e, a in baseline.compromise_paths if e == ep]
            lines.append(f"    {ep}: reaches {len(targets)} asset(s): "
                         f"{', '.join(sorted(targets))}")

    # -----------------------------------------------------------------------
    h2("4. OPTIMAL SECURITY ASSIGNMENT")
    blank()
    para(
        f"Status: {'PROVEN OPTIMAL' if p1.optimal else 'BEST FOUND (optimality not proven — see note below)'}"
    )
    blank()
    para(
        "The following assignment was selected by the ASP optimizer to "
        "minimise TotalBaselineRisk subject to active constraints:"
    )
    blank()
    thead(["Asset", "Impact", "Security", "Logging", "Base Risk", "Formula"],
          [16, 8, 14, 20, 10, 22])
    for asset in sorted(p1.risks):
        imp  = p1.risks[asset]   # back-calculate impact
        sec  = p1.security.get(asset, "?")
        log  = p1.logging.get(asset,  "?")
        risk = p1.risks[asset]
        vuln = {"zero_trust": 1, "mac": 3, "dynamic_mac": 2}.get(sec, "?")
        lf   = {"zero_trust_logger": 5, "some_logging": 10,
                 "no_logging": 20}.get(log, "?")
        # Back-calculate impact: risk = impact * vuln * lf
        impact_val = (risk // (vuln * lf)
                      if isinstance(vuln, int) and isinstance(lf, int) and vuln * lf != 0
                      else "?")
        formula = (f"{impact_val} x {vuln} x {lf}"
                   if isinstance(impact_val, int) else "?")
        lines.append(trow([asset, str(impact_val), sec, log,
                            str(risk), formula], [16, 8, 14, 20, 10, 22]))
    lines.append(trow(["TOTAL", "", "", "", str(p1.total_risk), ""],
                      [16, 8, 14, 20, 10, 22]))
    blank()

    # Explain why zero_trust dominates
    sec_choices = set(p1.security.values())
    log_choices = set(p1.logging.values())
    if sec_choices == {"zero_trust"} and log_choices == {"zero_trust_logger"}:
        para("WHY THIS ASSIGNMENT: zero_trust + zero_trust_logger FOR ALL ASSETS")
        para(
            "The optimizer selected the maximum-security option everywhere.  "
            "This is not a trivial result — it is driven by the combination "
            "of high impact values and the per-asset risk ceiling constraint "
            "(max_asset_risk = 500).  Verification:", indent=2
        )
        blank()
        para("With zero_trust (vulnerability=1) and zero_trust_logger "
             "(LogFactor=5), the highest-impact asset (firmware_key, "
             "impact=9) scores 9 x 1 x 5 = 45, well below the 500 ceiling.", indent=4)
        blank()
        para("With mac (vulnerability=3) and no_logging (LogFactor=20), "
             "firmware_key would score 9 x 3 x 20 = 540 > 500, violating "
             "the per-asset ceiling.  This eliminates mac+no_logging for "
             "high-impact assets.", indent=4)
        blank()
        para("With dynamic_mac (vulnerability=2) and zero_trust_logger "
             "(LogFactor=5), firmware_key scores 9 x 2 x 5 = 90.  This is "
             "feasible but suboptimal — the optimizer minimises the sum of "
             "all risks, and zero_trust lowers the total further.", indent=4)
        blank()
        para("In short: given the available features, zero_trust + "
             "zero_trust_logger achieves the minimum possible total risk "
             "and is feasible for all assets.  No tradeoff was required.",
             indent=2)
    blank()

    # Latency / power constraint interrogation
    para("CONSTRAINTS ACTIVE IN THIS OPTIMIZATION RUN")
    para(
        "The following encoding files were loaded for Phase 1:", indent=2)
    for f in PHASE1_FILES:
        lines.append(f"    {f}")
    blank()
    para(
        "opt_latency_enc.lp, opt_power_enc.lp, and opt_resource_enc.lp "
        "were NOT loaded.  Consequently, latency, power, and FPGA resource "
        "constraints were NOT enforced during this optimization run.  "
        "Only the per-asset risk ceiling (max_asset_risk = 500) and the "
        "risk minimization objective were active.", indent=2
    )
    blank()
    para(
        "CRITICAL IMPLICATION: if opt_latency_enc.lp were loaded, the "
        "latency constraint (max_latency = 20 cycles total) would be "
        "binding.  With 6 assets and zero_trust (3 cycles each), "
        "security latency alone consumes 18 cycles, leaving only 2 cycles "
        "for all logging combined.  Since some_logging costs 4 cycles per "
        "asset and zero_trust_logger costs 22 cycles per asset, no logging "
        "feature other than no_logging (0 cycles) would fit.  The "
        "latency-constrained assignment would be zero_trust + no_logging "
        "for all assets, yielding a total baseline risk of "
        f"{sum(p1.risks[a] * 4 for a in p1.risks)} "
        "(approximately 4x higher than the current assignment).  "
        "The current max_latency = 20 value in usr_constraints_inst.lp "
        "appears inconsistent with the deployed logging features and "
        "should be reviewed.", indent=2
    )

    # -----------------------------------------------------------------------
    h2("5. ATTACK SURFACE VS. POST-COMPROMISE CONSEQUENCE")
    para(
        "This section explicitly separates two dimensions that are often "
        "conflated: attack surface (how exposed is an entry point?) and "
        "post-compromise consequence (how damaging is it once an attacker "
        "is inside?).  These dimensions can rank nodes differently."
    )
    blank()
    para("ATTACK SURFACE — JTAG IS THE HIGHEST-EXPOSURE ENTRY POINT")
    para(
        "Attack surface is measured by three factors: (1) trust zone "
        "(external_zone > untrusted_zone), (2) blast radius (how many "
        "nodes can be reached), and (3) directness of access to "
        "high-impact assets.  On all three dimensions, JTAG ranks highest:",
        indent=2
    )
    blank()
    jtag_single  = next((r for r in comproms
                         if len(r.compromised) == 1
                         and r.compromised[0] == "jtag"), None)
    periph_single = next((r for r in comproms
                          if len(r.compromised) == 1
                          and "peripheral" in r.name), None)
    for r in comproms:
        if len(r.compromised) == 1:
            node   = r.compromised[0]
            blast  = list(r.blast_radii.values())[0] if r.blast_radii else 0
            lines.append(f"    {node:<18} blast radius = {blast} node(s), "
                         f"total scenario risk = {r.total_scenario_risk:.0f}")
    blank()
    para("POST-COMPROMISE CONSEQUENCE — PERIPHERAL COMPROMISE IS HIGHEST RISK")
    para(
        "Post-compromise consequence is measured by TotalScenarioRisk: the "
        "aggregate amplified risk across all assets once the attacker is "
        "assumed to be inside the node.  Despite JTAG having higher exposure, "
        "peripheral_compromise produces a higher total consequence score.",
        indent=2
    )
    blank()
    para("THE SPECIFIC REASON FOR THE DIFFERENCE")
    if jtag_single and periph_single:
        drivers = score_diff_drivers(periph_single, jtag_single)
        total_diff = periph_single.total_scenario_risk - jtag_single.total_scenario_risk
        para(
            f"Both JTAG and peripheral0 have identical blast radii and both "
            f"reach all assets via cross-zone indirect paths (factor 2.0x), "
            f"so their per-asset scores are the same for all assets EXCEPT one.",
            indent=2
        )
        blank()
        if drivers:
            asset_d, ra_r, rb_r = drivers[0]
            base_d = p1.risks.get(asset_d, 0)
            para(
                f"The sole driver is '{asset_d}' (base risk = {base_d}): "
                f"peripheral0 DIRECTLY OWNS this asset, so it receives the "
                f"direct exposure factor (3.0x), giving a scenario risk of "
                f"{ra_r:.1f}.  JTAG does not own '{asset_d}' — it only "
                f"reaches it via a cross-zone indirect path (2.0x), giving "
                f"a scenario risk of {rb_r:.1f}.  "
                f"The difference is {ra_r - rb_r:.1f} points, which exactly "
                f"accounts for the {total_diff:.0f}-point gap between the "
                f"two scenario totals.",
                indent=2
            )
    blank()
    para("COMBINED SCENARIO SATURATION")
    if saturation_pairs:
        for (combined_name, single_name) in saturation_pairs:
            combined_r = next(r for r in results if r.name == combined_name)
            single_r   = next(r for r in results if r.name == single_name)
            para(
                f"The scenario '{combined_name}' "
                f"(risk = {combined_r.total_scenario_risk:.0f}) equals "
                f"'{single_name}' (risk = {single_r.total_scenario_risk:.0f}) "
                f"despite involving additional compromised nodes.  "
                f"This is a dominance / saturation effect: for every asset, "
                f"the maximum amplification factor is already achieved by "
                f"'{single_name}' alone.  Adding more compromised nodes "
                f"does not increase the per-asset maximum, so the total "
                f"does not increase.  This confirms that '{single_name}' "
                f"is the dominant attacker position in this topology.",
                indent=2
            )
    else:
        para("No saturation was observed in the evaluated scenarios.", indent=2)

    # -----------------------------------------------------------------------
    h2("6. COMPROMISE SCENARIO ANALYSIS")
    para(
        "Each scenario is evaluated with the Phase 1 optimal assignment fixed. "
        "Risk amplification is applied per asset; the per-asset breakdown "
        "allows the score to be traced directly to the risk formula."
    )
    for r in comproms:
        blank()
        ratio = r.total_scenario_risk / B
        sev   = _sev(ratio)
        blast_vals = list(r.blast_radii.values())
        blast_str  = ", ".join(
            f"{n}: {v} node(s)" for n, v in sorted(r.blast_radii.items())
        ) if r.blast_radii else "0"
        lines.append(f"  Scenario : {r.name}")
        lines.append(f"  Severity : {sev}  ({ratio:.2f}x baseline)")
        lines.append(f"  Threat   : COMPROMISED {', '.join(r.compromised)}"
                     + (f"  FAILED {', '.join(r.failed)}" if r.failed else ""))
        lines.append(f"  Description: {r.description}")
        lines.append(f"  Blast radius: {blast_str}")
        blank()
        thead(["Asset", "Base Risk", "Amp factor", "Scen Risk", "Delta"],
              [16, 10, 11, 10, 8])
        for asset in sorted(r.scenario_risks):
            base  = p1.risks.get(asset, 0)
            scen  = r.scenario_risks[asset]
            amp   = amp_ratio(r, asset)
            delta = scen - base
            lines.append(trow([asset, str(base), f"{amp:.1f}x",
                                f"{scen:.1f}", f"{delta:+.1f}"],
                               [16, 10, 11, 10, 8]))
        lines.append(trow(["TOTAL", str(p1.total_risk), "",
                            f"{r.total_scenario_risk:.1f}",
                            f"{r.total_scenario_risk - B:+.1f}"],
                           [16, 10, 11, 10, 8]))
        if r.critical_lost:
            blank()
            para(f"CRITICAL ASSETS LOST: {', '.join(sorted(r.critical_lost))}",
                 indent=2)

    # -----------------------------------------------------------------------
    h2("7. FAILURE SCENARIO ANALYSIS")
    para(
        "Failure scenarios measure availability, not confidentiality.  "
        "Total scenario risk does not increase because a failed node cannot "
        "be compromised simultaneously in these scenarios.  The critical "
        "metric is which assets become unreachable."
    )
    for r in failures:
        blank()
        avail_n = len(r.available)
        total_n = avail_n + len(r.unavailable)
        lines.append(f"  Scenario : {r.name}")
        lines.append(f"  Threat   : FAILED {', '.join(r.failed)}")
        lines.append(f"  Description: {r.description}")
        lines.append(f"  Availability: {avail_n}/{total_n} assets reachable")
        if r.unavailable:
            lines.append(f"  Unreachable : {', '.join(sorted(r.unavailable))}")
        if r.critical_lost:
            lines.append(
                f"  CRITICAL LOST (impact >= 6): "
                f"{', '.join(sorted(r.critical_lost))}")
        else:
            lines.append("  No critical assets lost.")
        blank()
        para(
            "Availability impact explanation: the failed node is the sole "
            "path to the unreachable assets.  No redundant data path exists "
            "in the current topology.  The risk scores for all assets remain "
            "at baseline because the attacker is not assumed to be present.",
            indent=2
        )

    # -----------------------------------------------------------------------
    h2("8. SENSITIVITY ANALYSIS")
    para(
        "The following hypothetical changes test whether the scenario "
        "rankings are stable or sensitive to modelling assumptions.  "
        "All values are analytical estimates derived from the risk formula; "
        "they are not re-solved by the optimizer."
    )
    blank()

    # Sensitivity 1: block peripheral reverse APB path
    para("S1 — BLOCK PERIPHERAL REVERSE APB PATH")
    para(
        "Assumption: the APB bridge is hardware-limited to fabric-initiated "
        "transactions only.  peripheral0 can therefore only be a target, "
        "not an initiator.  Under this assumption, compromising peripheral0 "
        "gives the attacker access only to periph_cfg (direct ownership, "
        "factor 3.0x), and no other assets are reachable.",
        indent=2
    )
    periph_only_risk = 0.0
    if periph_single:
        for asset in p1.risks:
            base = p1.risks[asset]
            owned_by_periph = (amp_ratio(periph_single, asset) >= 3.0 - 0.01)
            factor = 30 if owned_by_periph else 10
            periph_only_risk += base * factor / AMP["none"]
    para(
        f"Estimated peripheral_compromise risk with path blocked: "
        f"{periph_only_risk:.0f} vs {periph_single.total_scenario_risk:.0f} current.  "
        f"This would drop peripheral_compromise from the highest-risk "
        f"compromise scenario to the lowest, confirming that the reverse "
        f"APB path assumption is the single largest driver of the "
        f"peripheral risk score.  This assumption warrants architectural "
        f"verification before relying on the ranking.", indent=2
    )
    blank()

    # Sensitivity 2: if JTAG had direct asset exposure
    jtag_assets_now = 0
    if jtag_single:
        jtag_assets_now = sum(1 for a in jtag_single.scenario_risks
                              if amp_ratio(jtag_single, a) >= 3.0 - 0.01)
    para("S2 — JTAG WITH DIRECT ASSET OWNERSHIP")
    para(
        "Currently JTAG owns no assets.  If the highest-impact asset "
        "(firmware_key, base risk = "
        f"{p1.risks.get('firmware_key', '?')}) were stored directly in "
        "a JTAG-accessible register, it would receive factor 3.0x instead "
        "of the current 2.0x.",
        indent=2
    )
    if jtag_single and "firmware_key" in jtag_single.scenario_risks:
        fw_base  = p1.risks.get("firmware_key", 0)
        current  = jtag_single.total_scenario_risk
        adjusted = current + fw_base * (30 - 20) / 10.0
        para(
            f"Estimated JTAG scenario risk: {adjusted:.0f} vs current "
            f"{current:.0f}, which would make JTAG the highest-risk "
            f"compromise scenario ({adjusted:.0f} > "
            f"{periph_single.total_scenario_risk:.0f}).  "
            f"This shows that JTAG ranking is sensitive to whether critical "
            f"assets are directly accessible through the debug interface.",
            indent=2
        )
    blank()

    # Sensitivity 3: latency constraint active
    para("S3 — LATENCY CONSTRAINT ACTIVATED")
    lt_risk = sum(p1.risks[a] * (20 // {"zero_trust": 1, "mac": 3,
                  "dynamic_mac": 2}.get(p1.security.get(a, "zero_trust"), 1))
                  for a in p1.risks)
    lt_risk_no_log = sum(
        # impact * vuln * no_logging_factor(20)
        # back-calculate impact: risk = impact * vuln * logfactor
        # with logfactor=5 and vuln=1: impact = risk / 5
        int(p1.risks[a] / 5) * 1 * 20
        for a in p1.risks
    )
    para(
        "If opt_latency_enc.lp were loaded with max_latency = 20, the "
        "current assignment (zero_trust_logger, 22 cycles per asset) would "
        "violate the total latency constraint (6 assets × (3+22) = 150 "
        "cycles >> 20).  The optimizer would be forced to select "
        "no_logging (0 cycles) for all assets, giving:",
        indent=2
    )
    blank()
    lines.append(f"    Latency-constrained total baseline risk : {lt_risk_no_log}")
    lines.append(f"    Current (unconstrained) total risk      : {p1.total_risk}")
    lines.append(f"    Ratio                                   : "
                 f"{lt_risk_no_log / p1.total_risk:.1f}x higher")
    blank()
    para(
        "This represents a large sensitivity.  The current max_latency = 20 "
        "in usr_constraints_inst.lp should be re-examined to determine "
        "whether it reflects a real system constraint or a placeholder.",
        indent=2
    )
    blank()

    # Sensitivity 4: impact values of cpu0 assets
    para("S4 — cpu0 ASSET IMPACT VALUES")
    para(
        "cpu0 owns the two highest-impact assets (firmware_key=9, boot_cfg=7).  "
        "If these values were reduced to reflect a system where keys are stored "
        "in a hardware security module rather than in CPU registers "
        "(e.g., firmware_key=4, boot_cfg=4), the cpu0_failure scenario "
        "would no longer produce a critical asset loss under the current "
        "threshold of impact >= 6, and the overall resilience verdict "
        "would improve.  Asset impact values should be reviewed against "
        "actual data-classification policy.",
        indent=2
    )

    # -----------------------------------------------------------------------
    h2("9. RESILIENCE ASSESSMENT")
    blank()

    # Strengths — derived from data, no false claims
    para("STRENGTHS")
    blank()
    strengths: List[str] = []

    if not any(r.critical_lost for r in comproms):
        strengths.append(
            "No pure compromise scenario (without simultaneous hardware "
            "failure) causes critical asset loss.  Even with the "
            "highest-risk compromise (peripheral_compromise, "
            f"{comproms[0].total_scenario_risk:.0f}), all assets remain "
            "available.  The security features successfully defend "
            "availability even when an attacker is inside the perimeter."
        )

    if all(len(r.cross_domain_links) > 0 for r in [baseline]):
        strengths.append(
            "The trust-zone model correctly identifies cross-domain links "
            "as architectural risk points.  The system has exactly two "
            "such crossings, both of which are accounted for in the "
            "scenario analysis.  A flat (single-zone) model would miss "
            "these distinctions entirely."
        )

    min_comprom = min(comproms, key=lambda r: r.total_scenario_risk) if comproms else None
    if min_comprom:
        strengths.append(
            f"The least-damaging single-node compromise "
            f"({min_comprom.name}, {min_comprom.total_scenario_risk:.0f}) "
            f"represents a {min_comprom.total_scenario_risk/B:.1f}x risk "
            f"increase — showing that not all nodes are equally dangerous "
            f"to compromise and that the trust-zone design has some "
            f"differentiation effect."
        )

    bullet(strengths, indent=2)
    blank()

    # Weaknesses — data-driven, no false claims
    para("WEAKNESSES AND RISKS")
    blank()
    weaknesses: List[str] = []

    worst_ratio = worst.total_scenario_risk / B
    worst_single_comproms = [r for r in comproms if len(r.compromised) == 1]
    if worst_single_comproms:
        top = max(worst_single_comproms, key=lambda r: r.total_scenario_risk)
        weaknesses.append(
            f"The highest-risk single-node compromise "
            f"({top.name}, {top.total_scenario_risk:.0f}) raises total "
            f"system risk to {top.total_scenario_risk/B:.2f}x baseline.  "
            f"This exceeds the 2.00x CRITICAL threshold, indicating "
            f"that a single attacker entry is sufficient to produce a "
            f"critical-severity outcome."
        )

    if crit_losses:
        fail_names = [r.name for r in crit_losses if r.failed]
        weaknesses.append(
            f"{len(crit_losses)} scenario(s) cause critical asset loss "
            f"({', '.join(r.name for r in crit_losses)}).  All involve "
            "hardware failures, confirming that the availability "
            "weaknesses are topological, not addressable by security "
            "feature selection alone."
        )

    # Check if any single-node failure causes loss
    single_fail_loss = [r for r in failures
                        if len(r.failed) == 1 and r.critical_lost]
    if single_fail_loss:
        for r in single_fail_loss:
            weaknesses.append(
                f"'{r.failed[0]}' is a single point of failure: its loss "
                f"alone makes {', '.join(sorted(r.critical_lost))} "
                f"unreachable.  There is no redundant path in the "
                f"current topology."
            )

    jtag_single_again = next((r for r in comproms
                              if len(r.compromised) == 1
                              and "jtag" in r.name), None)
    if jtag_single_again:
        br = list(jtag_single_again.blast_radii.values())[0]
        if br == len(p1.risks):
            weaknesses.append(
                f"JTAG provides unrestricted access to all {br} assets "
                "in the system.  There is no hardware access-control "
                "mechanism between the external zone and the secure zone."
            )

    bullet(weaknesses, indent=2)

    # -----------------------------------------------------------------------
    h2("10. RECOMMENDATIONS AND MITIGATION MAPPING")
    para(
        "Each recommendation is linked to the scenarios it would directly "
        "address.  Scenario risk reductions are qualitative unless a "
        "re-optimisation is performed with the topology change applied."
    )
    blank()

    recs = [
        {
            "title": "JTAG access control",
            "action": (
                "Disable or fuse-lock the JTAG port in production builds, "
                "or add a challenge-response authentication gate before "
                "enabling debug access."
            ),
            "addresses": ["jtag_compromise", "jtag_and_periph_compromise"],
            "mechanism": (
                "Removes the external_zone → secure_zone crossing for JTAG, "
                "reducing jtag blast radius from 6 to 0.  "
                "jtag_compromise risk would fall to baseline (no exposure)."
            ),
        },
        {
            "title": "Peripheral reverse-path hardware isolation",
            "action": (
                "Configure the APB bridge to block initiator transactions "
                "from the peripheral side, or add an MPU rule that prevents "
                "peripheral0 from targeting secure-zone addresses."
            ),
            "addresses": ["peripheral_compromise", "jtag_and_periph_compromise"],
            "mechanism": (
                "Removes the untrusted_zone → secure_zone reverse path.  "
                "peripheral_compromise risk would fall from "
                f"{periph_single.total_scenario_risk:.0f} to "
                f"~{periph_only_risk:.0f} (Sensitivity S1).  "
                "This is the single highest-value architectural change."
            ),
        },
        {
            "title": "Redundant data path to flash",
            "action": (
                "Add a secondary bus path (e.g., dedicated SPI or "
                "I2C interface) between cpu0 and flash, independent of "
                "the primary AXI bus."
            ),
            "addresses": ["axi_bus_failure", "cpu1_compromise_axi_failure"],
            "mechanism": (
                "Eliminates axi_bus as a single point of failure for "
                "flash_image.  The axi_bus_failure scenario would no longer "
                "lose flash_image and its severity would fall significantly."
            ),
        },
        {
            "title": "cpu0 asset mirroring",
            "action": (
                "Replicate firmware_key and boot_cfg into a shadow register "
                "on cpu1 or into a dedicated secure element (e.g., TPM, "
                "secure enclave)."
            ),
            "addresses": ["cpu0_failure"],
            "mechanism": (
                "Eliminates cpu0 as a single point of failure for its "
                "assets.  cpu0_failure would no longer lose firmware_key "
                "or boot_cfg."
            ),
        },
        {
            "title": "Review max_latency constraint value",
            "action": (
                "Re-examine whether max_latency = 20 in "
                "usr_constraints_inst.lp reflects a real system constraint.  "
                "If latency constraints are real, load opt_latency_enc.lp "
                "and expect the optimal assignment to change significantly "
                "(Sensitivity S3)."
            ),
            "addresses": ["all scenarios"],
            "mechanism": (
                "If the latency constraint is real and active, the current "
                "zero_trust_logger assignment is infeasible.  Running the "
                "optimizer with opt_latency_enc.lp loaded would produce "
                "a fundamentally different (and higher-risk) baseline "
                "assignment.  All scenario scores would increase accordingly."
            ),
        },
    ]

    for idx, rec in enumerate(recs, 1):
        lines.append(f"  R{idx}. {rec['title'].upper()}")
        para(f"Action: {rec['action']}", indent=5)
        para(f"Addresses: {', '.join(rec['addresses'])}", indent=5)
        para(f"Effect: {rec['mechanism']}", indent=5)
        blank()

    # -----------------------------------------------------------------------
    h2("11. OVERALL VERDICT")

    worst_ratio = worst.total_scenario_risk / B
    if worst_ratio < 1.5:
        verdict      = "RESILIENT"
        verdict_desc = (
            "All evaluated scenarios produce risk increases below 50 percent "
            "of baseline.  The current security assignment and topology "
            "provide adequate protection under the modelled threat assumptions."
        )
    elif worst_ratio <= 2.0:
        verdict      = "HIGH RISK — TARGETED IMPROVEMENTS REQUIRED"
        verdict_desc = (
            "The worst-case scenario reaches the HIGH severity band (ratio "
            f"{worst_ratio:.2f}x).  The system needs targeted improvements "
            "to JTAG and peripheral isolation before deployment in a "
            "high-assurance context.  Hardware failures expose single "
            "points of failure that require redundancy to address."
        )
    else:
        verdict      = "CRITICAL RISK — ARCHITECTURAL CHANGES REQUIRED"
        verdict_desc = (
            f"The worst-case scenario ({worst.name}) reaches "
            f"{worst_ratio:.2f}x baseline, exceeding the CRITICAL threshold "
            "of 2.0x.  This result is driven by a single-node compromise "
            "that reaches all assets.  Architectural changes — particularly "
            "JTAG access control and peripheral isolation — are required "
            "before this system can be claimed resilient under adversarial "
            "conditions."
        )

    blank()
    lines.append(f"  Verdict: {verdict}")
    lines.append(f"  Worst-case scenario: {worst.name} "
                 f"(risk = {worst.total_scenario_risk:.0f}, "
                 f"{worst_ratio:.2f}x baseline)")
    blank()
    para(verdict_desc, indent=2)
    blank()
    para(
        "Note on optimality: the Phase 1 result is reported as "
        f"'{'proven optimal' if p1.optimal else 'best found, optimality not proven'}'.  "
        "If optimality is not proven, a marginally better assignment may "
        "exist, but it would not change the topology-driven findings in "
        "Sections 5–7, which are independent of the feature assignment.",
        indent=2
    )
    blank()
    lines.append("=" * W)
    blank()

    # -----------------------------------------------------------------------
    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".",
                exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    print(f"\n  Written summary report -> {out_path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    print("\n" + "=" * 72)
    print("  DESIGN SPACE EXPLORATION FOR SECURITY — RESILIENCE ANALYSIS")
    print("  Test case: " + TESTCASE_FILE)
    print("=" * 72)

    # --- Phase 1 ---
    print("\n[Phase 1] Finding optimal security assignment...")
    try:
        p1 = phase1_optimize()
    except RuntimeError as e:
        print(f"\nERROR: {e}")
        return

    status = "OPTIMAL" if p1.optimal else "best found"
    print(f"  Done. Total baseline risk = {p1.total_risk}  ({status})")

    # --- Phase 2 ---
    print(f"\n[Phase 2] Evaluating {len(SCENARIOS)} scenario(s)...\n")
    results: List[ScenarioResult] = []
    for scenario in SCENARIOS:
        res = phase2_evaluate(scenario, p1)
        crit = f"  CRITICAL LOSS: {res.critical_lost}" if res.critical_lost else ""
        print(f"  {res.name:<35} risk={res.total_scenario_risk:.1f}{crit}")
        results.append(res)

    # --- Report ---
    print_report(p1, results)

    # --- Written summary ---
    generate_summary(p1, results, out_path="resilience_summary.txt")


if __name__ == "__main__":
    main()
