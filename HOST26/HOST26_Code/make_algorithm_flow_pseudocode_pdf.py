from __future__ import annotations

from pathlib import Path

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle


BASE_DIR = Path(__file__).resolve().parent
OUTPUT_PATH = BASE_DIR / "algorithm_flow_and_pseudocode.pdf"


def styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle(name="BodySmall", parent=s["BodyText"], fontName="Helvetica", fontSize=9.5, leading=12, spaceAfter=6))
    s.add(ParagraphStyle(name="Section", parent=s["Heading1"], fontName="Helvetica-Bold", fontSize=14, leading=17, textColor=colors.HexColor("#183153"), spaceBefore=8, spaceAfter=6))
    s.add(ParagraphStyle(name="Caption", parent=s["BodyText"], fontName="Helvetica-Oblique", fontSize=8.5, leading=10, textColor=colors.HexColor("#4a5a6a"), spaceAfter=8))
    return s


def build_table(rows, widths):
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d9e6f2")),
                ("GRID", (0, 0), (-1, -1), 0.45, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.6),
                ("LEADING", (0, 0), (-1, -1), 10.5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#eef3f7")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return t


def add_arrow(d: Drawing, x1, y1, x2, y2, color="#355c7d"):
    c = colors.HexColor(color)
    d.add(Line(x1, y1, x2, y2, strokeColor=c, strokeWidth=1.5))
    if x1 == x2:
        head = Polygon([x2 - 4, y2 + 7, x2 + 4, y2 + 7, x2, y2], fillColor=c, strokeColor=c)
    else:
        head = Polygon([x2 - 7, y2 - 4, x2 - 7, y2 + 4, x2, y2], fillColor=c, strokeColor=c)
    d.add(head)


def box(d: Drawing, x, y, w, h, title, lines, fill):
    d.add(Rect(x, y, w, h, rx=8, ry=8, fillColor=colors.HexColor(fill), strokeColor=colors.HexColor("#355c7d"), strokeWidth=1.2))
    d.add(String(x + 8, y + h - 16, title, fontName="Helvetica-Bold", fontSize=9.5))
    cy = y + h - 30
    for line in lines:
        d.add(String(x + 8, cy, line, fontName="Helvetica", fontSize=7.5))
        cy -= 10


def flowchart() -> Drawing:
    d = Drawing(480, 470)
    box(d, 60, 412, 340, 42, "Load Inputs", ["testCase9 facts, phase encodings, runtime monitor facts"], "#edf5ff")
    box(d, 60, 348, 340, 50, "Phase 1 Solve", ["solve LUT-based security DSE", "extract p1_security, p1_logging, p1_risk"], "#e8f7ec")
    box(d, 60, 276, 340, 50, "Phase 2 Solve", ["synthesize PEP and PS deployment", "derive policy and least-privilege findings"], "#fff4df")
    box(d, 60, 200, 340, 58, "Joint Runtime Solve", ["optional runtime-aware Phase 2 extension", "co-place monitors and optimize readiness"], "#f3e8ff")
    box(d, 60, 114, 340, 66, "Per-Scenario Runtime Solve", ["inject observed(node, signal, severity)", "compute observability, anomaly, trust, mode, response"], "#ffe9e9")
    box(d, 60, 28, 340, 66, "Resilience and Reporting", ["optional resilience scenarios with compromised/failed nodes", "emit summaries, flow report, and technical report"], "#eef3f7")
    for top, bottom in [(412, 398), (348, 326), (276, 258), (200, 180), (114, 94)]:
        add_arrow(d, 230, top, 230, bottom)
    return d


def header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#4a5a6a"))
    canvas.drawString(doc.leftMargin, 18, "HOST26 Algorithm Flow and Pseudocode")
    canvas.drawRightString(doc.pagesize[0] - doc.rightMargin, 18, f"Page {doc.page}")
    canvas.restoreState()


def main():
    s = styles()
    mono = ParagraphStyle("Mono", parent=s["BodyText"], fontName="Courier", fontSize=8.1, leading=9.7, spaceAfter=6)
    doc = SimpleDocTemplate(
        str(OUTPUT_PATH),
        pagesize=letter,
        leftMargin=0.65 * inch,
        rightMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.7 * inch,
        title="HOST26 Algorithm Flow and Pseudocode",
        author="OpenAI Codex",
    )

    story = []
    story.append(Paragraph("HOST26 Algorithm Flow and Pseudocode", s["Title"]))
    story.append(
        Paragraph(
            "This appendix describes the implemented solve order in HOST26. The flowchart follows the current Python runners and the pseudocode maps directly to the current Phase 1, Phase 2, runtime, and resilience entry points.",
            s["BodySmall"],
        )
    )

    story.append(Paragraph("1. Flowchart", s["Section"]))
    story.append(flowchart())
    story.append(Paragraph("Figure 1. Control and data flow across the implemented HOST26 algorithm.", s["Caption"]))

    story.append(Paragraph("2. Top-Level Pseudocode", s["Section"]))
    story.append(
        Preformatted(
            """function HOST26_RUNTIME_PIPELINE():
    testcase_facts <- load testCase9_inst.lp

    phase1_model <- SOLVE_OPTIMAL(
        testcase_facts
        + security_features_inst.lp
        + tgt_system_tc9_inst.lp
        + init_enc.lp
        + opt_redundancy_generic_enc.lp
        + opt_latency_enc.lp
        + opt_power_enc.lp
        + opt_resource_enc.lp
        + bridge_enc.lp
    )
    p1 <- PARSE_PHASE1_RESULT(phase1_model)
    p1_facts <- BUILD_P1_FACTS(p1)

    phase2_model <- SOLVE_OPTIMAL(testcase_facts + zta_policy_enc.lp + p1_facts)
    p2 <- PARSE_PHASE2_RESULT(phase2_model)

    joint_model <- SOLVE_OPTIMAL(testcase_facts + zta_policy_runtime_enc.lp + p1_facts)
    joint <- PARSE_JOINT_RUNTIME_RESULT(joint_model)
    deployment_facts <- BUILD_DEPLOYMENT_FACTS(joint)

    runtime_results <- []
    for scenario in RUNTIME_SCENARIOS:
        runtime_model <- SOLVE_OPTIMAL(
            testcase_facts
            + runtime_monitor_tc9_inst.lp
            + runtime_adaptive_tc9_enc.lp
            + p1_facts
            + deployment_facts
            + SCENARIO_OBSERVATIONS(scenario)
        )
        runtime_results.append(PARSE_RUNTIME_RESULT(runtime_model))

    resilience_results <- []
    for scenario in RESILIENCE_SCENARIOS:
        resilience_model <- SOLVE(
            testcase_facts
            + resilience_tc9_enc.lp
            + p1_risk facts
            + deployed PEP / PS facts
            + compromised(node), failed(node)
        )
        resilience_results.append(PARSE_RESILIENCE_RESULT(resilience_model))

    return p1, p2, joint, runtime_results, resilience_results""",
            mono,
        )
    )

    story.append(Paragraph("3. Runtime Scoring Pseudocode", s["Section"]))
    story.append(
        Preformatted(
            """for each observed node N:
    monitor_visibility(N) <- max strength of any deployed monitor covering N
    logging_visibility(N) <- 0 if no_logging, 6 if some_logging, 15 if zero_trust_logger
    observability_score(N) <- monitor_visibility(N) + logging_visibility(N)

    base_score(N) <- sum of static penalties from:
        missing attestation
        unsigned policy server
        missing hardware root of trust
        missing secure boot
        missing key storage on high-domain receivers

    alert_score(N) <- sum over observed(N, signal, severity):
        signal_weight(signal) * severity

    anomaly_score(N) <- base_score(N) + alert_score(N) + observability_score(N)

    if anomaly_score(N) >= 100:
        trust_state(N) <- compromised
    else if anomaly_score(N) >= 70:
        trust_state(N) <- low
    else if anomaly_score(N) >= 40:
        trust_state(N) <- medium
    else:
        trust_state(N) <- high

if any node is compromised:
    current_mode <- attack_confirmed
else if any safety-critical receiver or active policy server is low trust:
    current_mode <- attack_confirmed
else if any node is medium or low trust:
    current_mode <- attack_suspected
else:
    current_mode <- normal

if current_mode == attack_suspected:
    re_attest suspicious masters
    force signed policy on unsigned active policy servers
    deny suspicious access to critical targets

if current_mode == attack_confirmed:
    quarantine compromised or safety-critical low-trust nodes
    lockdown active PEPs
    deny all reachable accesses in confirmed mode""",
            mono,
        )
    )

    story.append(Paragraph("4. Joint Runtime Objective", s["Section"]))
    story.append(
        build_table(
            [
                ["Priority", "Objective", "Meaning"],
                ["4", "maximize response_readiness_score", "favor coverage of critical nodes and deployed control-plane elements"],
                ["3", "maximize detection_strength_score", "favor high-observability placements"],
                ["2", "minimize weighted_detection_latency", "favor fast monitor paths for important nodes"],
                ["1", "minimize false_positive_cost", "penalize expensive alert-handling placements"],
                ["0", "minimize monitor_total_cost", "prefer cheaper monitor sets when higher priorities tie"],
            ],
            [0.7 * inch, 2.4 * inch, 3.2 * inch],
        )
    )

    story.append(Paragraph("5. Phase Outputs", s["Section"]))
    story.append(
        build_table(
            [
                ["Stage", "Primary outputs"],
                ["Phase 1", "selected_security, selected_logging, new_risk, resource and power totals, p1_* facts"],
                ["Phase 2", "place_fw, place_ps, protected, governs_ip, allow/deny policy, trust-gap findings"],
                ["Joint runtime synthesis", "place_monitor, observability_score, detection_latency, response_readiness_score, false_positive_cost"],
                ["Runtime scenario solve", "current_mode, trust_state, response_action, adaptive_allow, adaptive_deny"],
                ["Resilience scenario solve", "scenario_asset_risk, scenario_total_risk, service degradation, control-plane degradation"],
            ],
            [1.4 * inch, 4.9 * inch],
        )
    )

    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)


if __name__ == "__main__":
    main()
