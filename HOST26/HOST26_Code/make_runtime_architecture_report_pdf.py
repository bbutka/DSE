from __future__ import annotations

from pathlib import Path

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle


BASE_DIR = Path(__file__).resolve().parent
OUTPUT_PATH = BASE_DIR / "runtime_architecture_technical_report.pdf"


def make_styles():
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="BodySmall",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=12,
            spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Section",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=18,
            textColor=colors.HexColor("#183153"),
            spaceBefore=10,
            spaceAfter=8,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Caption",
            parent=styles["BodyText"],
            fontName="Helvetica-Oblique",
            fontSize=8.5,
            leading=10,
            textColor=colors.HexColor("#4a5a6a"),
            spaceAfter=8,
        )
    )
    return styles


def build_table(rows, col_widths, header_bg="#d9e6f2", font_size=8.8):
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(header_bg)),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                ("GRID", (0, 0), (-1, -1), 0.45, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), font_size),
                ("LEADING", (0, 0), (-1, -1), font_size + 2),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#eef3f7")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def add_arrow(drawing: Drawing, x1: float, y1: float, x2: float, y2: float, color=colors.HexColor("#355c7d")):
    drawing.add(Line(x1, y1, x2, y2, strokeColor=color, strokeWidth=1.5))
    if x1 == x2:
        head = Polygon([x2 - 4, y2 + 7, x2 + 4, y2 + 7, x2, y2], fillColor=color, strokeColor=color)
    else:
        head = Polygon([x2 - 7, y2 - 4, x2 - 7, y2 + 4, x2, y2], fillColor=color, strokeColor=color)
    drawing.add(head)


def add_box(drawing: Drawing, x: float, y: float, w: float, h: float, title: str, lines: list[str], fill: str):
    drawing.add(
        Rect(
            x,
            y,
            w,
            h,
            rx=8,
            ry=8,
            fillColor=colors.HexColor(fill),
            strokeColor=colors.HexColor("#355c7d"),
            strokeWidth=1.2,
        )
    )
    drawing.add(String(x + 8, y + h - 16, title, fontName="Helvetica-Bold", fontSize=10))
    cursor = y + h - 30
    for line in lines:
        drawing.add(String(x + 8, cursor, line, fontName="Helvetica", fontSize=7.8))
        cursor -= 10


def architecture_pipeline_diagram() -> Drawing:
    d = Drawing(470, 420)
    add_box(d, 60, 352, 350, 48, "Inputs and Instance Facts", ["testCase9 topology, impacts, trust anchors", "resource budgets, monitor catalog, policy topology"], "#edf5ff")
    add_box(d, 60, 282, 350, 56, "Phase 1: LUT-Based Security DSE", ["select security and logging per component", "enforce latency, power, and resource constraints", "emit p1_security, p1_logging, and p1_risk facts"], "#e8f7ec")
    add_box(d, 60, 204, 350, 60, "Phase 2: ZTA Policy Synthesis", ["place PEPs and policy servers", "derive allow/deny policy and governance", "compute least-privilege and trust-gap findings"], "#fff4df")
    add_box(d, 60, 122, 350, 66, "Joint Runtime Synthesis", ["place monitors under max_monitor_cost", "maximize readiness and detection strength", "minimize latency and false-positive cost"], "#f3e8ff")
    add_box(d, 60, 40, 350, 68, "Runtime Adaptive Analysis", ["score observations, update trust state, and select system mode", "trigger re_attest, quarantine, or lockdown_pep", "evaluate baseline and anomaly scenarios"], "#ffe9e9")
    for y_top, y_bottom in [(352, 338), (282, 264), (204, 188), (122, 108)]:
        add_arrow(d, 235, y_top, 235, y_bottom)
    return d


def topology_diagram() -> Drawing:
    d = Drawing(500, 300)
    add_box(d, 18, 210, 70, 34, "sys_cpu", ["master", "domain=low"], "#edf5ff")
    add_box(d, 18, 150, 70, 34, "dma", ["master", "domain=low"], "#edf5ff")
    add_box(d, 132, 188, 86, 54, "noc0", ["c1-c5 path", "PEP: pep_group", "Monitor: mon_noc0"], "#fff4df")
    add_box(d, 132, 106, 86, 54, "noc1", ["c6-c8 path", "PEP: pep_standalone", "Monitor: mon_noc1"], "#fff4df")
    add_box(d, 252, 192, 210, 62, "Redundant Compute Group", ["c1 c2 c3 c4 c5", "redundant_group(1, c1..c5)", "high-domain receivers"], "#e8f7ec")
    add_box(d, 252, 88, 210, 82, "Standalone Receivers", ["c6 monitor node", "c7 low-domain support node", "c8 safety-critical node", "dedicated monitor: mon_c8"], "#e8f7ec")
    add_box(d, 354, 14, 122, 52, "Control Plane", ["ps0, ps1", "mon_ctrl", "governs pep_group", "ps0 also governs pep_standalone"], "#f3e8ff")
    add_arrow(d, 88, 227, 132, 215)
    add_arrow(d, 88, 167, 132, 215)
    add_arrow(d, 88, 167, 132, 133)
    add_arrow(d, 218, 215, 252, 223)
    add_arrow(d, 218, 133, 252, 129)
    add_arrow(d, 415, 66, 415, 88)
    add_arrow(d, 390, 66, 390, 188)
    add_arrow(d, 450, 66, 450, 106)
    return d


def closed_loop_diagram() -> Drawing:
    d = Drawing(500, 240)
    add_box(d, 20, 152, 96, 56, "Observed Signals", ["rate_spike", "cross_domain", "policy_violation", "sequence_violation"], "#edf5ff")
    add_box(d, 140, 152, 92, 56, "Evidence Scoring", ["signal_weight * severity", "observability bonus", "base penalties"], "#e8f7ec")
    add_box(d, 256, 152, 92, 56, "Trust Update", ["high", "medium", "low", "compromised"], "#fff4df")
    add_box(d, 372, 152, 102, 56, "Mode Transition", ["normal", "attack_suspected", "attack_confirmed"], "#ffe9e9")
    add_box(d, 154, 40, 110, 62, "Response Actions", ["re_attest(master)", "quarantine(node)", "lockdown_pep(pep)", "force_signed_policy(ps)"], "#f3e8ff")
    add_box(d, 306, 40, 132, 62, "Adaptive Policy", ["adaptive_allow", "adaptive_deny", "tightened access surface"], "#eef3f7")
    add_arrow(d, 116, 180, 140, 180)
    add_arrow(d, 232, 180, 256, 180)
    add_arrow(d, 348, 180, 372, 180)
    add_arrow(d, 423, 152, 378, 102)
    add_arrow(d, 264, 70, 306, 70)
    add_arrow(d, 372, 40, 372, 14)
    d.add(String(332, 6, "enforced on system accesses", fontName="Helvetica", fontSize=8))
    return d


def header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#4a5a6a"))
    canvas.drawString(doc.leftMargin, 18, "HOST26 Runtime-Adaptive Architecture Technical Report")
    canvas.drawRightString(doc.pagesize[0] - doc.rightMargin, 18, f"Page {doc.page}")
    canvas.restoreState()


def main():
    styles = make_styles()
    mono = ParagraphStyle("Mono", parent=styles["BodyText"], fontName="Courier", fontSize=8.2, leading=10, spaceAfter=6)
    doc = SimpleDocTemplate(
        str(OUTPUT_PATH),
        pagesize=letter,
        leftMargin=0.65 * inch,
        rightMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.7 * inch,
        title="HOST26 Runtime-Adaptive Architecture Technical Report",
        author="OpenAI Codex",
    )

    story = []
    story.append(Paragraph("HOST26 Runtime-Adaptive Architecture Technical Report", styles["Title"]))
    story.append(
        Paragraph(
            "This report documents the current runtime-aware HOST26 implementation in the tc9 benchmark. It mirrors the role of architecture.md, but it is aligned to the actual files and behavior in the current workspace. "
            "The report explains the implemented phases, the new runtime extension, the synthesized tc9 deployment, and the remaining weaknesses and work still required.",
            styles["BodySmall"],
        )
    )
    story.append(
        Paragraph(
            "Primary implementation files covered: runClingo_tc9.py, runClingo_tc9_runtime.py, runClingo_tc9_runtime_joint.py, Clingo/opt_redundancy_generic_enc.lp, "
            "Clingo/zta_policy_enc.lp, Clingo/zta_policy_runtime_enc.lp, Clingo/runtime_monitor_tc9_inst.lp, Clingo/runtime_adaptive_tc9_enc.lp, and Clingo/resilience_tc9_enc.lp.",
            styles["BodySmall"],
        )
    )

    story.append(Paragraph("1. Executive Summary", styles["Section"]))
    story.append(
        Paragraph(
            "The HOST26 architecture now extends the original three-phase Zero Trust design-space exploration flow with an explicit runtime observability and adaptive response layer. The pipeline still begins with Phase 1 feature allocation and Phase 2 control-plane synthesis, "
            "but it now also selects monitors, scores observed anomalies, updates trust state, transitions operating mode, and triggers adaptive response actions. This makes the implementation closer to a closed-loop architecture than the earlier design-time-only formulation.",
            styles["BodySmall"],
        )
    )
    story.append(
        Paragraph(
            "The implementation remains an architectural model rather than a deployed runtime security stack. Monitors and detector behavior are represented as facts and rules, not implemented monitor RTL or measured services. "
            "That makes the framework useful for design exploration and comparative analysis, while leaving calibration and deployment realism as follow-on work.",
            styles["BodySmall"],
        )
    )
    story.append(Spacer(1, 6))
    story.append(architecture_pipeline_diagram())
    story.append(Paragraph("Figure 1. End-to-end architecture pipeline from instance facts to runtime-adaptive scenario outputs.", styles["Caption"]))

    story.append(Paragraph("2. Architectural Scope and Inputs", styles["Section"]))
    story.append(
        Paragraph(
            "The benchmark system is defined by eight components, two masters, two buses, one redundancy group, candidate PEP and policy-server placements, trust anchors, mission modes, and service-level resilience facts. "
            "The topology comes from testCase9_inst.lp and defines both the data plane and the abstract control plane that later phases reason over.",
            styles["BodySmall"],
        )
    )
    story.append(
        build_table(
            [
                ["Category", "Implemented tc9 facts"],
                ["Components and assets", "c1..c8, one asset per component, read and write impacts per asset"],
                ["Redundancy", "redundant_group(1, c1..c5) for the compute service"],
                ["Masters", "sys_cpu and dma"],
                ["Interconnect", "noc0 for c1..c5, noc1 for c6..c8"],
                ["Control plane", "pep_group, pep_standalone, ps0, ps1"],
                ["Criticality", "c1..c6 and c8 are critical; c8 is safety-critical"],
                ["Trust anchors", "hardware_rot, secure_boot, attested, signed_policy, key_storage facts"],
                ["Mission semantics", "operational, maintenance, emergency access views plus explicit exceptions"],
            ],
            [1.55 * inch, 4.8 * inch],
        )
    )
    story.append(topology_diagram())
    story.append(Paragraph("Figure 2. Simplified tc9 architecture and monitoring topology.", styles["Caption"]))

    story.append(Paragraph("3. Phase 1: LUT-Based Security Design-Space Exploration", styles["Section"]))
    story.append(
        Paragraph(
            "Phase 1 chooses one security feature and one logging feature per component while respecting latency, power, and implementation constraints. The critical numeric change is that the overflow-prone size-5 multiplication in the redundancy equation "
            "was replaced by a generic recursive encoding in opt_redundancy_generic_enc.lp. This eliminates the LUT entirely and works for any group size by dividing by 1000 at each multiplication step, keeping intermediate values within Clingo's 32-bit integer range while preserving the intended fixed-point semantics.",
            styles["BodySmall"],
        )
    )
    story.append(
        Preformatted(
            """Phase 1 emits:
selected_security(component, feature)
selected_logging(component, logger)
new_risk(component, asset, action, risk)
resource and power totals

The runner converts those into:
p1_security(component, feature)
p1_logging(component, logger)
p1_risk(asset, max_risk)""",
            mono,
        )
    )
    story.append(
        build_table(
            [
                ["Phase 1 aspect", "Current implementation"],
                ["Optimization engine", "clingo with opt_redundancy_generic_enc.lp, opt_latency_enc.lp, opt_power_enc.lp, opt_resource_enc.lp, bridge_enc.lp"],
                ["Solve mode", "proven optimum mode with -n 0 and --opt-mode=optN"],
                ["Critical numeric fix", "replace 5-term multiplication with tc9_combined_prob_norm_size5_lut.lp lookup facts"],
                ["Downstream contract", "Phase 1 result becomes injected p1_* facts for later phases"],
                ["Current tc9 baseline", "reported baseline max-risk sum = 520"],
            ],
            [1.7 * inch, 4.65 * inch],
        )
    )

    story.append(Paragraph("4. Phase 2: Zero Trust Control-Plane Synthesis", styles["Section"]))
    story.append(
        Paragraph(
            "The second phase synthesizes the control plane. It selects PEPs and policy servers, derives who protects which IPs, determines which policy servers govern which paths, and computes final allow and deny decisions together with least-privilege findings. "
            "In the baseline non-runtime path, Phase 2 now runs in proven-optimal mode and Phase 3 consumes the resulting deployed PEP and PS facts.",
            styles["BodySmall"],
        )
    )
    story.append(
        build_table(
            [
                ["Construct", "Meaning in the implemented model"],
                ["place_fw(FW)", "select a candidate policy enforcement point"],
                ["place_ps(PS)", "select a candidate policy server"],
                ["protected(M, C)", "master M accesses receiver C only through deployed enforcement"],
                ["governs_ip(PS, C)", "policy server PS governs the IP path to receiver C"],
                ["policy_tightness(M, Score)", "coarse measure of how tightly granted access matches need"],
                ["excess_privilege / missing_privilege", "least-privilege diagnosis for master-component-action triples"],
                ["trust_gap_*", "findings tied to root of trust, secure boot, attestation, keys, or signed policy"],
            ],
            [1.8 * inch, 4.55 * inch],
        )
    )
    story.append(
        Paragraph(
            "In the pure ZTA path, the tc9 result places pep_group and pep_standalone with ps0 at a cost of 450. In the runtime-aware joint path, the optimizer may retain ps1 as well if the additional coverage and response value outweigh the cost.",
            styles["BodySmall"],
        )
    )

    story.append(PageBreak())

    story.append(Paragraph("5. Runtime Observability Layer", styles["Section"]))
    story.append(
        Paragraph(
            "The runtime extension adds an explicit monitor model. Each monitor has placement cost, detection strength, latency, false-positive handling cost, and coverage relations. "
            "These are architectural capabilities rather than synthesized monitor implementations, but they allow the solver to reason formally about where the design can observe suspicious activity and how expensive that visibility is.",
            styles["BodySmall"],
        )
    )
    story.append(
        build_table(
            [
                ["Monitor", "Coverage summary", "Cost", "Strength", "Latency", "False-positive cost"],
                ["mon_noc0", "sys_cpu, dma, c1..c5, pep_group", "120", "8", "3", "8"],
                ["mon_noc1", "dma, c6, c7, c8, pep_standalone", "90", "8", "3", "8"],
                ["mon_ctrl", "ps0, ps1, pep_group, pep_standalone", "110", "12", "2", "12"],
                ["mon_c8", "c8 only", "60", "18", "1", "24"],
            ],
            [1.1 * inch, 2.9 * inch, 0.55 * inch, 0.7 * inch, 0.7 * inch, 1.1 * inch],
        )
    )
    story.append(
        Paragraph(
            "Safety-critical and active control-plane coverage are hard constraints in the runtime model. c8, any active policy server, and any active PEP must be covered by at least one active monitor. "
            "This is the first place where observability is treated as a first-class synthesis concern instead of an indirect side effect of logging.",
            styles["BodySmall"],
        )
    )

    story.append(Paragraph("6. Runtime Evidence, Trust Update, and Mode Transitions", styles["Section"]))
    story.append(
        Paragraph(
            "The runtime_adaptive_tc9_enc.lp encoding turns observations into architectural consequences. The scoring model combines base penalties from weak trust anchors, signal-weighted anomaly evidence, and an observability bonus that reflects monitor plus logging coverage. "
            "That score determines trust state, and trust state determines system mode.",
            styles["BodySmall"],
        )
    )
    story.append(
        Preformatted(
            """observability_score(node) = monitor_visibility(node) + logging_visibility(node)
alert_score(node)        = sum(signal_weight(signal) * severity)
anomaly_score(node)      = base_score(node) + alert_score(node) + observability_score(node)

trust_state = high         if anomaly_score < 40
trust_state = medium       if 40 <= anomaly_score < 70
trust_state = low          if 70 <= anomaly_score < 100
trust_state = compromised  if anomaly_score >= 100

current_mode = attack_confirmed if any node is compromised
current_mode = attack_confirmed if a safety-critical receiver or active PS reaches low trust
current_mode = attack_suspected if no attack_confirmed trigger exists and any node is medium or low
current_mode = normal otherwise""",
            mono,
        )
    )
    story.append(closed_loop_diagram())
    story.append(Paragraph("Figure 3. Closed-loop runtime control logic from evidence to adaptive enforcement.", styles["Caption"]))
    story.append(
        Paragraph(
            "The response actions currently implemented are re_attest(master), quarantine(node), lockdown_pep(pep), and force_signed_policy(ps). These are explicit architectural outputs, even though they are not yet tied to a detailed execution-time recovery engine.",
            styles["BodySmall"],
        )
    )

    story.append(Paragraph("7. Joint Runtime-Aware Synthesis", styles["Section"]))
    story.append(
        Paragraph(
            "The zta_policy_runtime_enc.lp encoding folds runtime observability back into synthesis. It augments the Phase 2 ZTA model with monitor placement and adds new objective terms: response readiness, detection strength, weighted detection latency, false-positive cost, and monitor placement cost. "
            "The result is a second-stage optimization that trades control-plane cost against runtime assurance.",
            styles["BodySmall"],
        )
    )
    story.append(
        build_table(
            [
                ["Objective layer", "Direction", "Meaning"],
                ["Priority 4", "maximize", "response readiness over critical nodes and deployed control-plane elements"],
                ["Priority 3", "maximize", "detection strength from weighted observability"],
                ["Priority 2", "minimize", "weighted detection latency"],
                ["Priority 1", "minimize", "false-positive handling cost"],
                ["Priority 0", "minimize", "monitor placement cost"],
            ],
            [1.2 * inch, 1.0 * inch, 4.15 * inch],
        )
    )
    story.append(
        build_table(
            [
                ["Current tc9 joint synthesis result", "Value"],
                ["Firewalls", "pep_group, pep_standalone"],
                ["Policy servers", "ps0, ps1"],
                ["Monitors", "mon_c8, mon_ctrl, mon_noc0, mon_noc1"],
                ["ZTA cost", "630"],
                ["Monitor cost", "380"],
                ["Joint cost", "1010"],
                ["Response-readiness score", "300"],
                ["Detection-strength score", "4340"],
                ["Weighted detection latency", "905"],
                ["False-positive cost", "52"],
            ],
            [2.3 * inch, 1.3 * inch],
        )
    )
    story.append(
        Paragraph(
            "This result differs from the cheaper pure-ZTA solution. The runtime-aware optimizer accepts the extra cost of ps1 and complete monitor coverage because the readiness and observability objectives dominate the lower-priority cost terms. "
            "That is the clearest sign that the architecture has moved beyond static least privilege alone and now selects part of the control plane for runtime recoverability.",
            styles["BodySmall"],
        )
    )

    story.append(PageBreak())

    story.append(Paragraph("8. Scenario Behavior in the Current Implementation", styles["Section"]))
    story.append(
        Paragraph(
            "The runtime runner evaluates a set of anomaly scenarios using the joint deployment above. The goal is not yet to model every possible time sequence, but to test whether the monitor, trust, and mode logic reacts in the expected direction.",
            styles["BodySmall"],
        )
    )
    story.append(
        build_table(
            [
                ["Scenario", "Observed evidence", "Mode", "Representative response"],
                ["baseline", "none", "normal", "no response action required"],
                ["dma_rate_spike", "rate_spike + cross_domain on dma", "attack_suspected", "re_attest(dma), force_signed_policy(ps1), deny critical dma paths"],
                ["dma_privilege_creep", "privilege_creep + policy_violation on dma", "attack_suspected", "tightened dma access with lower trust state"],
                ["c8_sequence_anomaly", "sequence_violation + policy_violation on c8", "attack_confirmed", "quarantine(c8) and lockdown both PEPs"],
                ["ps0_policy_tamper", "policy_violation on ps0 + bypass_alert on pep_group", "attack_confirmed", "lockdown both PEPs"],
            ],
            [1.45 * inch, 2.35 * inch, 1.1 * inch, 2.15 * inch],
            font_size=8.4,
        )
    )
    story.append(
        Paragraph(
            "The current model therefore does perform a real architectural transition: it distinguishes suspicion from confirmed attack, demotes trust, and changes effective policy behavior. That is a material improvement over the earlier static scenario-analysis-only path.",
            styles["BodySmall"],
        )
    )

    story.append(Paragraph("9. What the New Architecture Improves", styles["Section"]))
    story.append(
        build_table(
            [
                ["Before runtime extension", "After runtime extension"],
                ["Feature allocation, policy synthesis, resilience what-if analysis", "Feature allocation, policy synthesis, monitor co-placement, anomaly scoring, trust update, adaptive response"],
                ["Logging lowered risk indirectly", "Logging now also contributes to observability_score"],
                ["Mode-aware policy existed statically", "Modes are now reachable through explicit trust and evidence rules"],
                ["No explicit monitor budget or detector tradeoff", "Monitor budget, latency, strength, and false-positive cost are optimized"],
                ["Scenario analysis was passive", "Scenario analysis now drives adaptive policy outputs"],
            ],
            [3.1 * inch, 3.1 * inch],
        )
    )

    story.append(Paragraph("10. Weaknesses and Work Remaining", styles["Section"]))
    story.append(
        Paragraph(
            "Although the new architecture is materially stronger, it is still not complete. The remaining work falls into model fidelity, control-loop depth, cross-phase optimization, hardware calibration, and deployment realism.",
            styles["BodySmall"],
        )
    )
    weaknesses = [
        "The monitor and detector model is still abstract. monitor_strength, signal_weight, latency, and false-positive cost are architectural scores rather than calibrated measurements from implemented monitors.",
        "Runtime evidence is injected as observed(node, signal, severity) facts rather than derived from transaction traces or a streaming event engine. The architecture models the response logic, not yet the feature-extraction mechanism.",
        "The trust-update logic is one-step and threshold-based. There is no history window, confidence fusion, or recovery hysteresis beyond the immediate rules.",
        "The response model is still access-control-centric. There is no detailed recovery orchestration, trusted restart, key rotation, forensic retention, or reintegration workflow.",
        "Phase 1 and runtime-aware synthesis remain staged. The system does not yet perform one global co-optimization over security features, control-plane placement, monitors, and runtime objectives in a single solve.",
        "Communication-path-aware runtime reasoning is not yet first-class. The architecture knows the bus topology, but it does not yet optimize runtime path risk over named end-to-end flows.",
        "Hardware cost calibration remains incomplete. Several resource tables are still approximate, and power accounting in the current code path still needs further cleanup before the report can claim implementation-faithful realism.",
        "The runtime scenarios are curated and finite. They validate response behavior, but they do not yet provide false-negative analysis, probabilistic coverage, or mean-time-to-detect style metrics.",
    ]
    for item in weaknesses:
        story.append(Paragraph(f"- {item}", styles["BodySmall"]))

    story.append(Paragraph("11. Recommended Next Implementation Steps", styles["Section"]))
    story.append(
        build_table(
            [
                ["Priority", "Recommended work item", "Why it matters"],
                ["1", "Add path-aware monitor and detector modeling for known communication flows", "This connects runtime reasoning to the communication-path problem the architecture is expected to protect."],
                ["2", "Calibrate monitor and feature costs from implementation reports", "This turns strength, latency, and resource costs into evidence-backed values."],
                ["3", "Extend trust update with temporal accumulation and recovery rules", "This makes runtime adaptation less brittle and more realistic."],
                ["4", "Model false negatives and detection coverage explicitly", "This closes a major realism gap in the current detector abstraction."],
                ["5", "Merge Phase 1 and runtime objectives more tightly", "A single co-optimization would let the solver trade feature hardness against observability and response cost directly."],
            ],
            [0.7 * inch, 2.8 * inch, 3.0 * inch],
        )
    )
    story.append(
        Paragraph(
            "The current HOST26 runtime-adaptive architecture is therefore best understood as a strong intermediate architecture: it now has explicit observability, trust, mode, and response logic, but still needs calibration and deeper integration to become a deployment-faithful co-optimization framework.",
            styles["BodySmall"],
        )
    )

    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)


if __name__ == "__main__":
    main()
