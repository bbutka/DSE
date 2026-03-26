from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle


BASE_DIR = Path(__file__).resolve().parent
OUTPUT_PATH = BASE_DIR / "phase1_old_vs_new_explanation.pdf"


def build_table(rows, col_widths):
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d9e6f2")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("LEADING", (0, 0), (-1, -1), 11),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey]),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def main():
    doc = SimpleDocTemplate(
        str(OUTPUT_PATH),
        pagesize=letter,
        leftMargin=0.65 * inch,
        rightMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
        title="Phase 1 Old vs New Calculation",
        author="OpenAI Codex",
    )

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
            name="HeadingSmall",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=14,
            spaceBefore=8,
            spaceAfter=6,
        )
    )
    mono_style = ParagraphStyle(
        "Mono",
        parent=styles["BodyText"],
        fontName="Courier",
        fontSize=8.5,
        leading=10,
        spaceAfter=6,
    )

    story = []
    story.append(Paragraph("Phase 1 Old vs New Calculation", styles["Title"]))
    story.append(
        Paragraph(
            "This document compares the original tc9 Phase 1 redundancy math with the new precise Python-side calculation.",
            styles["BodySmall"],
        )
    )

    story.append(Paragraph("Phase 1 Formula", styles["HeadingSmall"]))
    story.append(
        Preformatted(
            """original_prob = vulnerability_score * logging_score

normalized_prob = (original_prob - mu) * 1000 / (omega - mu)
where mu = 25 and omega = 1000

For the 5-member redundancy group c1..c5:
combined_prob_norm =
    normalized(c1) * normalized(c2) * normalized(c3) * normalized(c4) * normalized(c5)
    / 100000000

new_prob_denormalized = combined_prob_norm * (omega - mu) / 1000 + mu * 10

new_risk = impact * new_prob_denormalized / 100

Phase 1 total = sum over assets of max(read_risk, write_risk)""",
            mono_style,
        )
    )

    story.append(Paragraph("Old Runner: Actual Selected Design", styles["HeadingSmall"]))
    story.append(
        build_table(
            [
                ["Component", "Security", "Logging"],
                ["c1", "zero_trust", "no_logging"],
                ["c2", "mac", "no_logging"],
                ["c3", "mac", "no_logging"],
                ["c4", "mac", "no_logging"],
                ["c5", "mac", "some_logging"],
                ["c6", "zero_trust", "some_logging"],
                ["c7", "zero_trust", "some_logging"],
                ["c8", "mac", "no_logging"],
            ],
            [1.0 * inch, 1.6 * inch, 1.7 * inch],
        )
    )

    story.append(Paragraph("Old Method: Detailed Calculation", styles["HeadingSmall"]))
    story.append(
        build_table(
            [
                ["Component", "original_prob", "Exact normalized", "Old Clingo stored"],
                ["c1", "200", "175000 / 975 = 179.487...", "179"],
                ["c2", "600", "575000 / 975 = 589.743...", "589"],
                ["c3", "600", "575000 / 975 = 589.743...", "589"],
                ["c4", "600", "575000 / 975 = 589.743...", "589"],
                ["c5", "300", "275000 / 975 = 282.051...", "282"],
            ],
            [0.9 * inch, 1.0 * inch, 2.35 * inch, 1.25 * inch],
        )
    )
    story.append(
        Paragraph(
            "The mathematically expected integer product before dividing by 100000000 is 10,314,496,282,182. "
            "But the raw old Phase 1 model emitted combined_prob_norm(1,-20). That is the identifiable overflow.",
            styles["BodySmall"],
        )
    )
    story.append(
        Preformatted(
            """Old Clingo then continued with:

new_prob_denormalized = (-20 * 975 / 1000) + 250
                       = -19 + 250
                       = 231""",
            mono_style,
        )
    )
    story.append(
        build_table(
            [
                ["Component", "Read impact", "Write impact", "Old read risk", "Old write risk", "Old max"],
                ["c1", "1", "5", "2", "11", "11"],
                ["c2", "5", "2", "11", "4", "11"],
                ["c3", "3", "3", "6", "6", "6"],
                ["c4", "3", "4", "6", "9", "9"],
                ["c5", "4", "1", "9", "2", "9"],
            ],
            [0.85 * inch, 0.9 * inch, 0.9 * inch, 1.0 * inch, 1.0 * inch, 0.75 * inch],
        )
    )
    story.append(
        Paragraph(
            "Old Phase 1 total = 11 + 11 + 6 + 9 + 9 + 50 + 20 + 240 = 356.",
            styles["BodySmall"],
        )
    )

    story.append(Paragraph("Same Old Design, Recomputed Correctly", styles["HeadingSmall"]))
    story.append(
        Preformatted(
            """Using exact Python arithmetic on the same old design:

combined_prob_norm = 103144.96282182
new_prob_denormalized = 100816.3387512745""",
            mono_style,
        )
    )
    story.append(
        build_table(
            [
                ["Component", "Exact read risk", "Exact write risk", "Rounded max"],
                ["c1", "1008.16", "5040.82", "5041"],
                ["c2", "5040.82", "2016.33", "5041"],
                ["c3", "3024.49", "3024.49", "3024"],
                ["c4", "3024.49", "4032.65", "4033"],
                ["c5", "4032.65", "1008.16", "4033"],
            ],
            [0.9 * inch, 1.35 * inch, 1.35 * inch, 1.0 * inch],
        )
    )
    story.append(
        Paragraph(
            "The same old design therefore has a corrected Phase 1 total of 21482, not 356.",
            styles["BodySmall"],
        )
    )

    story.append(Paragraph("New Precise Runner: Selected Design", styles["HeadingSmall"]))
    story.append(
        build_table(
            [
                ["Component", "Security", "Logging"],
                ["c1", "mac", "some_logging"],
                ["c2", "mac", "some_logging"],
                ["c3", "mac", "some_logging"],
                ["c4", "mac", "some_logging"],
                ["c5", "zero_trust", "no_logging"],
                ["c6", "zero_trust", "some_logging"],
                ["c7", "zero_trust", "some_logging"],
                ["c8", "mac", "no_logging"],
            ],
            [1.0 * inch, 1.6 * inch, 1.7 * inch],
        )
    )

    story.append(Paragraph("New Method: Detailed Calculation", styles["HeadingSmall"]))
    story.append(
        Preformatted(
            """For the new precise design:

original_prob(c1..c4) = 300
original_prob(c5) = 200

Exact normalized:
  c1..c4 = 11000 / 39 = 282.051282...
  c5     =  7000 / 39 = 179.487179...

Exact combined_prob_norm =
  (11000/39)^4 * (7000/39) / 100000000
  = 1024870000000 / 90224199
  = 11359.147672...

Exact new_prob_denormalized =
  26200110250 / 2313441
  = 11325.168980...""",
            mono_style,
        )
    )
    story.append(
        build_table(
            [
                ["Component", "Read risk", "Write risk", "Rounded max"],
                ["c1", "113.25", "566.26", "566"],
                ["c2", "566.26", "226.50", "566"],
                ["c3", "339.76", "339.76", "340"],
                ["c4", "339.76", "453.01", "453"],
                ["c5", "453.01", "113.25", "453"],
                ["c6", "50.00", "30.00", "50"],
                ["c7", "10.00", "20.00", "20"],
                ["c8", "120.00", "240.00", "240"],
            ],
            [0.9 * inch, 1.1 * inch, 1.1 * inch, 1.0 * inch],
        )
    )
    story.append(
        Paragraph(
            "New precise Phase 1 total = 566 + 566 + 340 + 453 + 453 + 50 + 20 + 240 = 2688.",
            styles["BodySmall"],
        )
    )

    story.append(Paragraph("Bottom Line", styles["HeadingSmall"]))
    story.append(
        build_table(
            [
                ["Method", "Phase 1 design", "Group denorm prob", "Phase 1 total"],
                ["Old Clingo math", "old selected design", "231", "356"],
                ["Exact math on old design", "same design", "100816.3387...", "21482"],
                ["New precise runner", "new selected design", "11325.1689...", "2688"],
            ],
            [1.6 * inch, 1.7 * inch, 1.45 * inch, 1.0 * inch],
        )
    )
    story.append(
        Paragraph(
            "The old method understated risk because the redundancy product overflowed in Clingo and then continued through integer arithmetic with a negative combined probability. "
            "The new method is better because it computes the redundancy product exactly in Python, rounds once at the end, and then picks the best exact-risk candidate from the Clingo frontier.",
            styles["BodySmall"],
        )
    )

    doc.build(story)
    print(f"Wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
