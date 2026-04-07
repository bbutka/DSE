from __future__ import annotations

from pathlib import Path
import re

from reportlab.graphics.shapes import Drawing, Line, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "PIXHAWK6X_MODEL_SUMMARY.md"
OUTPUT = ROOT / "PIXHAWK6X_MODEL_SUMMARY.pdf"


def _styles():
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="BodySmall",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=12,
            spaceAfter=4,
        )
    )
    styles.add(
        ParagraphStyle(
            name="BulletSmall",
            parent=styles["BodySmall"],
            leftIndent=14,
            firstLineIndent=-8,
            bulletIndent=4,
            spaceBefore=0,
            spaceAfter=2,
        )
    )
    styles.add(
        ParagraphStyle(
            name="FigureCaption",
            parent=styles["BodySmall"],
            alignment=TA_CENTER,
            fontSize=9,
            textColor=colors.HexColor("#444444"),
            spaceBefore=4,
            spaceAfter=8,
        )
    )
    return styles


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _inline_code(text: str) -> str:
    return re.sub(r"`([^`]+)`", r"<font name='Courier'>\1</font>", _escape(text))


def _architecture_figure() -> Drawing:
    sx = 0.58
    sy = 0.58
    d = Drawing(7.2 * inch, 3.2 * inch)

    def box(x, y, w, h, label, fill, stroke=colors.HexColor("#333333"), font_size=9):
        x *= sx
        y *= sy
        w *= sx
        h *= sy
        d.add(Rect(x, y, w, h, rx=8 * sx, ry=8 * sy, fillColor=fill, strokeColor=stroke, strokeWidth=1))
        lines = label.split("\n")
        for i, line in enumerate(lines):
            d.add(
                String(
                    x + w / 2,
                    y + h / 2 + (len(lines) - 1) * 5 * sy - i * 10 * sy - 4 * sy,
                    line,
                    textAnchor="middle",
                    fontName="Helvetica-Bold" if i == 0 else "Helvetica",
                    fontSize=font_size * sy,
                    fillColor=colors.HexColor("#111111"),
                )
            )

    def arrow(x1, y1, x2, y2, dashed=False):
        d.add(
            Line(
                x1 * sx,
                y1 * sy,
                x2 * sx,
                y2 * sy,
                strokeColor=colors.HexColor("#444444"),
                strokeWidth=1.3,
                strokeDashArray=[4, 3] if dashed else None,
            )
        )

    box(18, 368, 88, 44, "ground_station", colors.HexColor("#FDE68A"))
    box(132, 368, 92, 44, "telem_radio", colors.HexColor("#FCA5A5"))
    box(252, 368, 92, 44, "telem1_port", colors.HexColor("#BFDBFE"))
    box(374, 336, 118, 110, "fmu_h753\n(FMU)", colors.HexColor("#C7D2FE"), font_size=10)

    box(24, 272, 84, 38, "gps_1", colors.HexColor("#FDE68A"))
    box(24, 224, 84, 38, "gps_2", colors.HexColor("#FDE68A"))
    box(136, 272, 92, 38, "gps1_port", colors.HexColor("#BFDBFE"))
    box(136, 224, 92, 38, "gps2_port", colors.HexColor("#BFDBFE"))

    box(22, 120, 84, 34, "imu_1", colors.HexColor("#BBF7D0"))
    box(22, 82, 84, 34, "imu_2", colors.HexColor("#BBF7D0"))
    box(22, 44, 84, 34, "imu_3", colors.HexColor("#BBF7D0"))
    box(132, 120, 92, 34, "imu_bus_1", colors.HexColor("#BFDBFE"))
    box(132, 82, 92, 34, "imu_bus_2", colors.HexColor("#BFDBFE"))
    box(132, 44, 92, 34, "imu_bus_3", colors.HexColor("#BFDBFE"))

    box(248, 176, 88, 34, "baro_bus_1", colors.HexColor("#BFDBFE"))
    box(248, 132, 88, 34, "baro_bus_2", colors.HexColor("#BFDBFE"))
    box(248, 88, 88, 34, "mag_bus", colors.HexColor("#BFDBFE"))
    box(128, 176, 92, 34, "baro_1", colors.HexColor("#BBF7D0"))
    box(128, 132, 92, 34, "baro_2", colors.HexColor("#BBF7D0"))
    box(128, 88, 92, 34, "mag", colors.HexColor("#BBF7D0"))

    box(522, 376, 90, 36, "ps_fmu", colors.HexColor("#DDD6FE"))
    box(520, 316, 92, 34, "pep_telem1", colors.HexColor("#E9D5FF"))
    box(520, 272, 92, 34, "pep_eth", colors.HexColor("#E9D5FF"))
    box(520, 228, 92, 34, "pep_can1", colors.HexColor("#E9D5FF"))
    box(520, 184, 92, 34, "pep_can2", colors.HexColor("#E9D5FF"))
    box(520, 140, 92, 34, "pep_gps2", colors.HexColor("#E9D5FF"))
    box(520, 96, 92, 34, "pep_px4io", colors.HexColor("#E9D5FF"))
    box(520, 52, 92, 34, "pep_se050", colors.HexColor("#E9D5FF"))

    box(620, 248, 92, 38, "eth_port", colors.HexColor("#BFDBFE"))
    box(620, 196, 92, 38, "companion", colors.HexColor("#FDE68A"))
    box(620, 144, 92, 38, "camera", colors.HexColor("#FDE68A"))

    box(620, 94, 92, 34, "can1", colors.HexColor("#BFDBFE"))
    box(620, 54, 92, 34, "can2", colors.HexColor("#BFDBFE"))
    box(730, 94, 94, 34, "esc_bus_1", colors.HexColor("#FDE68A"))
    box(730, 54, 94, 34, "esc_bus_2", colors.HexColor("#FDE68A"))

    box(618, 332, 94, 34, "px4io_link", colors.HexColor("#BFDBFE"))
    box(730, 332, 90, 34, "io_mcu", colors.HexColor("#FDE68A"))
    box(730, 288, 90, 34, "rc_receiver", colors.HexColor("#FDE68A"))
    box(620, 376, 92, 34, "spi5_ext", colors.HexColor("#BFDBFE"))
    box(730, 376, 90, 34, "flash_fram", colors.HexColor("#FDE68A"))
    box(620, 420, 92, 34, "se050", colors.HexColor("#FDE68A"))

    arrow(106, 390, 132, 390)
    arrow(224, 390, 252, 390)
    arrow(344, 390, 374, 390)

    arrow(108, 291, 136, 291)
    arrow(108, 243, 136, 243)
    arrow(228, 291, 374, 374)
    arrow(228, 243, 374, 360)

    arrow(106, 137, 132, 137)
    arrow(106, 99, 132, 99)
    arrow(106, 61, 132, 61)
    arrow(224, 137, 374, 340)
    arrow(224, 99, 374, 326)
    arrow(224, 61, 374, 312)

    arrow(220, 193, 248, 193)
    arrow(220, 149, 248, 149)
    arrow(220, 105, 248, 105)
    arrow(336, 193, 374, 348)
    arrow(336, 149, 374, 334)
    arrow(336, 105, 374, 320)

    arrow(492, 388, 520, 388, dashed=True)
    arrow(492, 388, 520, 333, dashed=True)
    arrow(492, 388, 520, 289, dashed=True)
    arrow(492, 388, 520, 245, dashed=True)
    arrow(492, 388, 520, 201, dashed=True)
    arrow(492, 388, 520, 157, dashed=True)
    arrow(492, 388, 520, 113, dashed=True)
    arrow(492, 388, 520, 69, dashed=True)

    arrow(492, 286, 620, 267)
    arrow(712, 215, 712, 182)
    arrow(492, 260, 620, 111)
    arrow(492, 246, 620, 71)
    arrow(712, 111, 730, 111)
    arrow(712, 71, 730, 71)

    arrow(492, 374, 620, 349)
    arrow(712, 349, 730, 349)
    arrow(712, 305, 730, 305)
    arrow(492, 430, 620, 437)
    arrow(712, 437, 620, 392)
    arrow(712, 392, 730, 392)

    return d


def _parse_markdown(md_text: str, styles):
    story = []
    lines = md_text.splitlines()
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        if stripped == "```mermaid":
            while i < len(lines) and lines[i].strip() != "```":
                i += 1
            if i < len(lines):
                i += 1
            story.append(_architecture_figure())
            story.append(Paragraph("Figure 1. Pixhawk 6X UAV overlay architecture used in the current DSE_Core model.", styles["FigureCaption"]))
            continue

        if stripped.startswith("# "):
            story.append(Paragraph(_inline_code(stripped[2:]), styles["Title"]))
            story.append(Spacer(1, 0.08 * inch))
            i += 1
            continue

        if stripped.startswith("## "):
            story.append(Spacer(1, 0.08 * inch))
            story.append(Paragraph(_inline_code(stripped[3:]), styles["Heading2"]))
            i += 1
            continue

        if stripped.startswith("### "):
            story.append(Spacer(1, 0.04 * inch))
            story.append(Paragraph(_inline_code(stripped[4:]), styles["Heading3"]))
            i += 1
            continue

        if stripped.startswith("#### "):
            story.append(Paragraph(_inline_code(stripped[5:]), styles["Heading4"]))
            i += 1
            continue

        if stripped.startswith("|"):
            table_lines = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                table_lines.append(lines[i].strip())
                i += 1
            rows = []
            for idx, row in enumerate(table_lines):
                if idx == 1 and set(row.replace("|", "").replace(":", "").replace("-", "").strip()) == set():
                    continue
                cells = [_inline_code(cell.strip()) for cell in row.strip("|").split("|")]
                rows.append([Paragraph(cell, styles["BodySmall"]) for cell in cells])
            if rows:
                col_widths = [1.15 * inch, 0.9 * inch, 0.72 * inch, 0.72 * inch, 0.72 * inch, 0.95 * inch, 0.95 * inch, 0.95 * inch, 1.4 * inch]
                tbl = Table(rows, colWidths=col_widths, repeatRows=1)
                tbl.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DCEBFF")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#111111")),
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#999999")),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7FAFC")]),
                            ("LEFTPADDING", (0, 0), (-1, -1), 4),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                            ("TOPPADDING", (0, 0), (-1, -1), 4),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ]
                    )
                )
                story.append(tbl)
                story.append(Spacer(1, 0.08 * inch))
            continue

        if stripped.startswith("- "):
            bullet_lines = []
            while i < len(lines) and lines[i].startswith("- "):
                item = lines[i][2:]
                i += 1
                while i < len(lines):
                    cont = lines[i]
                    if cont.startswith("  - ") or cont.startswith("- ") or not cont.strip():
                        break
                    item += " " + cont.strip()
                    i += 1
                bullet_lines.append(item)
            for item in bullet_lines:
                story.append(Paragraph(_inline_code(item), styles["BulletSmall"], bulletText="•"))
            continue

        paragraph_lines = [stripped]
        i += 1
        while i < len(lines):
            nxt = lines[i].strip()
            if not nxt or nxt.startswith("#") or nxt.startswith("- ") or nxt.startswith("|") or nxt == "```mermaid":
                break
            paragraph_lines.append(nxt)
            i += 1
        story.append(Paragraph(_inline_code(" ".join(paragraph_lines)), styles["BodySmall"]))

    return story


def build_pdf():
    styles = _styles()
    markdown = SOURCE.read_text(encoding="utf-8")
    story = _parse_markdown(markdown, styles)
    doc = SimpleDocTemplate(
        str(OUTPUT),
        pagesize=letter,
        leftMargin=0.65 * inch,
        rightMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
        title="Pixhawk 6X Model Summary",
        author="OpenAI Codex",
    )
    doc.build(story)


if __name__ == "__main__":
    build_pdf()
