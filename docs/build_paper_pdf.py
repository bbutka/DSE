"""
build_paper_pdf.py
==================
Converts DASC_2026_Paper_Draft.md to a formatted review PDF using reportlab.

Handles: sections, body text, bold/italic, tables, code blocks,
         figure callout boxes, bullet/numbered lists, references,
         page headers/footers.
"""

import re
import sys
import os
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether, Preformatted, PageBreak, Image
)
from reportlab.platypus.flowables import Flowable
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
try:
    from svglib.svglib import svg2rlg
    from reportlab.graphics import renderPDF
    from reportlab.graphics.shapes import Drawing
    HAS_SVGLIB = True
except ImportError:
    HAS_SVGLIB = False

# ---------------------------------------------------------------------------
# Page geometry
# ---------------------------------------------------------------------------
PAGE_W, PAGE_H = letter
L_MARGIN = R_MARGIN = 0.85 * inch
T_MARGIN = 1.0 * inch
B_MARGIN = 0.9 * inch
BODY_W = PAGE_W - L_MARGIN - R_MARGIN

TITLE_TEXT = "Assurance-Aware Design Space Exploration\nfor Zero-Trust Avionics SoC Security"
TITLE_SHORT = "ZT Avionics SoC DSE — DASC 2026 Draft"

# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------
IEEE_BLUE   = colors.HexColor("#003087")
SHADE_LIGHT = colors.HexColor("#F0F4F8")
SHADE_CODE  = colors.HexColor("#F5F5F5")
SHADE_FIG   = colors.HexColor("#EEF2FF")
BORDER_FIG  = colors.HexColor("#3B5BDB")
BORDER_CODE = colors.HexColor("#CCCCCC")
TABLE_HDR   = colors.HexColor("#1C3F6E")
TABLE_ALT   = colors.HexColor("#F7F9FC")

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
base_styles = getSampleStyleSheet()

def make_style(name, parent="Normal", **kwargs):
    return ParagraphStyle(name, parent=base_styles[parent], **kwargs)

S = {}
S["title"]     = make_style("PTitle", "Title",
                    fontSize=16, leading=20, textColor=IEEE_BLUE,
                    spaceAfter=4, alignment=TA_CENTER, fontName="Helvetica-Bold")
S["subtitle"]  = make_style("PSubtitle", "Normal",
                    fontSize=9, leading=12, textColor=colors.gray,
                    spaceAfter=8, alignment=TA_CENTER, fontName="Helvetica-Oblique")
S["abstract_head"] = make_style("PAbsHead", "Normal",
                    fontSize=9, leading=11, textColor=IEEE_BLUE,
                    spaceBefore=6, spaceAfter=2, fontName="Helvetica-Bold",
                    alignment=TA_CENTER)
S["abstract"]  = make_style("PAbstract", "Normal",
                    fontSize=9, leading=12, leftIndent=36, rightIndent=36,
                    spaceAfter=6, alignment=TA_JUSTIFY, fontName="Helvetica")
S["keywords"]  = make_style("PKeywords", "Normal",
                    fontSize=8.5, leading=11, leftIndent=36, rightIndent=36,
                    spaceAfter=10, fontName="Helvetica-Oblique")
S["h1"]        = make_style("PH1", "Heading1",
                    fontSize=10, leading=13, textColor=IEEE_BLUE,
                    spaceBefore=12, spaceAfter=4, fontName="Helvetica-Bold",
                    alignment=TA_CENTER)
S["h2"]        = make_style("PH2", "Heading2",
                    fontSize=9.5, leading=12, textColor=colors.HexColor("#1A3A6B"),
                    spaceBefore=8, spaceAfter=3, fontName="Helvetica-Bold")
S["h3"]        = make_style("PH3", "Heading3",
                    fontSize=9, leading=11,
                    spaceBefore=6, spaceAfter=2, fontName="Helvetica-BoldOblique")
S["body"]      = make_style("PBody", "Normal",
                    fontSize=9, leading=12, spaceAfter=5,
                    alignment=TA_JUSTIFY, fontName="Helvetica")
S["bullet"]    = make_style("PBullet", "Normal",
                    fontSize=9, leading=12, leftIndent=18, firstLineIndent=-12,
                    spaceAfter=2, fontName="Helvetica")
S["code"]      = make_style("PCode", "Code",
                    fontSize=7.5, leading=10, fontName="Courier",
                    leftIndent=8, rightIndent=8, spaceAfter=0, spaceBefore=0,
                    backColor=SHADE_CODE)
S["fig_title"] = make_style("PFigTitle", "Normal",
                    fontSize=8.5, leading=11, fontName="Helvetica-Bold",
                    textColor=BORDER_FIG, spaceAfter=2)
S["fig_body"]  = make_style("PFigBody", "Normal",
                    fontSize=8, leading=10.5, fontName="Helvetica",
                    textColor=colors.HexColor("#333333"))
S["caption"]   = make_style("PCaption", "Normal",
                    fontSize=8, leading=10, fontName="Helvetica-Oblique",
                    textColor=colors.HexColor("#444444"), spaceBefore=3)
S["ref"]       = make_style("PRef", "Normal",
                    fontSize=8.5, leading=11, leftIndent=18, firstLineIndent=-18,
                    spaceAfter=3, fontName="Helvetica")
S["hr_label"]  = make_style("PHrLabel", "Normal",
                    fontSize=7.5, leading=10, textColor=colors.lightgrey,
                    alignment=TA_CENTER, fontName="Helvetica")

# ---------------------------------------------------------------------------
# Custom flowables
# ---------------------------------------------------------------------------

class FigureBox(Flowable):
    """Shaded box for figure descriptions."""
    def __init__(self, title, lines, width):
        super().__init__()
        self.title = title
        self.lines = lines
        self.box_width = width
        self._build()

    def _build(self):
        pad = 8
        iw = self.box_width - 2 * pad
        # Title paragraph
        self._title_p = Paragraph(self._md(self.title), S["fig_title"])
        self._title_p.wrap(iw, 9999)
        # Body paragraphs
        self._body_ps = []
        for line in self.lines:
            if line.strip():
                p = Paragraph(self._md(line), S["fig_body"])
                p.wrap(iw, 9999)
                self._body_ps.append(p)
        self._pad = pad

    def _md(self, text):
        """Convert basic markdown bold/italic/code to reportlab XML."""
        text = re.sub(r'`([^`]+)`', r'<font name="Courier" size="7.5">\1</font>', text)
        text = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', text)
        text = re.sub(r'\*([^*]+)\*', r'<i>\1</i>', text)
        # Escape bare & < > that aren't already XML tags
        # (simplified — avoid double-escaping)
        return text

    def wrap(self, availWidth, availHeight):
        self.box_width = min(self.box_width, availWidth)
        self._build()
        pad = self._pad
        iw = self.box_width - 2 * pad
        h = pad
        tw, th = self._title_p.wrap(iw, 9999)
        h += th + 4
        for p in self._body_ps:
            pw, ph = p.wrap(iw, 9999)
            h += ph + 2
        h += pad
        self.height = h
        return self.box_width, h

    def draw(self):
        pad = self._pad
        w, h = self.box_width, self.height
        c = self.canv
        # Background fill
        c.setFillColor(SHADE_FIG)
        c.setStrokeColor(BORDER_FIG)
        c.setLineWidth(0.8)
        c.roundRect(0, 0, w, h, 4, fill=1, stroke=1)
        # Left accent bar
        c.setFillColor(BORDER_FIG)
        c.rect(0, 0, 3, h, fill=1, stroke=0)
        # Draw title
        iw = w - 2 * pad
        tw, th = self._title_p.wrap(iw, 9999)
        y = h - pad - th
        self._title_p.drawOn(c, pad + 3, y)
        y -= 4
        # Thin separator line
        c.setStrokeColor(BORDER_FIG)
        c.setLineWidth(0.4)
        c.line(pad + 3, y, w - pad, y)
        y -= 2
        # Draw body lines
        for p in self._body_ps:
            pw, ph = p.wrap(iw, 9999)
            y -= ph
            p.drawOn(c, pad + 3, y)
            y -= 2


def embed_svg(svg_path, max_width, max_height=3.5*inch):
    """Return a ReportLab drawing from an SVG file, scaled to fit."""
    if not HAS_SVGLIB or not os.path.exists(svg_path):
        return None
    try:
        drawing = svg2rlg(svg_path)
        if drawing is None:
            return None
        scale = min(max_width / drawing.width, max_height / drawing.height)
        drawing.width  = drawing.width  * scale
        drawing.height = drawing.height * scale
        drawing.transform = (scale, 0, 0, scale, 0, 0)
        return drawing
    except Exception as e:
        print(f"  SVG embed failed for {svg_path}: {e}")
        return None


class CodeBox(Flowable):
    """Code block with monospace font and light background."""
    def __init__(self, code_lines, width):
        super().__init__()
        self.code_lines = code_lines
        self.box_width = width

    def wrap(self, availWidth, availHeight):
        self.box_width = min(self.box_width, availWidth)
        pad = 6
        line_h = 9.5  # approx for 7.5pt Courier with leading 10
        # Estimate height
        self.height = pad * 2 + len(self.code_lines) * line_h
        return self.box_width, self.height

    def draw(self):
        pad = 6
        w, h = self.box_width, self.height
        c = self.canv
        c.setFillColor(SHADE_CODE)
        c.setStrokeColor(BORDER_CODE)
        c.setLineWidth(0.5)
        c.roundRect(0, 0, w, h, 3, fill=1, stroke=1)
        # Draw code lines
        c.setFont("Courier", 7.5)
        c.setFillColor(colors.black)
        line_h = 9.5
        y = h - pad - 7.5  # baseline of first line
        for line in self.code_lines:
            if y > 0:
                c.drawString(pad + 3, y, line)
            y -= line_h


# ---------------------------------------------------------------------------
# Header / Footer canvas
# ---------------------------------------------------------------------------

def on_page(canvas, doc):
    canvas.saveState()
    w, h = letter
    # Header line
    canvas.setStrokeColor(IEEE_BLUE)
    canvas.setLineWidth(0.5)
    canvas.line(L_MARGIN, h - T_MARGIN + 10, w - R_MARGIN, h - T_MARGIN + 10)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#555555"))
    canvas.drawString(L_MARGIN, h - T_MARGIN + 13, TITLE_SHORT)
    canvas.drawRightString(w - R_MARGIN, h - T_MARGIN + 13, "DASC 2026 — Double-Blind Draft")
    # Footer
    canvas.setLineWidth(0.3)
    canvas.line(L_MARGIN, B_MARGIN - 4, w - R_MARGIN, B_MARGIN - 4)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#888888"))
    canvas.drawCentredString(w / 2, B_MARGIN - 14, str(doc.page))
    canvas.restoreState()


# ---------------------------------------------------------------------------
# Markdown inline formatting
# ---------------------------------------------------------------------------

def md_inline(text):
    """Convert inline markdown to ReportLab XML markup."""
    # Escape XML special chars (but not our own tags)
    # Do this carefully — replace & first
    text = text.replace('&', '&amp;')
    # Only escape < and > that are NOT part of our injected tags
    # Process bold/italic/code first on raw text, then escape rest
    # Actually easier to not escape and trust input is clean
    text = text.replace('&amp;', '&')  # undo

    # Bold+italic: ***text***
    text = re.sub(r'\*\*\*([^*]+)\*\*\*', r'<b><i>\1</i></b>', text)
    # Bold: **text**
    text = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', text)
    # Italic: *text*
    text = re.sub(r'\*([^*]+)\*', r'<i>\1</i>', text)
    # Italic with underscore (but not in middle of words)
    text = re.sub(r'(?<!\w)_([^_]+)_(?!\w)', r'<i>\1</i>', text)
    # Inline code: `code`
    text = re.sub(r'`([^`]+)`',
                  r'<font name="Courier" size="7.5">\1</font>', text)
    # Escape lone & that are not entity refs
    text = re.sub(r'&(?!amp;|lt;|gt;|quot;|apos;|#)', '&amp;', text)
    return text


# ---------------------------------------------------------------------------
# Table parsing
# ---------------------------------------------------------------------------

def parse_md_table(lines):
    """Parse markdown table lines into list-of-lists."""
    rows = []
    for line in lines:
        line = line.strip()
        if not line or re.match(r'^[\|\s\-:]+$', line):
            continue
        cells = [c.strip() for c in line.strip('|').split('|')]
        rows.append(cells)
    return rows


def make_rl_table(rows):
    """Build a ReportLab Table from parsed rows."""
    if not rows:
        return None

    # Format cells
    styled_rows = []
    for ri, row in enumerate(rows):
        styled_row = []
        for cell in row:
            style = S["body"] if ri > 0 else make_style(
                f"TH{ri}", "Normal",
                fontSize=8.5, fontName="Helvetica-Bold",
                textColor=colors.white, alignment=TA_CENTER)
            p = Paragraph(md_inline(cell), style)
            styled_row.append(p)
        styled_rows.append(styled_row)

    # Auto column widths (equal split)
    ncols = max(len(r) for r in rows)
    col_w = BODY_W / ncols

    tbl = Table(styled_rows, colWidths=[col_w] * ncols,
                repeatRows=1, hAlign='LEFT')

    style_cmds = [
        ('BACKGROUND', (0, 0), (-1, 0), TABLE_HDR),
        ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
        ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',   (0, 0), (-1, 0), 8),
        ('ALIGN',      (0, 0), (-1, 0), 'CENTER'),
        ('FONTNAME',   (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE',   (0, 1), (-1, -1), 8),
        ('ALIGN',      (0, 1), (-1, -1), 'LEFT'),
        ('VALIGN',     (0, 0), (-1, -1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, TABLE_ALT]),
        ('GRID',       (0, 0), (-1, -1), 0.4, colors.HexColor("#BBBBBB")),
        ('LINEBELOW',  (0, 0), (-1, 0), 1.0, IEEE_BLUE),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING',   (0, 0), (-1, -1), 5),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 5),
    ]
    tbl.setStyle(TableStyle(style_cmds))
    return tbl


# ---------------------------------------------------------------------------
# Main parser: markdown → flowables
# ---------------------------------------------------------------------------

def parse_markdown(md_text, md_path=""):
    flowables = []
    lines = md_text.split('\n')
    i = 0
    in_abstract = False

    def add_space(h=4):
        flowables.append(Spacer(1, h))

    while i < len(lines):
        line = lines[i]

        # Skip the meta subtitle line (first italic paragraph)
        if line.startswith('*Paper draft for'):
            flowables.append(Paragraph(md_inline(line.strip('*')), S["subtitle"]))
            i += 1
            continue

        # === Title ===
        if line.startswith('# ') and not line.startswith('## '):
            text = line[2:].strip()
            flowables.append(Paragraph(text, S["title"]))
            i += 1
            continue

        # === HR ===
        if line.strip() == '---':
            if in_abstract:
                in_abstract = False
                add_space(8)
            else:
                flowables.append(HRFlowable(width="100%", thickness=0.4,
                                             color=colors.HexColor("#CCCCCC"),
                                             spaceAfter=4, spaceBefore=4))
            i += 1
            continue

        # === H2 headings ===
        if line.startswith('## '):
            text = line[3:].strip()
            if text.lower() == 'abstract':
                flowables.append(Paragraph("Abstract", S["abstract_head"]))
                in_abstract = True
            else:
                flowables.append(Paragraph(text, S["h1"]))
            i += 1
            continue

        # === H3 headings ===
        if line.startswith('### '):
            text = line[4:].strip()
            flowables.append(Paragraph(text, S["h2"]))
            i += 1
            continue

        # === H4 headings ===
        if line.startswith('#### '):
            text = line[5:].strip()
            flowables.append(Paragraph(f"<b>{text}</b>", S["body"]))
            i += 1
            continue

        # === Figure blockquote ===
        if line.startswith('> '):
            bq_lines = []
            while i < len(lines) and lines[i].startswith('> '):
                bq_lines.append(lines[i][2:])
                i += 1
            # Extract title (first line) and body
            fig_title = bq_lines[0] if bq_lines else ""
            fig_body = bq_lines[1:] if len(bq_lines) > 1 else []

            # Try to embed actual SVG for known figures
            fig_num_m = re.search(r'Fig\.\s*(\d+)', fig_title)
            svg_drawing = None
            if fig_num_m:
                fnum = fig_num_m.group(1)
                svg_map = {
                    "1": os.path.join(os.path.dirname(md_path), "fig1_workflow_overview.svg"),
                    "3": os.path.join(os.path.dirname(md_path), "fig3_tc9_topology.svg"),
                    "4": os.path.join(os.path.dirname(md_path), "fig4_darpa_uav_topology.svg"),
                }
                if fnum in svg_map:
                    svg_drawing = embed_svg(svg_map[fnum], BODY_W - 20, 3.2 * inch)

            flowables.append(Spacer(1, 4))
            if svg_drawing is not None:
                # Render figure title as caption above the SVG
                flowables.append(Paragraph(f"<b>{md_inline(fig_title)}</b>", S["fig_title"]))
                flowables.append(Spacer(1, 3))
                flowables.append(svg_drawing)
                # Caption line (last bq line starting with *Caption*)
                for bl in fig_body:
                    if bl.strip().startswith('*Caption*'):
                        cap = bl.replace('*Caption*:', '').strip().strip('*')
                        flowables.append(Spacer(1, 3))
                        flowables.append(Paragraph(md_inline(cap), S["caption"]))
                        break
            else:
                box = FigureBox(fig_title, fig_body, BODY_W)
                flowables.append(box)
            flowables.append(Spacer(1, 6))
            continue

        # === Code block ===
        if line.strip().startswith('```'):
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith('```'):
                code_lines.append(lines[i])
                i += 1
            i += 1  # skip closing ```
            # Remove trailing blank lines
            while code_lines and not code_lines[-1].strip():
                code_lines.pop()
            box = CodeBox(code_lines, BODY_W)
            flowables.append(Spacer(1, 3))
            flowables.append(box)
            flowables.append(Spacer(1, 5))
            continue

        # === Table ===
        if '|' in line and line.strip().startswith('|'):
            tbl_lines = []
            # Grab optional caption before table (lines like **Table X: ...**)
            caption = None
            while i < len(lines) and '|' in lines[i] and lines[i].strip().startswith('|'):
                tbl_lines.append(lines[i])
                i += 1
            rows = parse_md_table(tbl_lines)
            rl_tbl = make_rl_table(rows)
            if rl_tbl:
                flowables.append(Spacer(1, 4))
                flowables.append(rl_tbl)
                flowables.append(Spacer(1, 6))
            continue

        # === Numbered list ===
        if re.match(r'^\d+\.\s', line):
            items = []
            while i < len(lines) and re.match(r'^\d+\.\s', lines[i]):
                m = re.match(r'^(\d+)\.\s+(.*)', lines[i])
                if m:
                    items.append((m.group(1), m.group(2)))
                i += 1
            for num, text in items:
                p = Paragraph(f"<b>{num}.</b>  {md_inline(text)}", S["bullet"])
                flowables.append(p)
            add_space(3)
            continue

        # === Bullet list ===
        if line.startswith('- ') or line.startswith('* '):
            while i < len(lines) and (lines[i].startswith('- ') or lines[i].startswith('* ')):
                text = lines[i][2:].strip()
                p = Paragraph(f"&#x2022;  {md_inline(text)}", S["bullet"])
                flowables.append(p)
                i += 1
            add_space(3)
            continue

        # === Bold label paragraph (e.g. **Phase 1 Results.**) ===
        # These are inline — just render as body
        if line.strip() == '':
            if in_abstract:
                pass  # don't add big spaces in abstract
            else:
                add_space(3)
            i += 1
            continue

        # === Normal paragraph ===
        if line.strip():
            # Collect continuation lines
            para_lines = [line.strip()]
            i += 1
            while (i < len(lines) and lines[i].strip()
                   and not lines[i].startswith('#')
                   and not lines[i].startswith('>')
                   and not lines[i].startswith('```')
                   and not lines[i].startswith('|')
                   and not lines[i].startswith('- ')
                   and not lines[i].startswith('* ')
                   and not re.match(r'^\d+\.\s', lines[i])
                   and lines[i].strip() != '---'):
                para_lines.append(lines[i].strip())
                i += 1
            text = ' '.join(para_lines)
            style = S["abstract"] if in_abstract else S["body"]
            # Check for Keywords line
            if text.startswith('**Keywords**'):
                flowables.append(Paragraph(md_inline(text), S["keywords"]))
            # Check if it looks like a reference [N] ...
            elif re.match(r'^\[\d+\]', text):
                flowables.append(Paragraph(md_inline(text), S["ref"]))
            else:
                flowables.append(Paragraph(md_inline(text), style))
            continue

        i += 1

    return flowables


# ---------------------------------------------------------------------------
# Build PDF
# ---------------------------------------------------------------------------

def build_pdf(md_path, out_path):
    with open(md_path, encoding='utf-8') as f:
        md_text = f.read()

    doc = SimpleDocTemplate(
        out_path,
        pagesize=letter,
        leftMargin=L_MARGIN,
        rightMargin=R_MARGIN,
        topMargin=T_MARGIN,
        bottomMargin=B_MARGIN,
        title=TITLE_SHORT,
        author="[Author — Double-Blind]",
        subject="DASC 2026 Paper Draft",
    )

    flowables = parse_markdown(md_text, md_path)

    print(f"Building PDF: {len(flowables)} flowables...")
    doc.build(flowables, onFirstPage=on_page, onLaterPages=on_page)
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    import os
    base = os.path.dirname(os.path.abspath(__file__))
    md_path  = os.path.join(base, "DASC_2026_Paper_Draft_v2.md")
    out_path = os.path.join(base, "DASC_2026_Paper_Draft_v2_Review.pdf")
    build_pdf(md_path, out_path)
