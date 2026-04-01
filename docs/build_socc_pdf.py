"""
Build SOCC 2026 Paper Draft v5 as a formatted PDF using ReportLab.
"""
import re
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.colors import HexColor, black, grey
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, Preformatted
)
from reportlab.lib import colors

# ── Paths ──
MD_PATH = r"D:\DSE\DSE_ADD\docs\SOCC_2026_Paper_Draft_v5.md"
PDF_PATH = r"D:\DSE\DSE_ADD\docs\SOCC_2026_Paper_Draft_v5.pdf"

# ── Styles ──
styles = getSampleStyleSheet()

styles.add(ParagraphStyle(
    'PaperTitle', parent=styles['Title'],
    fontSize=16, leading=20, spaceAfter=6, alignment=TA_CENTER,
    textColor=HexColor('#1a1a2e')
))
styles.add(ParagraphStyle(
    'Subtitle', parent=styles['Normal'],
    fontSize=10, leading=13, alignment=TA_CENTER,
    textColor=grey, spaceAfter=12, fontName='Helvetica-Oblique'
))
styles.add(ParagraphStyle(
    'Keywords', parent=styles['Normal'],
    fontSize=9, leading=12, alignment=TA_LEFT,
    spaceAfter=14, fontName='Helvetica-Bold'
))
styles.add(ParagraphStyle(
    'SectionHead', parent=styles['Heading1'],
    fontSize=13, leading=16, spaceBefore=16, spaceAfter=6,
    textColor=HexColor('#1a1a2e'), fontName='Helvetica-Bold'
))
styles.add(ParagraphStyle(
    'SubsectionHead', parent=styles['Heading2'],
    fontSize=11, leading=14, spaceBefore=10, spaceAfter=4,
    textColor=HexColor('#2d3436'), fontName='Helvetica-Bold'
))
styles.add(ParagraphStyle(
    'BodyText2', parent=styles['Normal'],
    fontSize=10, leading=13, alignment=TA_JUSTIFY,
    spaceAfter=6, fontName='Helvetica'
))
styles.add(ParagraphStyle(
    'AbstractText', parent=styles['Normal'],
    fontSize=10, leading=13, alignment=TA_JUSTIFY,
    spaceAfter=6, fontName='Helvetica-Oblique',
    leftIndent=18, rightIndent=18
))
styles.add(ParagraphStyle(
    'BulletItem', parent=styles['Normal'],
    fontSize=10, leading=13, leftIndent=24, bulletIndent=12,
    spaceAfter=3, fontName='Helvetica'
))
styles.add(ParagraphStyle(
    'NumberedItem', parent=styles['Normal'],
    fontSize=10, leading=13, leftIndent=24, bulletIndent=12,
    spaceAfter=3, fontName='Helvetica'
))
styles.add(ParagraphStyle(
    'CodeBlock', parent=styles['Code'],
    fontSize=8, leading=10, leftIndent=12, rightIndent=12,
    spaceBefore=4, spaceAfter=6, fontName='Courier',
    backColor=HexColor('#f5f5f5'), borderWidth=0.5,
    borderColor=HexColor('#cccccc'), borderPadding=4
))
styles.add(ParagraphStyle(
    'TableCaption', parent=styles['Normal'],
    fontSize=9, leading=12, alignment=TA_LEFT,
    spaceBefore=8, spaceAfter=4, fontName='Helvetica-Bold',
    textColor=HexColor('#2d3436')
))
styles.add(ParagraphStyle(
    'RefText', parent=styles['Normal'],
    fontSize=8.5, leading=11, spaceAfter=3,
    fontName='Helvetica', leftIndent=18, firstLineIndent=-18
))


def escape_xml(text):
    """Escape XML special chars for ReportLab Paragraph."""
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    return text


def md_inline_to_para(text):
    """Convert markdown inline formatting to ReportLab XML."""
    # Bold+italic
    text = re.sub(r'\*\*\*(.+?)\*\*\*', r'<b><i>\1</i></b>', text)
    # Bold
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    # Italic
    text = re.sub(r'\*(.+?)\*', r'<i>\1</i>', text)
    # Inline code
    text = re.sub(r'`([^`]+)`', r'<font face="Courier" size="9">\1</font>', text)
    # References [N]
    text = re.sub(r'\[(\d+)\]', r'[\1]', text)
    return text


def parse_md_table(lines):
    """Parse markdown table lines into list of lists."""
    rows = []
    for line in lines:
        line = line.strip()
        if line.startswith('|') and not re.match(r'^\|[\s\-:|]+\|$', line):
            cells = [c.strip() for c in line.split('|')[1:-1]]
            rows.append(cells)
    return rows


def build_table(rows, caption=None):
    """Build a ReportLab Table from parsed rows."""
    elements = []
    if caption:
        elements.append(Paragraph(caption, styles['TableCaption']))

    # Convert cells to Paragraphs
    cell_style = ParagraphStyle('Cell', parent=styles['Normal'],
                                 fontSize=8, leading=10, fontName='Helvetica')
    header_style = ParagraphStyle('HeaderCell', parent=cell_style,
                                   fontName='Helvetica-Bold')

    table_data = []
    for i, row in enumerate(rows):
        styled_row = []
        for cell in row:
            cell_text = md_inline_to_para(cell)
            st = header_style if i == 0 else cell_style
            styled_row.append(Paragraph(cell_text, st))
        table_data.append(styled_row)

    if not table_data:
        return elements

    ncols = max(len(r) for r in table_data)
    col_width = (6.5 * inch) / ncols
    col_widths = [col_width] * ncols

    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2d3436')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, HexColor('#f8f8f8')]),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 6))
    return elements


def build_pdf():
    with open(MD_PATH, 'r', encoding='utf-8') as f:
        raw = f.read()

    lines = raw.split('\n')
    story = []

    i = 0
    in_code_block = False
    code_lines = []
    table_lines = []
    table_caption = None
    in_abstract = False
    numbered_counter = 0

    while i < len(lines):
        line = lines[i]

        # ── Code blocks ──
        if line.strip().startswith('```'):
            if in_code_block:
                code_text = escape_xml('\n'.join(code_lines))
                story.append(Preformatted(code_text, styles['CodeBlock']))
                code_lines = []
                in_code_block = False
            else:
                # Flush any pending table
                if table_lines:
                    story.extend(build_table(parse_md_table(table_lines), table_caption))
                    table_lines = []
                    table_caption = None
                in_code_block = True
            i += 1
            continue

        if in_code_block:
            code_lines.append(line)
            i += 1
            continue

        # ── Table lines ──
        if line.strip().startswith('|'):
            table_lines.append(line)
            i += 1
            continue
        elif table_lines:
            story.extend(build_table(parse_md_table(table_lines), table_caption))
            table_lines = []
            table_caption = None

        stripped = line.strip()

        # ── Empty line ──
        if not stripped:
            if in_abstract:
                in_abstract = False
            i += 1
            continue

        # ── Title (# ) ──
        if stripped.startswith('# ') and not stripped.startswith('## '):
            title_text = stripped[2:].strip()
            story.append(Paragraph(escape_xml(title_text), styles['PaperTitle']))
            i += 1
            continue

        # ── Subtitle / draft note ──
        if stripped.startswith('*Draft') or stripped.startswith('*draft'):
            story.append(Paragraph(md_inline_to_para(stripped), styles['Subtitle']))
            i += 1
            continue

        # ── Section heading (## ) ──
        if stripped.startswith('## ') and not stripped.startswith('### '):
            heading = stripped[3:].strip()
            if heading.lower() == 'abstract':
                story.append(Paragraph('Abstract', styles['SectionHead']))
                in_abstract = True
                i += 1
                continue
            story.append(Paragraph(escape_xml(heading), styles['SectionHead']))
            i += 1
            continue

        # ── Subsection heading (### ) ──
        if stripped.startswith('### '):
            heading = stripped[4:].strip()
            story.append(Paragraph(escape_xml(heading), styles['SubsectionHead']))
            i += 1
            continue

        # ── Keywords ──
        if stripped.startswith('**Keywords:**') or stripped.startswith('**Keywords:'):
            kw_text = md_inline_to_para(stripped)
            story.append(Paragraph(kw_text, styles['Keywords']))
            i += 1
            continue

        # ── Table caption ──
        if stripped.startswith('**Table '):
            table_caption = md_inline_to_para(stripped)
            i += 1
            continue

        # ── Numbered list ──
        m = re.match(r'^(\d+)\.\s+(.+)$', stripped)
        if m:
            num = m.group(1)
            content = md_inline_to_para(m.group(2))
            story.append(Paragraph(
                f'{num}. {content}', styles['NumberedItem']
            ))
            i += 1
            continue

        # ── Bullet list ──
        if stripped.startswith('- '):
            content = md_inline_to_para(stripped[2:])
            story.append(Paragraph(
                f'\u2022 {content}', styles['BulletItem']
            ))
            i += 1
            continue

        # ── References ──
        ref_match = re.match(r'^\[(\d+)\]\s+(.+)$', stripped)
        if ref_match:
            ref_num = ref_match.group(1)
            ref_text = md_inline_to_para(ref_match.group(2))
            story.append(Paragraph(f'[{ref_num}] {ref_text}', styles['RefText']))
            i += 1
            continue

        # ── Normal paragraph ──
        # Accumulate consecutive non-empty lines into one paragraph
        para_lines = [stripped]
        while i + 1 < len(lines):
            next_line = lines[i + 1].strip()
            if (not next_line or next_line.startswith('#') or
                next_line.startswith('|') or next_line.startswith('```') or
                next_line.startswith('- ') or next_line.startswith('**Table ') or
                next_line.startswith('**Keywords') or
                re.match(r'^\d+\.\s+', next_line) or
                re.match(r'^\[\d+\]', next_line)):
                break
            para_lines.append(next_line)
            i += 1

        full_text = ' '.join(para_lines)
        full_text = md_inline_to_para(full_text)

        if in_abstract:
            story.append(Paragraph(full_text, styles['AbstractText']))
        else:
            story.append(Paragraph(full_text, styles['BodyText2']))

        i += 1

    # Flush remaining table
    if table_lines:
        story.extend(build_table(parse_md_table(table_lines), table_caption))

    # ── Build doc ──
    doc = SimpleDocTemplate(
        PDF_PATH,
        pagesize=letter,
        leftMargin=1 * inch,
        rightMargin=1 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch
    )

    def add_page_number(canvas_obj, doc_obj):
        canvas_obj.saveState()
        canvas_obj.setFont('Helvetica', 8)
        canvas_obj.setFillColor(grey)
        page_num = canvas_obj.getPageNumber()
        text = f"SOCC 2026 Draft v5 — Page {page_num}"
        canvas_obj.drawCentredString(letter[0] / 2, 0.4 * inch, text)
        canvas_obj.restoreState()

    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    print(f"PDF generated: {PDF_PATH}")
    print(f"Pages: {doc.page}")


if __name__ == '__main__':
    build_pdf()
