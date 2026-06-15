"""PDF export for scan results.

Renders a VaultCheck ScanResult into a structured, self-contained PDF using
reportlab (no headless browser needed). Mirrors the HTML report's sections:
summary, secrets, dependencies, insecure code, git history and licenses.
"""
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_SEV_COLOR = {
    "CRITICAL": colors.HexColor("#b91c1c"),
    "HIGH": colors.HexColor("#ea580c"),
    "MEDIUM": colors.HexColor("#ca8a04"),
    "LOW": colors.HexColor("#2563eb"),
}


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("VCcell", parent=ss["Normal"], fontSize=8, leading=10))
    ss.add(ParagraphStyle("VChead", parent=ss["Normal"], fontSize=8, leading=10,
                          textColor=colors.white, fontName="Helvetica-Bold"))
    ss.add(ParagraphStyle("VCsection", parent=ss["Heading2"], fontSize=13,
                          spaceBefore=14, spaceAfter=4, textColor=colors.HexColor("#111827")))
    ss.add(ParagraphStyle("VCsub", parent=ss["Normal"], fontSize=8.5,
                          textColor=colors.HexColor("#6b7280"), spaceAfter=6))
    return ss


def _sev_para(sev: str, ss) -> Paragraph:
    color = _SEV_COLOR.get(sev, colors.grey)
    return Paragraph(f'<font color="#{color.hexval()[2:]}"><b>{sev}</b></font>', ss["VCcell"])


def _table(rows: list[list], col_widths: list, ss) -> Table:
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _section(story, title: str, subtitle: str, headers: list[str],
             findings: list, row_fn, col_widths: list, ss):
    story.append(Paragraph(title, ss["VCsection"]))
    story.append(Paragraph(subtitle, ss["VCsub"]))
    if not findings:
        story.append(Paragraph("No findings in this category.", ss["VCcell"]))
        story.append(Spacer(1, 4))
        return
    head = [Paragraph(h, ss["VChead"]) for h in headers]
    rows = [head] + [row_fn(f) for f in findings]
    story.append(_table(rows, col_widths, ss))
    story.append(Spacer(1, 4))


def generate_pdf_report(result, output_path: Path,
                        project_name: Optional[str] = None) -> Path:
    ss = _styles()
    doc = SimpleDocTemplate(
        str(output_path), pagesize=A4,
        leftMargin=16 * mm, rightMargin=16 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"VaultCheck report — {result.target}",
    )
    story: list = []

    # Header
    story.append(Paragraph("VaultCheck security report", ss["Title"]))
    story.append(Paragraph(f"Target: <b>{result.target}</b>", ss["Normal"]))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e5e7eb")))
    story.append(Spacer(1, 8))

    # Summary counts
    counts = result.severity_counts
    total = sum(counts.values())
    summary_rows = [[Paragraph(s, ss["VChead"]) for s in ["Severity", "Count"]]]
    for sev in _SEVERITY_ORDER:
        summary_rows.append([_sev_para(sev, ss), Paragraph(str(counts.get(sev, 0)), ss["VCcell"])])
    summary_rows.append([Paragraph("<b>TOTAL</b>", ss["VCcell"]),
                         Paragraph(f"<b>{total}</b>", ss["VCcell"])])
    story.append(_table(summary_rows, [60 * mm, 30 * mm], ss))
    story.append(Spacer(1, 4))

    ran = set(result.phases) if result.phases else set()

    def cell(text):
        return Paragraph(str(text), ss["VCcell"])

    if "secrets" in ran or result.secrets:
        _section(story, "Secrets", "Hardcoded credentials and keys detected in source files.",
                 ["Severity", "Type", "File", "Line", "Value"], result.secrets,
                 lambda f: [_sev_para(f.severity, ss), cell(f.secret_type), cell(f.file),
                            cell(f.line_number), cell(f.matched_value)],
                 [22 * mm, 40 * mm, 50 * mm, 14 * mm, 40 * mm], ss)

    if "deps" in ran or result.deps:
        _section(story, "Vulnerable dependencies", "Declared packages with known advisories (source: OSV).",
                 ["Severity", "Package", "Advisory", "Remediation"], result.deps,
                 lambda f: [_sev_para(f.severity, ss), cell(f"{f.package}@{f.version}"),
                            cell(f.vuln_id), cell(f.remediation)],
                 [22 * mm, 42 * mm, 36 * mm, 66 * mm], ss)

    if "code" in ran or result.code:
        _section(story, "Insecure code", "Risky patterns from static analysis, including Dockerfile, IaC and CI checks.",
                 ["Severity", "Issue", "File", "Line", "Detail"], result.code,
                 lambda f: [_sev_para(f.severity, ss), cell(f.issue_type), cell(f.file),
                            cell(f.line_number), cell(f.description)],
                 [22 * mm, 40 * mm, 38 * mm, 12 * mm, 54 * mm], ss)

    if "git_history" in ran or result.git_history:
        _section(story, "Git history", "Secrets found in past commits, even if removed from current code.",
                 ["Severity", "Type", "File / Commit", "Value"], result.git_history,
                 lambda f: [_sev_para(f.severity, ss), cell(f.secret_type), cell(f.file),
                            cell(f.matched_value)],
                 [22 * mm, 44 * mm, 60 * mm, 40 * mm], ss)

    if "licenses" in ran or result.licenses:
        _section(story, "Dependency licenses", "Copyleft or unknown licenses among dependencies.",
                 ["Severity", "Package", "License", "Note"], result.licenses,
                 lambda f: [_sev_para(f.severity, ss), cell(f"{f.package}@{f.version}"),
                            cell(f.license), cell(f.reason)],
                 [22 * mm, 42 * mm, 30 * mm, 72 * mm], ss)

    if result.errors:
        story.append(Paragraph("Errors", ss["VCsection"]))
        for e in result.errors:
            story.append(Paragraph(f"• {e}", ss["VCcell"]))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e5e7eb")))
    story.append(Paragraph(
        "Generated by VaultCheck. Findings are indicative — review before acting.",
        ss["VCsub"]))

    doc.build(story)
    return output_path
