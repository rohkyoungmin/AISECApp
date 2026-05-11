from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .models import ProjectAnalysisReport, SourceAnalysisReport, SourceFinding


@dataclass(slots=True)
class ExportedReportPaths:
    run_dir: Path
    json_path: Path
    markdown_path: Path
    pdf_path: Path
    llm_log_dir: Path


def export_project_report(report: ProjectAnalysisReport, output_dir: str | Path = "output") -> ExportedReportPaths:
    run_dir = Path(output_dir) / _safe_run_id(report.project_id)
    llm_log_dir = run_dir / "llm_logs"
    llm_log_dir.mkdir(parents=True, exist_ok=True)

    json_path = run_dir / "report.json"
    markdown_path = run_dir / "report.md"
    pdf_path = run_dir / "report.pdf"

    json_path.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    markdown = render_project_markdown(report)
    markdown_path.write_text(markdown, encoding="utf-8")
    write_report_pdf(pdf_path, report)
    write_agent_logs(report, llm_log_dir)

    return ExportedReportPaths(
        run_dir=run_dir,
        json_path=json_path,
        markdown_path=markdown_path,
        pdf_path=pdf_path,
        llm_log_dir=llm_log_dir,
    )


def write_report_pdf(path: Path, report: ProjectAnalysisReport) -> None:
    try:
        _write_fpdf2_report(path, report)
    except Exception:
        _write_fallback_pdf(path, render_project_markdown(report))


_FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")
_FONTS_LOADED = False


def _load_fonts(pdf) -> tuple[str, str, str]:
    """Register DejaVu fonts (Sans/Serif/Mono). Returns (body, display, mono) family names."""
    global _FONTS_LOADED
    if not _FONTS_LOADED and _FONT_DIR.exists():
        try:
            pdf.add_font("DVSans",  "",  str(_FONT_DIR / "DejaVuSans.ttf"),       uni=True)
            pdf.add_font("DVSans",  "B", str(_FONT_DIR / "DejaVuSans-Bold.ttf"),  uni=True)
            pdf.add_font("DVSerif", "",  str(_FONT_DIR / "DejaVuSerif.ttf"),       uni=True)
            pdf.add_font("DVSerif", "B", str(_FONT_DIR / "DejaVuSerif-Bold.ttf"), uni=True)
            pdf.add_font("DVMono",  "",  str(_FONT_DIR / "DejaVuSansMono.ttf"),   uni=True)
            _FONTS_LOADED = True
            return "DVSans", "DVSerif", "DVMono"
        except Exception:
            pass
    return "Helvetica", "Helvetica", "Courier"


def _write_fpdf2_report(path: Path, report: ProjectAnalysisReport) -> None:
    from fpdf import FPDF  # type: ignore[import]

    # ── Design tokens (matches web UI) ───────────────────────────────────────
    CANVAS   = (250, 249, 245)   # --canvas
    CARD     = (239, 233, 222)   # --surface-card
    DARK     = (24,  23,  21)    # --surface-dark
    PRIMARY  = (1,   64,  41)    # --primary (dark green)
    INK      = (20,  20,  19)    # --ink
    MUTED    = (108, 106, 100)   # --muted
    HAIRLINE = (230, 223, 216)   # --hairline
    WHITE    = (255, 255, 255)
    SUCCESS  = (26,  122, 69)    # --success
    ERROR    = (198, 69,  69)    # --error
    WARNING  = (212, 160, 23)    # --warning
    AMBER    = (232, 165, 90)    # --amber
    TEAL     = (93,  184, 166)   # --teal

    SEV_COLORS = {"critical": ERROR, "high": AMBER, "medium": WARNING, "low": TEAL}

    accepted = sum(len(fr.findings) for fr in report.file_reports)
    rejected = sum(len(fr.rejected_findings) for fr in report.file_reports)

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    BODY, DISPLAY, MONO = _load_fonts(pdf)
    pdf.add_page()

    # ── Cover: dark green header bar ─────────────────────────────────────────
    pdf.set_fill_color(*PRIMARY)
    pdf.rect(0, 0, 210, 54, style="F")

    pdf.set_xy(14, 12)
    pdf.set_font(DISPLAY, "B", 28)
    pdf.set_text_color(*WHITE)
    pdf.cell(0, 14, "Reporter")

    pdf.set_xy(14, 30)
    pdf.set_font(BODY, "", 11)
    pdf.set_text_color(180, 220, 195)
    pdf.cell(0, 7, "Security Analysis Report")

    # Status badge
    status_val = report.verifier_status.value.upper()
    badge_bg = SUCCESS if report.verifier_status.value == "pass" else ERROR
    pdf.set_fill_color(*badge_bg)
    pdf.set_text_color(*WHITE)
    pdf.set_font(BODY, "B", 9)
    pdf.set_xy(150, 20)
    pdf.cell(46, 10, status_val, border=0, align="C", fill=True)

    # ── Canvas background for rest of page ───────────────────────────────────
    pdf.set_fill_color(*CANVAS)
    pdf.rect(0, 54, 210, 243, style="F")

    # ── Project info ──────────────────────────────────────────────────────────
    pdf.set_xy(14, 64)
    info_rows = [
        ("Archive",           report.archive_name),
        ("Project ID",        report.project_id),
        ("Files analyzed",    f"{report.analyzed_files} / {report.total_files}"),
        ("Accepted findings", str(accepted)),
        ("Rejected findings", str(rejected)),
    ]
    for label, value in info_rows:
        pdf.set_x(14)
        pdf.set_font(BODY, "B", 8)
        pdf.set_text_color(*MUTED)
        pdf.cell(44, 5.5, label.upper())
        pdf.set_font(BODY, "", 9)
        pdf.set_text_color(*INK)
        pdf.cell(0, 5.5, _truncate(value, 90), ln=True)

    # Hairline divider
    pdf.ln(3)
    y_div = pdf.get_y()
    pdf.set_draw_color(*HAIRLINE)
    pdf.set_line_width(0.3)
    pdf.line(14, y_div, 196, y_div)
    pdf.ln(5)

    # ── Summary ───────────────────────────────────────────────────────────────
    _section_header(pdf, "SUMMARY", PRIMARY, INK, BODY)
    pdf.set_font(BODY, "", 10)
    pdf.set_text_color(*INK)
    pdf.set_x(14)
    pdf.multi_cell(182, 5.5, report.summary)

    # ── Stats row ─────────────────────────────────────────────────────────────
    pdf.ln(5)
    stats = [
        ("FILES",    str(report.analyzed_files), PRIMARY),
        ("ACCEPTED", str(accepted),              SUCCESS),
        ("REJECTED", str(rejected),              ERROR if rejected else MUTED),
        ("SKIPPED",  str(len(report.skipped_files)), MUTED),
    ]
    box_w = 44
    y_stat = pdf.get_y()
    for i, (label, val, color) in enumerate(stats):
        x = 14 + i * (box_w + 2)
        pdf.set_fill_color(*CARD)
        pdf.rect(x, y_stat, box_w, 20, style="F")
        pdf.set_fill_color(*color)
        pdf.rect(x, y_stat, box_w, 3, style="F")
        pdf.set_xy(x, y_stat + 4)
        pdf.set_font(DISPLAY, "B", 16)
        pdf.set_text_color(*color)
        pdf.cell(box_w, 8, val, align="C")
        pdf.set_xy(x, y_stat + 13)
        pdf.set_font(BODY, "", 7)
        pdf.set_text_color(*MUTED)
        pdf.cell(box_w, 4, label, align="C")
    pdf.set_y(y_stat + 26)

    # ── Per-file findings ─────────────────────────────────────────────────────
    for file_report in report.file_reports:
        if not file_report.findings and not file_report.rejected_findings:
            continue
        _file_section(pdf, file_report, PRIMARY, CARD, CANVAS, INK, MUTED, HAIRLINE,
                      SEV_COLORS, SUCCESS, ERROR, BODY, DISPLAY, MONO)

    # ── Footer on every page ──────────────────────────────────────────────────
    page_count = pdf.page
    for page_num in range(1, page_count + 1):
        pdf.page = page_num
        pdf.set_y(-12)
        pdf.set_font(BODY, "", 7)
        pdf.set_text_color(*MUTED)
        pdf.cell(0, 5, f"Reporter Security Report  ·  {report.project_id}  ·  Page {page_num}/{page_count}", align="C")

    pdf.output(str(path))


def _section_header(pdf, title: str, primary, ink, body="Helvetica") -> None:
    """Green left-border section label."""
    y = pdf.get_y()
    pdf.set_fill_color(*primary)
    pdf.rect(14, y, 3, 7, style="F")
    pdf.set_xy(20, y)
    pdf.set_font(body, "B", 8)
    pdf.set_text_color(*primary)
    pdf.cell(0, 7, title.upper(), ln=True)
    pdf.ln(2)


def _hairline(pdf, muted) -> None:
    y = pdf.get_y()
    pdf.set_draw_color(*muted)
    pdf.set_line_width(0.2)
    pdf.line(14, y, 196, y)
    pdf.ln(4)


def _file_section(pdf, report: SourceAnalysisReport, primary, card, canvas, ink, muted, hairline,
                  sev_colors: dict, success, error,
                  body="Helvetica", display="Helvetica", mono="Courier") -> None:
    if pdf.get_y() > 240:
        pdf.add_page()
        pdf.set_fill_color(*canvas)
        pdf.rect(0, 0, 210, 297, style="F")

    pdf.ln(4)

    # ── File header bar ───────────────────────────────────────────────────────
    y = pdf.get_y()
    pdf.set_fill_color(*card)
    pdf.rect(14, y, 182, 10, style="F")
    pdf.set_fill_color(*primary)
    pdf.rect(14, y, 3, 10, style="F")
    pdf.set_xy(20, y + 1.5)
    pdf.set_font(body, "B", 9)
    pdf.set_text_color(*ink)
    pdf.cell(100, 7, _truncate(report.filename, 60))
    status_color = success if report.findings else muted
    pdf.set_font(body, "", 8)
    pdf.set_text_color(*status_color)
    pdf.cell(0, 7, f"{report.verifier_status.value.upper()}  ·  {len(report.findings)} accepted", align="R", ln=True)

    pdf.ln(2)
    pdf.set_x(14)
    pdf.set_font(body, "I", 8) if body == "Helvetica" else pdf.set_font(body, "", 8)
    pdf.set_text_color(*muted)
    pdf.multi_cell(182, 4.5, report.summary)
    pdf.ln(3)

    for finding in report.findings:
        _finding_block(pdf, finding, sev_colors, canvas, card, ink, muted, hairline,
                       accepted=True, body=body, mono=mono)

    for finding in report.rejected_findings:
        _finding_block(pdf, finding, sev_colors, canvas, card, ink, muted, hairline,
                       accepted=False, body=body, mono=mono)


def _finding_block(pdf, finding: SourceFinding, sev_colors: dict,
                   canvas, card, ink, muted, hairline, accepted: bool,
                   body="Helvetica", mono="Courier") -> None:
    if pdf.get_y() > 250:
        pdf.add_page()
        pdf.set_fill_color(*canvas)
        pdf.rect(0, 0, 210, 297, style="F")

    sev = finding.severity.lower()
    sev_color = sev_colors.get(sev, muted)
    conf_pct = int(finding.confidence * 100)

    REJECT_STRIPE = (198, 69, 69)
    stripe_color = sev_color if accepted else REJECT_STRIPE

    # Left severity stripe (placeholder height, updated at end)
    y0 = pdf.get_y()

    # ── Title row ─────────────────────────────────────────────────────────────
    pdf.set_xy(20, y0)
    pdf.set_font(body, "B", 10)
    pdf.set_text_color(*ink)
    marker = "[REJECTED]  " if not accepted else ""
    pdf.multi_cell(172, 6, f"{marker}{finding.title}")
    pdf.ln(1)

    # ── Meta row ─────────────────────────────────────────────────────────────
    pdf.set_x(20)
    pdf.set_font(body, "B", 8)
    pdf.set_text_color(*sev_color)
    pdf.cell(28, 5, sev.upper())

    pdf.set_font(body, "", 8)
    pdf.set_text_color(*muted)
    if finding.line_start is not None:
        loc = str(finding.line_start)
        if finding.line_end and finding.line_end != finding.line_start:
            loc += f"–{finding.line_end}"
        pdf.cell(32, 5, f"L{loc}")
    pdf.cell(40, 5, _truncate(finding.function_name, 28))
    pdf.cell(0, 5, f"{conf_pct}% confidence", ln=True)

    # ── Root cause ────────────────────────────────────────────────────────────
    pdf.ln(1)
    pdf.set_x(20)
    pdf.set_font(body, "B", 8)
    pdf.set_text_color(*muted)
    pdf.cell(22, 5, "Root cause")
    pdf.set_font(body, "", 8)
    pdf.set_text_color(*ink)
    pdf.multi_cell(150, 5, _truncate(finding.root_cause, 160))

    # ── Evidence code block ───────────────────────────────────────────────────
    if finding.evidence_quote.strip():
        pdf.ln(1)
        quote_lines = finding.evidence_quote.strip().splitlines()
        code_y = pdf.get_y()
        line_h = 4.5
        block_h = len(quote_lines) * line_h + 6
        pdf.set_fill_color(*card)
        pdf.rect(20, code_y, 176, block_h, style="F")
        pdf.set_fill_color(*sev_color)
        pdf.rect(20, code_y, 2, block_h, style="F")
        pdf.set_xy(25, code_y + 3)
        pdf.set_font(mono, "", 7.5)
        pdf.set_text_color(*ink)
        for line in quote_lines:
            pdf.set_x(25)
            pdf.cell(0, line_h, _truncate(line, 95), ln=True)
        pdf.ln(1)

    # ── Remediation ───────────────────────────────────────────────────────────
    pdf.ln(1)
    pdf.set_x(20)
    pdf.set_font(body, "B", 8)
    pdf.set_text_color(*muted)
    pdf.cell(16, 5, "Fix")
    pdf.set_font(body, "", 8)
    pdf.set_text_color(*ink)
    pdf.multi_cell(156, 5, _truncate(finding.remediation, 200))

    # Update severity stripe height
    y1 = pdf.get_y()
    pdf.set_fill_color(*stripe_color)
    pdf.rect(14, y0, 3, y1 - y0, style="F")

    # Divider
    pdf.ln(3)
    _hairline(pdf, hairline)


def _truncate(value: str, max_len: int) -> str:
    if len(value) <= max_len:
        return value
    return value[:max_len - 1] + "…"


# ── Markdown export ───────────────────────────────────────────────────────────

def render_project_markdown(report: ProjectAnalysisReport) -> str:
    accepted = sum(len(file_report.findings) for file_report in report.file_reports)
    rejected = sum(len(file_report.rejected_findings) for file_report in report.file_reports)
    lines = [
        "# Reporter — Security Analysis Report",
        "",
        f"- Project ID: `{report.project_id}`",
        f"- Archive: `{report.archive_name}`",
        f"- Verifier Status: `{report.verifier_status.value}`",
        f"- Files: {report.analyzed_files} analyzed / {report.total_files} considered",
        f"- Accepted Findings: {accepted}",
        f"- Rejected Findings: {rejected}",
        "",
        "## Summary",
        "",
        report.summary,
        "",
    ]

    if report.skipped_files:
        lines.extend(["## Skipped Files", ""])
        lines.extend(f"- {item}" for item in report.skipped_files[:50])
        if len(report.skipped_files) > 50:
            lines.append(f"- ... {len(report.skipped_files) - 50} more")
        lines.append("")

    lines.extend(["## File Reports", ""])
    for file_report in report.file_reports:
        lines.extend(_render_file_report(file_report))
    return "\n".join(lines).strip() + "\n"


def write_agent_logs(report: ProjectAnalysisReport, log_dir: Path) -> None:
    for file_report in report.file_reports:
        safe_name = _safe_run_id(file_report.filename.replace("/", "__"))
        path = log_dir / f"{safe_name}.md"
        path.write_text(render_file_agent_log(file_report), encoding="utf-8")


def render_file_agent_log(report: SourceAnalysisReport) -> str:
    lines = [
        f"# Agent Log: {report.filename}",
        "",
        f"- Report ID: `{report.report_id}`",
        f"- Model: `{report.model}`",
        f"- Verdict: `{report.verdict.value}`",
        f"- Verifier Status: `{report.verifier_status.value}`",
        "",
        "## Reporter Summary",
        "",
        report.summary,
        "",
        "## Verifier Rationale",
        "",
        report.verifier_rationale,
        "",
        "## Accepted Findings",
        "",
    ]
    if report.findings:
        for finding in report.findings:
            lines.extend(_render_finding(finding))
    else:
        lines.append("- None")
    lines.extend(["", "## Rejected Findings", ""])
    if report.rejected_findings:
        for finding in report.rejected_findings:
            lines.extend(_render_finding(finding))
    else:
        lines.append("- None")
    return "\n".join(lines).strip() + "\n"


def _render_file_report(report: SourceAnalysisReport) -> list[str]:
    lines = [
        f"### `{report.filename}`",
        "",
        f"- Model: `{report.model}`",
        f"- Verdict: `{report.verdict.value}`",
        f"- Verifier: `{report.verifier_status.value}`",
        f"- Accepted: {len(report.findings)}",
        f"- Rejected: {len(report.rejected_findings)}",
        "",
        report.summary,
        "",
    ]
    if report.findings:
        lines.extend(["#### Accepted Findings", ""])
        for finding in report.findings:
            lines.extend(_render_finding(finding))
    if report.rejected_findings:
        lines.extend(["#### Rejected Findings", ""])
        for finding in report.rejected_findings:
            lines.extend(_render_finding(finding))
    return lines


def _render_finding(finding: SourceFinding) -> list[str]:
    location = "unknown"
    if finding.line_start is not None:
        location = str(finding.line_start)
        if finding.line_end is not None and finding.line_end != finding.line_start:
            location += f"-{finding.line_end}"
    return [
        f"- **{finding.title}**",
        f"  - Severity: `{finding.severity}`",
        f"  - Function: `{finding.function_name}`",
        f"  - Lines: `{location}`",
        f"  - Confidence: `{finding.confidence:.2f}`",
        f"  - Root cause: {finding.root_cause}",
        f"  - Evidence: `{finding.evidence_quote}`",
        f"  - Remediation: {finding.remediation}",
        "",
    ]


def _safe_run_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-") or "report"


# ── Fallback PDF (pure Python, no fpdf2) ─────────────────────────────────────

def _write_fallback_pdf(path: Path, text: str) -> None:
    lines = _pdf_lines(text)
    objects: list[bytes] = []
    content = _pdf_content_stream(lines)
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objects.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    objects.append(b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"\nendstream")

    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for idx, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{idx} 0 obj\n".encode("ascii"))
        output.extend(obj)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        (
            f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
    )
    path.write_bytes(bytes(output))


def _pdf_lines(markdown: str) -> list[str]:
    plain = []
    for line in markdown.splitlines():
        line = re.sub(r"[`*_#>-]+", "", line).strip()
        if not line:
            plain.append("")
            continue
        while len(line) > 92:
            plain.append(line[:92])
            line = line[92:]
        plain.append(line)
    return plain[:54]


def _pdf_content_stream(lines: list[str]) -> bytes:
    chunks = ["BT", "/F1 10 Tf", "50 760 Td", "14 TL"]
    for line in lines:
        chunks.append(f"({_escape_pdf_text(line)}) Tj")
        chunks.append("T*")
    chunks.append("ET")
    return "\n".join(chunks).encode("latin-1", errors="replace")


def _escape_pdf_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
