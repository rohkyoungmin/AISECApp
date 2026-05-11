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


def _write_fpdf2_report(path: Path, report: ProjectAnalysisReport) -> None:
    from fpdf import FPDF  # type: ignore[import]

    DARK_BG = (10, 12, 24)
    HEADER_BG = (15, 18, 40)
    ACCENT = (0, 180, 255)
    ACCENT_DIM = (0, 100, 160)
    WHITE = (220, 235, 255)
    DIM = (100, 130, 160)
    CRITICAL = (220, 30, 60)
    HIGH = (255, 120, 0)
    MEDIUM = (255, 200, 0)
    LOW = (60, 180, 255)
    SUCCESS = (0, 200, 100)
    REJECT = (180, 40, 60)

    accepted = sum(len(fr.findings) for fr in report.file_reports)
    rejected = sum(len(fr.rejected_findings) for fr in report.file_reports)

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # ── Cover header bar ──────────────────────────────────────────────────────
    pdf.set_fill_color(*HEADER_BG)
    pdf.rect(0, 0, 210, 50, style="F")

    pdf.set_fill_color(*ACCENT)
    pdf.rect(0, 0, 6, 50, style="F")

    pdf.set_xy(12, 10)
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_text_color(*ACCENT)
    pdf.cell(0, 12, "AISEC", ln=False)
    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(*DIM)
    pdf.set_xy(12, 24)
    pdf.cell(0, 8, "AI-Powered Source Security Analysis", ln=True)

    # Status badge top-right
    status_val = report.verifier_status.value.upper()
    badge_color = SUCCESS if report.verifier_status.value == "pass" else REJECT
    pdf.set_fill_color(*badge_color)
    pdf.set_text_color(*WHITE)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_xy(148, 16)
    pdf.cell(52, 10, f"  {status_val}  ", border=0, align="C", fill=True)

    # ── Project info block ─────────────────────────────────────────────────────
    pdf.set_xy(12, 58)
    pdf.set_fill_color(*DARK_BG)
    pdf.set_text_color(*DIM)
    pdf.set_font("Helvetica", "", 9)

    info_lines = [
        ("Archive", report.archive_name),
        ("Project ID", report.project_id),
        ("Files analyzed", f"{report.analyzed_files} / {report.total_files}"),
        ("Accepted findings", str(accepted)),
        ("Rejected findings", str(rejected)),
    ]
    for label, value in info_lines:
        pdf.set_text_color(*DIM)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(42, 6, label.upper(), ln=False)
        pdf.set_text_color(*WHITE)
        pdf.set_font("Courier", "", 9)
        pdf.cell(0, 6, _truncate(value, 80), ln=True)

    # ── Summary ────────────────────────────────────────────────────────────────
    pdf.ln(4)
    _section_header(pdf, "SUMMARY", ACCENT, HEADER_BG)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*WHITE)
    pdf.multi_cell(0, 6, report.summary)

    # ── Stats bar ─────────────────────────────────────────────────────────────
    pdf.ln(4)
    stats = [
        ("FILES", str(report.analyzed_files), ACCENT),
        ("ACCEPTED", str(accepted), SUCCESS),
        ("REJECTED", str(rejected), REJECT if rejected else DIM),
        ("SKIPPED", str(len(report.skipped_files)), DIM),
    ]
    box_w = 44
    start_x = 12
    y = pdf.get_y()
    for i, (label, val, color) in enumerate(stats):
        x = start_x + i * (box_w + 2)
        pdf.set_fill_color(*HEADER_BG)
        pdf.rect(x, y, box_w, 18, style="F")
        pdf.set_fill_color(*color)
        pdf.rect(x, y, box_w, 3, style="F")
        pdf.set_xy(x, y + 4)
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(*color)
        pdf.cell(box_w, 8, val, align="C")
        pdf.set_xy(x, y + 12)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(*DIM)
        pdf.cell(box_w, 4, label, align="C")
    pdf.set_y(y + 24)

    # ── Per-file findings ──────────────────────────────────────────────────────
    for file_report in report.file_reports:
        if not file_report.findings and not file_report.rejected_findings:
            continue
        _file_section(pdf, file_report, ACCENT, HEADER_BG, DARK_BG, WHITE, DIM, CRITICAL, HIGH, MEDIUM, LOW, SUCCESS, REJECT)

    # ── Footer on all pages ────────────────────────────────────────────────────
    page_count = pdf.page
    for page_num in range(1, page_count + 1):
        pdf.page = page_num
        pdf.set_y(-14)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(*DIM)
        pdf.cell(0, 6, f"AISEC Security Report  ·  {report.project_id}  ·  Page {page_num}/{page_count}", align="C")

    pdf.output(str(path))


def _section_header(pdf, title: str, accent, bg) -> None:
    pdf.set_fill_color(*bg)
    pdf.set_x(12)
    y = pdf.get_y()
    pdf.rect(12, y, 186, 9, style="F")
    pdf.set_fill_color(*accent)
    pdf.rect(12, y, 3, 9, style="F")
    pdf.set_xy(18, y + 1)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*accent)
    pdf.cell(0, 7, title, ln=True)
    pdf.ln(2)


def _file_section(pdf, report: SourceAnalysisReport, accent, header_bg, dark_bg, white, dim,
                  critical, high, medium, low, success, reject) -> None:
    pdf.ln(3)
    _section_header(pdf, f"FILE: {report.filename}", accent, header_bg)

    # File meta row
    pdf.set_font("Helvetica", "", 9)
    pdf.set_x(12)
    verdict_color = success if report.findings else dim
    pdf.set_text_color(*verdict_color)
    pdf.cell(60, 5, f"Status: {report.verifier_status.value.upper()}")
    pdf.set_text_color(*dim)
    pdf.cell(60, 5, f"Model: {report.model}")
    pdf.cell(0, 5, f"Findings: {len(report.findings)} accepted", ln=True)

    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(*dim)
    pdf.set_x(12)
    pdf.multi_cell(0, 5, report.summary)
    pdf.ln(2)

    severity_colors = {"critical": critical, "high": high, "medium": medium, "low": low}

    for finding in report.findings:
        _finding_block(pdf, finding, severity_colors, header_bg, white, dim, accepted=True)

    for finding in report.rejected_findings:
        _finding_block(pdf, finding, severity_colors, header_bg, white, dim, accepted=False)


def _finding_block(pdf, finding: SourceFinding, severity_colors: dict,
                   bg, white, dim, accepted: bool) -> None:
    REJECT_COLOR = (100, 50, 50)
    block_bg = bg if accepted else REJECT_COLOR
    sev = finding.severity.lower()
    sev_color = severity_colors.get(sev, dim)

    y = pdf.get_y()
    if y > 260:
        pdf.add_page()

    pdf.set_fill_color(*block_bg)
    pdf.set_x(12)
    # Draw block background
    block_h = 44
    pdf.rect(12, pdf.get_y(), 186, block_h, style="F")

    # Severity stripe
    pdf.set_fill_color(*sev_color)
    pdf.rect(12, pdf.get_y(), 3, block_h, style="F")

    current_y = pdf.get_y() + 2

    # Title line
    pdf.set_xy(18, current_y)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*white)
    label = "✓" if accepted else "✗"
    pdf.cell(170, 6, f"{label}  {_truncate(finding.title, 70)}", ln=True)

    # Severity + function + lines
    pdf.set_xy(18, pdf.get_y())
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*sev_color)
    pdf.cell(35, 5, sev.upper())
    pdf.set_text_color(*dim)
    pdf.cell(70, 5, f"fn: {_truncate(finding.function_name, 30)}")
    if finding.line_start is not None:
        loc = str(finding.line_start)
        if finding.line_end and finding.line_end != finding.line_start:
            loc += f"-{finding.line_end}"
        pdf.cell(40, 5, f"lines: {loc}")
    conf_pct = int(finding.confidence * 100)
    pdf.cell(0, 5, f"conf: {conf_pct}%", ln=True)

    # Root cause
    pdf.set_xy(18, pdf.get_y())
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*dim)
    pdf.cell(22, 5, "Cause:")
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*white)
    pdf.multi_cell(160, 5, _truncate(finding.root_cause, 100))

    # Evidence quote (monospace)
    pdf.set_xy(18, pdf.get_y())
    pdf.set_font("Courier", "", 7)
    pdf.set_text_color(160, 210, 255)
    quote = _truncate(finding.evidence_quote.replace("\n", "  "), 110)
    pdf.cell(0, 5, f"  {quote}", ln=True)

    # Remediation
    pdf.set_xy(18, pdf.get_y())
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(*dim)
    pdf.multi_cell(160, 5, _truncate(f"Fix: {finding.remediation}", 120))

    # Move past the block
    pdf.set_y(y + block_h + 3)


def _truncate(value: str, max_len: int) -> str:
    if len(value) <= max_len:
        return value
    return value[:max_len - 1] + "…"


# ── Markdown export ───────────────────────────────────────────────────────────

def render_project_markdown(report: ProjectAnalysisReport) -> str:
    accepted = sum(len(file_report.findings) for file_report in report.file_reports)
    rejected = sum(len(file_report.rejected_findings) for file_report in report.file_reports)
    lines = [
        "# AISEC Analysis Report",
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
