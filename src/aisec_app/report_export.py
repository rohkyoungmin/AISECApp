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
    write_simple_pdf(pdf_path, markdown)
    write_agent_logs(report, llm_log_dir)

    return ExportedReportPaths(
        run_dir=run_dir,
        json_path=json_path,
        markdown_path=markdown_path,
        pdf_path=pdf_path,
        llm_log_dir=llm_log_dir,
    )


def render_project_markdown(report: ProjectAnalysisReport) -> str:
    accepted = sum(len(file_report.findings) for file_report in report.file_reports)
    rejected = sum(len(file_report.rejected_findings) for file_report in report.file_reports)
    lines = [
        f"# AISEC Analysis Report",
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


def write_simple_pdf(path: Path, text: str) -> None:
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
