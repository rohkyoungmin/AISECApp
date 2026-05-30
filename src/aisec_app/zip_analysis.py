from __future__ import annotations

import hashlib
import io
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath

from .cve_mapping import map_cve_candidates_from_sources
from .models import CVECandidateSummary, ProjectAnalysisReport, SourceAnalysisReport, SourceArtifact, VerificationStatus
from .source_analysis import MultiAgentSourceAnalyzer, SourceAnalyzer, build_finding_cve_linker


SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
}


@dataclass(slots=True)
class ZipAnalysisLimits:
    max_files: int = 20
    max_file_bytes: int = 120_000
    max_total_bytes: int = 1_500_000


def analyze_zip_archive(
    archive_name: str,
    archive_bytes: bytes,
    analyzer: SourceAnalyzer,
    limits: ZipAnalysisLimits | None = None,
    progress_callback: Callable[[dict], None] | None = None,
    enable_cve_mapping: bool = False,
    nvd_cache_dir: str | Path | None = None,
) -> ProjectAnalysisReport:
    active_limits = limits or ZipAnalysisLimits()

    if progress_callback:
        progress_callback({"type": "stage", "stage": "extracting", "message": "Extracting ZIP archive..."})

    artifacts, skipped = collect_source_artifacts(archive_bytes, active_limits)
    total = len(artifacts)
    file_reports: list[SourceAnalysisReport] = []
    cve_candidates: list[CVECandidateSummary] = []

    if enable_cve_mapping and artifacts:
        if progress_callback:
            progress_callback({"type": "stage", "stage": "cve_mapping", "message": "Mapping NVD CVE candidates..."})
        cve_candidates = [
            candidate.to_summary()
            for candidate in map_cve_candidates_from_sources(
                artifacts,
                live_nvd=True,
                cache_dir=nvd_cache_dir or Path("output") / "nvd_query_cache",
            )
        ]
        if cve_candidates:
            context = _cve_context(cve_candidates)
            artifacts = [
                SourceArtifact(filename=artifact.filename, content=artifact.content, context=context)
                for artifact in artifacts
            ]

    for idx, artifact in enumerate(artifacts):
        if progress_callback:
            progress_callback({
                "type": "file_start",
                "file": artifact.filename,
                "file_index": idx + 1,
                "total_files": total,
                "message": f"Analyzing {artifact.filename} ({idx + 1}/{total})",
            })
        # Wire per-file progress into the multi-agent analyzer
        if isinstance(analyzer, MultiAgentSourceAnalyzer) and progress_callback:
            file_index = idx + 1

            def _make_cb(f: str, fi: int, t: int, cb: Callable[[dict], None]) -> Callable[[dict], None]:
                def inner(evt: dict) -> None:
                    cb({**evt, "file": f, "file_index": fi, "total_files": t})
                return inner

            analyzer.progress = _make_cb(artifact.filename, file_index, total, progress_callback)

        file_reports.append(analyzer.analyze(artifact))

    # Link accepted findings to CVE candidates
    if cve_candidates and any(r.findings for r in file_reports):
        linker = build_finding_cve_linker()
        if linker is not None:
            file_reports = linker.link(file_reports, cve_candidates)

    accepted_reports = [report for report in file_reports if report.findings]

    if progress_callback:
        progress_callback({"type": "stage", "stage": "finalizing", "message": "Finalizing report..."})

    if accepted_reports:
        status = VerificationStatus.PASS
        summary = f"Analyzed {len(file_reports)} source files and found grounded findings in {len(accepted_reports)} files."
    else:
        status = VerificationStatus.REJECT
        summary = f"Analyzed {len(file_reports)} source files and found no grounded findings."

    if cve_candidates:
        summary += f" Mapped {len(cve_candidates)} NVD CVE candidate(s)."

    return ProjectAnalysisReport(
        project_id=_project_id(archive_bytes),
        archive_name=archive_name,
        total_files=len(artifacts) + len(skipped),
        analyzed_files=len(artifacts),
        skipped_files=skipped,
        verifier_status=status,
        summary=summary,
        file_reports=file_reports,
        cve_candidates=cve_candidates,
    )


def collect_source_artifacts(archive_bytes: bytes, limits: ZipAnalysisLimits | None = None) -> tuple[list[SourceArtifact], list[str]]:
    active_limits = limits or ZipAnalysisLimits()
    artifacts: list[SourceArtifact] = []
    skipped: list[str] = []
    total_bytes = 0

    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        for info in sorted(archive.infolist(), key=lambda item: item.filename):
            normalized_name = _safe_member_name(info.filename)
            if normalized_name is None or info.is_dir():
                continue
            if not _is_source_file(normalized_name):
                skipped.append(f"{normalized_name}: unsupported extension")
                continue
            if len(artifacts) >= active_limits.max_files:
                skipped.append(f"{normalized_name}: max analyzed file count reached")
                continue
            if info.file_size > active_limits.max_file_bytes:
                skipped.append(f"{normalized_name}: file too large")
                continue
            if total_bytes + info.file_size > active_limits.max_total_bytes:
                skipped.append(f"{normalized_name}: total byte limit reached")
                continue

            content = archive.read(info)
            total_bytes += len(content)
            artifacts.append(
                SourceArtifact(
                    filename=normalized_name,
                    content=content.decode("utf-8", errors="replace"),
                )
            )

    return artifacts, skipped


def _safe_member_name(filename: str) -> str | None:
    path = PurePosixPath(filename.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        return None
    cleaned = str(path)
    return cleaned if cleaned and cleaned != "." else None


def _is_source_file(filename: str) -> bool:
    return PurePosixPath(filename).suffix.lower() in SOURCE_EXTENSIONS


def _project_id(archive_bytes: bytes) -> str:
    return f"project-{hashlib.sha256(archive_bytes).hexdigest()[:12]}"


def _cve_context(candidates: list[CVECandidateSummary]) -> str:
    lines = [
        "NVD candidate CVEs. Use these only as context; evidence_quote must come from uploaded source."
    ]
    for candidate in candidates[:5]:
        cvss = "unknown"
        if candidate.cvss_score is not None:
            cvss = f"{candidate.cvss_score:.1f} {candidate.cvss_severity}".strip()
        lines.append(
            f"- {candidate.cve_id} score={candidate.score:.2f} verified={candidate.verified} "
            f"cvss={cvss} cwe={','.join(candidate.weaknesses) or 'unknown'}"
        )
        if candidate.match_reasons:
            lines.append(f"  match_reasons: {', '.join(candidate.match_reasons[:3])}")
        if candidate.description:
            lines.append(f"  description: {candidate.description[:500]}")
    return "\n".join(lines)
