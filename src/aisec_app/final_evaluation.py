from __future__ import annotations

import argparse
import io
import json
import subprocess
import sys
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import load_claude_settings
from .cve_mapping import map_cve_candidates_from_sources
from .cve_metadata import discover_case_cve_ids
from .dataset import DatasetError, load_case_record, load_case_records
from .evaluation import evaluate_cases
from .models import SourceArtifact, VerificationStatus, Verdict
from .report_export import export_project_report
from .source_analysis import HeuristicSourceAnalyzer, LLMNotConfiguredError, build_source_analyzer, verify_source_report
from .zip_analysis import analyze_zip_archive, collect_source_artifacts


@dataclass(slots=True)
class CommandResult:
    command: str
    returncode: int
    stdout_tail: str
    stderr_tail: str


@dataclass(slots=True)
class VerifierCheck:
    name: str
    passed: bool
    rationale: str


@dataclass(slots=True)
class LLMSampleResult:
    sample_id: str
    status: str
    cache_hit: bool
    api_call_used: bool
    accepted_findings: int = 0
    rejected_findings: int = 0
    model: str = ""
    reason: str = ""
    report_path: str | None = None


def run_final_evaluation(
    output_dir: str | Path = "output/evaluation",
    max_llm_calls: int = 3,
    cases_root: str | Path = "data/cases",
) -> dict[str, Any]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    cases_path = Path(cases_root)
    dataset = _dataset_contract(cases_path)
    full_sweep = _full_magma_sweep(cases_path)
    scoring_interpretation = _scoring_interpretation(dataset, full_sweep)
    nvd = _nvd_metadata(cases_path, out / "nvd_query_cache")
    verifier = _verifier_reliability()
    robustness = _system_robustness(out)
    llm = _cost_limited_llm_evaluation(out, max_llm_calls)
    readiness = _completed_magma_readiness(dataset)

    result: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "command": " ".join(sys.argv) if sys.argv else "aisec_app.final_evaluation",
        "dataset_contract": dataset,
        "full_magma_sweep": full_sweep,
        "scoring_interpretation": scoring_interpretation,
        "nvd_metadata": nvd,
        "verifier_reliability": verifier,
        "system_robustness": robustness,
        "cost_limited_llm_evaluation": llm,
        "completed_magma_readiness": readiness,
        "notes": [
            "Magma labels were used only for scoring/readiness classification, not as analyzer evidence.",
            "Full Magma Sweep is deterministic/baseline over skeleton-inclusive imported cases.",
            "Completed Magma detection F1 is not claimed until completed source/artifact pairs are available.",
        ],
    }

    json_path = out / "evaluation.json"
    markdown_path = out / "evaluation.md"
    json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    markdown_path.write_text(render_evaluation_markdown(result), encoding="utf-8")
    return result


def render_evaluation_markdown(result: dict[str, Any]) -> str:
    dataset = result["dataset_contract"]
    sweep = result["full_magma_sweep"]
    nvd = result["nvd_metadata"]
    verifier = result["verifier_reliability"]
    robustness = result["system_robustness"]
    llm = result["cost_limited_llm_evaluation"]
    readiness = result["completed_magma_readiness"]
    interpretation = result["scoring_interpretation"]

    lines = [
        "# AISEC App Final Evaluation",
        "",
        f"- Generated at: `{result['generated_at']}`",
        f"- Command: `{result['command']}`",
        "",
        "## Summary",
        "",
        "| Axis | Result |",
        "| --- | --- |",
        f"| Dataset contract | {dataset['loaded_cases']}/{dataset['total_case_dirs']} cases loaded |",
        f"| Full Magma Sweep | {sweep['total_cases']} cases swept; {dataset['skeleton_cases']} skeleton/non-completed cases separated from final accuracy |",
        f"| Completed Magma Detection | {interpretation['completed_magma_detection']} |",
        f"| Runnable smoke baseline | {interpretation['smoke_passed']}/{interpretation['smoke_total']} passed |",
        f"| NVD metadata | {nvd['metadata_records']} metadata records across {nvd['cases_with_cve_ids']} CVE-linked cases |",
        f"| Verifier reliability | {verifier['passed_checks']}/{verifier['total_checks']} checks passed |",
        f"| System robustness | unittest return code {robustness['unittest']['returncode']}, ZIP filtering {'pass' if robustness['zip_filtering']['passed'] else 'fail'}, report export {'pass' if robustness['report_export']['passed'] else 'fail'} |",
        f"| Cost-limited LLM | {llm['actual_api_calls']} API calls, {llm['cache_hits']} cache hits, status {llm['status']} |",
        "",
        "## A. Dataset Contract Evaluation",
        "",
        f"- Total case directories: `{dataset['total_case_dirs']}`",
        f"- Loaded cases: `{dataset['loaded_cases']}`",
        f"- Load failures: `{len(dataset['load_failures'])}`",
        f"- Magma cases: `{dataset['magma_cases']}`",
        f"- Demo cases: `{dataset['demo_cases']}`",
        f"- Skeleton cases: `{dataset['skeleton_cases']}`",
        f"- Completed-like cases: `{dataset['completed_like_cases']}`",
        "",
        "## B. Full Magma Sweep",
        "",
        f"- Cases evaluated: `{sweep['total_cases']}`",
        f"- Raw skeleton-inclusive detection count: `{sweep['detection_correct']}/{sweep['total_cases']} ({sweep['detection_accuracy']:.2%})`",
        f"- Raw skeleton-inclusive function count: `{sweep['function_correct']}/{sweep['total_cases']} ({sweep['function_localization_accuracy']:.2%})`",
        f"- Verifier distribution: `{json.dumps(sweep['verifier_counts'], ensure_ascii=False)}`",
        f"- Completed Magma detection metric: `{interpretation['completed_magma_detection']}`",
        f"- Runnable smoke baseline: `{interpretation['smoke_passed']}/{interpretation['smoke_total']} passed`",
        "",
        "> The raw 2/139 number must not be presented as final model accuracy. It is a skeleton-inclusive baseline showing that strict verification rejects cases without completed analyzable evidence. Completed Magma Detection F1 is currently not measurable because completed source/artifact pairs are not present in this repository.",
        "",
        "## C. NVD Metadata Evaluation",
        "",
        f"- Cases with discovered CVE IDs: `{nvd['cases_with_cve_ids']}`",
        f"- Metadata records in manifests: `{nvd['metadata_records']}`",
        f"- Linked CVEs: `{', '.join(nvd['linked_cves']) or 'none'}`",
        f"- Records with CWE: `{nvd['records_with_cwe']}`",
        f"- Records with CVSS: `{nvd['records_with_cvss']}`",
        f"- Records with references: `{nvd['records_with_references']}`",
        f"- Fallback state: `{nvd['fallback_state']}`",
        f"- Candidate mapping smoke test: `{'pass' if nvd['candidate_mapping_smoke']['passed'] else 'fail'}`",
        "",
        "## D. Verifier Reliability Evaluation",
        "",
        "| Check | Result | Rationale |",
        "| --- | --- | --- |",
    ]

    for check in verifier["checks"]:
        lines.append(f"| {check['name']} | {'pass' if check['passed'] else 'fail'} | {check['rationale']} |")

    lines.extend([
        "",
        "## E. System Robustness Evaluation",
        "",
        f"- Unittest command: `{robustness['unittest']['command']}`",
        f"- Unittest return code: `{robustness['unittest']['returncode']}`",
        f"- ZIP filtering/path traversal: `{'pass' if robustness['zip_filtering']['passed'] else 'fail'}`",
        f"- Report export: `{'pass' if robustness['report_export']['passed'] else 'fail'}`",
        "- Frontend build: `not run in this backend/evaluation stage`",
        "",
        "## F. Cost-Limited LLM Evaluation",
        "",
        f"- API key present: `{llm['api_key_present']}`",
        f"- Max allowed calls: `{llm['max_allowed_calls']}`",
        f"- Actual API calls: `{llm['actual_api_calls']}`",
        f"- Cache hits: `{llm['cache_hits']}`",
        f"- Status: `{llm['status']}`",
        "",
        "| Sample | Status | Cache | API Call | Accepted | Rejected | Reason |",
        "| --- | --- | --- | --- | ---: | ---: | --- |",
    ])

    for sample in llm["samples"]:
        lines.append(
            "| "
            f"{sample['sample_id']} | {sample['status']} | {sample['cache_hit']} | "
            f"{sample['api_call_used']} | {sample['accepted_findings']} | {sample['rejected_findings']} | "
            f"{sample['reason']} |"
        )

    lines.extend([
        "",
        "## G. Completed Magma Evaluation Readiness",
        "",
        f"- Completed-like cases: `{readiness['completed_like_cases']}`",
        f"- Skeleton cases: `{readiness['skeleton_cases']}`",
        f"- Completed Magma Detection F1: `{readiness['completed_magma_detection_f1']}`",
        "",
        readiness["explanation"],
        "",
        "## Measurable Now",
        "",
        "- Dataset contract count and load success",
        "- Skeleton-inclusive deterministic sweep and verifier distribution",
        "- Runnable smoke-case pass rate",
        "- Verifier pass/reject distribution",
        "- NVD metadata presence for linked CVE cases",
        "- Synthetic verifier reliability",
        "- System robustness checks",
        "- Cost-limited LLM sample status when API key/cache is available",
        "",
        "## Not Fully Measurable Yet",
        "",
        "- Completed Magma Detection F1, because completed source/artifact pairs are not yet available in this repository",
        "- Real-world CVE candidate Top-k recall, because a labeled ZIP-to-CVE mapping dataset is not yet built",
        "- Runtime exploitability accuracy, because PoC/runtime traces are not yet connected",
        "",
        "## Demo Day Summary",
        "",
        "1. AISEC App performs ZIP-based C/C++ source analysis and produces structured JSON/Markdown/PDF reports.",
        "2. NVD metadata integration is available for CVE-linked cases and is treated as candidate context, not a final verdict.",
        "3. The verifier rejects ungrounded evidence, invalid line references, and findings with nearby mitigation patterns.",
        "4. Confidence is recalculated by deterministic evidence rules instead of trusting LLM self-confidence.",
        "5. Full Magma sweep was performed for readiness and verifier distribution, while final completed-Magma accuracy is explicitly marked not measurable until completed artifacts are added.",
        "",
    ])
    return "\n".join(lines)


def _dataset_contract(cases_root: Path) -> dict[str, Any]:
    case_dirs = sorted(path for path in cases_root.iterdir() if path.is_dir())
    failures: list[dict[str, str]] = []
    loaded = 0
    magma = 0
    demo = 0
    skeleton = 0
    completed_like = 0

    for case_dir in case_dirs:
        try:
            record = load_case_record(case_dir)
        except DatasetError as exc:
            failures.append({"case_id": case_dir.name, "error": str(exc)})
            continue

        loaded += 1
        if record.case.cve_id.startswith("MAGMA-"):
            magma += 1
        else:
            demo += 1
        if _is_skeleton_case(case_dir):
            skeleton += 1
        else:
            completed_like += 1

    return {
        "total_case_dirs": len(case_dirs),
        "loaded_cases": loaded,
        "load_failures": failures,
        "magma_cases": magma,
        "demo_cases": demo,
        "skeleton_cases": skeleton,
        "completed_like_cases": completed_like,
    }


def _full_magma_sweep(cases_root: Path) -> dict[str, Any]:
    records = load_case_records(cases_root)
    summary = evaluate_cases(records)
    return {
        "total_cases": summary.total_cases,
        "detection_correct": summary.detection_correct,
        "detection_accuracy": summary.detection_accuracy,
        "function_correct": summary.function_correct,
        "function_localization_accuracy": summary.function_localization_accuracy,
        "verifier_counts": summary.verifier_counts,
        "case_results": [asdict(case) for case in summary.cases],
        "warning": (
            "This is a deterministic baseline over skeleton-inclusive imported cases, "
            "not completed-Magma detection performance."
        ),
    }


def _scoring_interpretation(dataset: dict[str, Any], full_sweep: dict[str, Any]) -> dict[str, Any]:
    smoke_ids = {"demo-parse-header", "magma-libpng-png003"}
    smoke_cases = [
        item
        for item in full_sweep["case_results"]
        if item["case_id"] in smoke_ids
    ]
    passed_smoke = [
        item
        for item in smoke_cases
        if item["detection_correct"] and item["function_correct"] and item["verifier_status"] == VerificationStatus.PASS.value
    ]
    completed = dataset["completed_like_cases"]
    completed_detection = "not measurable yet" if completed == 0 else "requires completed-case scorer"
    return {
        "completed_magma_detection": completed_detection,
        "reason": (
            "Imported Magma cases are skeletons/placeholders, so raw 2/139 is not final detection accuracy. "
            "Completed Magma cases should be scored separately once source/artifact pairs are available."
        ),
        "smoke_total": len(smoke_cases),
        "smoke_passed": len(passed_smoke),
        "smoke_case_ids": [item["case_id"] for item in passed_smoke],
        "raw_rejects_are_expected_for_non_evaluable_skeletons": True,
    }


def _nvd_metadata(cases_root: Path, nvd_cache_dir: Path) -> dict[str, Any]:
    case_dirs = sorted(path for path in cases_root.iterdir() if path.is_dir())
    cases_with_cve_ids = 0
    metadata_records = 0
    records_with_cwe = 0
    records_with_cvss = 0
    records_with_references = 0
    linked_cves: list[str] = []
    case_links: list[dict[str, Any]] = []

    for case_dir in case_dirs:
        cve_ids = discover_case_cve_ids(case_dir)
        if cve_ids:
            cases_with_cve_ids += 1

        manifest_path = case_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        metadata = manifest.get("cve_metadata")
        if not isinstance(metadata, list):
            metadata = []
        linked = manifest.get("linked_cve_id")
        if isinstance(linked, str) and linked:
            linked_cves.append(linked)

        for item in metadata:
            if not isinstance(item, dict):
                continue
            metadata_records += 1
            if item.get("weaknesses"):
                records_with_cwe += 1
            if item.get("cvss"):
                records_with_cvss += 1
            if item.get("references"):
                records_with_references += 1

        if cve_ids or metadata:
            case_links.append(
                {
                    "case_id": case_dir.name,
                    "discovered_cve_ids": cve_ids,
                    "linked_cve_id": linked,
                    "metadata_records": len(metadata),
                }
            )

    candidate_smoke_artifacts = [
        SourceArtifact(
            filename="openssl_status_request.c",
            content=(
                "/* OpenSSL CVE-2016-6304 OCSP Status Request memory consumption test source */\n"
                "int tls_parse_ctos_status_request(void) { return 0; }\n"
            ),
        )
    ]
    candidates = map_cve_candidates_from_sources(
        candidate_smoke_artifacts,
        cases_root=cases_root,
        live_nvd=True,
        cache_dir=nvd_cache_dir,
        max_queries=3,
        results_per_query=8,
    )
    candidate_smoke = {
        "passed": bool(candidates) and candidates[0].cve_id == "CVE-2016-6304",
        "top_candidates": [candidate.to_dict() for candidate in candidates],
    }

    return {
        "cases_with_cve_ids": cases_with_cve_ids,
        "metadata_records": metadata_records,
        "records_with_cwe": records_with_cwe,
        "records_with_cvss": records_with_cvss,
        "records_with_references": records_with_references,
        "linked_cves": sorted(set(linked_cves)),
        "case_links": case_links,
        "candidate_mapping_smoke": candidate_smoke,
        "fallback_state": "live NVD keywordSearch enabled with local query cache",
    }


def _verifier_reliability() -> dict[str, Any]:
    checks: list[VerifierCheck] = []

    ungrounded = verify_source_report(
        SourceArtifact(filename="sample.c", content="int ok(void) { return 0; }\n"),
        {
            "findings": [
                {
                    "title": "invented issue",
                    "verdict": "vulnerable",
                    "severity": "high",
                    "function_name": "ok",
                    "line_start": 1,
                    "line_end": 1,
                    "confidence": 0.99,
                    "root_cause": "invented",
                    "evidence_quote": "strcpy(buf, input);",
                    "remediation": "add bounds check",
                }
            ]
        },
        model="synthetic",
    )
    checks.append(
        VerifierCheck(
            name="ungrounded evidence reject",
            passed=ungrounded.verifier_status == VerificationStatus.REJECT and not ungrounded.findings,
            rationale=ungrounded.verifier_rationale,
        )
    )

    invalid_line = verify_source_report(
        SourceArtifact(filename="sample.c", content="void f(char *s) { strcpy(buf, s); }\n"),
        {
            "findings": [
                {
                    "title": "unsafe copy",
                    "verdict": "vulnerable",
                    "severity": "medium",
                    "function_name": "f",
                    "line_start": 99,
                    "line_end": 99,
                    "confidence": 0.99,
                    "root_cause": "unbounded copy",
                    "evidence_quote": "void f(char *s) { strcpy(buf, s); }",
                    "remediation": "add bounds check",
                }
            ]
        },
        model="synthetic",
    )
    checks.append(
        VerifierCheck(
            name="invalid line reference reject",
            passed=invalid_line.verifier_status == VerificationStatus.REJECT and "line range" in invalid_line.verifier_rationale,
            rationale=invalid_line.verifier_rationale,
        )
    )

    mitigation = verify_source_report(
        SourceArtifact(
            filename="sample.c",
            content="void f(char *s, size_t n) {\n  if (n < sizeof(buf)) {\n    strcpy(buf, s);\n  }\n}\n",
        ),
        {
            "findings": [
                {
                    "title": "unsafe copy",
                    "verdict": "vulnerable",
                    "severity": "high",
                    "function_name": "f",
                    "line_start": 3,
                    "line_end": 3,
                    "confidence": 0.99,
                    "root_cause": "unbounded copy",
                    "evidence_quote": "strcpy(buf, s);",
                    "remediation": "add bounds check",
                }
            ]
        },
        model="synthetic",
    )
    checks.append(
        VerifierCheck(
            name="mitigation nearby reject",
            passed=mitigation.verifier_status == VerificationStatus.REJECT and "nearby mitigation" in mitigation.verifier_rationale,
            rationale=mitigation.verifier_rationale,
        )
    )

    artifact = SourceArtifact(filename="sample.c", content="void f(char *s) { strcpy(buf, s); }\n")
    base_finding = {
        "title": "unsafe copy",
        "verdict": "vulnerable",
        "severity": "medium",
        "function_name": "f",
        "line_start": 1,
        "line_end": 1,
        "root_cause": "unbounded copy",
        "evidence_quote": "void f(char *s) { strcpy(buf, s); }",
        "remediation": "add bounds check",
    }
    low = verify_source_report(artifact, {"findings": [{**base_finding, "confidence": 0.01}]}, model="synthetic")
    high = verify_source_report(artifact, {"findings": [{**base_finding, "confidence": 0.99}]}, model="synthetic")
    low_conf = low.findings[0].confidence if low.findings else None
    high_conf = high.findings[0].confidence if high.findings else None
    checks.append(
        VerifierCheck(
            name="deterministic confidence consistency",
            passed=low_conf is not None and low_conf == high_conf,
            rationale=f"low model confidence -> {low_conf}; high model confidence -> {high_conf}",
        )
    )

    passed = sum(1 for check in checks if check.passed)
    return {
        "total_checks": len(checks),
        "passed_checks": passed,
        "checks": [asdict(check) for check in checks],
    }


def _system_robustness(output_dir: Path) -> dict[str, Any]:
    unittest_result = _run_command([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"])

    zip_bytes = _make_zip(
        {
            "src/a.c": "void a(void) {}\n",
            "../escape.c": "bad\n",
            "README.md": "not source\n",
        }
    )
    artifacts, skipped = collect_source_artifacts(zip_bytes)
    zip_filtering = {
        "passed": [artifact.filename for artifact in artifacts] == ["src/a.c"]
        and skipped == ["README.md: unsupported extension"],
        "artifacts": [artifact.filename for artifact in artifacts],
        "skipped": skipped,
    }

    report_export: dict[str, Any]
    try:
        report = analyze_zip_archive(
            "robustness.zip",
            _make_zip({"src/vuln.c": "void f(char *s) { strcpy(buf, s); }\n"}),
            HeuristicSourceAnalyzer(),
        )
        paths = export_project_report(report, output_dir / "robustness_report")
        report_export = {
            "passed": paths.json_path.exists() and paths.markdown_path.exists() and paths.pdf_path.exists(),
            "json_path": str(paths.json_path),
            "markdown_path": str(paths.markdown_path),
            "pdf_path": str(paths.pdf_path),
        }
    except Exception as exc:
        report_export = {"passed": False, "error": str(exc)}

    return {
        "unittest": asdict(unittest_result),
        "zip_filtering": zip_filtering,
        "report_export": report_export,
        "frontend_build": {"status": "not run", "reason": "frontend is intentionally out of scope for this stage"},
    }


def _cost_limited_llm_evaluation(output_dir: Path, max_llm_calls: int) -> dict[str, Any]:
    settings = load_claude_settings()
    sample_dir = output_dir / "ai_sample_reports"
    sample_dir.mkdir(parents=True, exist_ok=True)

    samples = _llm_samples()
    results: list[LLMSampleResult] = [
        LLMSampleResult(
            sample_id="nvd_linked_openssl_cases",
            status="not_run",
            cache_hit=False,
            api_call_used=False,
            reason=(
                "NVD-linked OpenSSL cases exist, but their imported files are skeletons; "
                "skipped to avoid Magma patch-derived evidence leakage."
            ),
        )
    ]
    calls = 0
    cache_hits = 0

    for sample_id, artifact in samples:
        report_path = sample_dir / f"{sample_id}.json"
        if report_path.exists():
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            cache_hits += 1
            results.append(
                LLMSampleResult(
                    sample_id=sample_id,
                    status="cached",
                    cache_hit=True,
                    api_call_used=False,
                    accepted_findings=len(payload.get("findings", [])),
                    rejected_findings=len(payload.get("rejected_findings", [])),
                    model=str(payload.get("model") or ""),
                    reason="reused cached sample report",
                    report_path=str(report_path),
                )
            )
            continue

        if not settings.is_configured:
            results.append(
                LLMSampleResult(
                    sample_id=sample_id,
                    status="not_run",
                    cache_hit=False,
                    api_call_used=False,
                    reason="API key missing",
                    report_path=str(report_path),
                )
            )
            continue

        if calls >= max(0, max_llm_calls):
            results.append(
                LLMSampleResult(
                    sample_id=sample_id,
                    status="not_run",
                    cache_hit=False,
                    api_call_used=False,
                    reason="max LLM call limit reached",
                    report_path=str(report_path),
                )
            )
            continue

        try:
            analyzer = build_source_analyzer(require_llm=True)
            report = analyzer.analyze(artifact)
            calls += 1
            report_path.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
            results.append(
                LLMSampleResult(
                    sample_id=sample_id,
                    status="completed",
                    cache_hit=False,
                    api_call_used=True,
                    accepted_findings=len(report.findings),
                    rejected_findings=len(report.rejected_findings),
                    model=report.model,
                    reason="LLM sample evaluation completed",
                    report_path=str(report_path),
                )
            )
        except LLMNotConfiguredError as exc:
            results.append(
                LLMSampleResult(
                    sample_id=sample_id,
                    status="not_run",
                    cache_hit=False,
                    api_call_used=False,
                    reason=str(exc),
                    report_path=str(report_path),
                )
            )
        except Exception as exc:
            results.append(
                LLMSampleResult(
                    sample_id=sample_id,
                    status="failed",
                    cache_hit=False,
                    api_call_used=False,
                    reason=f"LLM evaluation failed: {exc}",
                    report_path=str(report_path),
                )
            )

    if calls:
        status = "completed"
    elif cache_hits:
        status = "cached"
    elif settings.is_configured:
        status = "not_run_or_failed"
    else:
        status = "not_run_api_key_missing"

    return {
        "api_key_present": settings.is_configured,
        "max_allowed_calls": max_llm_calls,
        "actual_api_calls": calls,
        "cache_hits": cache_hits,
        "status": status,
        "samples": [asdict(result) for result in results],
    }


def _completed_magma_readiness(dataset: dict[str, Any]) -> dict[str, Any]:
    completed = dataset["completed_like_cases"]
    skeleton = dataset["skeleton_cases"]
    return {
        "completed_like_cases": completed,
        "skeleton_cases": skeleton,
        "completed_magma_detection_f1": "not measurable yet",
        "explanation": (
            "Completed Magma Detection F1 is not claimed because the imported cases are skeletons "
            "with placeholder binaries or Magma-derived excerpts. Magma patch-derived evidence was "
            "not used as analyzer input; labels are reserved for scoring only."
        ),
    }


def _llm_samples() -> list[tuple[str, SourceArtifact]]:
    return [
        (
            "demo_vulnerable_strcpy",
            SourceArtifact(
                filename="demo_vulnerable.c",
                content=(
                    "void parse_header(char *user_data) {\n"
                    "  char buf[32];\n"
                    "  strcpy(buf, user_data);\n"
                    "}\n"
                ),
            ),
        ),
        (
            "mitigation_reject_strcpy",
            SourceArtifact(
                filename="mitigation_reject.c",
                content=(
                    "#include <string.h>\n"
                    "void parse_header(char *user_data, size_t n) {\n"
                    "  char buf[32];\n"
                    "  if (n < sizeof(buf)) {\n"
                    "    strcpy(buf, user_data);\n"
                    "  }\n"
                    "}\n"
                ),
            ),
        ),
        (
            "demo_memcpy_overflow",
            SourceArtifact(
                filename="demo_memcpy_overflow.c",
                content=(
                    "void parse_header(char *input, int input_len) {\n"
                    "  char buf[32];\n"
                    "  memcpy(buf, input, input_len);\n"
                    "}\n"
                ),
            ),
        ),
    ]


def _is_skeleton_case(case_dir: Path) -> bool:
    text_parts: list[str] = []
    for path in (
        case_dir / "vulnerable" / "binary",
        case_dir / "fixed" / "binary",
        case_dir / "vulnerable" / "decompiler.txt",
        case_dir / "fixed" / "decompiler.txt",
    ):
        if path.exists():
            text_parts.append(path.read_text(encoding="utf-8", errors="replace")[:1200].lower())
    joined = "\n".join(text_parts)
    return "placeholder" in joined or "magma-derived source-level excerpt" in joined


def _run_command(args: list[str]) -> CommandResult:
    completed = subprocess.run(args, cwd=Path.cwd(), text=True, capture_output=True, check=False)
    return CommandResult(
        command=" ".join(args),
        returncode=completed.returncode,
        stdout_tail=_tail(completed.stdout),
        stderr_tail=_tail(completed.stderr),
    )


def _tail(value: str, max_chars: int = 4000) -> str:
    if len(value) <= max_chars:
        return value
    return value[-max_chars:]


def _make_zip(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run final AISEC App evaluation and write evaluation artifacts.")
    parser.add_argument("--output-dir", default="output/evaluation")
    parser.add_argument("--max-llm-calls", type=int, default=3)
    parser.add_argument("--cases-root", default="data/cases")
    args = parser.parse_args()

    result = run_final_evaluation(
        output_dir=args.output_dir,
        max_llm_calls=args.max_llm_calls,
        cases_root=args.cases_root,
    )
    print(json.dumps({
        "evaluation_json": str(Path(args.output_dir) / "evaluation.json"),
        "evaluation_markdown": str(Path(args.output_dir) / "evaluation.md"),
        "full_magma_sweep": {
            "total_cases": result["full_magma_sweep"]["total_cases"],
            "detection_correct": result["full_magma_sweep"]["detection_correct"],
            "detection_accuracy": result["full_magma_sweep"]["detection_accuracy"],
            "function_correct": result["full_magma_sweep"]["function_correct"],
            "function_localization_accuracy": result["full_magma_sweep"]["function_localization_accuracy"],
            "verifier_counts": result["full_magma_sweep"]["verifier_counts"],
            "warning": result["full_magma_sweep"]["warning"],
        },
        "scoring_interpretation": result["scoring_interpretation"],
        "llm": {
            "actual_api_calls": result["cost_limited_llm_evaluation"]["actual_api_calls"],
            "cache_hits": result["cost_limited_llm_evaluation"]["cache_hits"],
            "status": result["cost_limited_llm_evaluation"]["status"],
        },
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
