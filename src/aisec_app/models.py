from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Verdict(str, Enum):
    VULNERABLE = "vulnerable"
    FIXED = "fixed"
    NEEDS_REVIEW = "needs_review"


class VerificationStatus(str, Enum):
    PASS = "pass"
    REJECT = "reject"
    NEEDS_REVIEW = "needs_review"


@dataclass(slots=True)
class BinaryMetadata:
    path: str
    architecture: str
    compiler: str
    optimization: str


@dataclass(slots=True)
class CVECase:
    case_id: str
    cve_id: str
    advisory: str
    binary_metadata: BinaryMetadata
    patch_diff: str
    decompiler_excerpt: str


@dataclass(slots=True)
class CaseLabels:
    expected_verdict: Verdict
    vulnerable_function: str
    vulnerable_address: str | None = None


@dataclass(slots=True)
class CaseRecord:
    case: CVECase
    labels: CaseLabels


@dataclass(slots=True)
class Evidence:
    source: str
    summary: str
    artifact_ref: str | None = None


@dataclass(slots=True)
class TriageResult:
    candidate_cves: list[str]
    rationale: str


@dataclass(slots=True)
class PatchPattern:
    root_cause: str
    fix_intent: str
    vulnerable_api: str | None = None
    evidence: list[Evidence] = field(default_factory=list)


@dataclass(slots=True)
class FunctionMatch:
    function_name: str
    address: str
    confidence: float
    verdict: Verdict
    rationale: str
    evidence: list[Evidence] = field(default_factory=list)


@dataclass(slots=True)
class VerificationDecision:
    status: VerificationStatus
    rationale: str
    checks: list[str]


@dataclass(slots=True)
class AnalysisReport:
    case_id: str
    cve_id: str
    verdict: Verdict
    function_name: str
    function_address: str
    confidence: float
    why_vulnerable: str
    patch_summary: str
    remediation_guidance: str
    verifier_status: VerificationStatus
    verifier_rationale: str
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class SourceArtifact:
    filename: str
    content: str


@dataclass(slots=True)
class SourceFinding:
    title: str
    verdict: Verdict
    severity: str
    function_name: str
    line_start: int | None
    line_end: int | None
    confidence: float
    root_cause: str
    evidence_quote: str
    remediation: str


@dataclass(slots=True)
class SourceAnalysisReport:
    report_id: str
    filename: str
    verdict: Verdict
    verifier_status: VerificationStatus
    verifier_rationale: str
    model: str
    summary: str
    findings: list[SourceFinding] = field(default_factory=list)
    rejected_findings: list[SourceFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class ProjectAnalysisReport:
    project_id: str
    archive_name: str
    total_files: int
    analyzed_files: int
    skipped_files: list[str]
    verifier_status: VerificationStatus
    summary: str
    file_reports: list[SourceAnalysisReport] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
