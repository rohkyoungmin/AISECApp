from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Protocol

from .config import ClaudeSettings, load_claude_settings
from .models import CVECandidateSummary, SourceAnalysisReport, SourceArtifact, SourceFinding, Verdict, VerificationStatus


class LLMNotConfiguredError(RuntimeError):
    pass


REJECT_POLICY = (
    "Reject findings when evidence is missing, evidence is not grounded in the submitted source, "
    "the verdict is not vulnerable, deterministic confidence is below threshold, root cause/remediation "
    "is missing, or line references are outside the source bounds. Claude verifier may additionally reject "
    "grounded findings when the quote does not directly support the claim or nearby code mitigates the issue."
)


DANGEROUS_CALL_WEIGHTS = {
    # C standard unsafe functions
    "gets": 0.30,
    "strcpy": 0.24,
    "strcat": 0.22,
    "sprintf": 0.22,
    "memcpy": 0.18,
    "scanf": 0.14,
    "recv": 0.12,
    "fread": 0.10,
    # NEON / SIMD intrinsics that read/write without built-in bounds checks
    "vld1q_u8": 0.20,
    "vld1q_u16": 0.18,
    "vld1q_u32": 0.18,
    "vst1q_u8": 0.20,
    "vst1q_u16": 0.18,
    "vst4q_u8": 0.22,
    "vst3_u8": 0.18,
    "vst3q_u8": 0.18,
}

MITIGATION_PATTERNS = (
    r"\bsizeof\s*\(",
    r"\bstrncpy\s*\(",
    r"\bsnprintf\s*\(",
    r"\bmemcpy_s\s*\(",
    r"\bstrlcpy\s*\(",
    r"\bif\s*\([^)]*(?:<|<=|>|>=)",
    r"\bbounds?\b",
    r"\blimit\b",
    r"\bvalidated?\b",
)


class SourceAnalyzer(Protocol):
    def analyze(self, artifact: SourceArtifact) -> SourceAnalysisReport:
        ...


@dataclass(slots=True)
class TriageResult:
    should_analyze: bool
    candidate_functions: list[str] = field(default_factory=list)
    risk_signals: list[str] = field(default_factory=list)
    rationale: str = ""


@dataclass(slots=True)
class FindingReview:
    finding: SourceFinding
    accepted: bool
    status: VerificationStatus
    rationale: str
    checks: list[str] = field(default_factory=list)


class TriageAgent(Protocol):
    def run(self, artifact: SourceArtifact) -> TriageResult:
        ...


class FindingAgent(Protocol):
    def run(self, artifact: SourceArtifact, triage: TriageResult) -> list[SourceFinding]:
        ...


class VerifierAgent(Protocol):
    def run(self, artifact: SourceArtifact, finding: SourceFinding) -> FindingReview:
        ...


class ReporterAgent(Protocol):
    def run(
        self,
        artifact: SourceArtifact,
        triage: TriageResult,
        reviews: list[FindingReview],
        model: str,
    ) -> SourceAnalysisReport:
        ...


@dataclass(slots=True)
class MultiAgentSourceAnalyzer:
    triage_agent: TriageAgent
    finding_agent: FindingAgent
    verifier_agent: VerifierAgent
    reporter_agent: ReporterAgent
    model: str
    progress: Callable[[dict], None] | None = field(default=None, repr=False)

    def analyze(self, artifact: SourceArtifact) -> SourceAnalysisReport:
        if self.progress:
            self.progress({"type": "stage", "stage": "triage", "file": artifact.filename})
        triage = self.triage_agent.run(artifact)

        if self.progress:
            self.progress({"type": "stage", "stage": "finding", "file": artifact.filename})
        findings = self.finding_agent.run(artifact, triage) if triage.should_analyze else []
        findings = [calibrate_finding_confidence(artifact, finding) for finding in findings]

        if self.progress:
            self.progress({"type": "stage", "stage": "verification", "file": artifact.filename})
        reviews = [self.verifier_agent.run(artifact, finding) for finding in findings]

        if self.progress:
            self.progress({"type": "stage", "stage": "reporting", "file": artifact.filename})
        return self.reporter_agent.run(artifact, triage, reviews, self.model)


@dataclass(slots=True)
class ClaudeClient:
    settings: ClaudeSettings

    def complete_json(self, system: str, user: str) -> dict[str, object]:
        if not self.settings.is_configured:
            raise LLMNotConfiguredError("ANTHROPIC_API_KEY is not configured. Copy .env.example to .env and set it.")

        try:
            import anthropic
        except ImportError as exc:
            raise LLMNotConfiguredError("anthropic is not installed. Install with `pip install -e .[llm]`.") from exc

        client = anthropic.Anthropic(api_key=self.settings.api_key)
        try:
            response = client.messages.create(
                model=self.settings.model,
                max_tokens=self.settings.max_tokens,
                temperature=self.settings.temperature,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except anthropic.NotFoundError as exc:
            raise LLMNotConfiguredError(
                f"Anthropic model `{self.settings.model}` is not available for this API key. "
                "Set ANTHROPIC_MODEL in .env to a model returned by the Anthropic Models API. "
                "Current recommended default: claude-sonnet-4-6."
            ) from exc
        return _parse_json_object(_extract_text(response))


@dataclass(slots=True)
class ClaudeTriageAgent:
    client: ClaudeClient

    def run(self, artifact: SourceArtifact) -> TriageResult:
        payload = self.client.complete_json(
            system=(
                "You are a conservative source triage security agent. "
                "Select functions and risk signals worth deeper analysis. Return JSON only."
            ),
            user=_triage_prompt(artifact),
        )
        return TriageResult(
            should_analyze=bool(payload.get("should_analyze", True)),
            candidate_functions=_string_list(payload.get("candidate_functions")),
            risk_signals=_string_list(payload.get("risk_signals")),
            rationale=str(payload.get("rationale") or ""),
        )


@dataclass(slots=True)
class ClaudeFindingAgent:
    client: ClaudeClient

    def run(self, artifact: SourceArtifact, triage: TriageResult) -> list[SourceFinding]:
        payload = self.client.complete_json(
            system=(
                "You are a source vulnerability analysis agent. Produce candidate findings only when "
                "you can cite exact source evidence. Return JSON only."
            ),
            user=_finding_prompt(artifact, triage),
        )
        return [_finding_from_payload(item) for item in _payload_findings(payload)]


@dataclass(slots=True)
class ClaudeSkepticVerifierAgent:
    client: ClaudeClient
    deterministic_policy: "EvidencePolicyVerifier" = field(default_factory=lambda: EvidencePolicyVerifier())

    def run(self, artifact: SourceArtifact, finding: SourceFinding) -> FindingReview:
        policy_review = self.deterministic_policy.run(artifact, finding)
        if not policy_review.accepted:
            return policy_review

        payload = self.client.complete_json(
            system=(
                "You are a skeptical security verifier. Your job is to reject unsupported findings. "
                "Accept only if the evidence quote directly supports the claim. Return JSON only."
            ),
            user=_verifier_prompt(artifact, finding),
        )
        accepted = bool(payload.get("accepted", False))
        status = VerificationStatus.PASS if accepted else VerificationStatus.REJECT
        rationale = str(payload.get("rationale") or "Claude verifier did not provide a rationale.")
        checks = [*policy_review.checks, *_string_list(payload.get("checks"))]
        return FindingReview(finding=finding, accepted=accepted, status=status, rationale=rationale, checks=checks)


@dataclass(slots=True)
class EvidencePolicyVerifier:
    min_confidence: float = 0.5

    def run(self, artifact: SourceArtifact, finding: SourceFinding) -> FindingReview:
        checks: list[str] = []
        failures: list[str] = []

        if finding.evidence_quote.strip():
            checks.append("evidence-quote-present")
        else:
            failures.append("missing evidence quote")

        if _quote_is_grounded(artifact.content, finding.evidence_quote):
            checks.append("evidence-grounded-in-source")
        else:
            failures.append("evidence quote is not present in source")

        if finding.verdict == Verdict.VULNERABLE:
            checks.append("vulnerable-verdict")
        else:
            failures.append("finding verdict is not vulnerable")

        if finding.confidence >= self.min_confidence:
            checks.append("deterministic-confidence-threshold-met")
        else:
            failures.append("deterministic confidence below threshold")

        if finding.root_cause.strip():
            checks.append("root-cause-present")
        else:
            failures.append("missing root cause")

        if finding.remediation.strip():
            checks.append("remediation-present")
        else:
            failures.append("missing remediation")

        if _line_range_plausible(artifact.content, finding):
            checks.append("line-range-plausible")
        else:
            failures.append("line range is outside source bounds")

        dangerous_calls = _dangerous_calls(finding.evidence_quote)
        if dangerous_calls:
            checks.append("dangerous-operation-present")
        elif finding.severity.lower() in {"high", "critical"}:
            failures.append("high severity finding lacks a dangerous operation in evidence")

        if _mitigation_near_finding(artifact.content, finding):
            checks.append("nearby-mitigation-detected")

        accepted = not failures
        status = VerificationStatus.PASS if accepted else VerificationStatus.REJECT
        rationale = "Accepted by deterministic evidence policy." if accepted else "Rejected: " + "; ".join(failures)
        return FindingReview(finding=finding, accepted=accepted, status=status, rationale=rationale, checks=checks)


class HeuristicTriageAgent:
    def run(self, artifact: SourceArtifact) -> TriageResult:
        functions = _extract_function_names(artifact.content)
        risk_signals = _risk_signals(artifact.content)
        return TriageResult(
            should_analyze=bool(risk_signals),
            candidate_functions=functions,
            risk_signals=risk_signals,
            rationale="Local triage found risky API usage." if risk_signals else "No local risk signals found.",
        )


class HeuristicFindingAgent:
    def run(self, artifact: SourceArtifact, triage: TriageResult) -> list[SourceFinding]:
        findings: list[SourceFinding] = []
        lines = artifact.content.splitlines()
        current_function = "unknown"
        function_pattern = re.compile(r"\b([A-Za-z_]\w*)\s*\([^;]*\)\s*\{")
        risky_calls = {
            "gets": "Unbounded input read can overflow the destination buffer.",
            "strcpy": "Unbounded string copy can overflow the destination buffer.",
            "strcat": "Unbounded string concatenation can overflow the destination buffer.",
            "sprintf": "Unbounded formatting can overflow the destination buffer.",
            "memcpy": "Memory copy requires a trusted size check before copying.",
        }

        for line_no, line in enumerate(lines, start=1):
            match = function_pattern.search(line)
            if match:
                current_function = match.group(1)
            for call, root_cause in risky_calls.items():
                if re.search(rf"\b{call}\s*\(", line):
                    findings.append(
                        SourceFinding(
                            title=f"Potential unsafe {call} use",
                            verdict=Verdict.VULNERABLE,
                            severity="medium",
                            function_name=current_function,
                            line_start=line_no,
                            line_end=line_no,
                            confidence=0.62,
                            root_cause=root_cause,
                            evidence_quote=line.strip(),
                            remediation=f"Add bounds validation or replace `{call}` with a bounded alternative.",
                        )
                    )
        return findings


class SourceReporterAgent:
    def run(
        self,
        artifact: SourceArtifact,
        triage: TriageResult,
        reviews: list[FindingReview],
        model: str,
    ) -> SourceAnalysisReport:
        accepted = [review.finding for review in reviews if review.accepted]
        rejected = [review.finding for review in reviews if not review.accepted]

        if accepted:
            status = VerificationStatus.PASS
            verdict = Verdict.VULNERABLE
            rationale = _join_review_rationales(reviews)
        elif rejected:
            status = VerificationStatus.REJECT
            verdict = Verdict.NEEDS_REVIEW
            rationale = _join_review_rationales(reviews)
        else:
            status = VerificationStatus.REJECT
            verdict = Verdict.NEEDS_REVIEW
            rationale = "No findings were produced by the finding agent."

        summary = (
            f"Triage signals: {', '.join(triage.risk_signals) or 'none'}. "
            f"Accepted findings: {len(accepted)}. Rejected findings: {len(rejected)}."
        )
        return SourceAnalysisReport(
            report_id=_report_id(artifact),
            filename=artifact.filename,
            verdict=verdict,
            verifier_status=status,
            verifier_rationale=rationale,
            model=model,
            summary=summary,
            findings=accepted,
            rejected_findings=rejected,
        )


class HeuristicSourceAnalyzer(MultiAgentSourceAnalyzer):
    def __init__(self, model: str = "heuristic-multi-agent") -> None:
        super().__init__(
            triage_agent=HeuristicTriageAgent(),
            finding_agent=HeuristicFindingAgent(),
            verifier_agent=EvidencePolicyVerifier(),
            reporter_agent=SourceReporterAgent(),
            model=model,
        )


class ClaudeSourceAnalyzer(MultiAgentSourceAnalyzer):
    def __init__(self, settings: ClaudeSettings) -> None:
        client = ClaudeClient(settings=settings)
        super().__init__(
            triage_agent=ClaudeTriageAgent(client),
            finding_agent=ClaudeFindingAgent(client),
            verifier_agent=ClaudeSkepticVerifierAgent(client),
            reporter_agent=SourceReporterAgent(),
            model=settings.model,
        )


def build_source_analyzer(require_llm: bool = True, force_heuristic: bool = False) -> SourceAnalyzer:
    if force_heuristic:
        return HeuristicSourceAnalyzer()
    settings = load_claude_settings()
    if settings.is_configured:
        return ClaudeSourceAnalyzer(settings=settings)
    if require_llm:
        raise LLMNotConfiguredError("ANTHROPIC_API_KEY is not configured. Copy .env.example to .env and set it.")
    return HeuristicSourceAnalyzer()


class ClaudeFindingCVELinker:
    """Single Claude call that links accepted findings to relevant CVE candidates."""

    def __init__(self, client: ClaudeClient) -> None:
        self._client = client

    def link(
        self,
        file_reports: list[SourceAnalysisReport],
        cve_candidates: list[CVECandidateSummary],
    ) -> list[SourceAnalysisReport]:
        all_findings = [
            (report.filename, i, finding)
            for report in file_reports
            for i, finding in enumerate(report.findings)
        ]
        if not all_findings or not cve_candidates:
            return file_reports

        findings_text = "\n".join(
            f"- key=\"{fn}::{f.title}\" severity={f.severity} "
            f"root_cause=\"{f.root_cause[:120]}\""
            for fn, _, f in all_findings
        )
        cves_text = "\n".join(
            f"- {c.cve_id} CVSS={c.cvss_score or '?'} {c.cvss_severity} "
            f"CWE={','.join(c.weaknesses) or 'unknown'}: {c.description[:200]}"
            for c in cve_candidates
        )

        try:
            payload = self._client.complete_json(
                system=(
                    "You are a security analyst linking findings to CVE candidates. "
                    "Only link a CVE when the vulnerability class genuinely matches. "
                    "Return JSON only."
                ),
                user=f"""For each finding, list CVE IDs that match its vulnerability class (0–3 per finding).

Findings:
{findings_text}

CVE Candidates:
{cves_text}

Return JSON:
{{
  "links": [
    {{"key": "filename::finding title", "cve_ids": ["CVE-XXXX-XXXX"]}}
  ]
}}
""",
            )
        except Exception:
            return file_reports

        link_map: dict[str, list[str]] = {}
        for item in payload.get("links") or []:
            if isinstance(item, dict):
                key = item.get("key")
                ids = item.get("cve_ids")
                if isinstance(key, str) and isinstance(ids, list):
                    link_map[key] = [str(c) for c in ids if isinstance(c, str)]

        updated: list[SourceAnalysisReport] = []
        for report in file_reports:
            new_findings = [
                replace(f, linked_cves=link_map.get(f"{report.filename}::{f.title}", []))
                for f in report.findings
            ]
            updated.append(replace(report, findings=new_findings))
        return updated


def build_finding_cve_linker() -> ClaudeFindingCVELinker | None:
    settings = load_claude_settings()
    if not settings.is_configured:
        return None
    return ClaudeFindingCVELinker(ClaudeClient(settings=settings))


def verify_source_report(artifact: SourceArtifact, payload: dict[str, object], model: str) -> SourceAnalysisReport:
    findings = [
        calibrate_finding_confidence(artifact, _finding_from_payload(item))
        for item in _payload_findings(payload)
    ]
    reviews = [EvidencePolicyVerifier().run(artifact, finding) for finding in findings]
    triage = TriageResult(
        should_analyze=bool(findings),
        candidate_functions=[finding.function_name for finding in findings],
        risk_signals=["legacy-payload"],
        rationale="Compatibility path for pre-agent report payloads.",
    )
    return SourceReporterAgent().run(artifact, triage, reviews, model)


def finding_to_payload(finding: SourceFinding) -> dict[str, object]:
    return {
        "title": finding.title,
        "verdict": finding.verdict.value,
        "severity": finding.severity,
        "function_name": finding.function_name,
        "line_start": finding.line_start,
        "line_end": finding.line_end,
        "confidence": finding.confidence,
        "root_cause": finding.root_cause,
        "evidence_quote": finding.evidence_quote,
        "remediation": finding.remediation,
    }


def calibrate_finding_confidence(artifact: SourceArtifact, finding: SourceFinding) -> SourceFinding:
    """Replace model self-confidence with a deterministic evidence score."""
    score = deterministic_confidence(artifact, finding)
    return replace(finding, confidence=score)


def deterministic_confidence(artifact: SourceArtifact, finding: SourceFinding) -> float:
    score = 0.10

    if finding.verdict == Verdict.VULNERABLE:
        score += 0.10
    if _quote_is_grounded(artifact.content, finding.evidence_quote):
        score += 0.20
    if _line_range_plausible(artifact.content, finding):
        score += 0.10
    if finding.root_cause.strip():
        score += 0.10
    if finding.remediation.strip():
        score += 0.10

    dangerous_calls = _dangerous_calls(finding.evidence_quote)
    if dangerous_calls:
        score += max(DANGEROUS_CALL_WEIGHTS[call] for call in dangerous_calls)

    if finding.function_name != "unknown" and finding.function_name in _extract_function_names(artifact.content):
        score += 0.05

    if _mitigation_near_finding(artifact.content, finding):
        score -= 0.25

    return round(max(0.0, min(1.0, score)), 2)


def _finding_from_payload(payload: dict[str, object]) -> SourceFinding:
    return SourceFinding(
        title=str(payload.get("title") or "Untitled finding"),
        verdict=_parse_verdict(payload.get("verdict")),
        severity=str(payload.get("severity") or "unknown"),
        function_name=str(payload.get("function_name") or "unknown"),
        line_start=_optional_int(payload.get("line_start")),
        line_end=_optional_int(payload.get("line_end")),
        confidence=_bounded_float(payload.get("confidence"), default=0.0),
        root_cause=str(payload.get("root_cause") or ""),
        evidence_quote=str(payload.get("evidence_quote") or ""),
        remediation=str(payload.get("remediation") or ""),
    )


def _payload_findings(payload: dict[str, object]) -> list[dict[str, object]]:
    raw_findings = payload.get("findings")
    if not isinstance(raw_findings, list):
        return []
    return [item for item in raw_findings if isinstance(item, dict)]


def _quote_is_grounded(source: str, quote: str) -> bool:
    normalized_quote = _normalize(quote)
    if not normalized_quote:
        return False
    return normalized_quote in _normalize(source)


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _parse_verdict(value: object) -> Verdict:
    try:
        return Verdict(str(value))
    except ValueError:
        return Verdict.NEEDS_REVIEW


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _bounded_float(value: object, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, parsed))


def _report_id(artifact: SourceArtifact) -> str:
    digest = hashlib.sha256(artifact.content.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"source-{digest}"


def _extract_text(response: object) -> str:
    content = getattr(response, "content", [])
    chunks: list[str] = []
    for block in content:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            chunks.append(text)
    return "\n".join(chunks)


def _parse_json_object(text: str) -> dict[str, object]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.S)
        if not match:
            raise
        value = json.loads(match.group(0))
    if not isinstance(value, dict):
        raise ValueError("LLM response must be a JSON object")
    return value


def _triage_prompt(artifact: SourceArtifact) -> str:
    numbered = _numbered_source(artifact)
    return f"""Triage this source file for security-relevant analysis priority.

Filename: {artifact.filename}

Return JSON only:
{{
  "should_analyze": true,
  "candidate_functions": ["function_a"],
  "risk_signals": ["memcpy", "parser", "external input"],
  "rationale": "short rationale"
}}

Source:
{numbered}
"""


def _finding_prompt(artifact: SourceArtifact, triage: TriageResult) -> str:
    numbered = _numbered_source(artifact)
    context = artifact.context.strip() or "No external CVE candidate context was provided."
    return f"""Analyze this source file for memory-safety or security-relevant vulnerabilities.

Filename: {artifact.filename}
Candidate functions: {triage.candidate_functions}
Risk signals: {triage.risk_signals}
External CVE candidate context:
{context}

Return JSON only. The JSON schema is:
{{
  "summary": "short summary",
  "findings": [
    {{
      "title": "short title",
      "verdict": "vulnerable|fixed|needs_review",
      "severity": "low|medium|high|critical",
      "function_name": "function name or unknown",
      "line_start": 1,
      "line_end": 1,
      "confidence": 0.0,
      "root_cause": "why this is risky",
      "evidence_quote": "exact contiguous quote copied from the source",
      "remediation": "specific fix guidance"
    }}
  ]
}}

Rules:
- evidence_quote must be an exact contiguous substring from the uploaded source.
- Do not use the external CVE context as evidence_quote.
- If evidence is weak, use verdict "needs_review".
- Do not invent functions, line numbers, or code.
- Prefer rejecting uncertainty over unsupported claims.

Source:
{numbered}
"""


def _verifier_prompt(artifact: SourceArtifact, finding: SourceFinding) -> str:
    numbered = _numbered_source(artifact)
    return f"""Review this candidate finding.

Finding:
{json.dumps(finding_to_payload(finding), indent=2, ensure_ascii=False)}

Return JSON only:
{{
  "accepted": true,
  "rationale": "why accepted or rejected",
  "checks": ["quote supports claim"]
}}

Accept if the evidence quote directly supports the root cause and the vulnerability is plausible.

Reject only if:
- the evidence quote does not appear in the source or does not support the root cause
- the source clearly contains a mitigating bounds check that specifically addresses this exact access
- the finding depends on code not present in the source

Note: the presence of unrelated bounds checks or loop conditions nearby does NOT by itself justify rejection.
For SIMD/NEON intrinsics, assess whether the calling code guarantees sufficient buffer size before
the intrinsic call — if that guarantee is absent or unclear, accept the finding.

Source:
{numbered}
"""


def _numbered_source(artifact: SourceArtifact) -> str:
    return "\n".join(f"{idx + 1}: {line}" for idx, line in enumerate(artifact.content.splitlines()))


def _extract_function_names(source: str) -> list[str]:
    names: list[str] = []
    pattern = re.compile(r"\b([A-Za-z_]\w*)\s*\([^;]*\)\s*\{")
    for match in pattern.finditer(source):
        name = match.group(1)
        if name not in names:
            names.append(name)
    return names


def _risk_signals(source: str) -> list[str]:
    signals: list[str] = []
    for token in ("gets", "strcpy", "strcat", "sprintf", "memcpy", "malloc", "realloc", "fread", "recv"):
        if re.search(rf"\b{re.escape(token)}\s*\(", source):
            signals.append(token)
    return signals


def _dangerous_calls(text: str) -> list[str]:
    calls: list[str] = []
    for call in DANGEROUS_CALL_WEIGHTS:
        if re.search(rf"\b{re.escape(call)}\s*\(", text):
            calls.append(call)
    return calls


def _mitigation_near_finding(source: str, finding: SourceFinding) -> bool:
    lines = source.splitlines()
    if not lines:
        return False

    if finding.line_start is not None:
        start = max(0, finding.line_start - 4)
        end = min(len(lines), (finding.line_end or finding.line_start) + 3)
        window = "\n".join(lines[start:end])
    elif finding.evidence_quote.strip():
        normalized_quote = _normalize(finding.evidence_quote)
        window = ""
        for index, line in enumerate(lines):
            if normalized_quote and _normalize(line) in normalized_quote:
                start = max(0, index - 3)
                end = min(len(lines), index + 4)
                window = "\n".join(lines[start:end])
                break
    else:
        window = ""

    if not window:
        return False
    return any(re.search(pattern, window, flags=re.IGNORECASE) for pattern in MITIGATION_PATTERNS)


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item.strip()]


def _line_range_plausible(source: str, finding: SourceFinding) -> bool:
    line_count = max(1, len(source.splitlines()))
    if finding.line_start is None and finding.line_end is None:
        return True
    if finding.line_start is None or finding.line_end is None:
        return False
    return 1 <= finding.line_start <= finding.line_end <= line_count


def _join_review_rationales(reviews: list[FindingReview]) -> str:
    if not reviews:
        return "No finding reviews were produced."
    return " | ".join(f"{review.status.value}: {review.rationale}" for review in reviews)
