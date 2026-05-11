from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from .config import ClaudeSettings, load_claude_settings
from .models import SourceAnalysisReport, SourceArtifact, SourceFinding, Verdict, VerificationStatus


class LLMNotConfiguredError(RuntimeError):
    pass


# ── Exploitability heuristics ─────────────────────────────────────────────────

# Functions that are unconditionally dangerous (no bounds parameter at all)
_ALWAYS_UNSAFE = re.compile(
    r"\b(gets|strcpy|strcat|sprintf|vsprintf|stpcpy|strdupa)\s*\(",
    re.I,
)

# Functions dangerous depending on usage (need to appear in evidence for HIGH+)
_POSSIBLY_UNSAFE = re.compile(
    r"\b(memcpy|memmove|malloc|realloc|calloc|scanf|sscanf|fscanf|read|recv|fread|strdup)\s*\("
    r"|\bmalloc\s*\([^)]*[\+\*]"   # malloc with arithmetic = size confusion risk
    r"|\bfree\s*\([^)]+\)",
    re.I,
)

# Integer operations that can overflow into memory ops
_INT_OVERFLOW_SIGNAL = re.compile(
    r"\b(int|unsigned|size_t|uint\d+_t|long)\s+\w+\s*=\s*[^;]*[\+\-\*][^;]*;",
    re.I,
)

# Common mitigations that meaningfully reduce exploitability
_MITIGATIONS = re.compile(
    r"\b(strncpy|strncat|snprintf|vsnprintf|strlcpy|strlcat|fgets)\s*\("
    r"|\bif\s*\([^)]{0,120}(len|size|count|n|length)\s*[<>]=?\s*",
    re.I,
)

# Severity rank for threshold lookup
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _exploitability_failures(finding: SourceFinding) -> list[str]:
    """Return a list of exploitability failure reasons (empty = passes)."""
    failures: list[str] = []
    sev = finding.severity.lower()
    rank = _SEV_RANK.get(sev, 1)
    evidence = finding.evidence_quote

    # ── Confidence thresholds by severity ─────────────────────────────────────
    thresholds = {4: 0.70, 3: 0.60, 2: 0.50, 1: 0.40}
    min_conf = thresholds.get(rank, 0.40)
    if finding.confidence < min_conf:
        failures.append(
            f"{sev} finding requires confidence ≥{int(min_conf*100)}% (got {int(finding.confidence*100)}%)"
        )

    # ── Verdict strictness ────────────────────────────────────────────────────
    # CRITICAL/HIGH must be VULNERABLE; MEDIUM/LOW allow NEEDS_REVIEW
    if rank >= 3 and finding.verdict != Verdict.VULNERABLE:
        failures.append(
            f"{sev} finding must have VULNERABLE verdict (got {finding.verdict.value})"
        )

    # ── Dangerous operation must appear in evidence for HIGH/CRITICAL ─────────
    if rank >= 3:
        has_danger = bool(
            _ALWAYS_UNSAFE.search(evidence)
            or _POSSIBLY_UNSAFE.search(evidence)
            or _INT_OVERFLOW_SIGNAL.search(evidence)
        )
        if not has_danger:
            failures.append(
                f"{sev} finding evidence contains no dangerous operation or integer arithmetic"
            )

    # ── Mitigation check: if safe alternative present and no unsafe call, reject ─
    if rank >= 3 and not _ALWAYS_UNSAFE.search(evidence):
        if _MITIGATIONS.search(evidence) and not _POSSIBLY_UNSAFE.search(evidence):
            failures.append(
                "evidence shows mitigated code path with no residual dangerous call"
            )

    return failures


REJECT_POLICY = (
    "Reject findings when evidence is missing, evidence is not grounded in the submitted source, "
    "the verdict is not vulnerable, confidence is below threshold, root cause/remediation is missing, "
    "or line references are outside the source bounds. Claude verifier may additionally reject grounded "
    "findings when the quote does not directly support the claim or nearby code mitigates the issue."
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
    def run(self, artifact: SourceArtifact, finding: SourceFinding) -> FindingReview:
        checks: list[str] = []
        failures: list[str] = []

        # ── Evidence presence & grounding ─────────────────────────────────────
        if finding.evidence_quote.strip():
            checks.append("evidence-quote-present")
        else:
            failures.append("missing evidence quote")

        if _quote_is_grounded(artifact.content, finding.evidence_quote):
            checks.append("evidence-grounded-in-source")
        else:
            failures.append("evidence quote not found in source")

        # ── Structural completeness ───────────────────────────────────────────
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
            failures.append("line range outside source bounds")

        # ── Exploitability policy (severity-aware) ────────────────────────────
        exploit_failures = _exploitability_failures(finding)
        if exploit_failures:
            failures.extend(exploit_failures)
        else:
            checks.append("exploitability-policy-passed")

        accepted = not failures
        status = VerificationStatus.PASS if accepted else VerificationStatus.REJECT
        rationale = (
            "Accepted: evidence grounded and exploitability policy passed."
            if accepted
            else "Rejected: " + "; ".join(failures)
        )
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
            triage_agent=HeuristicTriageAgent(),
            finding_agent=ClaudeFindingAgent(client),
            verifier_agent=EvidencePolicyVerifier(),
            reporter_agent=SourceReporterAgent(),
            model=settings.model,
        )


def build_source_analyzer(require_llm: bool = True) -> SourceAnalyzer:
    settings = load_claude_settings()
    if settings.is_configured:
        return ClaudeSourceAnalyzer(settings=settings)
    if require_llm:
        raise LLMNotConfiguredError("ANTHROPIC_API_KEY is not configured. Copy .env.example to .env and set it.")
    return HeuristicSourceAnalyzer()


def verify_source_report(artifact: SourceArtifact, payload: dict[str, object], model: str) -> SourceAnalysisReport:
    findings = [_finding_from_payload(item) for item in _payload_findings(payload)]
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
    norm_source = _normalize(source)
    # Split on ellipsis markers and check each fragment independently
    fragments = re.split(r"\.\.\.|…|\[\.\.\.\]|\[\.\.\.?\]", quote)
    for frag in fragments:
        norm = _normalize(frag)
        if not norm:
            continue
        # Full fragment match (≥8 chars is specific enough for a code token)
        if len(norm) >= 8 and norm in norm_source:
            return True
        # Sliding 12-char window within this fragment
        if len(norm) >= 12:
            for i in range(len(norm) - 11):
                if norm[i : i + 12] in norm_source:
                    return True
    return False


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
    return f"""Analyze this source file for memory-safety or security-relevant vulnerabilities.

Filename: {artifact.filename}
Candidate functions: {triage.candidate_functions}
Risk signals: {triage.risk_signals}

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
- If evidence is weak, use verdict "needs_review".
- Do not invent functions, line numbers, or code.
- Prefer rejecting uncertainty over unsupported claims.

Source:
{numbered}
"""


def _verifier_prompt(artifact: SourceArtifact, finding: SourceFinding) -> str:
    numbered = _numbered_source(artifact)
    return f"""Review this candidate finding skeptically.

Finding:
{json.dumps(finding_to_payload(finding), indent=2, ensure_ascii=False)}

Return JSON only:
{{
  "accepted": false,
  "rationale": "why accepted or rejected",
  "checks": ["quote supports claim"]
}}

Reject if:
- the evidence quote does not directly support the root cause
- a bounds check or validation in nearby code appears to mitigate the issue
- severity or confidence is overstated
- the finding depends on code not present in the source

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


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item.strip()]


def _line_range_plausible(source: str, finding: SourceFinding) -> bool:
    line_count = max(1, len(source.splitlines()))
    if finding.line_start is None:
        return True  # no location info — don't penalise
    end = finding.line_end if finding.line_end is not None else finding.line_start
    return 1 <= finding.line_start <= end <= line_count


def _join_review_rationales(reviews: list[FindingReview]) -> str:
    if not reviews:
        return "No finding reviews were produced."
    return " | ".join(f"{review.status.value}: {review.rationale}" for review in reviews)
