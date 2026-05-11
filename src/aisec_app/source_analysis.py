from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Protocol

from .config import ClaudeSettings, load_claude_settings
from .models import SourceAnalysisReport, SourceArtifact, SourceFinding, Verdict, VerificationStatus


class LLMNotConfiguredError(RuntimeError):
    pass


class SourceAnalyzer(Protocol):
    def analyze(self, artifact: SourceArtifact) -> SourceAnalysisReport:
        ...


@dataclass(slots=True)
class ClaudeSourceAnalyzer:
    settings: ClaudeSettings

    def analyze(self, artifact: SourceArtifact) -> SourceAnalysisReport:
        if not self.settings.is_configured:
            raise LLMNotConfiguredError("ANTHROPIC_API_KEY is not configured. Copy .env.example to .env and set it.")

        try:
            import anthropic
        except ImportError as exc:
            raise LLMNotConfiguredError("anthropic is not installed. Install with `pip install -e .[llm]`.") from exc

        client = anthropic.Anthropic(api_key=self.settings.api_key)
        response = client.messages.create(
            model=self.settings.model,
            max_tokens=self.settings.max_tokens,
            temperature=self.settings.temperature,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": _build_user_prompt(artifact)}],
        )
        text = _extract_text(response)
        payload = _parse_json_object(text)
        return verify_source_report(artifact, payload, model=self.settings.model)


@dataclass(slots=True)
class HeuristicSourceAnalyzer:
    model: str = "heuristic-local"

    def analyze(self, artifact: SourceArtifact) -> SourceAnalysisReport:
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

        payload = {
            "summary": "Local heuristic scan completed.",
            "findings": [finding_to_payload(finding) for finding in findings],
        }
        return verify_source_report(artifact, payload, model=self.model)


def build_source_analyzer(require_llm: bool = True) -> SourceAnalyzer:
    settings = load_claude_settings()
    if settings.is_configured:
        return ClaudeSourceAnalyzer(settings=settings)
    if require_llm:
        raise LLMNotConfiguredError("ANTHROPIC_API_KEY is not configured. Copy .env.example to .env and set it.")
    return HeuristicSourceAnalyzer()


def verify_source_report(artifact: SourceArtifact, payload: dict[str, object], model: str) -> SourceAnalysisReport:
    accepted: list[SourceFinding] = []
    rejected: list[SourceFinding] = []
    for item in _payload_findings(payload):
        finding = _finding_from_payload(item)
        if _quote_is_grounded(artifact.content, finding.evidence_quote):
            accepted.append(finding)
        else:
            rejected.append(finding)

    if accepted:
        status = VerificationStatus.PASS
        verdict = Verdict.VULNERABLE
        rationale = "At least one finding has an evidence quote grounded in the uploaded source."
    elif rejected:
        status = VerificationStatus.REJECT
        verdict = Verdict.NEEDS_REVIEW
        rationale = "All findings were rejected because their evidence quotes were not found in the uploaded source."
    else:
        status = VerificationStatus.REJECT
        verdict = Verdict.NEEDS_REVIEW
        rationale = "No findings were produced."

    return SourceAnalysisReport(
        report_id=_report_id(artifact),
        filename=artifact.filename,
        verdict=verdict,
        verifier_status=status,
        verifier_rationale=rationale,
        model=model,
        summary=str(payload.get("summary") or "No summary provided."),
        findings=accepted,
        rejected_findings=rejected,
    )


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


def _build_user_prompt(artifact: SourceArtifact) -> str:
    numbered = "\n".join(f"{idx + 1}: {line}" for idx, line in enumerate(artifact.content.splitlines()))
    return f"""Analyze this uploaded source file for memory-safety or security-relevant vulnerabilities.

Filename: {artifact.filename}

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


_SYSTEM_PROMPT = """You are a conservative application security analysis agent.
Your job is to inspect source code, identify memory-safety or security-relevant findings, and produce evidence-grounded JSON.
Every finding must include an exact source quote. Unsupported findings are worse than missed findings."""
