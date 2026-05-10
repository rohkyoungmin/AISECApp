from __future__ import annotations

from dataclasses import asdict
from typing import Protocol

from .models import (
    AnalysisReport,
    CVECase,
    Evidence,
    FunctionMatch,
    PatchPattern,
    TriageResult,
    Verdict,
    VerificationDecision,
    VerificationStatus,
)


class TriageStage(Protocol):
    def run(self, case: CVECase) -> TriageResult:
        ...


class PatchAnalysisStage(Protocol):
    def run(self, case: CVECase, triage: TriageResult) -> PatchPattern:
        ...


class BinaryMatchStage(Protocol):
    def run(self, case: CVECase, patch: PatchPattern) -> FunctionMatch:
        ...


class VerificationStage(Protocol):
    def run(
        self,
        case: CVECase,
        patch: PatchPattern,
        match: FunctionMatch,
    ) -> VerificationDecision:
        ...


class ReportStage(Protocol):
    def run(
        self,
        case: CVECase,
        patch: PatchPattern,
        match: FunctionMatch,
        verification: VerificationDecision,
    ) -> AnalysisReport:
        ...


class SimpleTriageAgent:
    def run(self, case: CVECase) -> TriageResult:
        rationale = (
            "Selected the advertised CVE as the primary candidate because the "
            "demo input carries a single advisory and a matching binary context."
        )
        return TriageResult(candidate_cves=[case.cve_id], rationale=rationale)


class SimplePatchAnalysisAgent:
    def run(self, case: CVECase, triage: TriageResult) -> PatchPattern:
        lower_diff = case.patch_diff.lower()
        if "memcpy" in lower_diff and "sizeof" in lower_diff:
            root_cause = "Length validation is missing before a copy into a fixed-size buffer."
            fix_intent = "Introduce a guard that rejects oversized input before copying."
            vulnerable_api = "memcpy"
            evidence_summary = "The patched version adds a size check before copying user-controlled input."
        elif "max_palette_length" in lower_diff and "png_handle_plte" in lower_diff:
            root_cause = "Palette length can exceed the maximum palette size before PLTE entries are processed."
            fix_intent = "Clamp the PLTE entry count to max_palette_length before palette processing continues."
            vulnerable_api = "palette entry processing"
            evidence_summary = "The fixed build clamps num to max_palette_length and the canary flags num > max_palette_length."
        else:
            root_cause = "Potential unsafe memory operation identified in the diff."
            fix_intent = "Add validation and safe bounds handling around the changed code path."
            vulnerable_api = None
            evidence_summary = "The patch changes validation around a potentially unsafe code path."

        evidence = [
            Evidence(
                source="patch_diff",
                summary=evidence_summary,
                artifact_ref="patch:lines-1-3",
            )
        ]
        return PatchPattern(
            root_cause=root_cause,
            fix_intent=fix_intent,
            vulnerable_api=vulnerable_api,
            evidence=evidence,
        )


class SimpleBinaryMatchAgent:
    def run(self, case: CVECase, patch: PatchPattern) -> FunctionMatch:
        excerpt = case.decompiler_excerpt.lower()
        function_name = "unknown"
        address = "unknown"
        confidence = 0.45
        verdict = Verdict.NEEDS_REVIEW
        rationale = "The current demo matcher found only weak evidence in the decompiler excerpt."
        evidence: list[Evidence] = []

        if "parse_header" in excerpt:
            function_name = "parse_header"
        if "0x401234" in excerpt:
            address = "0x401234"
        if "png_handle_plte" in excerpt:
            function_name = "png_handle_PLTE"
        if "source:pngrutil.c:984" in excerpt:
            address = "source:pngrutil.c:984"
        if "memcpy" in excerpt and "input_len" in excerpt:
            confidence = 0.87
            verdict = Verdict.VULNERABLE
            rationale = (
                "Decompiler evidence shows the same unchecked copy pattern described by the patch analysis."
            )
            evidence.append(
                Evidence(
                    source="decompiler_excerpt",
                    summary="The function copies attacker-controlled input into a buffer before validation.",
                    artifact_ref="decompiler:parse_header",
                )
            )
        elif (
            patch.vulnerable_api == "palette entry processing"
            and "num > max_palette_length" in excerpt
            and "i < num" in excerpt
        ):
            confidence = 0.82
            verdict = Verdict.VULNERABLE
            rationale = (
                "Binary-side evidence shows PLTE entry processing can continue with num greater than max_palette_length."
            )
            evidence.append(
                Evidence(
                    source="decompiler_excerpt",
                    summary="The vulnerable PLTE handler processes palette entries using an unclamped attacker-controlled count.",
                    artifact_ref="decompiler:png_handle_PLTE",
                )
            )

        return FunctionMatch(
            function_name=function_name,
            address=address,
            confidence=confidence,
            verdict=verdict,
            rationale=rationale,
            evidence=evidence,
        )


class SimpleVerifier:
    def run(
        self,
        case: CVECase,
        patch: PatchPattern,
        match: FunctionMatch,
    ) -> VerificationDecision:
        checks: list[str] = []

        if patch.evidence:
            checks.append("patch-evidence-present")
        if match.evidence:
            checks.append("binary-evidence-present")
        if match.verdict == Verdict.VULNERABLE:
            checks.append("verdict-supported")
        if match.confidence >= 0.80:
            checks.append("confidence-threshold-met")

        if {"patch-evidence-present", "binary-evidence-present", "verdict-supported"}.issubset(checks):
            status = VerificationStatus.PASS
            rationale = "Patch and binary evidence agree on the vulnerable behavior."
        elif not match.evidence:
            status = VerificationStatus.REJECT
            rationale = "The finding is rejected because no binary-side evidence was produced."
        else:
            status = VerificationStatus.NEEDS_REVIEW
            rationale = "Some evidence exists, but it is not strong enough for automatic acceptance."

        return VerificationDecision(status=status, rationale=rationale, checks=checks)


class SimpleReporter:
    def run(
        self,
        case: CVECase,
        patch: PatchPattern,
        match: FunctionMatch,
        verification: VerificationDecision,
    ) -> AnalysisReport:
        remediation_guidance = (
            f"Review `{match.function_name}` and insert bounds validation before `{patch.vulnerable_api or 'the affected memory operation'}`."
        )
        return AnalysisReport(
            case_id=case.case_id,
            cve_id=case.cve_id,
            verdict=match.verdict,
            function_name=match.function_name,
            function_address=match.address,
            confidence=match.confidence,
            why_vulnerable=match.rationale,
            patch_summary=patch.fix_intent,
            remediation_guidance=remediation_guidance,
            verifier_status=verification.status,
            verifier_rationale=verification.rationale,
            evidence=[*patch.evidence, *match.evidence],
        )


class AnalysisPipeline:
    def __init__(
        self,
        triage: TriageStage,
        patch_analysis: PatchAnalysisStage,
        binary_match: BinaryMatchStage,
        verifier: VerificationStage,
        reporter: ReportStage,
    ) -> None:
        self.triage = triage
        self.patch_analysis = patch_analysis
        self.binary_match = binary_match
        self.verifier = verifier
        self.reporter = reporter

    def run(self, case: CVECase) -> AnalysisReport:
        triage_result = self.triage.run(case)
        patch_pattern = self.patch_analysis.run(case, triage_result)
        match = self.binary_match.run(case, patch_pattern)
        verification = self.verifier.run(case, patch_pattern, match)
        return self.reporter.run(case, patch_pattern, match, verification)

    def snapshot(self, case: CVECase) -> dict[str, object]:
        triage_result = self.triage.run(case)
        patch_pattern = self.patch_analysis.run(case, triage_result)
        match = self.binary_match.run(case, patch_pattern)
        verification = self.verifier.run(case, patch_pattern, match)
        report = self.reporter.run(case, patch_pattern, match, verification)
        return {
            "case": asdict(case),
            "triage": asdict(triage_result),
            "patch_pattern": asdict(patch_pattern),
            "function_match": asdict(match),
            "verification": asdict(verification),
            "report": report.to_dict(),
        }


def build_demo_pipeline() -> AnalysisPipeline:
    return AnalysisPipeline(
        triage=SimpleTriageAgent(),
        patch_analysis=SimplePatchAnalysisAgent(),
        binary_match=SimpleBinaryMatchAgent(),
        verifier=SimpleVerifier(),
        reporter=SimpleReporter(),
    )
