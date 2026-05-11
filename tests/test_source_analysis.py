from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from aisec_app.models import SourceArtifact, VerificationStatus, Verdict
from aisec_app.source_analysis import (
    HeuristicSourceAnalyzer,
    LLMNotConfiguredError,
    build_source_analyzer,
    verify_source_report,
)


class SourceAnalysisTests(unittest.TestCase):
    def test_heuristic_report_accepts_grounded_evidence(self) -> None:
        artifact = SourceArtifact(
            filename="sample.c",
            content="int parse(char *input, int input_len) {\n  memcpy(buf, input, input_len);\n}\n",
        )

        report = HeuristicSourceAnalyzer().analyze(artifact)

        self.assertEqual(report.verdict, Verdict.VULNERABLE)
        self.assertEqual(report.verifier_status, VerificationStatus.PASS)
        self.assertEqual(report.findings[0].function_name, "parse")
        self.assertIn("memcpy", report.findings[0].evidence_quote)

    def test_report_rejects_ungrounded_evidence(self) -> None:
        artifact = SourceArtifact(filename="sample.c", content="int ok(void) { return 0; }\n")
        payload = {
            "summary": "bad claim",
            "findings": [
                {
                    "title": "invented issue",
                    "verdict": "vulnerable",
                    "severity": "high",
                    "function_name": "ok",
                    "line_start": 1,
                    "line_end": 1,
                    "confidence": 0.9,
                    "root_cause": "invented",
                    "evidence_quote": "memcpy(buf, input, input_len);",
                    "remediation": "add bounds check",
                }
            ],
        }

        report = verify_source_report(artifact, payload, model="test")

        self.assertEqual(report.verifier_status, VerificationStatus.REJECT)
        self.assertEqual(len(report.findings), 0)
        self.assertEqual(len(report.rejected_findings), 1)

    def test_report_rejects_implausible_line_reference(self) -> None:
        artifact = SourceArtifact(filename="sample.c", content="void f(char *s) { strcpy(buf, s); }\n")
        payload = {
            "summary": "bad line",
            "findings": [
                {
                    "title": "unsafe copy",
                    "verdict": "vulnerable",
                    "severity": "medium",
                    "function_name": "f",
                    "line_start": 100,
                    "line_end": 100,
                    "confidence": 0.9,
                    "root_cause": "unbounded copy",
                    "evidence_quote": "void f(char *s) { strcpy(buf, s); }",
                    "remediation": "add bounds check",
                }
            ],
        }

        report = verify_source_report(artifact, payload, model="test")

        self.assertEqual(report.verifier_status, VerificationStatus.REJECT)
        self.assertEqual(len(report.findings), 0)
        self.assertIn("line range", report.verifier_rationale)

    def test_build_source_analyzer_requires_key_by_default(self) -> None:
        old_key = os.environ.get("ANTHROPIC_API_KEY")
        os.environ["ANTHROPIC_API_KEY"] = ""
        try:
            with self.assertRaises(LLMNotConfiguredError):
                build_source_analyzer(require_llm=True)
        finally:
            if old_key is not None:
                os.environ["ANTHROPIC_API_KEY"] = old_key
            else:
                os.environ.pop("ANTHROPIC_API_KEY", None)

    def test_source_cli_heuristic_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source_path = Path(tmp) / "sample.c"
            source_path.write_text("void f(char *s) { strcpy(buf, s); }\n", encoding="utf-8")

            report = HeuristicSourceAnalyzer().analyze(
                SourceArtifact(filename=source_path.name, content=source_path.read_text(encoding="utf-8"))
            )

        self.assertEqual(report.verifier_status, VerificationStatus.PASS)
        self.assertEqual(report.findings[0].function_name, "f")


if __name__ == "__main__":
    unittest.main()
