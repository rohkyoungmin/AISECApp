from __future__ import annotations

import unittest

from aisec_app.models import CVECase, VerificationStatus, Verdict
from aisec_app.pipeline import build_demo_pipeline
from aisec_app.sample_data import demo_case


class PipelineTests(unittest.TestCase):
    def test_demo_case_passes_verification(self) -> None:
        report = build_demo_pipeline().run(demo_case())
        self.assertEqual(report.verdict, Verdict.VULNERABLE)
        self.assertEqual(report.verifier_status, VerificationStatus.PASS)
        self.assertEqual(report.function_name, "parse_header")

    def test_missing_binary_evidence_is_rejected(self) -> None:
        case = demo_case()
        weak_case = CVECase(
            case_id=case.case_id,
            cve_id=case.cve_id,
            advisory=case.advisory,
            binary_metadata=case.binary_metadata,
            patch_diff=case.patch_diff,
            decompiler_excerpt="function_x @ 0x555555 no dangerous copy visible",
        )
        report = build_demo_pipeline().run(weak_case)
        self.assertEqual(report.verifier_status, VerificationStatus.REJECT)


if __name__ == "__main__":
    unittest.main()
