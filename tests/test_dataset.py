from __future__ import annotations

import unittest
from pathlib import Path

from aisec_app.dataset import load_case, load_cases
from aisec_app.models import Verdict, VerificationStatus
from aisec_app.pipeline import build_demo_pipeline


CASES_ROOT = Path("data/cases")
DEMO_CASE_DIR = CASES_ROOT / "demo-parse-header"


class DatasetTests(unittest.TestCase):
    def test_load_case_from_manifest(self) -> None:
        case = load_case(DEMO_CASE_DIR)

        self.assertEqual(case.case_id, "demo-parse-header")
        self.assertEqual(case.cve_id, "CVE-2021-XXXX")
        self.assertEqual(case.binary_metadata.architecture, "x86_64")
        self.assertIn("memcpy", case.patch_diff)
        self.assertIn("parse_header", case.decompiler_excerpt)

    def test_load_cases_from_root(self) -> None:
        cases = load_cases(CASES_ROOT)

        self.assertEqual([case.case_id for case in cases], ["demo-parse-header"])

    def test_manifest_case_runs_through_pipeline(self) -> None:
        case = load_case(DEMO_CASE_DIR)
        report = build_demo_pipeline().run(case)

        self.assertEqual(report.verdict, Verdict.VULNERABLE)
        self.assertEqual(report.verifier_status, VerificationStatus.PASS)
        self.assertEqual(report.function_name, "parse_header")


if __name__ == "__main__":
    unittest.main()
