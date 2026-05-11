from __future__ import annotations

import unittest
from pathlib import Path

from aisec_app.dataset import load_case, load_case_record, load_case_records, load_cases
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

    def test_load_case_record_includes_labels(self) -> None:
        record = load_case_record(DEMO_CASE_DIR)

        self.assertEqual(record.case.case_id, "demo-parse-header")
        self.assertEqual(record.labels.expected_verdict, Verdict.VULNERABLE)
        self.assertEqual(record.labels.vulnerable_function, "parse_header")
        self.assertEqual(record.labels.vulnerable_address, "0x401234")

    def test_load_cases_from_root(self) -> None:
        cases = load_cases(CASES_ROOT)

        self.assertEqual(
            [case.case_id for case in cases],
            ["demo-parse-header", "magma-libpng-png003"],
        )

    def test_load_case_records_from_root(self) -> None:
        records = load_case_records(CASES_ROOT)

        self.assertEqual(
            [record.case.case_id for record in records],
            ["demo-parse-header", "magma-libpng-png003"],
        )
        self.assertEqual([record.labels.expected_verdict for record in records], [Verdict.VULNERABLE, Verdict.VULNERABLE])

    def test_manifest_case_runs_through_pipeline(self) -> None:
        case = load_case(DEMO_CASE_DIR)
        report = build_demo_pipeline().run(case)

        self.assertEqual(report.verdict, Verdict.VULNERABLE)
        self.assertEqual(report.verifier_status, VerificationStatus.PASS)
        self.assertEqual(report.function_name, "parse_header")

    def test_magma_libpng_case_runs_through_pipeline(self) -> None:
        case = load_case(CASES_ROOT / "magma-libpng-png003")
        report = build_demo_pipeline().run(case)

        self.assertEqual(report.verdict, Verdict.VULNERABLE)
        self.assertEqual(report.verifier_status, VerificationStatus.PASS)
        self.assertEqual(report.function_name, "png_handle_PLTE")


if __name__ == "__main__":
    unittest.main()
