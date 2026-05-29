from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aisec_app.cve_metadata import (
    CVEMetadata,
    CVSSMetadata,
    discover_case_cve_ids,
    enrich_cases,
    extract_cve_ids,
    parse_nvd_cve_payload,
)


class CVEMetadataTests(unittest.TestCase):
    def test_extract_cve_ids_deduplicates_and_normalizes(self) -> None:
        text = "first cve-2016-6304 then CVE-2016-6304 and CVE-2024-12345"

        self.assertEqual(extract_cve_ids(text), ["CVE-2016-6304", "CVE-2024-12345"])

    def test_parse_nvd_cve_payload_extracts_report_fields(self) -> None:
        metadata = parse_nvd_cve_payload(
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2016-6304",
                            "vulnStatus": "Analyzed",
                            "published": "2016-09-16T00:59:13.783",
                            "lastModified": "2023-11-07T02:59:00.000",
                            "descriptions": [{"lang": "en", "value": "OpenSSL issue."}],
                            "weaknesses": [
                                {"description": [{"lang": "en", "value": "CWE-400"}]},
                            ],
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "cvssData": {
                                            "version": "3.1",
                                            "baseScore": 7.5,
                                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                        },
                                        "baseSeverity": "HIGH",
                                    }
                                ]
                            },
                            "references": {
                                "referenceData": [{"url": "https://www.openssl.org/news/secadv/20160922.txt"}]
                            },
                        }
                    }
                ]
            }
        )

        self.assertIsNotNone(metadata)
        assert metadata is not None
        self.assertEqual(metadata.cve_id, "CVE-2016-6304")
        self.assertEqual(metadata.weaknesses, ["CWE-400"])
        self.assertEqual(metadata.cvss, CVSSMetadata("3.1", 7.5, "HIGH", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"))
        self.assertEqual(metadata.references, ["https://www.openssl.org/news/secadv/20160922.txt"])

    def test_enrich_cases_writes_nvd_metadata_to_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "case"
            case_dir.mkdir()
            (case_dir / "manifest.json").write_text(
                json.dumps({"case_id": "case", "cve_id": "MAGMA-SSL005"}), encoding="utf-8"
            )
            (case_dir / "patch.diff").write_text("/* CVE-2016-6304 */", encoding="utf-8")

            def fake_fetcher(cve_id: str, api_key: str | None = None) -> CVEMetadata | None:
                return CVEMetadata(
                    cve_id=cve_id,
                    source="NVD",
                    status="Analyzed",
                    published="2016-09-16T00:59:13.783",
                    last_modified="2023-11-07T02:59:00.000",
                    description="OpenSSL issue.",
                    weaknesses=["CWE-400"],
                    cvss=CVSSMetadata("3.1", 7.5, "HIGH", "vector"),
                    references=["https://example.test/advisory"],
                )

            result = enrich_cases(tmp, write=True, delay_seconds=0, fetcher=fake_fetcher)
            manifest = json.loads((case_dir / "manifest.json").read_text(encoding="utf-8"))

            self.assertEqual(result.total_cases, 1)
            self.assertEqual(result.metadata_found, 1)
            self.assertEqual(result.manifests_updated, 1)
            self.assertEqual(manifest["linked_cve_id"], "CVE-2016-6304")
            self.assertEqual(manifest["cve_metadata"][0]["weaknesses"], ["CWE-400"])

    def test_discover_case_cve_ids_scans_patch_and_decompiler(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp)
            (case_dir / "manifest.json").write_text("{}", encoding="utf-8")
            (case_dir / "patch.diff").write_text("patch mentions CVE-2016-6305", encoding="utf-8")
            (case_dir / "vulnerable").mkdir()
            (case_dir / "vulnerable" / "decompiler.txt").write_text("also CVE-2016-6304", encoding="utf-8")

            self.assertEqual(discover_case_cve_ids(case_dir), ["CVE-2016-6304", "CVE-2016-6305"])


if __name__ == "__main__":
    unittest.main()
