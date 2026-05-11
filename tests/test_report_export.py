from __future__ import annotations

import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from aisec_app.report_export import export_project_report
from aisec_app.source_analysis import HeuristicSourceAnalyzer
from aisec_app.zip_analysis import analyze_zip_archive


class ReportExportTests(unittest.TestCase):
    def test_export_project_report_writes_json_markdown_pdf_and_logs(self) -> None:
        archive_bytes = _make_zip({"src/vuln.c": "void f(char *s) { strcpy(buf, s); }\n"})
        report = analyze_zip_archive("project.zip", archive_bytes, HeuristicSourceAnalyzer())

        with tempfile.TemporaryDirectory() as tmp:
            paths = export_project_report(report, tmp)

            self.assertTrue(paths.json_path.exists())
            self.assertTrue(paths.markdown_path.exists())
            self.assertTrue(paths.pdf_path.exists())
            self.assertTrue(paths.pdf_path.read_bytes().startswith(b"%PDF-1.4"))
            self.assertTrue((paths.llm_log_dir / "src__vuln.c.md").exists())
            self.assertIn("AISEC Analysis Report", paths.markdown_path.read_text(encoding="utf-8"))


def _make_zip(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


if __name__ == "__main__":
    unittest.main()
