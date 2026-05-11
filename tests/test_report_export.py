from __future__ import annotations

import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from aisec_app.report_export import export_project_report
from aisec_app.source_analysis import HeuristicSourceAnalyzer
from aisec_app.zip_analysis import analyze_zip_archive
from aisec_app.zip_cli import resolve_zip_path


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

    def test_resolve_zip_path_uses_single_zip_from_input_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            input_dir = Path(tmp)
            zip_path = input_dir / "project.zip"
            zip_path.write_bytes(_make_zip({"src/main.c": "int main(void) { return 0; }\n"}))

            self.assertEqual(zip_path, resolve_zip_path(None, input_dir))

    def test_resolve_zip_path_requires_explicit_choice_for_multiple_zips(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            input_dir = Path(tmp)
            (input_dir / "a.zip").write_bytes(_make_zip({"a.c": ""}))
            (input_dir / "b.zip").write_bytes(_make_zip({"b.c": ""}))

            with self.assertRaises(SystemExit):
                resolve_zip_path(None, input_dir)


def _make_zip(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


if __name__ == "__main__":
    unittest.main()
