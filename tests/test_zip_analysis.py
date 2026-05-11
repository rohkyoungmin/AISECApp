from __future__ import annotations

import io
import unittest
import zipfile

from aisec_app.source_analysis import HeuristicSourceAnalyzer
from aisec_app.zip_analysis import ZipAnalysisLimits, analyze_zip_archive, collect_source_artifacts


def make_zip(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


class ZipAnalysisTests(unittest.TestCase):
    def test_collect_source_artifacts_filters_supported_files(self) -> None:
        archive = make_zip(
            {
                "src/a.c": "void a(void) {}\n",
                "README.md": "not source\n",
                "../escape.c": "bad\n",
            }
        )

        artifacts, skipped = collect_source_artifacts(archive)

        self.assertEqual([artifact.filename for artifact in artifacts], ["src/a.c"])
        self.assertEqual(skipped, ["README.md: unsupported extension"])

    def test_analyze_zip_archive_returns_project_report(self) -> None:
        archive = make_zip({"src/vuln.c": "void f(char *s) { strcpy(buf, s); }\n"})

        report = analyze_zip_archive(
            archive_name="project.zip",
            archive_bytes=archive,
            analyzer=HeuristicSourceAnalyzer(),
        )

        self.assertEqual(report.archive_name, "project.zip")
        self.assertEqual(report.analyzed_files, 1)
        self.assertEqual(len(report.file_reports), 1)
        self.assertEqual(report.file_reports[0].findings[0].function_name, "f")

    def test_collect_source_artifacts_respects_max_files(self) -> None:
        archive = make_zip({"a.c": "void a(void) {}\n", "b.c": "void b(void) {}\n"})

        artifacts, skipped = collect_source_artifacts(archive, ZipAnalysisLimits(max_files=1))

        self.assertEqual(len(artifacts), 1)
        self.assertEqual(skipped, ["b.c: max analyzed file count reached"])


if __name__ == "__main__":
    unittest.main()
