from __future__ import annotations

import argparse
import json
from pathlib import Path

from .report_export import export_project_report
from .source_analysis import LLMNotConfiguredError, build_source_analyzer
from .zip_analysis import ZipAnalysisLimits, analyze_zip_archive


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze a ZIP archive of C/C++ source files.")
    parser.add_argument("zip_file")
    parser.add_argument("--allow-heuristic", action="store_true")
    parser.add_argument("--max-files", type=int, default=20)
    parser.add_argument("--output-dir", default="output")
    parser.add_argument("--no-export", action="store_true", help="Print JSON only and do not write output files.")
    args = parser.parse_args()

    zip_path = Path(args.zip_file)
    try:
        analyzer = build_source_analyzer(require_llm=not args.allow_heuristic)
        report = analyze_zip_archive(
            archive_name=zip_path.name,
            archive_bytes=zip_path.read_bytes(),
            analyzer=analyzer,
            limits=ZipAnalysisLimits(max_files=args.max_files),
        )
    except LLMNotConfiguredError as exc:
        raise SystemExit(str(exc)) from exc

    if args.no_export:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        return

    paths = export_project_report(report, args.output_dir)
    print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    print("")
    print(f"Saved JSON: {paths.json_path}")
    print(f"Saved Markdown: {paths.markdown_path}")
    print(f"Saved PDF: {paths.pdf_path}")
    print(f"Saved agent logs: {paths.llm_log_dir}")


if __name__ == "__main__":
    main()
