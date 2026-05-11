from __future__ import annotations

import argparse
import json
from pathlib import Path

from .models import SourceArtifact
from .source_analysis import LLMNotConfiguredError, build_source_analyzer


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze an uploaded source file and emit a verified report.")
    parser.add_argument("source_file", help="Path to a C/C++ source file to analyze.")
    parser.add_argument(
        "--allow-heuristic",
        action="store_true",
        help="Use local heuristic analysis when ANTHROPIC_API_KEY is not configured.",
    )
    args = parser.parse_args()

    source_path = Path(args.source_file)
    artifact = SourceArtifact(
        filename=source_path.name,
        content=source_path.read_text(encoding="utf-8", errors="replace"),
    )

    try:
        analyzer = build_source_analyzer(require_llm=not args.allow_heuristic)
        report = analyzer.analyze(artifact)
    except LLMNotConfiguredError as exc:
        raise SystemExit(str(exc)) from exc

    print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
