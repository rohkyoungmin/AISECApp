from __future__ import annotations

import argparse
import json

from .dataset import load_case
from .pipeline import build_demo_pipeline
from .sample_data import demo_case


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the AISEC analysis pipeline.")
    parser.add_argument(
        "case_dir",
        nargs="?",
        help="Optional path to a data/cases/{case_id} directory. Uses built-in demo data when omitted.",
    )
    args = parser.parse_args()

    case = load_case(args.case_dir) if args.case_dir else demo_case()
    pipeline = build_demo_pipeline()
    snapshot = pipeline.snapshot(case)
    print(json.dumps(snapshot, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
