from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .dataset import load_case_records
from .models import AnalysisReport, CaseRecord, VerificationStatus
from .pipeline import AnalysisPipeline, build_demo_pipeline


@dataclass(slots=True)
class CaseEvaluation:
    case_id: str
    cve_id: str
    expected_verdict: str
    actual_verdict: str
    expected_function: str
    actual_function: str
    verifier_status: str
    detection_correct: bool
    function_correct: bool


@dataclass(slots=True)
class EvaluationSummary:
    total_cases: int
    detection_correct: int
    function_correct: int
    verifier_counts: dict[str, int] = field(default_factory=dict)
    cases: list[CaseEvaluation] = field(default_factory=list)

    @property
    def detection_accuracy(self) -> float:
        return _ratio(self.detection_correct, self.total_cases)

    @property
    def function_localization_accuracy(self) -> float:
        return _ratio(self.function_correct, self.total_cases)

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["detection_accuracy"] = self.detection_accuracy
        data["function_localization_accuracy"] = self.function_localization_accuracy
        return data


def evaluate_cases(records: list[CaseRecord], pipeline: AnalysisPipeline | None = None) -> EvaluationSummary:
    active_pipeline = pipeline or build_demo_pipeline()
    evaluations: list[CaseEvaluation] = []
    verifier_counts = {status.value: 0 for status in VerificationStatus}

    for record in records:
        report = active_pipeline.run(record.case)
        evaluation = evaluate_report(record, report)
        evaluations.append(evaluation)
        verifier_counts[evaluation.verifier_status] = verifier_counts.get(evaluation.verifier_status, 0) + 1

    return EvaluationSummary(
        total_cases=len(evaluations),
        detection_correct=sum(1 for item in evaluations if item.detection_correct),
        function_correct=sum(1 for item in evaluations if item.function_correct),
        verifier_counts=verifier_counts,
        cases=evaluations,
    )


def evaluate_report(record: CaseRecord, report: AnalysisReport) -> CaseEvaluation:
    expected_verdict = record.labels.expected_verdict.value
    actual_verdict = report.verdict.value
    expected_function = record.labels.vulnerable_function
    actual_function = report.function_name

    return CaseEvaluation(
        case_id=record.case.case_id,
        cve_id=record.case.cve_id,
        expected_verdict=expected_verdict,
        actual_verdict=actual_verdict,
        expected_function=expected_function,
        actual_function=actual_function,
        verifier_status=report.verifier_status.value,
        detection_correct=actual_verdict == expected_verdict,
        function_correct=actual_function == expected_function,
    )


def format_summary(summary: EvaluationSummary) -> str:
    lines = [
        f"Cases: {summary.total_cases}",
        f"Detection Accuracy: {summary.detection_correct}/{summary.total_cases} ({summary.detection_accuracy:.2%})",
        (
            "Function Localization Accuracy: "
            f"{summary.function_correct}/{summary.total_cases} ({summary.function_localization_accuracy:.2%})"
        ),
        "Verifier Status:",
    ]
    for status, count in sorted(summary.verifier_counts.items()):
        lines.append(f"  {status}: {count}")

    lines.append("Case Results:")
    for case in summary.cases:
        lines.append(
            "  "
            f"{case.case_id}: detection={_mark(case.detection_correct)} "
            f"function={_mark(case.function_correct)} "
            f"verifier={case.verifier_status}"
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate AISEC cases against manifest labels.")
    parser.add_argument("cases_root", nargs="?", default="data/cases", help="Path to the data/cases directory.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON instead of text.")
    args = parser.parse_args()

    records = load_case_records(Path(args.cases_root))
    summary = evaluate_cases(records)
    if args.json:
        print(json.dumps(summary.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(format_summary(summary))


def _ratio(value: int, total: int) -> float:
    if total == 0:
        return 0.0
    return value / total


def _mark(value: bool) -> str:
    return "pass" if value else "fail"


if __name__ == "__main__":
    main()
