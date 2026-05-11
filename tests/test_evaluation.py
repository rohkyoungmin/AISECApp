from __future__ import annotations

import unittest
from pathlib import Path

from aisec_app.dataset import load_case_records
from aisec_app.evaluation import evaluate_cases, format_summary


class EvaluationTests(unittest.TestCase):
    def test_evaluate_cases_summarizes_accuracy(self) -> None:
        records = load_case_records(Path("data/cases"))
        summary = evaluate_cases(records)

        self.assertEqual(summary.total_cases, 2)
        self.assertEqual(summary.detection_correct, 2)
        self.assertEqual(summary.function_correct, 2)
        self.assertEqual(summary.verifier_counts["pass"], 2)

    def test_format_summary_includes_metrics(self) -> None:
        records = load_case_records(Path("data/cases"))
        summary = evaluate_cases(records)
        formatted = format_summary(summary)

        self.assertIn("Cases: 2", formatted)
        self.assertIn("Detection Accuracy: 2/2", formatted)
        self.assertIn("Function Localization Accuracy: 2/2", formatted)
        self.assertIn("magma-libpng-png003", formatted)


if __name__ == "__main__":
    unittest.main()
