#!/usr/bin/env python3
"""Automated verification test for LSA Evaluation Run 3 benchmark metrics (Issue #49)."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
LSA_ROOT = TESTS_DIR.parent
EVAL_RUN_3_DIR = LSA_ROOT / "examples" / "eval-run-3"
GROUND_TRUTH = LSA_ROOT / "examples" / "eval-qwen35" / "ground-truth.json"


class TestEvaluationRun3Benchmark(unittest.TestCase):
    """Verify Evaluation Run 3 meets >=95% recall and 0 false positives on safe code."""

    def test_eval_run_3_artifacts_exist(self) -> None:
        """All reference files must exist in assess/lsa/examples/eval-run-3/."""
        expected = [
            "findings.json",
            "findings.sarif",
            "coverage.json",
            "stack-profile.json",
            "report.md",
            "report.ja.md",
            "EXECUTIVE-SUMMARY.md",
        ]
        for name in expected:
            self.assertTrue(
                (EVAL_RUN_3_DIR / name).is_file(),
                f"Missing expected artifact in eval-run-3: {name}",
            )

    def test_eval_run_3_meets_recall_and_zero_fp_thresholds(self) -> None:
        """score_findings.py on eval-run-3 must report >=95% recall and 0 safe-code FPs."""
        score_script = TESTS_DIR / "score_findings.py"
        proc = subprocess.run(
            [sys.executable, str(score_script), str(GROUND_TRUTH), str(EVAL_RUN_3_DIR)],
            capture_output=True,
            text=True,
            check=True,
        )
        report = json.loads(proc.stdout)

        bola = report["per_category"]["bola"]
        inj = report["per_category"]["injection"]

        self.assertGreaterEqual(bola["recall"], 0.95, f"BOLA recall below 95%: {bola}")
        self.assertEqual(bola["recall"], 1.0)
        self.assertEqual(bola["false_positive_on_safe_code"], [])
        self.assertEqual(bola["missed"], [])

        self.assertGreaterEqual(inj["recall"], 0.95, f"Injection recall below 95%: {inj}")
        self.assertEqual(inj["recall"], 1.0)
        self.assertEqual(inj["false_positive_on_safe_code"], [])
        self.assertEqual(inj["missed"], [])

        self.assertGreaterEqual(report["precision"], 0.98)
        self.assertEqual(report["unmatched_findings"], [])


if __name__ == "__main__":
    unittest.main()
