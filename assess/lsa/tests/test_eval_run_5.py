#!/usr/bin/env python3
"""Keeps the archived Evaluation Run 5 numbers (Issue #319) in step with the scorer and EVAL-RESULTS.md."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
LSA_ROOT = TESTS_DIR.parent
EVAL_RUN_5_DIR = LSA_ROOT / "examples" / "eval-run-5"
GROUND_TRUTH = EVAL_RUN_5_DIR / "ground-truth.json"
RUNS = ("gptoss-a", "gptoss-b")
# (BOLA, injection, BFLA, mass assignment) found by location, then BFLA / mass found by auditor verdict
EXPECTED = {
    "gptoss-a": {"marker": (24, 34, 10, 10), "verdict": (10, 15)},
    "gptoss-b": {"marker": (12, 32, 9, 14), "verdict": (10, 15)},
}

def score(run: str) -> dict:
    proc = subprocess.run(
        [sys.executable, str(TESTS_DIR / "score_findings.py"), "--verdicts", str(GROUND_TRUTH), str(EVAL_RUN_5_DIR / run)],
        capture_output=True, text=True, check=True,
    )
    return json.loads(proc.stdout)


class TestEvaluationRun5(unittest.TestCase):
    def test_artifacts_exist(self) -> None:
        self.assertTrue(GROUND_TRUTH.is_file())
        for run in RUNS:
            for name in ("findings.json", "coverage.json", "score.json"):
                self.assertTrue((EVAL_RUN_5_DIR / run / name).is_file(), f"{run}/{name}")

    def test_archived_scores_match_the_scorer(self) -> None:
        for run in RUNS:
            with self.subTest(run=run):
                archived = json.loads((EVAL_RUN_5_DIR / run / "score.json").read_text(encoding="utf-8"))
                self.assertEqual(score(run), archived)

    def test_final_harness_numbers_match_eval_results(self) -> None:
        for run, want in EXPECTED.items():
            with self.subTest(run=run):
                report = score(run)
                pc, vl = report["per_category"], report["verdict_level"]
                got = tuple(pc[c]["found"] for c in ("bola", "injection", "bfla", "mass_assignment"))
                self.assertEqual(got, want["marker"])
                self.assertEqual((vl["bfla"]["found"], vl["mass_assignment"]["found"]), want["verdict"])

    def test_final_harness_has_no_false_positive_on_safe_code(self) -> None:
        for run in EXPECTED:
            with self.subTest(run=run):
                report = score(run)
                for cat, row in report["per_category"].items():
                    self.assertEqual(row["false_positive_on_safe_code"], [], cat)
                for cat, row in report["verdict_level"].items():
                    self.assertEqual(row["flagged_safe"], [], cat)

    def test_final_harness_records_run_stats(self) -> None:
        for run in EXPECTED:
            with self.subTest(run=run):
                stats = json.loads((EVAL_RUN_5_DIR / run / "ai-run-stats.json").read_text(encoding="utf-8"))
                self.assertEqual(stats["model"], "gpt-oss:20b")
                self.assertGreater(stats["totals"]["prompt_tokens"], 0)
                self.assertEqual(stats["call_errors"], {})
                self.assertEqual(stats["anchoring"]["unanchored"], [])


if __name__ == "__main__":
    unittest.main()
