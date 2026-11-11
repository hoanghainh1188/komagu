#!/usr/bin/env python3
"""Keeps the archived Evaluation Run 6 numbers (Issue #323) in step with the scorer and EVAL-RESULTS.md."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
LSA_ROOT = TESTS_DIR.parent
EVAL_RUN_6_DIR = LSA_ROOT / "examples" / "eval-run-6"
GROUND_TRUTH = EVAL_RUN_6_DIR / "ground-truth.json"
RUNS = ("gptoss-a", "gptoss-b")
QWEN_PARTIAL = EVAL_RUN_6_DIR / "qwen-16k-partial"
# (BOLA, injection, BFLA, mass assignment) found by location, then BFLA / mass found by auditor verdict
EXPECTED = {
    "gptoss-a": {"marker": (26, 34, 10, 14), "verdict": (10, 15)},
    "gptoss-b": {"marker": (26, 34, 10, 14), "verdict": (10, 14)},
}
# Findings that land on a SAFE marker, by category (see EVAL-RESULTS.md, Run 6)
SAFE_HITS = {
    "gptoss-a": {"injection": ["classic-asp/shop/member.asp:6"]},
    "gptoss-b": {"injection": ["python-flask/app.py:12"]},
}


def score(run: str) -> dict:
    proc = subprocess.run(
        [sys.executable, str(TESTS_DIR / "score_findings.py"), "--verdicts", str(GROUND_TRUTH), str(EVAL_RUN_6_DIR / run)],
        capture_output=True, text=True, check=True,
    )
    return json.loads(proc.stdout)


class TestEvaluationRun6(unittest.TestCase):
    def test_ground_truth_is_the_121_item_set(self) -> None:
        items = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))["items"]
        self.assertEqual(len(items), 121)

    def test_artifacts_exist(self) -> None:
        for run in RUNS:
            for name in ("findings.json", "coverage.json", "score.json", "ai-run-stats.json"):
                self.assertTrue((EVAL_RUN_6_DIR / run / name).is_file(), f"{run}/{name}")

    def test_archived_scores_match_the_scorer(self) -> None:
        for run in RUNS:
            with self.subTest(run=run):
                archived = json.loads((EVAL_RUN_6_DIR / run / "score.json").read_text(encoding="utf-8"))
                self.assertEqual(score(run), archived)

    def test_numbers_match_eval_results(self) -> None:
        for run, want in EXPECTED.items():
            with self.subTest(run=run):
                report = score(run)
                pc, vl = report["per_category"], report["verdict_level"]
                got = tuple(pc[c]["found"] for c in ("bola", "injection", "bfla", "mass_assignment"))
                self.assertEqual(got, want["marker"])
                self.assertEqual((vl["bfla"]["found"], vl["mass_assignment"]["found"]), want["verdict"])

    def test_safe_marker_hits_are_the_documented_ones(self) -> None:
        for run in RUNS:
            with self.subTest(run=run):
                report = score(run)
                for cat, row in report["per_category"].items():
                    self.assertEqual(row["false_positive_on_safe_code"], SAFE_HITS[run].get(cat, []), cat)
                for cat, row in report["verdict_level"].items():
                    self.assertEqual(row["flagged_safe"], [], cat)

    def test_no_batch_lost_to_parse_or_call_errors(self) -> None:
        for run in RUNS:
            with self.subTest(run=run):
                stats = json.loads((EVAL_RUN_6_DIR / run / "ai-run-stats.json").read_text(encoding="utf-8"))
                self.assertEqual(stats["parse_failures"], {})
                self.assertEqual(stats["call_errors"], {})
                self.assertEqual(stats["anchoring"]["unanchored"], [])

    def test_qwen_partial_score_matches_eval_results(self) -> None:
        """The stopped qwen3.5:9b 16K run: indicative score of its unverified findings (EVAL-RESULTS, Run 6)."""
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(QWEN_PARTIAL / "findings.partial.json", Path(tmp) / "findings.json")
            proc = subprocess.run(
                [sys.executable, str(TESTS_DIR / "score_findings.py"), str(GROUND_TRUTH), tmp],
                capture_output=True, text=True, check=True,
            )
        report = json.loads(proc.stdout)
        archived = json.loads((QWEN_PARTIAL / "score.partial.json").read_text(encoding="utf-8"))
        self.assertEqual(report, archived)
        pc = report["per_category"]
        got = tuple(pc[c]["found"] for c in ("bola", "injection", "bfla", "mass_assignment"))
        self.assertEqual(got, (12, 22, 0, 0))
        self.assertEqual(report["precision"], 0.733)
        for row in pc.values():
            self.assertEqual(row["false_positive_on_safe_code"], [])


if __name__ == "__main__":
    unittest.main()
