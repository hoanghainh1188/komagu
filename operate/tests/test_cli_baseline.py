#!/usr/bin/env python3
"""End-to-end tests for komainu scan baseline flags (Issue #270, part a).

Validates --baseline, --update-baseline, --fail-on and --fail-severity on a
real fixture: fingerprints reach findings.json and SARIF, a rescan against its
own baseline reports nothing new, and the CI gate maps to exit codes 0/1/2.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BIN_KOMAINU = REPO_ROOT / "bin" / "komainu"
FIXTURE_PATH = REPO_ROOT / "assess" / "lsa" / "tests" / "fixtures" / "php-plain"

FINDING = {
    "finding_id": "INJ-I-0001-1",
    "category": "sql_injection",
    "subtype": "string_concatenation",
    "title": "Search query concatenates request input",
    "endpoint": {"method": "GET", "path": "/search.php"},
    "location": {"file": "search.php", "start_line": 3},
    "evidence": [{"file": "search.php", "line": 3, "code": "query", "why": "concat"}],
    "severity": "medium",
    "confidence": "high",
    "cwe": ["CWE-89"],
    "recommendation": "Use a prepared statement.",
    "status": "confirmed",
}


class TestScanBaseline(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name) / "out"
        self.out.mkdir()
        self.baseline = Path(tmp.name) / "baseline.json"
        (self.out / "findings.json").write_text(json.dumps({"findings": [FINDING], "summary": {}}), encoding="utf-8")

    def scan(self, *extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(BIN_KOMAINU), "scan", str(FIXTURE_PATH), "--out", str(self.out), "--format", "sarif", *extra],
            capture_output=True,
            text=True,
        )

    def sarif_result(self) -> dict:
        sarif = json.loads((self.out / "findings.sarif").read_text(encoding="utf-8"))
        return sarif["runs"][0]["results"][0]

    def test_default_scan_adds_fingerprint_and_passes(self) -> None:
        res = self.scan()
        self.assertEqual(res.returncode, 0, res.stderr + res.stdout)
        self.assertTrue(self.sarif_result()["partialFingerprints"]["komainu/v1"].startswith("kfp1:"))

    def test_fail_on_new_without_baseline_fails(self) -> None:
        res = self.scan("--fail-on", "new")
        self.assertEqual(res.returncode, 1, res.stderr + res.stdout)
        self.assertIn("CI gate failed", res.stdout)
        self.assertIn("INJ-I-0001-1", res.stdout)

    def test_severity_threshold_lets_medium_pass(self) -> None:
        res = self.scan("--fail-on", "new", "--fail-severity", "high")
        self.assertEqual(res.returncode, 0, res.stderr + res.stdout)

    def test_rescan_against_own_baseline_passes(self) -> None:
        first = self.scan("--baseline", str(self.baseline), "--update-baseline")
        self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
        self.assertTrue(self.baseline.is_file())

        second = self.scan("--baseline", str(self.baseline), "--fail-on", "new")
        self.assertEqual(second.returncode, 0, second.stderr + second.stdout)
        self.assertEqual(self.sarif_result()["baselineState"], "unchanged")
        self.assertIn("0 new, 1 unchanged", second.stdout)

    def test_unreadable_baseline_is_usage_error(self) -> None:
        self.baseline.write_text("not json", encoding="utf-8")
        res = self.scan("--baseline", str(self.baseline))
        self.assertEqual(res.returncode, 2, res.stderr + res.stdout)


if __name__ == "__main__":
    unittest.main()
