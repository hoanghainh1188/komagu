#!/usr/bin/env python3
"""Tests for approved finding suppressions (Issue #270, part b).

Validates:
1. suppressions.json loading and validation (fingerprint, reason, approver,
   expiry date, duplicates) against the contract schema.
2. Matching by fingerprint; expired and unused suppressions are reported and
   expired ones no longer hide the finding.
3. Suppressed findings never trip the CI gate but stay in the baseline.
4. SARIF suppressions[] output and the baseline.py --suppressions CLI.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
KIT = HERE.parent
sys.path.insert(0, str(KIT / "scripts"))

from baseline import compare, gate  # noqa: E402
from findings_to_sarif import to_sarif  # noqa: E402
from lsa_common import write_json  # noqa: E402
from merge_findings import load_validator  # noqa: E402
from suppressions import SuppressionError, apply_suppressions, load_suppressions  # noqa: E402

BASELINE_PY = KIT / "scripts" / "baseline.py"
FP_A = "kfp1:" + "a" * 64
FP_B = "kfp1:" + "b" * 64
FP_C = "kfp1:" + "c" * 64
TODAY = "2026-11-10"


def _finding(fid: str, fp: str, **overrides: object) -> dict:
    base = {
        "finding_id": f"BOLA-{fid}",
        "category": "bola",
        "subtype": "missing_ownership_check",
        "title": f"Finding {fid}",
        "location": {"file": "orders.php", "start_line": 3},
        "evidence": [{"file": "orders.php", "line": 3, "code": "q($id)", "why": "no owner check"}],
        "severity": "high",
        "confidence": "high",
        "cwe": ["CWE-639"],
        "recommendation": "Bind to the current user.",
        "status": "confirmed",
        "fingerprint": fp,
    }
    base.update(overrides)
    return base


def _entry(fp: str, **overrides: object) -> dict:
    base = {"fingerprint": fp, "reason": "Internal network only", "approved_by": "person-b@client.example", "expires": "2026-12-31"}
    base.update(overrides)
    return base


class _FileMixin:
    def write(self, doc: object) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)  # type: ignore[attr-defined]
        path = Path(tmp.name) / "suppressions.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        return path


class TestLoadSuppressions(_FileMixin, unittest.TestCase):
    def test_valid_file_matches_schema_and_loads(self) -> None:
        doc = {"version": 1, "suppressions": [_entry(FP_A), _entry(FP_B, expires=None)]}
        self.assertEqual(load_validator("suppressions.schema.json")(doc), [])
        loaded = load_suppressions(self.write(doc))
        self.assertEqual([s.fingerprint for s in loaded], [FP_A, FP_B])
        self.assertIsNone(loaded[1].expires)

    def test_invalid_entries_rejected(self) -> None:
        bad_entries = [
            _entry("kfp1:short"),
            _entry(FP_A, reason="  "),
            _entry(FP_A, approved_by=""),
            _entry(FP_A, expires="31/12/2026"),
            _entry(FP_A, expires="2026-02-30"),
        ]
        for entry in bad_entries:
            with self.subTest(entry=entry):
                with self.assertRaises(SuppressionError):
                    load_suppressions(self.write({"version": 1, "suppressions": [entry]}))

    def test_duplicate_fingerprints_rejected(self) -> None:
        with self.assertRaises(SuppressionError):
            load_suppressions(self.write({"version": 1, "suppressions": [_entry(FP_A), _entry(FP_A)]}))

    def test_unreadable_or_wrong_shape_rejected(self) -> None:
        for doc in ([_entry(FP_A)], {"version": 2, "suppressions": []}, {"version": 1}):
            with self.subTest(doc=doc):
                with self.assertRaises(SuppressionError):
                    load_suppressions(self.write(doc))
        with self.assertRaises(SuppressionError):
            load_suppressions(Path("/nonexistent/suppressions.json"))


class TestApplySuppressions(_FileMixin, unittest.TestCase):
    def setUp(self) -> None:
        self.findings = [_finding("A", FP_A), _finding("B", FP_B), _finding("C", FP_C)]
        self.rules = load_suppressions(self.write({"version": 1, "suppressions": [
            _entry(FP_A),
            _entry(FP_B, expires="2026-11-09"),
            _entry("kfp1:" + "d" * 64, reason="Route removed"),
        ]}))

    def test_matching_expired_and_unused(self) -> None:
        result = apply_suppressions(self.findings, self.rules, TODAY)
        by_id = {f["finding_id"][5:]: f for f in result.findings}
        self.assertEqual(by_id["A"]["suppression"]["approved_by"], "person-b@client.example")
        self.assertNotIn("suppression", by_id["B"])
        self.assertNotIn("suppression", by_id["C"])
        self.assertEqual([s.fingerprint for s in result.expired], [FP_B])
        self.assertEqual([s.fingerprint for s in result.unused], ["kfp1:" + "d" * 64])

    def test_expiry_day_itself_is_still_valid(self) -> None:
        result = apply_suppressions(self.findings, self.rules, "2026-11-09")
        self.assertIn("suppression", {f["finding_id"][5:]: f for f in result.findings}["B"])

    def test_rejected_findings_not_suppressed(self) -> None:
        result = apply_suppressions([_finding("A", FP_A, status="rejected")], self.rules, TODAY)
        self.assertNotIn("suppression", result.findings[0])
        self.assertEqual([s.fingerprint for s in result.unused][0], FP_A)

    def test_does_not_mutate_input(self) -> None:
        apply_suppressions(self.findings, self.rules, TODAY)
        self.assertNotIn("suppression", self.findings[0])

    def test_suppressed_findings_skip_gate_but_stay_in_baseline(self) -> None:
        applied = apply_suppressions(self.findings, self.rules, TODAY).findings
        diff = compare(applied, {})
        self.assertEqual(diff.counts["new"], 3)
        tripped = sorted(f["finding_id"][5:] for f in gate(diff.findings, "any", "info"))
        self.assertEqual(tripped, ["B", "C"])

    def test_finding_schema_accepts_suppression(self) -> None:
        applied = apply_suppressions(self.findings, self.rules, TODAY).findings
        self.assertEqual(load_validator("finding.schema.json")(applied[0]), [])


class TestSarifSuppressions(unittest.TestCase):
    def test_suppressed_result_has_external_accepted_suppression(self) -> None:
        f = _finding("A", FP_A, suppression={"reason": "Internal only", "approved_by": "lead@x", "expires": "2026-12-31"})
        result = to_sarif({"findings": [f, _finding("C", FP_C)]})["runs"][0]["results"]
        sup = result[0]["suppressions"]
        self.assertEqual(sup[0]["kind"], "external")
        self.assertEqual(sup[0]["status"], "accepted")
        self.assertIn("Internal only", sup[0]["justification"])
        self.assertIn("lead@x", sup[0]["justification"])
        self.assertIn("2026-12-31", sup[0]["justification"])
        self.assertNotIn("suppressions", result[1])


class TestBaselineCliSuppressions(_FileMixin, unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name)
        write_json(self.out / "findings.json", {"findings": [_finding("A", FP_A)], "summary": {}})

    def run_cli(self, *extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(BASELINE_PY), str(self.out), "--today", TODAY, "--fail-on", "new", *extra],
            capture_output=True,
            text=True,
        )

    def fingerprint(self) -> str:
        """baseline.py recomputes fingerprints; read back the one it assigned."""
        self.run_cli()
        return json.loads((self.out / "findings.json").read_text(encoding="utf-8"))["findings"][0]["fingerprint"]

    def test_active_suppression_passes_gate(self) -> None:
        path = self.write({"version": 1, "suppressions": [_entry(self.fingerprint())]})
        res = self.run_cli("--suppressions", str(path))
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        diff = json.loads((self.out / "baseline-diff.json").read_text(encoding="utf-8"))
        self.assertEqual(diff["counts"]["suppressed"], 1)

    def test_expired_suppression_fails_gate_with_warning(self) -> None:
        path = self.write({"version": 1, "suppressions": [_entry(self.fingerprint(), expires="2026-01-01")]})
        res = self.run_cli("--suppressions", str(path))
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("expired", res.stdout)
        diff = json.loads((self.out / "baseline-diff.json").read_text(encoding="utf-8"))
        self.assertEqual(len(diff["expired_suppressions"]), 1)

    def test_invalid_suppressions_file_is_usage_error(self) -> None:
        path = self.write({"version": 1, "suppressions": [_entry("bad")]})
        self.assertEqual(self.run_cli("--suppressions", str(path)).returncode, 2)


if __name__ == "__main__":
    unittest.main()
