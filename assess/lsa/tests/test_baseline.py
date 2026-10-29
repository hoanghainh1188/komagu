#!/usr/bin/env python3
"""Tests for finding fingerprints and scan baselines (Issue #270, part a).

Validates:
1. kfp1 fingerprints are line-independent, whitespace/number tolerant, and
   distinguish duplicate sinks in the same file.
2. Baseline comparison classifies findings as new / unchanged / regressed and
   lists fixed entries; SARIF baselines are accepted.
3. Baseline updates are immutable and keep first_seen history.
4. CI gating by --fail-on and --fail-severity, and the baseline.py CLI.
5. SARIF baselineState and baseline.json schema conformity.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
KIT = HERE.parent
sys.path.insert(0, str(KIT / "scripts"))

from baseline import (  # noqa: E402
    BaselineError,
    compare,
    gate,
    load_baseline,
    update_baseline,
)
from fingerprint import assign_fingerprints, compute_fingerprint, normalize_code  # noqa: E402
from findings_to_sarif import to_sarif  # noqa: E402
from lsa_common import write_json  # noqa: E402
from merge_findings import load_validator  # noqa: E402

BASELINE_PY = KIT / "scripts" / "baseline.py"
FP_RE = re.compile(r"^kfp1:[0-9a-f]{64}$")

SOURCE = """<?php
// orders controller
$id = $_GET['id'];
$order = db_query("SELECT * FROM orders WHERE id = " . $id);
echo json_encode($order);
"""


def _finding(fid: str = "INJ-I-0001-1", line: int = 4, **overrides: object) -> dict:
    base = {
        "finding_id": fid,
        "category": "sql_injection",
        "subtype": "string_concatenation",
        "title": "Order lookup concatenates GET id",
        "endpoint": {"method": "GET", "path": "/orders.php"},
        "location": {"file": "orders.php", "start_line": line},
        "evidence": [{"file": "orders.php", "line": line, "code": "$order = db_query(...)", "why": "concat"}],
        "severity": "high",
        "confidence": "high",
        "cwe": ["CWE-89"],
        "recommendation": "Use a prepared statement.",
        "status": "confirmed",
    }
    base.update(overrides)
    return base


class _TargetMixin:
    def make_target(self, text: str = SOURCE) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)  # type: ignore[attr-defined]
        root = Path(tmp.name)
        (root / "orders.php").write_text(text, encoding="utf-8")
        return root


class TestFingerprint(_TargetMixin, unittest.TestCase):
    def test_format(self) -> None:
        self.assertRegex(compute_fingerprint(_finding()), FP_RE)

    def test_stable_when_lines_are_inserted_above(self) -> None:
        before = assign_fingerprints([_finding(line=4)], self.make_target())[0]["fingerprint"]
        shifted = "<?php\n\n// added\n" + SOURCE.split("\n", 1)[1]
        after = assign_fingerprints([_finding(line=6)], self.make_target(shifted))[0]["fingerprint"]
        self.assertEqual(before, after)

    def test_stable_when_finding_id_and_title_change(self) -> None:
        a = compute_fingerprint(_finding(fid="INJ-I-0001-1"))
        b = compute_fingerprint(_finding(fid="INJ-I-0099-3", title="Reworded by another model run"))
        self.assertEqual(a, b)

    def test_changes_with_category_file_or_code(self) -> None:
        base = compute_fingerprint(_finding(), source_line="$a = q($id);")
        self.assertNotEqual(base, compute_fingerprint(_finding(subtype="string_interpolation"), source_line="$a = q($id);"))
        self.assertNotEqual(base, compute_fingerprint(_finding(location={"file": "other.php", "start_line": 4}), source_line="$a = q($id);"))
        self.assertNotEqual(base, compute_fingerprint(_finding(), source_line="$b = q($name);"))

    def test_endpoint_path_parameters_normalized(self) -> None:
        a = compute_fingerprint(_finding(endpoint={"method": "get", "path": "/api/orders/{id}"}))
        b = compute_fingerprint(_finding(endpoint={"method": "GET", "path": "/api/orders/:orderId"}))
        c = compute_fingerprint(_finding(endpoint={"method": "GET", "path": "/api/orders/123"}))
        self.assertEqual(a, b)
        self.assertEqual(a, c)

    def test_normalize_code_ignores_whitespace_and_numbers(self) -> None:
        self.assertEqual(normalize_code("  $x = f($id,   10); "), normalize_code("$x=f($id,20);"))
        self.assertEqual(normalize_code("query(id) // old note"), normalize_code("query(id) // new note"))

    def test_duplicate_sinks_get_distinct_fingerprints(self) -> None:
        text = "<?php\nq('a' . $id);\nq('a' . $id);\n"
        fps = assign_fingerprints([_finding(line=2), _finding(fid="INJ-2", line=3)], self.make_target(text))
        self.assertNotEqual(fps[0]["fingerprint"], fps[1]["fingerprint"])

    def test_assign_does_not_mutate_input(self) -> None:
        original = [_finding()]
        result = assign_fingerprints(original, None)
        self.assertNotIn("fingerprint", original[0])
        self.assertIn("fingerprint", result[0])

    def test_missing_or_escaping_source_falls_back_to_evidence(self) -> None:
        target = self.make_target()
        escaping = _finding(location={"file": "../../etc/passwd", "start_line": 1})
        missing = _finding(location={"file": "gone.php", "start_line": 1})
        for f in (escaping, missing):
            with self.subTest(file=f["location"]["file"]):
                self.assertRegex(assign_fingerprints([f], target)[0]["fingerprint"], FP_RE)


class TestBaselineCompare(unittest.TestCase):
    def setUp(self) -> None:
        self.a = {**_finding(fid="A"), "fingerprint": "kfp1:" + "a" * 64}
        self.b = {**_finding(fid="B", severity="low"), "fingerprint": "kfp1:" + "b" * 64}
        self.c = {**_finding(fid="C"), "fingerprint": "kfp1:" + "c" * 64}

    def _baseline(self, findings: list, today: str = "2026-11-01") -> dict:
        return update_baseline({}, compare(findings, {}), today)

    def test_without_baseline_everything_is_new(self) -> None:
        diff = compare([self.a, self.b], {})
        self.assertEqual([f["baseline_state"] for f in diff.findings], ["new", "new"])
        self.assertEqual(diff.fixed, [])

    def test_unchanged_new_and_fixed(self) -> None:
        entries = self._baseline([self.a, self.b])["entries"]
        diff = compare([self.a, self.c], {e["fingerprint"]: e for e in entries})
        states = {f["finding_id"]: f["baseline_state"] for f in diff.findings}
        self.assertEqual(states, {"A": "unchanged", "C": "new"})
        self.assertEqual([e["fingerprint"] for e in diff.fixed], [self.b["fingerprint"]])
        self.assertEqual(diff.counts, {"new": 1, "unchanged": 1, "regressed": 0, "fixed": 1})

    def test_regressed_after_fix(self) -> None:
        first = self._baseline([self.a, self.b])
        index = {e["fingerprint"]: e for e in first["entries"]}
        second = update_baseline(index, compare([self.a], index), "2026-11-08")
        index2 = {e["fingerprint"]: e for e in second["entries"]}
        self.assertEqual(index2[self.b["fingerprint"]]["state"], "fixed")
        self.assertEqual(index2[self.b["fingerprint"]]["fixed_at"], "2026-11-08")

        diff = compare([self.a, self.b], index2)
        states = {f["finding_id"]: f["baseline_state"] for f in diff.findings}
        self.assertEqual(states["B"], "regressed")
        third = update_baseline(index2, diff, "2026-11-15")
        entry = {e["fingerprint"]: e for e in third["entries"]}[self.b["fingerprint"]]
        self.assertEqual((entry["state"], entry["fixed_at"], entry["first_seen"]), ("open", None, "2026-11-01"))

    def test_rejected_findings_are_ignored(self) -> None:
        rejected = {**self.a, "status": "rejected"}
        diff = compare([rejected], {})
        self.assertEqual(diff.findings[0].get("baseline_state"), None)
        self.assertEqual(diff.counts["new"], 0)

    def test_update_is_immutable(self) -> None:
        index = {e["fingerprint"]: e for e in self._baseline([self.a])["entries"]}
        snapshot = json.dumps(index, sort_keys=True)
        update_baseline(index, compare([], index), "2026-12-01")
        self.assertEqual(json.dumps(index, sort_keys=True), snapshot)

    def test_baseline_document_matches_schema(self) -> None:
        doc = self._baseline([self.a, self.b])
        self.assertEqual(load_validator("baseline.schema.json")(doc), [])


class TestLoadBaseline(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def test_loads_baseline_json(self) -> None:
        doc = update_baseline({}, compare([{**_finding(), "fingerprint": "kfp1:" + "d" * 64}], {}), "2026-11-01")
        write_json(self.dir / "baseline.json", doc)
        self.assertEqual(list(load_baseline(self.dir / "baseline.json")), ["kfp1:" + "d" * 64])

    def test_loads_sarif_partial_fingerprints(self) -> None:
        sarif = to_sarif({"findings": [{**_finding(), "fingerprint": "kfp1:" + "e" * 64}]})
        write_json(self.dir / "prev.sarif", sarif)
        entries = load_baseline(self.dir / "prev.sarif")
        self.assertEqual(entries["kfp1:" + "e" * 64]["state"], "open")

    def test_invalid_file_raises(self) -> None:
        (self.dir / "bad.json").write_text("{not json", encoding="utf-8")
        with self.assertRaises(BaselineError):
            load_baseline(self.dir / "bad.json")
        write_json(self.dir / "wrong.json", {"hello": 1})
        with self.assertRaises(BaselineError):
            load_baseline(self.dir / "wrong.json")
        with self.assertRaises(BaselineError):
            load_baseline(self.dir / "missing.json")


class TestGate(unittest.TestCase):
    def setUp(self) -> None:
        self.findings = [
            {**_finding(fid="N", severity="medium"), "baseline_state": "new"},
            {**_finding(fid="U", severity="critical"), "baseline_state": "unchanged"},
            {**_finding(fid="R", severity="low"), "baseline_state": "regressed"},
        ]

    def ids(self, tripped: list) -> list:
        return sorted(f["finding_id"] for f in tripped)

    def test_none_never_fails(self) -> None:
        self.assertEqual(gate(self.findings, "none", "info"), [])

    def test_new_includes_regressed(self) -> None:
        self.assertEqual(self.ids(gate(self.findings, "new", "low")), ["N", "R"])

    def test_any_includes_unchanged(self) -> None:
        self.assertEqual(self.ids(gate(self.findings, "any", "low")), ["N", "R", "U"])

    def test_severity_threshold(self) -> None:
        self.assertEqual(self.ids(gate(self.findings, "new", "medium")), ["N"])
        self.assertEqual(self.ids(gate(self.findings, "any", "high")), ["U"])

    def test_rejected_never_trips(self) -> None:
        rejected = [{**self.findings[0], "status": "rejected"}]
        self.assertEqual(gate(rejected, "any", "info"), [])


class TestSarifBaselineState(unittest.TestCase):
    def test_baseline_state_mapping(self) -> None:
        findings = [
            {**_finding(fid="N"), "baseline_state": "new"},
            {**_finding(fid="U", line=5), "baseline_state": "unchanged"},
            {**_finding(fid="R", line=3), "baseline_state": "regressed"},
            _finding(fid="X", line=2),
        ]
        results = {r["partialFingerprints"]["lsaFindingId"]: r for r in to_sarif({"findings": findings})["runs"][0]["results"]}
        self.assertEqual(results["N"]["baselineState"], "new")
        self.assertEqual(results["U"]["baselineState"], "unchanged")
        self.assertEqual(results["R"]["baselineState"], "new")
        self.assertTrue(results["R"]["properties"]["regressed"])
        self.assertNotIn("baselineState", results["X"])

    def test_finding_schema_accepts_baseline_state(self) -> None:
        validate = load_validator("finding.schema.json")
        self.assertEqual(validate({**_finding(), "baseline_state": "regressed"}), [])
        self.assertNotEqual(validate({**_finding(), "baseline_state": "fixed"}), [])


class TestBaselineCli(_TargetMixin, unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name) / "out"
        self.target = self.make_target()
        write_json(self.out / "findings.json", {"findings": [_finding()], "summary": {}})

    def run_cli(self, *extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(BASELINE_PY), str(self.out), "--target-dir", str(self.target), "--today", "2026-11-01", *extra],
            capture_output=True,
            text=True,
        )

    def test_assigns_fingerprints_and_writes_diff(self) -> None:
        res = self.run_cli()
        self.assertEqual(res.returncode, 0, res.stderr)
        doc = json.loads((self.out / "findings.json").read_text(encoding="utf-8"))
        self.assertRegex(doc["findings"][0]["fingerprint"], FP_RE)
        self.assertEqual(doc["findings"][0]["baseline_state"], "new")
        diff = json.loads((self.out / "baseline-diff.json").read_text(encoding="utf-8"))
        self.assertEqual(diff["counts"]["new"], 1)

    def test_rescan_against_own_baseline_has_no_new_findings(self) -> None:
        baseline = self.out / "baseline.json"
        self.assertEqual(self.run_cli("--baseline", str(baseline), "--update-baseline").returncode, 0)
        self.assertTrue(baseline.is_file())
        res = self.run_cli("--baseline", str(baseline), "--fail-on", "new")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        diff = json.loads((self.out / "baseline-diff.json").read_text(encoding="utf-8"))
        self.assertEqual(diff["counts"], {"new": 0, "unchanged": 1, "regressed": 0, "fixed": 0})

    def test_fail_on_new_exits_1(self) -> None:
        res = self.run_cli("--fail-on", "new")
        self.assertEqual(res.returncode, 1)
        self.assertIn("INJ-I-0001-1", res.stdout)

    def test_missing_baseline_without_update_is_usage_error(self) -> None:
        res = self.run_cli("--baseline", str(self.out / "nope.json"))
        self.assertEqual(res.returncode, 2)

    def test_missing_baseline_with_update_starts_fresh(self) -> None:
        res = self.run_cli("--baseline", str(self.out / "first.json"), "--update-baseline")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue((self.out / "first.json").is_file())


if __name__ == "__main__":
    unittest.main()
