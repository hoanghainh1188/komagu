#!/usr/bin/env python3
"""Tests for scan history, MTTR and the trend report section (Issue #270, part d).

Validates:
1. Snapshots count open findings by severity, excluding suppressed ones.
2. History replaces a same-day snapshot, stays sorted and is capped.
3. MTTR per severity from baseline first_seen / fixed_at.
4. baseline.py stores history in baseline.json and a trend in baseline-diff.json.
5. Markdown (EN/JA) and HTML reports render a trend section only when a
   trend exists; HTML stays self-contained and escapes text.
"""
from __future__ import annotations

import datetime
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
KIT = HERE.parent
sys.path.insert(0, str(KIT / "scripts"))

from lsa_common import write_json  # noqa: E402
from merge_findings import load_validator  # noqa: E402
from render_report import render_en, render_html, render_ja  # noqa: E402
from trend import HISTORY_LIMIT, append_history, mttr_by_severity, render_trend_html, snapshot  # noqa: E402

BASELINE_PY = KIT / "scripts" / "baseline.py"


def _finding(fid: str, severity: str, **overrides: object) -> dict:
    base = {
        "finding_id": f"BOLA-{fid}",
        "category": "bola",
        "subtype": "missing_ownership_check",
        "title": f"Finding {fid}",
        "location": {"file": f"{fid}.php", "start_line": 2},
        "evidence": [{"file": f"{fid}.php", "line": 2, "code": f"q_{fid}($id)", "why": "no owner check"}],
        "severity": severity,
        "confidence": "high",
        "cwe": ["CWE-639"],
        "recommendation": "Bind to the current user.",
        "status": "confirmed",
    }
    base.update(overrides)
    return base


class TestSnapshotAndHistory(unittest.TestCase):
    def test_snapshot_excludes_suppressed_and_rejected(self) -> None:
        findings = [
            {**_finding("a", "high"), "baseline_state": "new"},
            {**_finding("b", "critical"), "baseline_state": "unchanged"},
            {**_finding("c", "high"), "baseline_state": "unchanged", "suppression": {"reason": "r", "approved_by": "x"}},
            {**_finding("d", "low", status="rejected")},
        ]
        counts = {"new": 1, "unchanged": 2, "regressed": 0, "fixed": 3, "suppressed": 1}
        snap = snapshot(counts, findings, "2026-11-01")
        self.assertEqual(snap["date"], "2026-11-01")
        self.assertEqual(snap["open"], 2)
        self.assertEqual(snap["by_severity"], {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0})
        self.assertEqual((snap["new"], snap["fixed"], snap["suppressed"]), (1, 3, 1))

    def test_same_day_replaced_sorted_and_capped(self) -> None:
        history = [{"date": "2026-11-02", "open": 5}, {"date": "2026-11-01", "open": 6}]
        updated = append_history(history, {"date": "2026-11-02", "open": 4})
        self.assertEqual([(h["date"], h["open"]) for h in updated], [("2026-11-01", 6), ("2026-11-02", 4)])
        self.assertEqual(len(history), 2)

        start = datetime.date(2025, 1, 1)
        long_history = [{"date": (start + datetime.timedelta(days=i)).isoformat(), "open": 1} for i in range(400)]
        capped = append_history(long_history, {"date": "2026-12-31", "open": 0})
        self.assertEqual(len(capped), HISTORY_LIMIT)
        self.assertEqual(capped[-1]["date"], "2026-12-31")

    def test_mttr_by_severity(self) -> None:
        entries = [
            {"severity": "high", "state": "fixed", "first_seen": "2026-11-01", "fixed_at": "2026-11-11"},
            {"severity": "high", "state": "fixed", "first_seen": "2026-11-01", "fixed_at": "2026-11-21"},
            {"severity": "critical", "state": "fixed", "first_seen": "2026-11-01", "fixed_at": "2026-11-03"},
            {"severity": "high", "state": "open", "first_seen": "2026-11-01", "fixed_at": None},
            {"severity": "low", "state": "fixed", "first_seen": None, "fixed_at": "2026-11-05"},
        ]
        self.assertEqual(mttr_by_severity(entries), {
            "critical": {"fixed": 1, "mean_days": 2.0},
            "high": {"fixed": 2, "mean_days": 15.0},
        })


class TestBaselineHistory(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name) / "out"
        self.baseline = Path(tmp.name) / "baseline.json"

    def run_cli(self, today: str, *findings: dict, update: bool = True) -> dict:
        write_json(self.out / "findings.json", {"findings": list(findings), "summary": {}})
        cmd = [sys.executable, str(BASELINE_PY), str(self.out), "--baseline", str(self.baseline), "--today", today]
        if update:
            cmd.append("--update-baseline")
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads((self.out / "baseline-diff.json").read_text(encoding="utf-8"))

    def test_history_and_mttr_across_scans(self) -> None:
        a, b = _finding("a", "high"), _finding("b", "critical")
        self.run_cli("2026-11-01", a, b)
        self.run_cli("2026-11-04", a)
        diff = self.run_cli("2026-11-04", a)  # same-day rerun replaces the snapshot

        doc = json.loads(self.baseline.read_text(encoding="utf-8"))
        self.assertEqual(load_validator("baseline.schema.json")(doc), [])
        self.assertEqual([(h["date"], h["open"]) for h in doc["history"]], [("2026-11-01", 2), ("2026-11-04", 1)])
        self.assertEqual(diff["trend"]["history"], doc["history"])
        self.assertEqual(diff["trend"]["mttr"], {"critical": {"fixed": 1, "mean_days": 3.0}})

    def test_without_update_trend_shows_current_scan_but_file_is_untouched(self) -> None:
        self.run_cli("2026-11-01", _finding("a", "high"))
        before = self.baseline.read_text(encoding="utf-8")
        diff = self.run_cli("2026-11-02", update=False)
        self.assertEqual(self.baseline.read_text(encoding="utf-8"), before)
        self.assertEqual([h["date"] for h in diff["trend"]["history"]], ["2026-11-01", "2026-11-02"])
        self.assertEqual(diff["trend"]["mttr"], {"high": {"fixed": 1, "mean_days": 1.0}})


    def test_diff_scan_does_not_add_history(self) -> None:
        self.run_cli("2026-11-01", _finding("a", "high"))
        write_json(self.out / "diff-scope.json", {"base_ref": "main", "changed": ["a.php"], "selected": ["a.php"]})
        write_json(self.out / "findings.json", {"findings": [_finding("a", "high")], "summary": {}})
        res = subprocess.run(
            [sys.executable, str(BASELINE_PY), str(self.out), "--baseline", str(self.baseline), "--update-baseline",
             "--diff-scope", str(self.out / "diff-scope.json"), "--today", "2026-11-05"],
            capture_output=True, text=True,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        doc = json.loads(self.baseline.read_text(encoding="utf-8"))
        self.assertEqual([h["date"] for h in doc["history"]], ["2026-11-01"])

class TestTrendReport(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name)
        summary = {
            "total": 1,
            "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            "by_category": {"bola": 1, "sql_injection": 0, "nosql_injection": 0},
            "by_status": {"confirmed": 1},
        }
        write_json(self.out / "findings.json", {"findings": [_finding("a", "high")], "summary": summary})
        self.trend = {
            "history": [
                {"date": "2026-11-01", "open": 4, "new": 4, "regressed": 0, "fixed": 0, "suppressed": 0,
                 "by_severity": {"critical": 1, "high": 3, "medium": 0, "low": 0, "info": 0}},
                {"date": "2026-11-08", "open": 1, "new": 0, "regressed": 0, "fixed": 3, "suppressed": 0,
                 "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}},
            ],
            "mttr": {"critical": {"fixed": 1, "mean_days": 7.0}, "high": {"fixed": 2, "mean_days": 7.0}},
        }

    def add_trend(self) -> None:
        write_json(self.out / "baseline-diff.json", {"counts": {}, "trend": self.trend})

    def test_no_trend_section_without_baseline(self) -> None:
        self.assertNotIn("Trend", render_en(self.out, "App"))
        self.assertNotIn("推移", render_ja(self.out, "App"))
        self.assertNotIn('class="trend-svg"', render_html(self.out, "App"))

    def test_markdown_trend_sections(self) -> None:
        self.add_trend()
        en = render_en(self.out, "App")
        self.assertIn("## Trend and time to fix", en)
        self.assertIn("| 2026-11-08 | 1 | 0 | 0 | 3 | 0 |", en)
        self.assertIn("| high | 2 | 7.0 |", en)
        ja = render_ja(self.out, "App")
        self.assertIn("## 検出推移と平均修正日数 (MTTR)", ja)
        self.assertIn("| 2026-11-01 | 4 | 4 | 0 | 0 | 0 |", ja)

    def test_html_trend_card(self) -> None:
        self.add_trend()
        html_doc = render_html(self.out, "App")
        self.assertIn('class="trend-svg"', html_doc)
        self.assertIn("polyline", html_doc)
        self.assertIn('data-ja="平均修正日数 (MTTR)"', html_doc)

    def test_html_escapes_untrusted_dates(self) -> None:
        self.trend["history"][0]["date"] = "<script>alert(1)</script>"
        fragment = render_trend_html(self.trend)
        self.assertNotIn("<script>", fragment)
        self.assertIn("&lt;script&gt;", fragment)

    def test_single_snapshot_renders_without_error(self) -> None:
        self.trend["history"] = self.trend["history"][:1]
        self.assertIn("trend-svg", render_trend_html(self.trend))


if __name__ == "__main__":
    unittest.main()
