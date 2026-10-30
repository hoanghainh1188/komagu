#!/usr/bin/env python3
"""Reports show BFLA and mass assignment (#269e).

Checks the EN / JA Markdown and the HTML dashboard:
1. Scope names BFLA and mass assignment.
2. Coverage lists privileged routes and mass assignment candidates when
   coverage.json has them, and keeps the old table when it does not.
3. The HTML category filter and KPI card show the new categories only when found.
4. Default fix text in the HTML drawer matches the finding's category.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))

from render_report import render_en, render_html, render_ja  # noqa: E402


def finding(fid, cat, subtype, cwe, fix=None):
    f = {
        "finding_id": fid, "category": cat, "subtype": subtype, "title": f"{cat} title",
        "location": {"file": "app/x.php", "start_line": 3},
        "endpoint": {"method": "POST", "path": "/admin/x"},
        "evidence": [], "severity": "high", "confidence": "high",
        "cwe": [cwe], "owasp": [], "recommendation": "r", "status": "confirmed",
    }
    if fix:
        f["fix_example"] = fix
    return f


PRIV = [
    finding("BFLA-R-1-1", "bfla", "missing_role_check", "CWE-285"),
    finding("MASS-M-1-1", "mass_assignment", "whole_object_binding", "CWE-915"),
]
LEGACY = [finding("BOLA-R-2-1", "bola", "missing_ownership_check", "CWE-639", fix="bind owner")]
PRIV_COVERAGE = {"inventoried": 5, "route_candidates": 5, "bola_routes_to_audit": 4,
                 "injection_candidates": 2, "bfla_routes_to_audit": 3, "mass_candidates": 2}
OLD_COVERAGE = {"inventoried": 5, "route_candidates": 5, "bola_routes_to_audit": 4, "injection_candidates": 2}


def write_out(d: Path, findings, coverage):
    by_cat = {"bola": 0, "sql_injection": 0, "nosql_injection": 0}
    for f in findings:
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
    (d / "findings.json").write_text(json.dumps({
        "summary": {"total": len(findings), "by_severity": {"high": len(findings)},
                    "by_category": by_cat, "by_status": {"confirmed": len(findings)}},
        "findings": findings}), encoding="utf-8")
    (d / "coverage.json").write_text(json.dumps(coverage), encoding="utf-8")


class ReportCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()


class TestMarkdown(ReportCase):
    def test_en_scope_and_coverage(self):
        write_out(self.out, LEGACY + PRIV, PRIV_COVERAGE)
        md = render_en(self.out, "p")
        self.assertIn("BFLA", md.split("## 1.")[0])
        self.assertIn("mass assignment", md.split("## 1.")[0])
        self.assertIn("| Privileged routes audited for BFLA | 3 |", md)
        self.assertIn("| Mass assignment candidates reviewed | 2 |", md)

    def test_en_old_coverage_has_no_new_rows(self):
        write_out(self.out, LEGACY, OLD_COVERAGE)
        md = render_en(self.out, "p")
        self.assertNotIn("Privileged routes audited", md)
        self.assertNotIn("Mass assignment candidates", md)

    def test_ja_scope_and_coverage(self):
        write_out(self.out, LEGACY + PRIV, PRIV_COVERAGE)
        md = render_ja(self.out, "p")
        head = md.split("## 1.")[0]
        self.assertIn("BFLA", head)
        self.assertIn("マスアサインメント", head)
        self.assertIn("| BFLA監査対象の特権エンドポイント数 | 3 |", md)
        self.assertIn("| レビュー対象マスアサインメント候補数 | 2 |", md)

    def test_ja_old_coverage_has_no_new_rows(self):
        write_out(self.out, LEGACY, OLD_COVERAGE)
        self.assertNotIn("BFLA監査対象", render_ja(self.out, "p"))


class TestHtml(ReportCase):
    def test_filter_and_kpi_show_new_categories(self):
        write_out(self.out, LEGACY + PRIV, PRIV_COVERAGE)
        page = render_html(self.out, "p")
        self.assertIn('<option value="bfla"', page)
        self.assertIn('<option value="mass_assignment"', page)
        self.assertIn("BFLA: 3", page)
        self.assertIn("Mass: 2", page)
        self.assertIn("CWE-285", page.split(">Scope:</strong>")[1][:600])

    def test_filter_unchanged_without_new_categories(self):
        write_out(self.out, LEGACY, OLD_COVERAGE)
        page = render_html(self.out, "p")
        self.assertNotIn('<option value="bfla"', page)
        self.assertNotIn('<option value="mass_assignment"', page)
        self.assertNotIn("BFLA: ", page)

    def test_default_fix_matches_category(self):
        write_out(self.out, PRIV, PRIV_COVERAGE)
        page = render_html(self.out, "p")
        self.assertNotIn("Parameterize query", page)
        self.assertIn("role", page.split('id="patch-code-0"')[1][:300])
        self.assertIn("allow-list", page.split('id="patch-code-1"')[1][:300])


if __name__ == "__main__":
    unittest.main()
