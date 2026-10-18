#!/usr/bin/env python3
"""Tests for LSA Self-Contained Interactive HTML Audit Dashboard (Issue #50).

Verifies:
1. render_html produces valid, self-contained HTML5 with zero external HTTP/CDN dependencies.
2. Dashboard includes executive header, risk rating badge, KPI cards, and inline SVG charts.
3. Bilingual EN/JA attributes (data-en / data-ja) and toggleLanguage() switcher are present.
4. Interactive table filters, search box, expandable drawers, and Copy Remediation Patch buttons work.
5. CLI flags --format html, --format all, and --out-file custom.html produce expected files.
"""

from __future__ import annotations

from html.parser import HTMLParser
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
KIT = HERE.parent
sys.path.insert(0, str(KIT / "scripts"))

from render_report import render_html  # noqa: E402


class _HTMLStructureValidator(HTMLParser):
    """Lightweight HTML5 structure validator for unit testing."""

    def __init__(self) -> None:
        super().__init__()
        self.has_doctype = False
        self.tags_seen: set[str] = set()
        self.external_urls: list[str] = []
        self.bilingual_nodes = 0

    def handle_decl(self, decl: str) -> None:
        if decl.lower().startswith("doctype html"):
            self.has_doctype = True

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags_seen.add(tag.lower())
        attr_dict = dict(attrs)
        for attr_name in ("src", "href"):
            val = attr_dict.get(attr_name) or ""
            if val.startswith(("http://", "https://", "//")):
                self.external_urls.append(val)
        if "data-en" in attr_dict and "data-ja" in attr_dict:
            self.bilingual_nodes += 1


class TestHTMLDashboardGeneration(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp_dir.name)

        findings_data = {
            "summary": {
                "total": 3,
                "by_severity": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0},
                "by_category": {"bola": 1, "sql_injection": 1, "nosql_injection": 0},
                "by_status": {"confirmed": 2, "rejected": 1},
            },
            "findings": [
                {
                    "finding_id": "BOLA-orders-001",
                    "category": "bola",
                    "subtype": "missing_ownership_check",
                    "title": "Order detail readable by arbitrary order ID",
                    "location": {"file": "php-plain/order_detail.php", "start_line": 42},
                    "endpoint": {"method": "GET", "path": "/order_detail.php"},
                    "evidence": [
                        {
                            "file": "php-plain/order_detail.php",
                            "line": 45,
                            "code": "$order = Order::find($_GET['id']);",
                            "why": "No session user_id or tenant_id ownership predicate bound to query.",
                        }
                    ],
                    "data_flow": ["$_GET['id']", "Order::find($id)"],
                    "severity": "high",
                    "confidence": "confirmed",
                    "cwe": ["CWE-639"],
                    "owasp": ["API1:2023"],
                    "attack_scenario": "Authenticated user B changes ?id= to read user A's order.",
                    "impact": "Unauthorized disclosure of customer PII and order history.",
                    "recommendation": "Use Guard::requireOwnership($pdo, 'orders', 'id', $id, 'user_id', $_SESSION['user_id']).",
                    "fix_example": "Guard::requireOwnership($pdo, 'orders', 'id', $id, 'user_id', $_SESSION['user_id']);",
                    "status": "confirmed",
                    "verification": {
                        "verdict": "confirmed",
                        "checked": ["php-plain/inc/auth.php"],
                        "notes": "Verified inc/auth.php only checks login state.",
                    },
                },
                {
                    "finding_id": "INJ-search-001",
                    "category": "sql_injection",
                    "subtype": "string_concatenation",
                    "title": "SQL injection via concatenated search query",
                    "location": {"file": "java-servlet-jsp/SearchServlet.java", "start_line": 20},
                    "endpoint": {"method": "GET", "path": "/search"},
                    "evidence": [
                        {
                            "file": "java-servlet-jsp/SearchServlet.java",
                            "line": 22,
                            "code": "String sql = \"SELECT * FROM items WHERE name = '\" + q + \"'\";",
                            "why": "Untrusted request parameter concatenated into SQL string.",
                        }
                    ],
                    "severity": "critical",
                    "confidence": "confirmed",
                    "cwe": ["CWE-89"],
                    "owasp": ["A03:2021"],
                    "attack_scenario": "Attacker supplies SQL metacharacters in q parameter.",
                    "impact": "Full database read/write compromise.",
                    "recommendation": "Use SafeSql.queryList(conn, sql, params).",
                    "fix_example": "SafeSql.queryList(conn, \"SELECT * FROM items WHERE name = ?\", List.of(q));",
                    "status": "confirmed",
                },
                {
                    "finding_id": "BOLA-internal-002",
                    "category": "bola",
                    "subtype": "missing_ownership_check",
                    "title": "Internal token helper without HTTP exposure",
                    "location": {"file": "java-struts1/UserDAO.java", "start_line": 88},
                    "endpoint": {"method": "INTERNAL", "path": "UserDAO.findByResetToken"},
                    "evidence": [],
                    "severity": "medium",
                    "confidence": "low",
                    "cwe": ["CWE-639"],
                    "owasp": ["API1:2023"],
                    "recommendation": "N/A",
                    "status": "rejected",
                    "verification": {
                        "verdict": "rejected",
                        "checked": ["struts-config.xml"],
                        "notes": "Not exposed as an HTTP action; internal password reset token lookup.",
                    },
                },
            ],
        }

        coverage_data = {
            "inventoried": 18,
            "route_candidates": 20,
            "bola_routes_to_audit": 12,
            "injection_candidates": 9,
        }

        stack_data = {"stacks": [{"id": "php-plain"}, {"id": "java-servlet-jsp"}]}

        (self.out / "findings.json").write_text(json.dumps(findings_data), encoding="utf-8")
        (self.out / "coverage.json").write_text(json.dumps(coverage_data), encoding="utf-8")
        (self.out / "stack-profile.json").write_text(json.dumps(stack_data), encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_html_is_self_contained_and_valid_html5(self) -> None:
        """HTML dashboard must be valid HTML5 with zero external CDN/HTTP links."""
        html_doc = render_html(self.out, "TestEnterpriseApp")
        validator = _HTMLStructureValidator()
        validator.feed(html_doc)

        self.assertTrue(validator.has_doctype, "Missing <!DOCTYPE html> declaration")
        for required_tag in ("html", "head", "style", "body", "svg", "table", "script"):
            self.assertIn(required_tag, validator.tags_seen, f"Missing <{required_tag}> tag")
        self.assertEqual(
            validator.external_urls,
            [],
            f"HTML dashboard must have zero external dependencies, found: {validator.external_urls}",
        )
        self.assertGreaterEqual(validator.bilingual_nodes, 25, "Expected bilingual data-en/data-ja attributes")

    def test_html_contains_charts_filters_bilingual_and_drawer_controls(self) -> None:
        """Verify executive header, SVG charts, filters, bilingual toggle, and copy patch button."""
        html_doc = render_html(self.out, "TestEnterpriseApp")

        # Executive Header & Risk Rating
        self.assertIn("Security Audit Dashboard — TestEnterpriseApp", html_doc)
        self.assertIn("セキュリティ監査ダッシュボード — TestEnterpriseApp", html_doc)
        self.assertIn("CRITICAL RISK", html_doc)
        self.assertIn("総合リスク: 緊急 (CRITICAL)", html_doc)

        # Charts & Findings
        self.assertIn('aria-label="Severity Distribution Chart"', html_doc)
        self.assertIn('aria-label="Category Breakdown Chart"', html_doc)
        self.assertIn("BOLA-orders-001", html_doc)
        self.assertIn("INJ-search-001", html_doc)
        self.assertIn("BOLA-internal-002", html_doc)  # In Appendix A rejected table

        # Interactive Controls
        self.assertIn('id="lang-toggle"', html_doc)
        self.assertIn('id="search-input"', html_doc)
        self.assertIn('id="sev-filter"', html_doc)
        self.assertIn('id="cat-filter"', html_doc)
        self.assertIn('id="stack-filter"', html_doc)
        self.assertIn("copyPatch(", html_doc)
        self.assertIn("toggleLanguage()", html_doc)
        self.assertIn("@media print", html_doc)

    def test_cli_format_options(self) -> None:
        """Verify CLI --format html, --format all, and --out-file custom.html."""
        script = str(KIT / "scripts" / "render_report.py")

        # 1. --format html -> produces report.html
        res = subprocess.run(
            [sys.executable, script, str(self.out), "--format", "html"],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(res.returncode, 0)
        self.assertTrue((self.out / "report.html").is_file())

        # 2. --format all --lang all -> produces report.md, report.ja.md, and report.html
        (self.out / "report.html").unlink()
        res = subprocess.run(
            [sys.executable, script, str(self.out), "--format", "all", "--lang", "all"],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertTrue((self.out / "report.md").is_file())
        self.assertTrue((self.out / "report.ja.md").is_file())
        self.assertTrue((self.out / "report.html").is_file())

        # 3. --out-file custom-dashboard.html
        custom_html = self.out / "custom-dashboard.html"
        res = subprocess.run(
            [sys.executable, script, str(self.out), "--lang", "ja", "--out-file", str(custom_html)],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertTrue(custom_html.is_file())
        content = custom_html.read_text(encoding="utf-8")
        self.assertIn('<html lang="ja">', content)


if __name__ == "__main__":
    unittest.main()
