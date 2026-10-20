#!/usr/bin/env python3
"""Tests for Enterprise SARIF 2.1.0 Exporter (Issue #198).

Validates:
1. SARIF 2.1.0 structure, schema conformity, invocations telemetry.
2. CWE taxonomy (taxa) and relationships mapping.
3. OWASP Top 10 tags and GitHub CodeQL tag conventions.
4. Code snippet extraction from target codebase with evidence fallback.
5. CLI integration (--target-dir, --sarif-out, komainu scan --sarif-out).
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

from findings_to_sarif import extract_snippet, normalize_cwe_id, to_sarif  # noqa: E402
from lsa_common import write_json  # noqa: E402


class TestSarifExport(unittest.TestCase):
    def setUp(self) -> None:
        self.sample_findings_doc = {
            "$schema": "https://raw.githubusercontent.com/hoanghainh1188/komainu/main/contracts/schemas/finding.schema.json",
            "findings": [
                {
                    "finding_id": "BOLA-order-1",
                    "category": "bola",
                    "subtype": "missing_ownership_check",
                    "title": "Order readable by arbitrary user ID",
                    "endpoint": {"method": "GET", "path": "/api/orders/{id}"},
                    "location": {"file": "controllers/orders.py", "start_line": 15, "end_line": 17},
                    "evidence": [
                        {"file": "controllers/orders.py", "line": 16, "code": "order = Order.get(req.params['id'])", "why": "Unchecked id lookup"}
                    ],
                    "severity": "high",
                    "confidence": "high",
                    "cwe": ["CWE-639"],
                    "recommendation": "Bind lookup to current user: Order.get(id, user_id=current_user.id)",
                    "status": "confirmed",
                },
                {
                    "finding_id": "INJ-search-1",
                    "category": "sql_injection",
                    "subtype": "string_concatenation",
                    "title": "Raw SQL query constructed via concatenation",
                    "endpoint": {"method": "GET", "path": "/search"},
                    "location": {"file": "models/query.py", "start_line": 42},
                    "evidence": [
                        {"file": "models/query.py", "line": 42, "code": 'db.exec("SELECT * FROM items WHERE q = " + q)', "why": "Direct concat"}
                    ],
                    "severity": "critical",
                    "confidence": "high",
                    "cwe": [89],
                    "recommendation": "Use parameterized query placeholders.",
                    "status": "confirmed",
                },
                {
                    "finding_id": "BOLA-rejected-1",
                    "category": "bola",
                    "subtype": "missing_ownership_check",
                    "title": "False positive BOLA",
                    "location": {"file": "controllers/public.py", "start_line": 5},
                    "evidence": [],
                    "severity": "low",
                    "confidence": "low",
                    "cwe": ["CWE-639"],
                    "recommendation": "None",
                    "status": "rejected",
                },
            ],
            "summary": {
                "total": 3,
                "by_severity": {"critical": 1, "high": 1, "medium": 0, "low": 1, "info": 0},
                "by_status": {"confirmed": 2, "rejected": 1},
            },
        }

    def test_sarif_structure_and_schema_basics(self) -> None:
        sarif = to_sarif(self.sample_findings_doc, include_rejected=False)

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(sarif["$schema"].endswith("sarif-2.1.0.json"))
        self.assertIn("runs", sarif)
        self.assertEqual(len(sarif["runs"]), 1)

        run = sarif["runs"][0]
        # Invocations telemetry
        self.assertIn("invocations", run)
        self.assertEqual(len(run["invocations"]), 1)
        inv = run["invocations"][0]
        self.assertTrue(inv["executionSuccessful"])
        self.assertTrue(inv["startTimeUtc"].endswith("Z"))
        self.assertTrue(inv["endTimeUtc"].endswith("Z"))

        # Results filtering (rejected omitted by default)
        results = run["results"]
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["level"], "error")
        self.assertEqual(results[0]["properties"]["security-severity"], "8.0")
        self.assertEqual(results[1]["properties"]["security-severity"], "9.5")

    def test_taxonomies_and_relationships(self) -> None:
        sarif = to_sarif(self.sample_findings_doc, include_rejected=False)
        run = sarif["runs"][0]

        # Taxonomies
        self.assertIn("taxonomies", run)
        self.assertEqual(len(run["taxonomies"]), 1)
        cwe_tax = run["taxonomies"][0]
        self.assertEqual(cwe_tax["name"], "CWE")
        taxa_ids = [t["id"] for t in cwe_tax["taxa"]]
        self.assertIn("CWE-639", taxa_ids)
        self.assertIn("CWE-89", taxa_ids)

        # Tool driver supportedTaxonomies
        driver = run["tool"]["driver"]
        self.assertEqual(driver["supportedTaxonomies"], [{"name": "CWE", "index": 0}])

        # Rule relationships
        rules = driver["rules"]
        self.assertEqual(len(rules), 2)
        bola_rule = next(r for r in rules if r["name"] == "bola.missing_ownership_check")
        self.assertTrue(any(rel["target"]["id"] == "CWE-639" for rel in bola_rule["relationships"]))

        # GitHub and OWASP tags
        tags = bola_rule["properties"]["tags"]
        self.assertIn("security", tags)
        self.assertIn("external/cwe/cwe-639", tags)
        self.assertIn("OWASP:A01:2021-Broken Access Control", tags)
        self.assertIn("OWASP-API1:2023-BOLA", tags)

        sql_rule = next(r for r in rules if r["name"] == "sql_injection.string_concatenation")
        sql_tags = sql_rule["properties"]["tags"]
        self.assertIn("external/cwe/cwe-89", sql_tags)
        self.assertIn("OWASP:A03:2021-Injection", sql_tags)

    def test_snippet_extraction_from_target_dir(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo_dir = Path(td)
            ctrl_dir = repo_dir / "controllers"
            ctrl_dir.mkdir(parents=True)
            orders_file = ctrl_dir / "orders.py"

            content = [f"# Line {i}\n" for i in range(1, 15)]
            content.append("def get_order(req):\n")  # Line 15
            content.append("    order_id = req.params['id']\n")  # Line 16
            content.append("    return db.fetch(order_id)\n")  # Line 17
            orders_file.write_text("".join(content), encoding="utf-8")

            sarif = to_sarif(self.sample_findings_doc, include_rejected=False, target_dir=repo_dir)
            bola_result = sarif["runs"][0]["results"][0]
            region = bola_result["locations"][0]["physicalLocation"]["region"]

            self.assertIn("snippet", region)
            self.assertEqual(
                region["snippet"]["text"],
                "def get_order(req):\n    order_id = req.params['id']\n    return db.fetch(order_id)",
            )

    def test_snippet_fallback_to_evidence(self) -> None:
        # Without target_dir, should fall back to evidence code
        sarif = to_sarif(self.sample_findings_doc, include_rejected=False, target_dir=None)
        sql_result = sarif["runs"][0]["results"][1]
        region = sql_result["locations"][0]["physicalLocation"]["region"]

        self.assertIn("snippet", region)
        self.assertEqual(region["snippet"]["text"], 'db.exec("SELECT * FROM items WHERE q = " + q)')

    def test_cli_findings_to_sarif_flags(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "out"
            out_dir.mkdir()
            findings_file = out_dir / "findings.json"
            write_json(findings_file, self.sample_findings_doc)

            custom_sarif = Path(td) / "reports" / "custom-output.sarif"
            cmd = [
                sys.executable,
                str(KIT / "scripts" / "findings_to_sarif.py"),
                str(out_dir),
                "--sarif-out",
                str(custom_sarif),
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertTrue(custom_sarif.is_file())

            sarif_data = json.loads(custom_sarif.read_text(encoding="utf-8"))
            self.assertEqual(sarif_data["version"], "2.1.0")
            self.assertEqual(len(sarif_data["runs"][0]["results"]), 2)


if __name__ == "__main__":
    unittest.main()
