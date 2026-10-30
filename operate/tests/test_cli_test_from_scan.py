#!/usr/bin/env python3
"""Tests for Komagu Test Ingestion from LSA Scan Output (TASK-1.3, TASK-1.4, TASK-1.6).

Validates:
1. Parsing BOLA endpoints from native findings.json and OASIS SARIF 2.1.0.
2. Filtering by Multi-AI Consensus score threshold.
3. End-to-end active exploit verification against mock HTTP server.
4. Correct exit codes: 1 when BOLA breach detected, 0 when protected.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from operate.cli.main import main as cli_main
from operate.cross_user_tester.mock_test_server import start_mock_server
from operate.cross_user_tester.runner import (
    CrossUserTestRunner,
    generate_test_cases_from_findings,
)


class TestCliTestFromScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Start in-memory mock server for cross-user test
        cls.server, cls.thread, cls.base_url = start_mock_server(port=0)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.server_close()

    def setUp(self) -> None:
        self.sample_findings = {
            "$schema": "https://raw.githubusercontent.com/hoanghainh1188/komainu/main/contracts/schemas/finding.schema.json",
            "findings": [
                {
                    "finding_id": "BOLA-vulnerable-order",
                    "category": "bola",
                    "subtype": "missing_ownership_check",
                    "title": "Legacy Order accessible across tenants",
                    "endpoint": {"method": "GET", "path": "/api/legacy-orders/{id}"},
                    "location": {"file": "controllers/orders.py", "start_line": 10},
                    "evidence": [{"file": "controllers/orders.py", "line": 10, "why": "Unchecked lookup"}],
                    "severity": "critical",
                    "confidence": "high",
                    "cwe": ["CWE-639"],
                    "status": "confirmed",
                    "consensus": {
                        "score": 0.95,
                        "agreement_level": "unanimous",
                        "voted_models": ["gemini-2.0-pro", "claude-3-7", "deepseek-r1"],
                    },
                    "recommendation": "Enforce session user isolation",
                },
                {
                    "finding_id": "BOLA-protected-order",
                    "category": "bola",
                    "subtype": "missing_ownership_check",
                    "title": "Modern Order endpoint",
                    "endpoint": {"method": "GET", "path": "/api/orders/{id}"},
                    "location": {"file": "controllers/orders_d1.py", "start_line": 20},
                    "evidence": [{"file": "controllers/orders_d1.py", "line": 20, "why": "Check user"}],
                    "severity": "high",
                    "confidence": "high",
                    "cwe": ["CWE-639"],
                    "status": "confirmed",
                    "consensus": {
                        "score": 0.85,
                        "agreement_level": "majority",
                        "voted_models": ["gemini-2.0-pro", "claude-3-7"],
                    },
                    "recommendation": "None",
                },
                {
                    "finding_id": "BOLA-low-consensus",
                    "category": "bola",
                    "subtype": "missing_ownership_check",
                    "title": "Disputed BOLA finding",
                    "endpoint": {"method": "GET", "path": "/api/disputed/{id}"},
                    "location": {"file": "controllers/disputed.py", "start_line": 5},
                    "evidence": [{"file": "controllers/disputed.py", "line": 5, "why": "Unclear"}],
                    "severity": "low",
                    "confidence": "low",
                    "cwe": ["CWE-639"],
                    "status": "likely",
                    "consensus": {
                        "score": 0.40,
                        "agreement_level": "disputed",
                        "voted_models": ["model-a"],
                    },
                    "recommendation": "Review manually",
                },
                {
                    "finding_id": "BOLA-rejected-order",
                    "category": "bola",
                    "subtype": "missing_ownership_check",
                    "title": "False Positive",
                    "endpoint": {"method": "GET", "path": "/api/public/{id}"},
                    "location": {"file": "controllers/public.py", "start_line": 1},
                    "evidence": [],
                    "severity": "low",
                    "confidence": "low",
                    "cwe": ["CWE-639"],
                    "status": "rejected",
                    "recommendation": "None",
                },
                {
                    "finding_id": "INJ-search",
                    "category": "sql_injection",
                    "subtype": "string_concatenation",
                    "title": "SQL Injection",
                    "endpoint": {"method": "GET", "path": "/search"},
                    "location": {"file": "models/query.py", "start_line": 42},
                    "evidence": [],
                    "severity": "critical",
                    "confidence": "high",
                    "cwe": ["CWE-89"],
                    "status": "confirmed",
                    "recommendation": "Parameterized query",
                },
            ],
        }

    def test_synthesize_test_cases_filters_correctly(self) -> None:
        """Verifies only valid BOLA findings are synthesized into test cases."""
        cases = generate_test_cases_from_findings(
            scan_data_or_path=self.sample_findings,
            default_resource_id="1",
            attacker_token="attacker-token",
        )
        # Should include BOLA-vulnerable-order, BOLA-protected-order, and BOLA-low-consensus (likely)
        # BOLA-rejected-order (rejected) and INJ-search (sql_injection) must be excluded
        self.assertEqual(len(cases), 3)
        paths = [c.path for c in cases]
        self.assertIn("/api/legacy-orders/1", paths)
        self.assertIn("/api/orders/1", paths)

    def test_consensus_score_filtering(self) -> None:
        """Findings below min_consensus_score must be ignored."""
        cases = generate_test_cases_from_findings(
            scan_data_or_path=self.sample_findings,
            default_resource_id="1",
            min_consensus_score=0.80,
        )
        # BOLA-low-consensus (0.40) must be filtered out
        self.assertEqual(len(cases), 2)
        finding_ids = [c.finding_id for c in cases]
        self.assertIn("BOLA-vulnerable-order", finding_ids)
        self.assertIn("BOLA-protected-order", finding_ids)
        self.assertNotIn("BOLA-low-consensus", finding_ids)

    def test_sarif_ingestion(self) -> None:
        """Parses BOLA results from SARIF 2.1.0 format."""
        sarif_doc = {
            "version": "2.1.0",
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "bola.missing_ownership_check",
                            "message": {"text": "BOLA found at /api/legacy-orders/{id}"},
                            "properties": {
                                "finding_id": "SARIF-BOLA-1",
                                "endpoint": {"method": "GET", "path": "/api/legacy-orders/{id}"},
                                "consensus_score": 0.9,
                            },
                        },
                        {
                            "ruleId": "sql_injection.string_concatenation",
                            "message": {"text": "SQL injection at /api/search"},
                        },
                    ]
                }
            ],
        }
        cases = generate_test_cases_from_findings(sarif_doc, default_resource_id="99")
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].path, "/api/legacy-orders/99")
        self.assertEqual(cases[0].finding_id, "SARIF-BOLA-1")

    def test_cli_test_from_scan_catches_breach(self) -> None:
        """CLI returns exit code 1 when a BOLA breach is actively confirmed."""
        with tempfile.TemporaryDirectory() as td:
            scan_file = Path(td) / "findings.json"
            out_file = Path(td) / "test_out.json"
            scan_file.write_text(json.dumps(self.sample_findings), encoding="utf-8")

            # Run komagu test pointing to our mock server
            # BOLA-vulnerable-order targets /api/legacy-orders/1 which returns 200 (Breach)
            exit_code = cli_main([
                "--no-banner",
                "test",
                "--url", self.base_url,
                "--from-scan", str(scan_file),
                "--resource-id", "1",
                "--output", str(out_file),
            ])
            self.assertEqual(exit_code, 1)
            self.assertTrue(out_file.is_file())

            res_data = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertFalse(res_data["success"])
            breaches = [r for r in res_data["results"] if r["is_breach"]]
            self.assertTrue(any(b["path"] == "/api/legacy-orders/1" for b in breaches))

    def test_cli_test_from_scan_secure_passes(self) -> None:
        """CLI returns exit code 0 when all tested endpoints enforce the 404 invariant."""
        with tempfile.TemporaryDirectory() as td:
            scan_file = Path(td) / "protected_findings.json"
            protected_only = {
                "findings": [
                    {
                        "finding_id": "BOLA-protected-1",
                        "category": "bola",
                        "subtype": "missing_ownership_check",
                        "title": "D1-Protected Orders",
                        "endpoint": {"method": "GET", "path": "/api/orders/{id}"},
                        "status": "confirmed",
                    }
                ]
            }
            scan_file.write_text(json.dumps(protected_only), encoding="utf-8")

            # Against Persona B token, /api/orders/1 returns 404 (Pass)
            exit_code = cli_main([
                "--no-banner",
                "test",
                "--url", self.base_url,
                "--from-scan", str(scan_file),
                "--resource-id", "1",
                "--token", "persona-b-attacker",
            ])
            self.assertEqual(exit_code, 0)



if __name__ == "__main__":
    unittest.main()
