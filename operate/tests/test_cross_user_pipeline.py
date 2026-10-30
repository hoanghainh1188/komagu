#!/usr/bin/env python3
"""Integration and Unit Tests for Komagu Operate Continuous Verification Pipeline.

Validates:
1. Cross-user test runner correctly catches planted BOLA breaches (GET, PUT, DELETE).
2. Cross-user test runner passes clean on D1-protected endpoints (404 Not Found).
3. LSA-to-SARIF converter outputs valid OASIS SARIF v2.1.0 data.
4. CLI execution returns expected exit codes (1 on BOLA, 0 on secure).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

# Add project root to sys.path so modules can be imported directly
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(CURRENT_DIR))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from operate.cross_user_tester.mock_test_server import start_mock_server
from operate.cross_user_tester.runner import (
    CrossUserTestRunner,
    TestCase,
    generate_crud_test_cases,
)
from operate.lsa_sarif.lsa_to_sarif import convert_findings_to_sarif


class TestCrossUserPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server, cls.thread, cls.base_url = start_mock_server(port=0)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.server_close()

    def test_planted_bola_read_detected(self) -> None:
        """Planted BOLA GET returns 200 -> flagged as breach."""
        runner = CrossUserTestRunner(base_url=self.base_url)
        tc = TestCase(
            name="Vulnerable Read",
            path="/api/legacy-orders/1",
            method="GET",
            attacker_token="attacker-token",
        )
        res = runner.execute_test(tc)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.is_breach)
        self.assertFalse(res.is_secure)

    def test_planted_bola_update_detected(self) -> None:
        """Planted BOLA PUT returns 200 -> flagged as breach."""
        runner = CrossUserTestRunner(base_url=self.base_url)
        tc = TestCase(
            name="Vulnerable Update",
            path="/api/legacy-orders/1",
            method="PUT",
            payload={"status": "tampered"},
            attacker_token="attacker-token",
        )
        res = runner.execute_test(tc)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.is_breach)
        self.assertFalse(res.is_secure)

    def test_planted_bola_delete_detected(self) -> None:
        """Planted BOLA DELETE returns 204 -> flagged as breach."""
        runner = CrossUserTestRunner(base_url=self.base_url)
        tc = TestCase(
            name="Vulnerable Delete",
            path="/api/legacy-orders/1",
            method="DELETE",
            attacker_token="attacker-token",
        )
        res = runner.execute_test(tc)
        self.assertEqual(res.status_code, 204)
        self.assertTrue(res.is_breach)
        self.assertFalse(res.is_secure)

    def test_d1_protected_crud_suite_passes(self) -> None:
        """D1 protected endpoints return 404 for non-owner -> all tests pass."""
        runner = CrossUserTestRunner(
            base_url=self.base_url,
            default_attacker_token="token-user-b",
        )
        cases = generate_crud_test_cases(
            resource_path="/api/orders/{id}",
            resource_id="1",
            name_prefix="Order Resource",
        )
        results = runner.run_suite(cases)
        self.assertEqual(len(results), 3)
        for res in results:
            self.assertEqual(res.status_code, 404)
            self.assertFalse(res.is_breach)
            self.assertTrue(res.is_secure)

    def test_runner_cli_exit_code_on_vulnerable(self) -> None:
        """CLI runner must exit with code 1 when BOLA breach is detected."""
        runner_path = os.path.join(
            PROJECT_ROOT, "operate", "cross-user-tester", "runner.py"
        )
        proc = subprocess.run(
            [
                sys.executable,
                runner_path,
                "--base-url",
                self.base_url,
                "--auto-crud-path",
                "/api/legacy-orders/{id}",
                "--resource-id",
                "1",
                "--attacker-token",
                "token-user-b",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("[FAIL - BOLA BREACH]", proc.stdout)

    def test_runner_cli_exit_code_on_secure(self) -> None:
        """CLI runner must exit with code 0 when all endpoints are D1 secure."""
        runner_path = os.path.join(
            PROJECT_ROOT, "operate", "cross-user-tester", "runner.py"
        )
        proc = subprocess.run(
            [
                sys.executable,
                runner_path,
                "--base-url",
                self.base_url,
                "--auto-crud-path",
                "/api/orders/{id}",
                "--resource-id",
                "1",
                "--attacker-token",
                "token-user-b",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("[PASS - SECURE]", proc.stdout)

    def test_lsa_to_sarif_conversion(self) -> None:
        """SARIF converter produces compliant OASIS SARIF v2.1.0 output."""
        sample_findings = [
            {
                "finding_id": "BOLA-order-001",
                "category": "bola",
                "subtype": "missing_ownership_check",
                "title": "Missing ownership check on orders endpoint",
                "location": {
                    "file": "legacy/orders.php",
                    "start_line": 42,
                    "end_line": 50,
                },
                "evidence": [
                    {
                        "file": "legacy/orders.php",
                        "line": 45,
                        "code": "$order = get_order($_GET['id']);",
                        "why": "Direct fetch by id without user scoping",
                    }
                ],
                "severity": "critical",
                "confidence": "confirmed",
                "cwe": 639,
                "recommendation": "Use D1 ObjectAuthorizationService to scope query.",
                "status": "confirmed",
            },
            {
                "finding_id": "INJ-user-001",
                "category": "sql_injection",
                "subtype": "string_concatenation",
                "title": "SQL query built via string concatenation",
                "location": {
                    "file": "legacy/user.php",
                    "start_line": 15,
                    "end_line": 18,
                },
                "evidence": [],
                "severity": "high",
                "confidence": "high",
                "cwe": 89,
                "recommendation": "Use parameterized queries or Komagu query helpers.",
                "status": "confirmed",
            },
        ]

        sarif = convert_findings_to_sarif(sample_findings)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("runs", sarif)
        self.assertEqual(len(sarif["runs"]), 1)

        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "Komagu LSA")
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 2)
        self.assertEqual(len(run["results"]), 2)

        # Check BOLA result mapping
        bola_res = run["results"][0]
        self.assertEqual(bola_res["ruleId"], "KOMAGU-BOLA-CWE639")
        self.assertEqual(bola_res["level"], "error")
        loc = bola_res["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "legacy/orders.php")
        self.assertEqual(loc["region"]["startLine"], 42)
        self.assertEqual(len(bola_res["relatedLocations"]), 1)

        # Check SQLi result mapping
        sqli_res = run["results"][1]
        self.assertEqual(sqli_res["ruleId"], "KOMAGU-INJ-CWE89")
        self.assertEqual(sqli_res["level"], "error")

    def test_sarif_cli_execution(self) -> None:
        """CLI converter reads JSON and writes valid SARIF file."""
        sample_finding = {
            "finding_id": "BOLA-test-01",
            "category": "bola",
            "subtype": "missing_ownership_check",
            "title": "BOLA vulnerability",
            "location": {"file": "app.py", "start_line": 10},
            "evidence": [],
            "severity": "high",
            "confidence": "high",
            "cwe": 639,
            "recommendation": "Fix it",
            "status": "new",
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            input_file = os.path.join(tmp_dir, "findings.json")
            output_file = os.path.join(tmp_dir, "report.sarif")

            with open(input_file, "w", encoding="utf-8") as f:
                json.dump([sample_finding], f)

            converter_path = os.path.join(
                PROJECT_ROOT, "operate", "lsa-sarif", "lsa_to_sarif.py"
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    converter_path,
                    "--input",
                    input_file,
                    "--output",
                    output_file,
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertTrue(os.path.isfile(output_file))

            with open(output_file, "r", encoding="utf-8") as f:
                sarif_data = json.load(f)
            self.assertEqual(sarif_data["version"], "2.1.0")
            self.assertEqual(len(sarif_data["runs"][0]["results"]), 1)


if __name__ == "__main__":
    unittest.main()
