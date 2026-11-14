#!/usr/bin/env python3
"""Tests for Tier 2 AI-assisted multi-line remediation and verification gate (#394)."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from operate.ai.mock_server import MockLLMHandler, start_mock_llm_server
from operate.cli.main import main as cli_main
from operate.remediator.ai_fixer import AITier2Fixer
from operate.remediator.runner import RemediationRunner


class TestAITier2Fixer(unittest.TestCase):
    """Verify AI multi-line patching, redaction, and mandatory verification gates."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server, cls.thread, cls.base_url = start_mock_llm_server()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="komagu_ai_fix_test_")).resolve()
        MockLLMHandler.response_generator = None
        MockLLMHandler.received_requests = []

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_java_legacy_multiline_sqli_fix_and_secret_redaction(self) -> None:
        java_file = self.temp_dir / "OrderDao.java"
        java_file.write_text(
            "import java.sql.*;\n"
            "public class OrderDao {\n"
            '    private String dbPassword = "SuperSecretPassword99";\n'
            "    public ResultSet find(Connection conn, String id) throws SQLException {\n"
            "        Statement st = conn.createStatement();\n"
            '        return st.executeQuery("SELECT * FROM orders WHERE id = \'" + id + "\'");\n'
            "    }\n"
            "}\n",
            encoding="utf-8",
        )

        def reply(messages, model):
            return json.dumps(
                {
                    "start_line": 5,
                    "end_line": 6,
                    "patched_snippet": (
                        '        PreparedStatement ps = conn.prepareStatement("SELECT * FROM orders WHERE id = ?");\n'
                        "        ps.setString(1, id);\n"
                        "        return ps.executeQuery();\n"
                    ),
                    "explanation": "Replaced Statement concatenation with PreparedStatement.",
                }
            )

        MockLLMHandler.response_generator = reply

        findings_path = self.temp_dir / "findings.json"
        findings_path.write_text(
            json.dumps(
                {
                    "findings": [
                        {
                            "finding_id": "INJ-JAVA-01",
                            "category": "sql_injection",
                            "cwe": "CWE-89",
                            "title": "Dynamic SQL in OrderDao",
                            "location": {"file": "OrderDao.java", "start_line": 6},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        fixer = AITier2Fixer(endpoint=self.base_url, model="mock-model")
        runner = RemediationRunner(
            target_dir=self.temp_dir,
            findings_path=findings_path,
            dry_run=True,
            ai_fixer=fixer,
        )
        report = runner.run()

        self.assertEqual(report.planned_count, 1)
        plan = report.plans[0]
        self.assertIn("[AI-GENERATED — REQUIRES PERSON B REVIEW]", plan.reason)
        self.assertIn("PreparedStatement ps = conn.prepareStatement", plan.patched_content)

        # Ensure secret was redacted before leaving the host
        sent_user_msg = MockLLMHandler.received_requests[-1]["messages"][1]["content"]
        self.assertNotIn("SuperSecretPassword99", sent_user_msg)
        self.assertIn("[REDACTED]", sent_user_msg)

    def test_php_legacy_multiline_sqli_fix(self) -> None:
        php_file = self.temp_dir / "orders.php"
        php_file.write_text(
            "<?php\n"
            "$id = $_GET['id'];\n"
            '$res = mysql_query("SELECT * FROM orders WHERE id = " . $id);\n',
            encoding="utf-8",
        )

        def reply(messages, model):
            return json.dumps(
                {
                    "start_line": 3,
                    "end_line": 3,
                    "patched_snippet": (
                        '$stmt = $pdo->prepare("SELECT * FROM orders WHERE id = ?");\n'
                        "$stmt->execute([$id]);\n"
                        "$res = $stmt->fetchAll();\n"
                    ),
                    "explanation": "Migrated mysql_query concatenation to PDO prepared statement.",
                }
            )

        MockLLMHandler.response_generator = reply
        fixer = AITier2Fixer(endpoint=self.base_url, model="mock-model")
        res = fixer.generate_verified_patch(
            php_file,
            php_file.read_text(encoding="utf-8"),
            {"category": "sql_injection", "cwe": "CWE-89", "location": {"start_line": 3}},
        )
        self.assertTrue(res.changed)
        self.assertTrue(res.verified)
        self.assertIn("$pdo->prepare", res.patched_content)

    def test_rejects_comment_only_patch(self) -> None:
        java_file = self.temp_dir / "Legacy.java"
        content = (
            "public class Legacy {\n"
            '    String q = "SELECT * FROM users WHERE name = \'" + name + "\'";\n'
            "}\n"
        )
        java_file.write_text(content, encoding="utf-8")

        MockLLMHandler.response_generator = lambda m, mdl: json.dumps(
            {
                "start_line": 2,
                "end_line": 2,
                "patched_snippet": (
                    "    // TODO: parameterize query\n"
                    '    String q = "SELECT * FROM users WHERE name = \'" + name + "\'";\n'
                ),
                "explanation": "Added comment.",
            }
        )

        fixer = AITier2Fixer(endpoint=self.base_url, model="mock-model")
        res = fixer.generate_verified_patch(
            java_file,
            content,
            {"category": "sql_injection", "location": {"start_line": 2}},
        )
        self.assertFalse(res.changed)
        self.assertIn("comment-only", res.explanation)

    def test_rejects_python_syntax_error_patch(self) -> None:
        py_file = self.temp_dir / "bad.py"
        content = "def get_user(cur, uid):\n    cur.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
        py_file.write_text(content, encoding="utf-8")

        MockLLMHandler.response_generator = lambda m, mdl: json.dumps(
            {
                "start_line": 2,
                "end_line": 2,
                "patched_snippet": "    cur.execute('SELECT * FROM users WHERE id = %s', (uid,)\n",  # missing ')'
                "explanation": "Broken syntax.",
            }
        )

        fixer = AITier2Fixer(endpoint=self.base_url, model="mock-model")
        res = fixer.generate_verified_patch(
            py_file,
            content,
            {"category": "sql_injection", "location": {"start_line": 2}},
        )
        self.assertFalse(res.changed)
        self.assertIn("py_compile failed", res.explanation)

    def test_rejects_patch_that_leaves_injection_sink_intact(self) -> None:
        java_file = self.temp_dir / "StillBad.java"
        content = (
            "public class StillBad {\n"
            "    void run(Statement st, String id) {\n"
            '        st.executeQuery("SELECT * FROM t WHERE id = " + id);\n'
            "    }\n"
            "}\n"
        )
        java_file.write_text(content, encoding="utf-8")

        MockLLMHandler.response_generator = lambda m, mdl: json.dumps(
            {
                "start_line": 3,
                "end_line": 3,
                "patched_snippet": '        st.executeQuery("SELECT * FROM t WHERE id = " + id.trim());\n',
                "explanation": "Trimmed input but still concatenated.",
            }
        )

        fixer = AITier2Fixer(endpoint=self.base_url, model="mock-model")
        res = fixer.generate_verified_patch(
            java_file,
            content,
            {"category": "sql_injection", "location": {"start_line": 3}},
        )
        self.assertFalse(res.changed)
        self.assertIn("Tier 1 re-scan still flags", res.explanation)

    def test_cli_fix_with_ai_flag_end_to_end(self) -> None:
        java_file = self.temp_dir / "App.java"
        java_file.write_text(
            "import java.sql.*;\n"
            "public class App {\n"
            "    void run(Connection c, String id) throws SQLException {\n"
            "        Statement st = c.createStatement();\n"
            '        st.executeQuery("SELECT * FROM items WHERE id = " + id);\n'
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        findings_path = self.temp_dir / "findings.json"
        findings_path.write_text(
            json.dumps(
                {
                    "findings": [
                        {
                            "finding_id": "INJ-01",
                            "category": "sql_injection",
                            "cwe": "CWE-89",
                            "location": {"file": "App.java", "start_line": 5},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        MockLLMHandler.response_generator = lambda m, mdl: json.dumps(
            {
                "start_line": 4,
                "end_line": 5,
                "patched_snippet": (
                    '        PreparedStatement ps = c.prepareStatement("SELECT * FROM items WHERE id = ?");\n'
                    "        ps.setString(1, id);\n"
                    "        ps.executeQuery();\n"
                ),
                "explanation": "Use PreparedStatement.",
            }
        )

        exit_code = cli_main(
            [
                "--no-banner",
                "fix",
                str(self.temp_dir),
                "--findings",
                str(findings_path),
                "--dry-run",
                "--ai",
                "--ai-endpoint",
                self.base_url,
                "--ai-model",
                "mock-model",
                "--format",
                "json",
            ]
        )
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
