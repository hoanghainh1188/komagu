#!/usr/bin/env python3
"""Automated verification tests for Parameterized Query Patcher (Issue #187)."""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from remediate.query.patcher import ParameterizedQueryPatcher, RewrittenQuery


class TestParameterizedQueryPatcher(unittest.TestCase):
    """Test suite verifying SQL injection and dynamic query rewriting across languages."""

    def setUp(self) -> None:
        self.patcher = ParameterizedQueryPatcher()
        self.temp_dir = tempfile.mkdtemp(prefix="komainu_sqli_patch_test_")
        self.test_dir = Path(self.temp_dir).resolve()

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_detect_language(self) -> None:
        """Language must be inferred accurately from file extension."""
        self.assertEqual(self.patcher.detect_language("db.py"), "python")
        self.assertEqual(self.patcher.detect_language("query.ts"), "javascript")
        self.assertEqual(self.patcher.detect_language("app.js"), "javascript")
        self.assertEqual(self.patcher.detect_language("model.php"), "php")
        self.assertEqual(self.patcher.detect_language("Repo.cs"), "csharp")
        self.assertEqual(self.patcher.detect_language("Dao.java"), "java")
        self.assertEqual(self.patcher.detect_language("unknown.xyz"), "generic")

    def test_rewrite_python_fstring_execute(self) -> None:
        """Python execute(f'SELECT...') must be rewritten to use '?' and tuple."""
        vulnerable = "    cur.execute(f\"SELECT * FROM products WHERE name LIKE '%{q}%'\")"
        res = self.patcher.patch_code_line(vulnerable, "python")

        self.assertTrue(res.changed)
        self.assertIn("cur.execute(\"SELECT * FROM products WHERE name LIKE ?\", (q,))", res.patched_line)
        self.assertEqual(res.placeholders, ["?"])
        self.assertEqual(res.params, ["q"])

    def test_rewrite_javascript_template_literal(self) -> None:
        """JavaScript db.query(`SELECT...${var}`, cb) must convert to parameterized array."""
        vulnerable = "  db.query(`SELECT COUNT(*) AS n FROM orders WHERE shop_id = ${req.query.shop}`, function (e, r) { res.json(r); });"
        res = self.patcher.patch_code_line(vulnerable, "javascript")

        self.assertTrue(res.changed)
        self.assertIn('db.query("SELECT COUNT(*) AS n FROM orders WHERE shop_id = ?", [req.query.shop]', res.patched_line)
        self.assertEqual(res.placeholders, ["?"])
        self.assertEqual(res.params, ["req.query.shop"])

    def test_rewrite_javascript_binary_concat(self) -> None:
        """JavaScript db.query with binary concatenation must convert to parameterized array."""
        vulnerable = "  db.query(\"SELECT * FROM reports WHERE month = '\" + req.query.month + \"'\", function (e, rows) { res.json(rows); });"
        res = self.patcher.patch_code_line(vulnerable, "javascript")

        self.assertTrue(res.changed)
        self.assertIn('db.query("SELECT * FROM reports WHERE month = ?", [req.query.month]', res.patched_line)

    def test_rewrite_php_dot_concat(self) -> None:
        """PHP mysql_query with dot concatenation must convert to parameterized placeholder."""
        vulnerable = "$res = mysql_query(\"SELECT * FROM orders WHERE id = \" . $id);"
        res = self.patcher.patch_code_line(vulnerable, "php")

        self.assertTrue(res.changed)
        self.assertIn('mysql_query("SELECT * FROM orders WHERE id = ?", [$id]);', res.patched_line)
        self.assertIn("[KOMAINU-FIX]", res.patched_line)

    def test_rewrite_php_variable_interp(self) -> None:
        """PHP double-quote interpolation must convert to placeholder."""
        vulnerable = '        mysql_query("DELETE FROM users WHERE id = $id");'
        res = self.patcher.patch_code_line(vulnerable, "php")

        self.assertTrue(res.changed)
        self.assertIn('mysql_query("DELETE FROM users WHERE id = ?", [$id]);', res.patched_line)

    def test_rewrite_csharp_interpolation(self) -> None:
        """C# string interpolation must rewrite to @param placeholder."""
        vulnerable = '        var sql = $"SELECT * FROM Users WHERE Id = {id}";'
        res = self.patcher.patch_code_line(vulnerable, "csharp")

        self.assertTrue(res.changed)
        self.assertIn('var sql = "SELECT * FROM Users WHERE Id = @id";', res.patched_line)
        self.assertIn("cmd.Parameters.AddWithValue", res.patched_line)

    def test_rewrite_java_concatenation(self) -> None:
        """Java string concatenation must rewrite to PreparedStatement placeholder."""
        vulnerable = '        String sql = "SELECT * FROM orders WHERE id = " + id;'
        res = self.patcher.patch_code_line(vulnerable, "java")

        self.assertTrue(res.changed)
        self.assertIn('String sql = "SELECT * FROM orders WHERE id = ?";', res.patched_line)
        self.assertIn("PreparedStatement", res.patched_line)

    def test_patch_file_and_verification_loop(self) -> None:
        """Patching a file must write changes and verify with LSA find_injection.py."""
        target_file = self.test_dir / "app.py"
        target_file.write_text(
            "import sqlite3\n"
            "def query(q):\n"
            "    cur = conn.cursor()\n"
            "    cur.execute(f\"SELECT * FROM products WHERE name LIKE '%{q}%'\")\n"
            "    return cur.fetchall()\n",
            encoding="utf-8",
        )

        patched_content, res = self.patcher.patch_file(target_file, 4)
        self.assertTrue(res.changed)
        self.assertIn("cur.execute(\"SELECT * FROM products WHERE name LIKE ?\", (q,))", patched_content)

        # Write to disk and verify with find_injection.py
        target_file.write_text(patched_content, encoding="utf-8")
        verified = self.patcher.verify_fix(target_file, 4)
        self.assertTrue(verified, "LSA pre-scan verification failed: patched line was still flagged as candidate.")


if __name__ == "__main__":
    unittest.main()
