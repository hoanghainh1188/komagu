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
        self.temp_dir = tempfile.mkdtemp(prefix="komagu_sqli_patch_test_")
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

    def test_php_mysql_query_is_manual(self) -> None:
        """mysql_query takes no parameter array (and is gone in PHP 7): no automated rewrite (#216)."""
        for vulnerable in (
            "$res = mysql_query(\"SELECT * FROM orders WHERE id = \" . $id);",
            '        mysql_query("DELETE FROM users WHERE id = $id");',
        ):
            with self.subTest(line=vulnerable):
                res = self.patcher.patch_code_line(vulnerable, "php")
                self.assertFalse(res.changed)
                self.assertEqual(res.patched_line, vulnerable)

    def test_csharp_sqlcommand_interpolation_binds_parameter(self) -> None:
        """A SqlCommand declaration gets a real AddWithValue statement, not a comment (#216)."""
        vulnerable = '        var cmd = new SqlCommand($"SELECT * FROM Users WHERE Id = {id}", conn);\n'
        res = self.patcher.patch_code_line(vulnerable, "csharp")

        self.assertTrue(res.changed)
        self.assertEqual(
            res.patched_line,
            '        var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = @id", conn);\n'
            '        cmd.Parameters.AddWithValue("@id", id);\n',
        )

    def test_csharp_sqlcommand_concat_quoted_value_binds_parameter(self) -> None:
        vulnerable = "SqlCommand cmd = new SqlCommand(\"SELECT * FROM Users WHERE Name = '\" + name + \"'\", conn);"
        res = self.patcher.patch_code_line(vulnerable, "csharp")

        self.assertTrue(res.changed)
        self.assertIn('new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);', res.patched_line)
        self.assertIn('cmd.Parameters.AddWithValue("@name", name);', res.patched_line)

    def test_csharp_without_command_declaration_is_manual(self) -> None:
        """A bare SQL string has no command object to bind to: manual fix (#216)."""
        for vulnerable in (
            '        var sql = $"SELECT * FROM Users WHERE Id = {id}";',
            '        var cmd = new SqlCommand($"SELECT * FROM t WHERE a = {a} AND b = {b}", conn);',
            '        using (var cmd = new SqlCommand($"SELECT * FROM t WHERE a = {a}", conn))',
        ):
            with self.subTest(line=vulnerable):
                self.assertFalse(self.patcher.patch_code_line(vulnerable, "csharp").changed)

    def test_java_statement_concat_is_manual(self) -> None:
        """Java needs a PreparedStatement and setX calls across lines: manual fix (#216)."""
        for vulnerable in (
            '        String sql = "SELECT * FROM orders WHERE id = " + id;',
            '        ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE id = " + id);',
        ):
            with self.subTest(line=vulnerable):
                self.assertFalse(self.patcher.patch_code_line(vulnerable, "java").changed)

    def test_python_execute_concat_rewritten_with_line_ending(self) -> None:
        """cur.execute("..." + x) used to crash (query read from the wrong group) (#216)."""
        cases = {
            "    cursor.execute('SELECT * FROM users WHERE id = ' + user_id)\n":
                '    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n',
            '    cur.execute("SELECT * FROM x WHERE id = " + str(uid))  # lookup\r\n':
                '    cur.execute("SELECT * FROM x WHERE id = ?", (str(uid),))  # lookup\r\n',
        }
        for vulnerable, expected in cases.items():
            with self.subTest(line=vulnerable):
                res = self.patcher.patch_code_line(vulnerable, "python")
                self.assertTrue(res.changed)
                self.assertEqual(res.patched_line, expected)

    def test_python_execute_concat_not_last_operand_is_manual(self) -> None:
        for vulnerable in (
            "    cur.execute(\"SELECT * FROM x WHERE name = '\" + n + \"'\")\n",
            '    cur.execute("SELECT * FROM x WHERE id = " + uid, other)\n',
        ):
            with self.subTest(line=vulnerable):
                self.assertFalse(self.patcher.patch_code_line(vulnerable, "python").changed)

    def test_python_concat_assignment_is_manual(self) -> None:
        """Turning `q = "..." + x` into a tuple breaks the later execute(q): manual fix (#216)."""
        res = self.patcher.patch_code_line('    q = "SELECT * FROM t WHERE id = " + uid\n', "python")
        self.assertFalse(res.changed)

    def test_verify_fix_flags_unpatched_line(self) -> None:
        """verify_fix must really run find_injection and fail while the line is still vulnerable (#216)."""
        target_file = self.test_dir / "vuln.py"
        target_file.write_text(
            "def query(q):\n"
            "    cur.execute(f\"SELECT * FROM products WHERE id = {q}\")\n",
            encoding="utf-8",
        )
        self.assertFalse(self.patcher.verify_fix(target_file, 2))

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
