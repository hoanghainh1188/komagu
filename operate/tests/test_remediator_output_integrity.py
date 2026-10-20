#!/usr/bin/env python3
"""Regression tests for #216: `komainu fix` must not corrupt files or claim non-functional fixes."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from operate.remediator.runner import RemediationRunner

BOM = b"\xef\xbb\xbf"
PY_VULN = 'cur.execute(f"SELECT * FROM t WHERE id = {uid}")\n'


def _finding(fid: str, file: str, line: int) -> dict:
    return {
        "finding_id": fid,
        "category": "sql_injection",
        "title": fid,
        "severity": "high",
        "location": {"file": file, "start_line": line, "end_line": line},
    }


class TestRemediatorOutputIntegrity(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.app = self.root / "app"
        self.app.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _run(self, *findings: dict):
        path = self.root / "findings.json"
        path.write_text(json.dumps({"findings": list(findings)}), encoding="utf-8")
        report = RemediationRunner(self.app, path).run()
        return {p.finding_id: p for p in report.plans}

    # --- BOM handling -------------------------------------------------------

    def test_bomless_utf8_file_stays_bomless(self) -> None:
        src = self.app / "svc.py"
        src.write_bytes(PY_VULN.encode("utf-8"))
        plans = self._run(_finding("A", "svc.py", 1))
        self.assertEqual(plans["A"].status, "applied", plans["A"].reason)
        self.assertFalse(src.read_bytes().startswith(BOM), "a BOM was added to a BOM-less file")

    def test_existing_bom_is_kept(self) -> None:
        src = self.app / "svc.py"
        src.write_bytes(BOM + PY_VULN.encode("utf-8"))
        plans = self._run(_finding("A", "svc.py", 1))
        self.assertEqual(plans["A"].status, "applied", plans["A"].reason)
        data = src.read_bytes()
        self.assertTrue(data.startswith(BOM))
        self.assertFalse(data[3:].startswith(BOM), "BOM duplicated")

    # --- Byte-exact round trip ----------------------------------------------

    def test_cp932_duplicate_code_point_file_not_rewritten(self) -> None:
        # 0xFA5C (IBM extension) decodes to U+7E8A, which cp932 re-encodes as 0xED40 (NEC selected);
        # 0x8790 (NEC row 13 "≒") re-encodes as 0x81E0.
        raw = b"# \xfa\x5c \x87\x90\n" + PY_VULN.encode("ascii")
        src = self.app / "jp.py"
        src.write_bytes(raw)
        plans = self._run(_finding("A", "jp.py", 2))
        self.assertNotEqual(plans["A"].status, "applied")
        self.assertEqual(src.read_bytes(), raw)

    def test_mixed_line_endings_file_not_rewritten(self) -> None:
        raw = b"import sqlite3\r\n" + PY_VULN.encode("ascii") + b"x = 1\r\n"
        src = self.app / "mixed.py"
        src.write_bytes(raw)
        plans = self._run(_finding("A", "mixed.py", 2))
        self.assertNotEqual(plans["A"].status, "applied")
        self.assertEqual(src.read_bytes(), raw)

    # --- Only complete, working rewrites are applied --------------------------

    def test_incomplete_rewrites_are_manual_and_untouched(self) -> None:
        cases = {
            "order.php": '<?php\n$res = mysql_query("SELECT * FROM orders WHERE id = " . $id);\n',
            "Dao.java": 'ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE id = " + id);\n',
            "svc.py": 'q = "SELECT * FROM t WHERE id = " + uid\n',
            "Repo.cs": 'var sql = $"SELECT * FROM orders WHERE id = {id}";\n',
        }
        findings = []
        for name, text in cases.items():
            (self.app / name).write_text(text, encoding="utf-8")
            line = 2 if name.endswith(".php") else 1
            findings.append(_finding(name, name, line))
        plans = self._run(*findings)
        for name, text in cases.items():
            with self.subTest(file=name):
                self.assertEqual(plans[name].status, "needs manual fix", plans[name].reason)
                self.assertEqual((self.app / name).read_text(encoding="utf-8"), text)

    def test_csharp_sqlcommand_gets_real_parameter_binding(self) -> None:
        src = self.app / "Repo.cs"
        src.write_text(
            "    using var cmd = new SqlCommand($\"SELECT * FROM orders WHERE id = {orderId}\", conn);\r\n"
            "    var reader = cmd.ExecuteReader();\r\n",
            encoding="utf-8",
        )
        plans = self._run(_finding("A", "Repo.cs", 1))
        self.assertEqual(plans["A"].status, "applied", plans["A"].reason)
        lines = src.read_bytes().decode("utf-8").split("\r\n")
        self.assertEqual(lines[0], '    using var cmd = new SqlCommand("SELECT * FROM orders WHERE id = @orderId", conn);')
        self.assertEqual(lines[1], '    cmd.Parameters.AddWithValue("@orderId", orderId);')
        self.assertEqual(lines[2], "    var reader = cmd.ExecuteReader();")
        self.assertNotIn("//", src.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
