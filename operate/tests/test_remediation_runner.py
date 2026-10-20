#!/usr/bin/env python3
"""Automated verification tests for Komainu Remediation Runner and CLI Fix Subcommand (Issue #186 & #208)."""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from operate.cli.main import build_parser, main
from operate.remediator.models import RemediationPlan, RemediationReport
from operate.remediator.runner import (
    RemediationRunner,
    read_source_file_safe,
    safe_resolve_target_file,
    write_source_file_safe,
)
from operate.remediator.strategies import (
    BOLARemediationStrategy,
    SQLInjectionRemediationStrategy,
    StrategyRegistry,
)


class TestRemediationRunner(unittest.TestCase):
    """Test suite verifying the remediation orchestrator, safety guards, and CLI fix subcommand."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="komainu_fix_test_")
        self.target_path = Path(self.temp_dir).resolve()

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_sample_repo(self) -> Tuple[Path, Path]:
        """Create a mock codebase with SQLi and BOLA vulnerabilities."""
        # 1. SQLi file
        sql_file = self.target_path / "src" / "db_helper.py"
        sql_file.parent.mkdir(parents=True, exist_ok=True)
        sql_content = (
            "import sqlite3\n"
            "def get_user(user_id):\n"
            "    query = 'SELECT * FROM users WHERE id = ' + user_id\n"
            "    return query\n"
        )
        sql_file.write_text(sql_content, encoding="utf-8")

        # 2. BOLA file
        bola_file = self.target_path / "src" / "order_controller.ts"
        bola_content = (
            "export class OrderController {\n"
            "    @Get(':id')\n"
            "    async getOrder(@Param('id') id: string) {\n"
            "        return this.orderService.find(id);\n"
            "    }\n"
            "}\n"
        )
        bola_file.write_text(bola_content, encoding="utf-8")

        # 3. Findings report
        findings_data = {
            "findings": [
                {
                    "finding_id": "INJ-SQL-001",
                    "category": "sql_injection",
                    "title": "String concatenated dynamic query",
                    "cwe": "CWE-89",
                    "location": {
                        "file": "src/db_helper.py",
                        "start_line": 3,
                    },
                    "status": "confirmed",
                },
                {
                    "finding_id": "BOLA-ORD-001",
                    "category": "bola",
                    "title": "Missing ownership check on order endpoint",
                    "cwe": "CWE-639",
                    "location": {
                        "file": "src/order_controller.ts",
                        "start_line": 2,
                    },
                    "status": "confirmed",
                },
            ]
        }
        findings_file = self.target_path / "findings.json"
        findings_file.write_text(json.dumps(findings_data), encoding="utf-8")

        return sql_file, findings_file

    def test_load_findings_formats(self) -> None:
        """RemediationRunner must support dict {findings: []}, list [], and SARIF formats."""
        # A. Dict format
        d_file = self.target_path / "dict_findings.json"
        d_file.write_text(json.dumps({"findings": [{"finding_id": "INJ-1", "category": "sql_injection"}]}), encoding="utf-8")
        runner_d = RemediationRunner(self.target_path, d_file)
        self.assertEqual(len(runner_d.load_findings()), 1)

        # B. List format
        l_file = self.target_path / "list_findings.json"
        l_file.write_text(json.dumps([{"finding_id": "BOLA-1", "category": "bola"}]), encoding="utf-8")
        runner_l = RemediationRunner(self.target_path, l_file)
        self.assertEqual(len(runner_l.load_findings()), 1)

        # C. SARIF format
        s_file = self.target_path / "sarif_findings.json"
        sarif_data = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "BOLA-01",
                            "message": {"text": "BOLA detected"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/api.py"},
                                        "region": {"startLine": 10},
                                    }
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        s_file.write_text(json.dumps(sarif_data), encoding="utf-8")
        runner_s = RemediationRunner(self.target_path, s_file)
        findings_s = runner_s.load_findings()
        self.assertEqual(len(findings_s), 1)
        self.assertEqual(findings_s[0]["category"], "bola")
        self.assertEqual(findings_s[0]["location"]["file"], "src/api.py")

    def test_dry_run_generates_diff_without_modifying_file(self) -> None:
        """Dry-run mode must generate valid unified diffs and leave original files unchanged."""
        sql_file, findings_file = self._create_sample_repo()
        original_sql = sql_file.read_text(encoding="utf-8")

        runner = RemediationRunner(
            target_dir=self.target_path,
            findings_path=findings_file,
            dry_run=True,
        )
        report = runner.run()

        self.assertEqual(report.total_findings, 2)
        # In dry-run, planned_count is 2 and applied_count is 0
        self.assertEqual(report.planned_count, 2)
        self.assertEqual(report.applied_count, 0)
        self.assertEqual(report.error_count, 0)
        self.assertEqual(report.skipped_count, 0)

        # Ensure original file is untouched
        self.assertEqual(sql_file.read_text(encoding="utf-8"), original_sql)

        # Ensure diff was generated
        plan_sql = [p for p in report.plans if p.finding_id == "INJ-SQL-001"][0]
        self.assertTrue(plan_sql.diff)
        self.assertIn("SELECT * FROM users WHERE id = ?", plan_sql.diff)

    def test_apply_mode_modifies_files_in_place(self) -> None:
        """Apply mode (dry_run=False) must update source files with security fixes."""
        sql_file, findings_file = self._create_sample_repo()

        runner = RemediationRunner(
            target_dir=self.target_path,
            findings_path=findings_file,
            dry_run=False,
        )
        report = runner.run()

        self.assertEqual(report.applied_count, 2)
        self.assertEqual(report.planned_count, 0)
        patched_sql = sql_file.read_text(encoding="utf-8")
        self.assertIn("SELECT * FROM users WHERE id = ?", patched_sql)

        patched_ts = (self.target_path / "src" / "order_controller.ts").read_text(encoding="utf-8")
        self.assertIn("@RequireOwnership(ResourceOperation.READ", patched_ts)
        self.assertIn("OwnershipGuard", patched_ts)

    def test_export_patch_file(self) -> None:
        """RemediationRunner must write unified diffs to the requested patch file."""
        _, findings_file = self._create_sample_repo()
        patch_path = self.target_path / "out" / "remediation.patch"

        runner = RemediationRunner(
            target_dir=self.target_path,
            findings_path=findings_file,
            dry_run=True,
            output_patch=patch_path,
        )
        report = runner.run()

        self.assertTrue(patch_path.is_file())
        patch_text = patch_path.read_text(encoding="utf-8")
        self.assertIn("--- a/src/db_helper.py", patch_text)
        self.assertIn("--- a/src/order_controller.ts", patch_text)
        self.assertEqual(report.patch_file, str(patch_path))

    def test_skip_nonexistent_target_file(self) -> None:
        """Findings with missing target files should be marked as skipped without error."""
        findings_file = self.target_path / "ghost_findings.json"
        findings_file.write_text(
            json.dumps({
                "findings": [
                    {
                        "finding_id": "INJ-002",
                        "category": "sql_injection",
                        "location": {"file": "non_existent_file.py", "start_line": 5},
                    }
                ]
            }),
            encoding="utf-8",
        )

        runner = RemediationRunner(self.target_path, findings_file)
        report = runner.run()

        self.assertEqual(report.total_findings, 1)
        self.assertEqual(report.skipped_count, 1)
        self.assertEqual(report.plans[0].status, "skipped")
        self.assertIn("Target file not found", report.plans[0].reason)

    def test_path_traversal_defense(self) -> None:
        """Paths escaping target directory (e.g. sub/../../victim.py) must be rejected with error."""
        outside_file = Path(self.temp_dir).parent / "komainu_outside_victim.py"
        outside_file.write_text("# innocent victim", encoding="utf-8")

        try:
            findings_file = self.target_path / "traversal_findings.json"
            findings_file.write_text(
                json.dumps({
                    "findings": [
                        {
                            "finding_id": "TRAV-001",
                            "category": "sql_injection",
                            "location": {"file": "sub/../../komainu_outside_victim.py", "start_line": 1},
                        }
                    ]
                }),
                encoding="utf-8",
            )

            runner = RemediationRunner(self.target_path, findings_file)
            report = runner.run()

            self.assertEqual(report.total_findings, 1)
            self.assertEqual(report.error_count, 1)
            self.assertEqual(report.plans[0].status, "error")
            self.assertIn("Path traversal detected", report.plans[0].reason)
            self.assertEqual(outside_file.read_text(encoding="utf-8"), "# innocent victim")
        finally:
            if outside_file.exists():
                outside_file.unlink()

    def test_symlink_defense(self) -> None:
        """Symlinks pointing inside or outside the target directory must be rejected."""
        real_file = self.target_path / "real.py"
        real_file.write_text("SELECT * FROM x", encoding="utf-8")
        link_file = self.target_path / "symlink.py"

        try:
            link_file.symlink_to(real_file)
        except OSError:
            # Skip if OS does not permit symlinks without admin privileges
            return

        findings_file = self.target_path / "symlink_findings.json"
        findings_file.write_text(
            json.dumps({
                "findings": [
                    {
                        "finding_id": "SYM-001",
                        "category": "sql_injection",
                        "location": {"file": "symlink.py", "start_line": 1},
                    }
                ]
            }),
            encoding="utf-8",
        )

        runner = RemediationRunner(self.target_path, findings_file)
        report = runner.run()

        self.assertEqual(report.total_findings, 1)
        self.assertEqual(report.error_count, 1)
        self.assertEqual(report.plans[0].status, "error")
        self.assertIn("Symlinks are not allowed", report.plans[0].reason)

    def test_dotfile_path_normalization(self) -> None:
        """Dotfiles like .env or .github/action.yml must retain their leading dot."""
        env_file = self.target_path / ".env"
        env_file.write_text("DB_USER=test", encoding="utf-8")

        resolved, clean_rel, err = safe_resolve_target_file(self.target_path, ".env")
        self.assertIsNone(err)
        self.assertEqual(clean_rel, ".env")
        self.assertEqual(resolved, env_file)

        gh_file = self.target_path / ".github" / "workflow.yml"
        gh_file.parent.mkdir(parents=True, exist_ok=True)
        gh_file.write_text("name: CI", encoding="utf-8")

        resolved_gh, clean_rel_gh, err_gh = safe_resolve_target_file(self.target_path, "./.github/workflow.yml")
        self.assertIsNone(err_gh)
        self.assertEqual(clean_rel_gh, ".github/workflow.yml")

    def test_cp932_japanese_encoding_preservation(self) -> None:
        """Legacy Japanese files encoded in CP932 (Shift-JIS) must not be corrupted into EF BF BD."""
        asp_file = self.target_path / "legacy_search.asp"
        # Japanese phrase: "テスト検索" in CP932
        cp932_bytes = "query = \"SELECT * FROM users WHERE name = '\" & userName & \"'\"\n' テスト検索コメント\n".encode("cp932")
        asp_file.write_bytes(cp932_bytes)

        findings_file = self.target_path / "cp932_findings.json"
        findings_file.write_text(
            json.dumps({
                "findings": [
                    {
                        "finding_id": "INJ-ASP-001",
                        "category": "sql_injection",
                        "location": {"file": "legacy_search.asp", "start_line": 1},
                    }
                ]
            }),
            encoding="utf-8",
        )

        runner = RemediationRunner(self.target_path, findings_file, dry_run=False)
        report = runner.run()

        # Read back bytes
        resulting_bytes = asp_file.read_bytes()
        # Verify no replacement characters \xef\xbf\xbd were written
        self.assertNotIn(b"\xef\xbf\xbd", resulting_bytes)

        # Verify decoded properly using CP932
        decoded_text = resulting_bytes.decode("cp932")
        self.assertIn("テスト検索コメント", decoded_text)

    def test_crlf_line_ending_preservation(self) -> None:
        """Windows CRLF files must preserve \\r\\n line endings after patching."""
        crlf_file = self.target_path / "crlf_sample.py"
        crlf_content = "def test():\r\n    query = 'SELECT * FROM x WHERE id = ' + uid\r\n    return query\r\n"
        crlf_file.write_bytes(crlf_content.encode("utf-8"))

        findings_file = self.target_path / "crlf_findings.json"
        findings_file.write_text(
            json.dumps({
                "findings": [
                    {
                        "finding_id": "INJ-CRLF-001",
                        "category": "sql_injection",
                        "location": {"file": "crlf_sample.py", "start_line": 2},
                    }
                ]
            }),
            encoding="utf-8",
        )

        runner = RemediationRunner(self.target_path, findings_file, dry_run=False)
        report = runner.run()

        self.assertEqual(report.applied_count, 1)
        patched_bytes = crlf_file.read_bytes()
        self.assertIn(b"\r\n", patched_bytes)
        # Ensure no standalone \n without \r
        clean_text = patched_bytes.replace(b"\r\n", b"")
        self.assertNotIn(b"\n", clean_text)

    def test_comment_only_fixes_suppressed_with_needs_manual_fix(self) -> None:
        """When no code rewrite applies, do NOT inject fake comments; mark status as needs manual fix."""
        complex_sql_file = self.target_path / "complex_query.py"
        # Complex multi-line query that cannot be parsed by line-based regex
        content = "def execute_custom():\n    raw_call_without_sql_keywords(foo, bar)\n"
        complex_sql_file.write_text(content, encoding="utf-8")

        findings_file = self.target_path / "manual_findings.json"
        findings_file.write_text(
            json.dumps({
                "findings": [
                    {
                        "finding_id": "INJ-COMPLEX-001",
                        "category": "sql_injection",
                        "location": {"file": "complex_query.py", "start_line": 2},
                    }
                ]
            }),
            encoding="utf-8",
        )

        runner = RemediationRunner(self.target_path, findings_file, dry_run=False)
        report = runner.run()

        self.assertEqual(report.total_findings, 1)
        self.assertEqual(report.applied_count, 0)
        self.assertEqual(report.manual_fix_count, 1)
        self.assertEqual(report.plans[0].status, "needs manual fix")
        self.assertIn("No automated parameterized query rewrite applicable", report.plans[0].reason)

        # File content must be 100% unchanged - NO comments injected
        self.assertEqual(complex_sql_file.read_text(encoding="utf-8"), content)
        self.assertNotIn("[KOMAINU-FIX]", complex_sql_file.read_text(encoding="utf-8"))

    def test_cli_fix_command_dry_run(self) -> None:
        """CLI: komainu fix <target> --dry-run must execute successfully and report planned counts."""
        _, findings_file = self._create_sample_repo()

        out = io.StringIO()
        with redirect_stdout(out):
            code = main([
                "fix",
                str(self.target_path),
                "--findings",
                str(findings_file),
                "--dry-run",
            ])
        self.assertEqual(code, 0)
        output = out.getvalue()
        self.assertIn("Komainu Remediation Summary", output)
        self.assertIn("Mode: DRY-RUN (Simulated)", output)
        self.assertIn("Patches planned", output)
        self.assertIn("Patches applied", output)
        self.assertIn("0 (dry-run)", output)

    def test_cli_fix_command_json_format(self) -> None:
        """CLI: komainu fix <target> --format json must output valid JSON."""
        _, findings_file = self._create_sample_repo()

        out = io.StringIO()
        with redirect_stdout(out):
            code = main([
                "fix",
                str(self.target_path),
                "--findings",
                str(findings_file),
                "--dry-run",
                "--format",
                "json",
            ])
        self.assertEqual(code, 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["total_findings"], 2)
        self.assertEqual(data["planned_count"], 2)
        self.assertEqual(data["applied_count"], 0)
        self.assertTrue(data["dry_run"])

    def test_cli_fix_help_subcommand(self) -> None:
        """CLI: komainu help fix and komainu fix --help must show usage."""
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["help", "fix"])
        self.assertEqual(code, 0)
        self.assertIn("usage: komainu fix", out.getvalue())
        self.assertIn("Examples:", out.getvalue())


if __name__ == "__main__":
    unittest.main()
