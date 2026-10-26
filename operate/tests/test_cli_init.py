#!/usr/bin/env python3
"""Tests for `komainu init --ai <runtime>` (Issue #244)."""

from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BIN_KOMAINU = REPO_ROOT / "bin" / "komainu"

from operate.cli.main import build_parser, main  # noqa: E402


def run_quiet(argv: list) -> int:
    with contextlib.redirect_stdout(io.StringIO()):
        return main(argv)


class TestInitCommand(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dest = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_parser_defaults_to_current_directory(self) -> None:
        args = build_parser().parse_args(["init", "--ai", "codex"])
        self.assertEqual(args.subcommand, "init")
        self.assertEqual(args.ai, "codex")
        self.assertEqual(args.dest, ".")

    def test_rejects_unknown_runtime(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            build_parser().parse_args(["init", "--ai", "copilot"])
        self.assertEqual(ctx.exception.code, 2)

    def test_requires_ai_flag(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            build_parser().parse_args(["init"])

    def test_codex_generates_skill_agents_and_agents_md(self) -> None:
        self.assertEqual(run_quiet(["--no-banner", "init", "--ai", "codex", str(self.dest)]), 0)
        self.assertTrue((self.dest / ".agents" / "skills" / "legacy-security-audit" / "SKILL.md").is_file())
        self.assertTrue((self.dest / ".codex" / "agents" / "lsa-finding-verifier.toml").is_file())
        self.assertTrue((self.dest / "AGENTS.md").is_file())

    def test_claude_alias_generates_claude_code_files(self) -> None:
        self.assertEqual(run_quiet(["--no-banner", "init", "--ai", "claude", str(self.dest)]), 0)
        self.assertTrue((self.dest / ".claude" / "skills" / "legacy-security-audit" / "SKILL.md").is_file())

    def test_creates_missing_destination(self) -> None:
        dest = self.dest / "audits" / "acme"
        self.assertEqual(run_quiet(["--no-banner", "init", "--ai", "cursor", str(dest)]), 0)
        self.assertTrue((dest / ".cursor" / "rules" / "lsa-orchestrator.mdc").is_file())

    def test_destination_that_is_a_file_fails(self) -> None:
        target = self.dest / "file.txt"
        target.write_text("x", encoding="utf-8")
        self.assertEqual(run_quiet(["--no-banner", "init", "--ai", "generic", str(target)]), 1)

    def test_invalid_agents_md_reports_error_without_traceback(self) -> None:
        (self.dest / "AGENTS.md").write_bytes(b"# caf\xe9\n")
        res = subprocess.run([sys.executable, str(BIN_KOMAINU), "--no-banner", "init", "--ai", "codex", str(self.dest)],
                             capture_output=True, text=True)
        self.assertEqual(res.returncode, 1)
        self.assertNotIn("Traceback", res.stderr)
        self.assertIn("not UTF-8", res.stdout + res.stderr)

    def test_generic_refuses_foreign_contract_without_traceback(self) -> None:
        contract = self.dest / "contract.json"
        contract.write_text('{"openapi": "3.0.0"}', encoding="utf-8")
        res = subprocess.run([sys.executable, str(BIN_KOMAINU), "--no-banner", "init", "--ai", "generic", str(self.dest)],
                             capture_output=True, text=True)
        self.assertEqual(res.returncode, 1)
        self.assertNotIn("Traceback", res.stderr)
        self.assertIn("contract.json", res.stdout + res.stderr)
        self.assertEqual(contract.read_text(encoding="utf-8"), '{"openapi": "3.0.0"}')
        self.assertEqual([p.name for p in self.dest.iterdir()], ["contract.json"])

    def test_generic_rerun_refreshes_own_bundle(self) -> None:
        self.assertEqual(run_quiet(["--no-banner", "init", "--ai", "generic", str(self.dest)]), 0)
        self.assertEqual(run_quiet(["--no-banner", "init", "--ai", "generic", str(self.dest)]), 0)
        self.assertTrue((self.dest / "system-prompts" / "orchestrator.md").is_file())

    def test_help_topic_and_examples(self) -> None:
        res = subprocess.run([sys.executable, str(BIN_KOMAINU), "help", "init"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("usage: komainu init", res.stdout)
        self.assertIn("Examples:", res.stdout)
        self.assertIn("codex", res.stdout)

    def test_bin_end_to_end(self) -> None:
        res = subprocess.run([sys.executable, str(BIN_KOMAINU), "--no-banner", "init", "--ai", "codex", str(self.dest)],
                             capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("Run the legacy-security-audit skill", res.stdout)


if __name__ == "__main__":
    unittest.main()
