#!/usr/bin/env python3
"""Automated verification tests for Komainu Unified CLI (Issue #51)."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BIN_KOMAINU = REPO_ROOT / "bin" / "komainu"
FIXTURE_PATH = REPO_ROOT / "assess" / "lsa" / "tests" / "fixtures" / "php-plain"

from operate.cli.main import build_parser, main  # noqa: E402
from operate.cross_user_tester.mock_test_server import start_mock_server  # noqa: E402


class TestKomainuCLI(unittest.TestCase):
    """Test suite verifying unified komainu CLI subcommands and behaviors."""

    def test_bin_executable_exists_and_is_executable(self) -> None:
        """bin/komainu must exist and have execute permission."""
        self.assertTrue(BIN_KOMAINU.is_file(), f"Executable not found at {BIN_KOMAINU}")
        self.assertTrue(BIN_KOMAINU.stat().st_mode & 0o111 != 0, "bin/komainu is not executable")

    def test_version_and_help(self) -> None:
        """CLI must output version and help banner without error."""
        res_v = subprocess.run([sys.executable, str(BIN_KOMAINU), "--version"], capture_output=True, text=True)
        self.assertEqual(res_v.returncode, 0)
        self.assertIn("komainu v", res_v.stdout)

        res_h = subprocess.run([sys.executable, str(BIN_KOMAINU), "--help"], capture_output=True, text=True)
        self.assertEqual(res_h.returncode, 0)
        self.assertIn("scan", res_h.stdout)
        self.assertIn("protect", res_h.stdout)
        self.assertIn("test", res_h.stdout)
        self.assertIn("demo", res_h.stdout)

    def test_help_subcommand_and_topic_routing(self) -> None:
        """komainu help and komainu help <topic> must output relevant help and examples."""
        res_help = subprocess.run([sys.executable, str(BIN_KOMAINU), "help"], capture_output=True, text=True)
        self.assertEqual(res_help.returncode, 0)
        self.assertIn("Quick Start Workflow:", res_help.stdout)
        self.assertIn("komainu help <command>", res_help.stdout)

        for topic in ("scan", "protect", "test", "demo"):
            res_topic = subprocess.run([sys.executable, str(BIN_KOMAINU), "help", topic], capture_output=True, text=True)
            self.assertEqual(res_topic.returncode, 0)
            self.assertIn(f"usage: komainu {topic}", res_topic.stdout)
            self.assertIn("Examples:", res_topic.stdout)

    def test_python_module_entrypoint(self) -> None:
        """python3 -m operate.cli.main must work identically."""
        res = subprocess.run([sys.executable, "-m", "operate.cli.main", "--version"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("komainu v", res.stdout)

    def test_subcommand_parser_builds_cleanly(self) -> None:
        """In-process parser must parse subcommands without throwing."""
        parser = build_parser()
        args_scan = parser.parse_args(["scan", "/tmp", "--format", "html"])
        self.assertEqual(args_scan.subcommand, "scan")
        self.assertEqual(args_scan.format, "html")

        args_protect = parser.parse_args(["protect", "--dry-run", "--up"])
        self.assertEqual(args_protect.subcommand, "protect")
        self.assertTrue(args_protect.dry_run)
        self.assertTrue(args_protect.up)

        args_test = parser.parse_args(["test", "--url", "http://localhost:5001", "--strict"])
        self.assertEqual(args_test.subcommand, "test")
        self.assertEqual(args_test.base_url, "http://localhost:5001")
        self.assertTrue(args_test.strict)

        args_demo = parser.parse_args(["demo", "--backend", "all", "--dry-run"])
        self.assertEqual(args_demo.subcommand, "demo")
        self.assertEqual(args_demo.backend, "all")

    def test_scan_subcommand_execution(self) -> None:
        """komainu scan must run deterministic pre-scan and generate report files."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "out"
            res = subprocess.run(
                [
                    sys.executable,
                    str(BIN_KOMAINU),
                    "scan",
                    str(FIXTURE_PATH),
                    "--out",
                    str(out_dir),
                    "--format",
                    "all",
                    "--lang",
                    "all",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, f"Scan command failed: {res.stderr}\n{res.stdout}")
            self.assertTrue((out_dir / "stack-profile.json").is_file())
            self.assertTrue((out_dir / "routes.candidates.json").is_file())
            self.assertTrue((out_dir / "injection.candidates.json").is_file())
            self.assertTrue((out_dir / "findings.sarif").is_file())
            self.assertTrue((out_dir / "report.md").is_file())
            self.assertTrue((out_dir / "report.ja.md").is_file())
            self.assertTrue((out_dir / "report.html").is_file())
            self.assertIn("Komainu Security Audit Summary", res.stdout)

    def test_scan_subcommand_parallel_workers(self) -> None:
        """komainu scan with --workers / -j must execute cleanly and generate all artifacts."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "out"
            res = subprocess.run(
                [
                    sys.executable,
                    str(BIN_KOMAINU),
                    "scan",
                    str(FIXTURE_PATH),
                    "--out",
                    str(out_dir),
                    "--workers",
                    "2",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, f"Scan command failed: {res.stderr}\n{res.stdout}")
            self.assertTrue((out_dir / "routes.candidates.json").is_file())
            self.assertTrue((out_dir / "injection.candidates.json").is_file())
            self.assertTrue((out_dir / "report.html").is_file())

    def test_scan_subcommand_default_out_preserves_target_read_only(self) -> None:
        """komainu scan without --out must output to ./komainu-out in CWD, keeping target untouched."""
        with tempfile.TemporaryDirectory() as work_dir:
            res = subprocess.run(
                [
                    sys.executable,
                    str(BIN_KOMAINU),
                    "scan",
                    str(FIXTURE_PATH),
                ],
                cwd=work_dir,
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, f"Scan command failed: {res.stderr}\n{res.stdout}")
            default_out = Path(work_dir) / "komainu-out"
            self.assertTrue(default_out.is_dir(), "default komainu-out directory was not created in CWD")
            self.assertTrue((default_out / "stack-profile.json").is_file())
            # Ensure target directory was untouched
            self.assertFalse((FIXTURE_PATH / ".komainu").exists(), "target directory was polluted with .komainu")

    def test_protect_subcommand_dry_run(self) -> None:
        """komainu protect --dry-run must validate assets without error."""
        res = subprocess.run(
            [sys.executable, str(BIN_KOMAINU), "protect", "--dry-run", "--up"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"Protect failed: {res.stderr}")
        self.assertIn("Komainu Perimeter Protection Status", res.stdout)
        self.assertIn("Kong Gateway", res.stdout)
        self.assertIn("Coraza Caddy", res.stdout)

    def test_demo_subcommand_dry_run(self) -> None:
        """komainu demo --dry-run must validate compose without launching docker."""
        res = subprocess.run(
            [sys.executable, str(BIN_KOMAINU), "demo", "--backend", "all", "--dry-run"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"Demo failed: {res.stderr}")
        self.assertIn("Member Portal Reference Demo Status", res.stdout)
        self.assertIn("postgres", res.stdout)
        self.assertIn("backend-dotnet", res.stdout)
        self.assertIn("backend-spring", res.stdout)

    def test_test_subcommand_against_mock_server(self) -> None:
        """komainu test must execute cross-user verification against mock server and report PASS."""
        server, thread, base_url = start_mock_server(port=0)
        try:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_out:
                out_path = Path(tmp_out.name)

            res = subprocess.run(
                [
                    sys.executable,
                    str(BIN_KOMAINU),
                    "test",
                    "--url",
                    base_url,
                    "--auto-crud",
                    "/api/members",
                    "--output",
                    str(out_path),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, f"Test failed: {res.stderr}\n{res.stdout}")
            self.assertIn("KOMAINU CROSS-USER AUTHORIZATION TEST REPORT", res.stdout)
            self.assertIn("PASSED (SECURE)", res.stdout)

            # Verify saved report
            saved_report = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertTrue(saved_report["success"])
            self.assertGreaterEqual(saved_report["total"], 3)
            out_path.unlink(missing_ok=True)
        finally:
            server.shutdown()


if __name__ == "__main__":
    unittest.main()
