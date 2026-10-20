#!/usr/bin/env python3
"""Automated tests for parallel processing in LSA pre-scan (Issue #196)."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
LSA_SCRIPTS = REPO_ROOT / "assess" / "lsa" / "scripts"
FIXTURES = REPO_ROOT / "assess" / "lsa" / "tests" / "fixtures"
sys.path.insert(0, str(LSA_SCRIPTS))

from find_injection import find_injection  # noqa: E402
from lsa_common import load_config  # noqa: E402
from map_routes import map_routes  # noqa: E402


class TestParallelScan(unittest.TestCase):
    """Verifies that parallel workers produce 100% deterministic, identical results to sequential runs."""

    def setUp(self) -> None:
        self.config = load_config(None)
        self.fixture = FIXTURES / "dotnet-legacy"

    def test_find_injection_deterministic_across_worker_counts(self) -> None:
        """find_injection must produce identical output with 1, 2, and 4 workers."""
        seq_res = find_injection(self.fixture, self.config, workers=1)
        par2_res = find_injection(self.fixture, self.config, workers=2)
        par4_res = find_injection(self.fixture, self.config, workers=4)

        self.assertEqual(seq_res["summary"], par2_res["summary"])
        self.assertEqual(seq_res["summary"], par4_res["summary"])
        self.assertEqual(seq_res["candidates"], par2_res["candidates"])
        self.assertEqual(seq_res["candidates"], par4_res["candidates"])
        self.assertEqual(seq_res["suppressed"], par2_res["suppressed"])
        self.assertEqual(seq_res["suppressed"], par4_res["suppressed"])

    def test_map_routes_deterministic_across_worker_counts(self) -> None:
        """map_routes must produce identical output with 1, 2, and 4 workers."""
        stacks = {"dotnet-webforms", "dotnet-handlers", "dotnet-mvc"}
        seq_res = map_routes(self.fixture, self.config, stacks, workers=1)
        par2_res = map_routes(self.fixture, self.config, stacks, workers=2)
        par4_res = map_routes(self.fixture, self.config, stacks, workers=4)

        self.assertEqual(seq_res["summary"], par2_res["summary"])
        self.assertEqual(seq_res["summary"], par4_res["summary"])
        self.assertEqual(seq_res["candidates"], par2_res["candidates"])
        self.assertEqual(seq_res["candidates"], par4_res["candidates"])

    def test_run_prescan_cli_with_workers_flag(self) -> None:
        """run_prescan.py must accept --workers and -j arguments and report worker count."""
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "out"
            cmd = [
                sys.executable,
                str(LSA_SCRIPTS / "run_prescan.py"),
                str(self.fixture),
                str(out_dir),
                "--workers",
                "2",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"run_prescan failed: {res.stderr}")

            summary_md = (out_dir / "prescan-summary.md").read_text(encoding="utf-8")
            self.assertIn("- Workers: 2", summary_md)

            # Ensure candidate files exist and contain valid candidates
            rc = json.loads((out_dir / "routes.candidates.json").read_text(encoding="utf-8"))
            ic = json.loads((out_dir / "injection.candidates.json").read_text(encoding="utf-8"))
            self.assertTrue(rc["summary"]["total"] > 0)
            self.assertTrue(ic["summary"]["total"] > 0)


if __name__ == "__main__":
    unittest.main()
