#!/usr/bin/env python3
"""Automated tests for content-hash caching engine in LSA pre-scan (Issue #197)."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
LSA_SCRIPTS = REPO_ROOT / "assess" / "lsa" / "scripts"
FIXTURES = REPO_ROOT / "assess" / "lsa" / "tests" / "fixtures"
sys.path.insert(0, str(LSA_SCRIPTS))

from scan_cache import ScanCache, compute_config_hash, compute_file_sha256  # noqa: E402


class TestScanCache(unittest.TestCase):
    """Test suite for ScanCache unit behavior and incremental scan acceleration."""

    def test_01_cache_put_get_and_persistence(self) -> None:
        """ScanCache stores entries, detects hits by stat and hash, and saves to disk."""
        with tempfile.TemporaryDirectory() as td:
            cache_dir = Path(td) / ".cache"
            cache = ScanCache(cache_dir=cache_dir, enabled=True)
            cfg_hash = "test-config-hash-1234"
            self.assertFalse(cache.load(cfg_hash))

            test_file = Path(td) / "example.php"
            test_file.write_text("<?php echo $_GET['id']; ?>", encoding="utf-8")

            # Initial get is a miss
            self.assertIsNone(cache.get_routes("example.php", test_file))
            self.assertEqual(cache.stats["routes_misses"], 1)

            # Put route & injection entries and save
            cache.put_routes(
                rel="example.php",
                path=test_file,
                route_items=[{"route_id": "R-0001", "path": "/example.php"}],
            )
            cache.put_injection(
                rel="example.php",
                path=test_file,
                injection_items=[{"file": "example.php", "line": 1, "rule": "php-sqli"}],
                injection_suppressed=[],
            )
            cache.save()
            self.assertTrue((cache_dir / "lsa-cache.json").is_file())

            # Reload cache in fresh instance
            cache2 = ScanCache(cache_dir=cache_dir, enabled=True)
            self.assertTrue(cache2.load(cfg_hash))
            route_hit = cache2.get_routes("example.php", test_file)
            self.assertIsNotNone(route_hit)
            self.assertEqual(cache2.stats["routes_hits"], 1)
            self.assertEqual(route_hit[0][0]["route_id"], "R-0001")

            inj_hit = cache2.get_injection("example.php", test_file)
            self.assertIsNotNone(inj_hit)
            self.assertEqual(cache2.stats["injection_hits"], 1)
            self.assertEqual(inj_hit[0][0]["rule"], "php-sqli")

            # Modify file content -> must return miss
            test_file.write_text("<?php echo 'safe'; ?>", encoding="utf-8")
            self.assertIsNone(cache2.get_routes("example.php", test_file))
            self.assertEqual(cache2.stats["routes_misses"], 1)

    def test_02_cache_invalidation_on_config_change(self) -> None:
        """Cache automatically invalidates when config hash changes."""
        with tempfile.TemporaryDirectory() as td:
            cache_dir = Path(td) / ".cache"
            cache = ScanCache(cache_dir=cache_dir, enabled=True)
            test_file = Path(td) / "test.php"
            test_file.write_text("<?php phpinfo(); ?>", encoding="utf-8")

            cache.load("initial-hash-v1")
            cache.put_routes("test.php", test_file, [])
            cache.save()

            # Load with altered config hash
            cache_reloaded = ScanCache(cache_dir=cache_dir, enabled=True)
            loaded = cache_reloaded.load("changed-hash-v2")
            self.assertFalse(loaded)
            self.assertEqual(len(cache_reloaded.entries), 0)

    def test_03_run_prescan_incremental_speedup_and_determinism(self) -> None:
        """Consecutive scans achieve high cache hit rates and produce 100% identical outputs."""
        fixture = FIXTURES / "php-plain"
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "out"

            # Run 1: Cold cache
            cmd = [
                sys.executable,
                str(LSA_SCRIPTS / "run_prescan.py"),
                str(fixture),
                str(out_dir),
            ]
            t0 = time.time()
            res1 = subprocess.run(cmd, capture_output=True, text=True)
            dur1 = time.time() - t0
            self.assertEqual(res1.returncode, 0, f"Run 1 failed: {res1.stderr}")
            self.assertIn("0 hits", res1.stdout)

            routes1 = json.loads((out_dir / "routes.candidates.json").read_text(encoding="utf-8"))
            inj1 = json.loads((out_dir / "injection.candidates.json").read_text(encoding="utf-8"))

            # Run 2: Warm cache (unmodified files)
            t1 = time.time()
            res2 = subprocess.run(cmd, capture_output=True, text=True)
            dur2 = time.time() - t1
            self.assertEqual(res2.returncode, 0, f"Run 2 failed: {res2.stderr}")
            self.assertIn("100.0% hit rate", res2.stdout)

            routes2 = json.loads((out_dir / "routes.candidates.json").read_text(encoding="utf-8"))
            inj2 = json.loads((out_dir / "injection.candidates.json").read_text(encoding="utf-8"))

            # Outputs must be 100% deterministic and identical
            self.assertEqual(routes1["candidates"], routes2["candidates"])
            self.assertEqual(inj1["candidates"], inj2["candidates"])
            self.assertEqual(routes1["summary"], routes2["summary"])
            self.assertEqual(inj1["summary"], inj2["summary"])

    def test_04_run_prescan_no_cache_and_clean_cache_flags(self) -> None:
        """--no-cache disables caching and --clean-cache clears the cache."""
        fixture = FIXTURES / "php-plain"
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "out"

            # 1. Run with --no-cache
            res_no_cache = subprocess.run(
                [
                    sys.executable,
                    str(LSA_SCRIPTS / "run_prescan.py"),
                    str(fixture),
                    str(out_dir),
                    "--no-cache",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res_no_cache.returncode, 0)
            self.assertIn("- Cache: disabled", res_no_cache.stdout)
            self.assertFalse((out_dir / ".cache" / "lsa-cache.json").is_file())

            # 2. Run normal to generate cache
            subprocess.run(
                [
                    sys.executable,
                    str(LSA_SCRIPTS / "run_prescan.py"),
                    str(fixture),
                    str(out_dir),
                ],
                capture_output=True,
                text=True,
            )
            self.assertTrue((out_dir / ".cache" / "lsa-cache.json").is_file())

            # 3. Run with --clean-cache
            res_clean = subprocess.run(
                [
                    sys.executable,
                    str(LSA_SCRIPTS / "run_prescan.py"),
                    str(fixture),
                    str(out_dir),
                    "--clean-cache",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res_clean.returncode, 0)
            # Cold run because cache was cleaned
            self.assertIn("0 hits", res_clean.stdout)


if __name__ == "__main__":
    unittest.main()
