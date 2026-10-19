#!/usr/bin/env python3
"""Tests for merge_findings and security boundaries (Issue #115)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import List

HERE = Path(__file__).resolve().parent
KIT = HERE.parent
sys.path.insert(0, str(KIT / "scripts"))

from lsa_common import iter_source_files, load_config, write_json  # noqa: E402
from merge_findings import load_validator, _validate_node  # noqa: E402


class TestMergeAndSecurity(unittest.TestCase):
    def test_recursive_stdlib_validator(self):
        """Verify that pure stdlib fallback validator catches nested schema errors without KeyError."""
        finding_schema = json.loads((KIT.parent.parent / "contracts" / "schemas" / "finding.schema.json").read_text())

        # Missing nested required field 'start_line'
        bad_finding = {
            "finding_id": "BOLA-test-1",
            "category": "bola",
            "subtype": "missing_ownership_check",
            "title": "Test Title",
            "location": {"file": "test.php"},  # missing start_line
            "evidence": [{"file": "test.php", "line": 1, "code": "foo", "why": "bar"}],
            "severity": "high",
            "confidence": "high",
            "cwe": ["CWE-639"],
            "recommendation": "Fix it",
            "status": "unverified",
        }
        errs: List[str] = []
        _validate_node(bad_finding, finding_schema, finding_schema, "", errs)
        self.assertTrue(any("start_line" in e for e in errs), f"Expected missing start_line error, got {errs}")

        # Invalid enum
        bad_enum = dict(bad_finding, location={"file": "test.php", "start_line": 1}, severity="super_critical")
        errs = []
        _validate_node(bad_enum, finding_schema, finding_schema, "", errs)
        self.assertTrue(any("super_critical" in e for e in errs), f"Expected enum error, got {errs}")

        # Invalid pattern
        bad_pattern = dict(bad_finding, finding_id="INVALID_ID_PATTERN", location={"file": "test.php", "start_line": 1})
        errs = []
        _validate_node(bad_pattern, finding_schema, finding_schema, "", errs)
        self.assertTrue(any("does not match pattern" in e for e in errs), f"Expected pattern error, got {errs}")

        # Type mismatch on nested object
        bad_type = dict(bad_finding, location="invalid_string_location")
        errs = []
        _validate_node(bad_type, finding_schema, finding_schema, "", errs)
        self.assertTrue(any("expected ['object']" in e for e in errs), f"Expected type mismatch error, got {errs}")

    def test_dedupe_prefers_confirmed_over_rejected(self):
        """Verify deduplication applies verification first and prefers confirmed findings."""
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            out.mkdir()
            (out / "findings").mkdir()

            # Finding A: high severity, but rejected by verifier
            finding_a = {
                "finding_id": "BOLA-route-1-a",
                "category": "bola",
                "subtype": "missing_ownership_check",
                "title": "High finding",
                "route_id": "r1",
                "location": {"file": "order.php", "start_line": 10},
                "evidence": [{"file": "order.php", "line": 10, "code": "foo", "why": "bar"}],
                "severity": "high",
                "confidence": "high",
                "cwe": ["CWE-639"],
                "recommendation": "Fix",
                "status": "unverified",
            }

            # Finding B: medium severity, but confirmed by verifier at same location
            finding_b = {
                "finding_id": "BOLA-route-1-b",
                "category": "bola",
                "subtype": "missing_ownership_check",
                "title": "Medium finding",
                "route_id": "r1",
                "location": {"file": "order.php", "start_line": 10},
                "evidence": [{"file": "order.php", "line": 10, "code": "foo", "why": "bar"}],
                "severity": "medium",
                "confidence": "medium",
                "cwe": ["CWE-639"],
                "recommendation": "Fix",
                "status": "unverified",
            }

            write_json(out / "findings" / "bola-01.json", {"batch_id": "b1", "findings": [finding_a, finding_b]})
            write_json(out / "findings" / "verified-01.json", {
                "verifications": [
                    {"finding_id": "BOLA-route-1-a", "verdict": "rejected", "checked": ["order.php"], "notes": "FP"},
                    {"finding_id": "BOLA-route-1-b", "verdict": "confirmed", "checked": ["order.php"], "notes": "True Positive"},
                ]
            })

            # Run merge_findings.py
            r = subprocess.run([sys.executable, str(KIT / "scripts" / "merge_findings.py"), str(out)], capture_output=True, text=True)
            res = json.loads(r.stdout)
            self.assertEqual(res["summary"]["active"], 1, "Should have 1 active finding remaining")

            fj = json.loads((out / "findings.json").read_text())
            active_fids = [f["finding_id"] for f in fj["findings"] if f["status"] != "rejected"]
            self.assertIn("BOLA-route-1-b", active_fids, "Confirmed medium finding should be kept over rejected high")

            cov = json.loads((out / "coverage.json").read_text())
            dupes = cov.get("duplicates_removed", [])
            self.assertEqual(len(dupes), 1)
            self.assertEqual(dupes[0]["kept"], "BOLA-route-1-b")
            self.assertEqual(dupes[0]["dropped"], "BOLA-route-1-a")

    def test_dedupe_drops_unverified_from_coverage(self):
        """Verify that when an unverified finding is dropped by deduplication, it is not reported in coverage."""
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            out.mkdir()
            (out / "findings").mkdir()

            # Finding A: high severity, confirmed by verifier
            finding_a = {
                "finding_id": "BOLA-route-1-a",
                "category": "bola",
                "subtype": "missing_ownership_check",
                "title": "Confirmed finding",
                "route_id": "r1",
                "location": {"file": "order.php", "start_line": 10},
                "evidence": [{"file": "order.php", "line": 10, "code": "foo", "why": "bar"}],
                "severity": "high",
                "confidence": "high",
                "cwe": ["CWE-639"],
                "recommendation": "Fix",
                "status": "unverified",
            }

            # Finding B: medium severity, unverified (no verification output) at same location
            finding_b = {
                "finding_id": "BOLA-route-1-b",
                "category": "bola",
                "subtype": "missing_ownership_check",
                "title": "Unverified duplicate finding",
                "route_id": "r1",
                "location": {"file": "order.php", "start_line": 10},
                "evidence": [{"file": "order.php", "line": 10, "code": "foo", "why": "bar"}],
                "severity": "medium",
                "confidence": "medium",
                "cwe": ["CWE-639"],
                "recommendation": "Fix",
                "status": "unverified",
            }

            write_json(out / "findings" / "bola-01.json", {"batch_id": "b1", "findings": [finding_a, finding_b]})
            # Only verify finding_a
            write_json(out / "findings" / "verified-01.json", {
                "verifications": [
                    {"finding_id": "BOLA-route-1-a", "verdict": "confirmed", "checked": ["order.php"], "notes": "True Positive"},
                ]
            })

            subprocess.run([sys.executable, str(KIT / "scripts" / "merge_findings.py"), str(out)], capture_output=True, text=True)
            cov = json.loads((out / "coverage.json").read_text())
            unverified_list = cov.get("findings_without_verification", [])
            self.assertNotIn("BOLA-route-1-b", unverified_list, "Dropped duplicate must not appear in findings_without_verification")

    def test_missing_route_inventory_fails_with_candidates(self):
        """Missing or empty route inventory with candidates must exit 1 and report all missing."""
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            out.mkdir()

            # Create candidate file with 2 candidates
            write_json(out / "routes.candidates.json", {
                "candidates": [
                    {"route_id": "r-001", "file": "a.php", "line": 1},
                    {"route_id": "r-002", "file": "b.php", "line": 1},
                ]
            })

            # Write a stale routes.json that should be cleaned up
            write_json(out / "routes.json", {"stale": True})

            # Run merge without OUT/routes directory
            r = subprocess.run([sys.executable, str(KIT / "scripts" / "merge_findings.py"), str(out)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1, "Must exit 1 when routes are missing from inventory")

            cov = json.loads((out / "coverage.json").read_text())
            self.assertEqual(len(cov["missing_from_inventory"]), 2)
            self.assertIn("r-001", cov["missing_from_inventory"])
            self.assertIn("r-002", cov["missing_from_inventory"])

            # Verify stale routes.json was replaced
            routes_doc = json.loads((out / "routes.json").read_text())
            self.assertNotIn("stale", routes_doc)
            self.assertEqual(routes_doc["routes"], [])

    def test_malformed_agent_output_captured_per_item(self):
        """Malformed agent outputs (lists, missing IDs, non-objects) must not crash merge."""
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            out.mkdir()
            (out / "findings").mkdir()

            # Malformed JSON doc (root is list)
            (out / "findings" / "bad_list.json").write_text('[{"some": "item"}]')

            # Malformed finding missing finding_id and non-dict items
            write_json(out / "findings" / "bad_items.json", {
                "findings": ["invalid_string_item", {"category": "bola"}],
                "verifications": ["invalid_verif", {}],
                "route_verdicts": ["invalid_route"],
                "candidate_verdicts": ["invalid_cand"],
                "new_issues": ["invalid_issue"],
            })

            r = subprocess.run([sys.executable, str(KIT / "scripts" / "merge_findings.py"), str(out)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1, "Must exit 1 with validation errors")

            cov = json.loads((out / "coverage.json").read_text())
            errors = cov.get("validation_errors", [])
            self.assertTrue(any("bad_list.json: expected JSON object" in e for e in errors))
            self.assertTrue(any("bad_items.json: finding item is not an object" in e for e in errors))
            self.assertTrue(any("bad_items.json: malformed route_verdict item" in e for e in errors))

    def test_symlink_and_boundary_protection(self):
        """Verify symlinks pointing outside target directory are skipped by iter_source_files."""
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "target"
            outside = Path(td) / "outside"
            target.mkdir()
            outside.mkdir()

            # Real source file
            (target / "legit.php").write_text("<?php echo 1;")

            # Symlink to outside secret
            (outside / "secret.txt").write_text("CONFIDENTIAL")
            try:
                os.symlink(outside / "secret.txt", target / "leak.php")
                os.symlink(outside, target / "symlinked_dir")
            except OSError:
                self.skipTest("Symlinks not supported on this platform/environment")

            cfg = load_config(None)
            cfg["scope"]["exclude"] = []
            files = list(iter_source_files(target, cfg))
            rel_files = [rel for _, rel in files]

            self.assertIn("legit.php", rel_files)
            self.assertNotIn("leak.php", rel_files, "Symlink leak.php should be skipped")
            self.assertFalse(any(rel.startswith("symlinked_dir") for rel in rel_files), "Symlinked dir should be skipped")


if __name__ == "__main__":
    unittest.main()
