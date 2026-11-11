#!/usr/bin/env python3
"""`.github/scripts/audit_minimum_versions.py`: audits the lowest version each requirement allows (#390)."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[2] / ".github" / "scripts" / "audit_minimum_versions.py"
_spec = importlib.util.spec_from_file_location("audit_minimum_versions", SCRIPT)
amv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(amv)


def _report(*vulns: tuple) -> dict:
    deps = {}
    for name, version, vuln_id, fixes in vulns:
        deps.setdefault((name, version), []).append({"id": vuln_id, "fix_versions": fixes})
    return {"dependencies": [{"name": n, "version": v, "vulns": vs} for (n, v), vs in deps.items()]}


class TestMinimumPins(unittest.TestCase):
    def test_lower_bounds_and_exact_pins_become_pins(self) -> None:
        text = "# comment\npyjwt>=2.15.0\ncryptography[ssh] >= 50.0.0  # note\nrequests==2.32.3\n"
        self.assertEqual(amv.minimum_pins(text), ["pyjwt==2.15.0", "cryptography==50.0.0", "requests==2.32.3"])

    def test_unversioned_and_upper_bounds_are_ignored(self) -> None:
        self.assertEqual(amv.minimum_pins("flask\nurllib3<3\n-r other.txt\n"), [])


class TestClassify(unittest.TestCase):
    def test_fixable_and_unfixable_are_split_and_deduplicated(self) -> None:
        report = _report(
            ("pyjwt", "2.8.0", "PYSEC-1", ["2.12.0"]),
            ("pyjwt", "2.8.0", "PYSEC-1", ["2.12.0"]),
            ("pyjwt", "2.8.0", "PYSEC-2", []),
        )
        fixable, unfixable = amv.classify(report)
        self.assertEqual(fixable, ["pyjwt 2.8.0: PYSEC-1 (fixed in 2.12.0)"])
        self.assertEqual(unfixable, ["pyjwt 2.8.0: PYSEC-2 (no fixed version)"])


class TestMain(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="komagu_amv_")
        self.req = os.path.join(self.tmp, "requirements.txt")
        self.summary = os.path.join(self.tmp, "summary.md")
        with open(self.req, "w", encoding="utf-8") as handle:
            handle.write("pyjwt>=2.8.0\n")

    def _run(self, report: dict) -> int:
        with mock.patch.object(amv, "audit", return_value=report) as audit, \
                mock.patch("builtins.print"):
            code = amv.main(["--summary", self.summary, self.req])
        audit.assert_called_once_with(["pyjwt==2.8.0"])
        return code

    def test_fixable_vulnerability_at_the_minimum_fails(self) -> None:
        self.assertEqual(self._run(_report(("pyjwt", "2.8.0", "PYSEC-1", ["2.12.0"]))), 1)
        with open(self.summary, encoding="utf-8") as handle:
            self.assertIn("FAIL pyjwt 2.8.0: PYSEC-1", handle.read())

    def test_vulnerability_without_a_fix_is_only_reported(self) -> None:
        self.assertEqual(self._run(_report(("pyjwt", "2.8.0", "PYSEC-2", []))), 0)
        with open(self.summary, encoding="utf-8") as handle:
            self.assertIn("note pyjwt 2.8.0: PYSEC-2", handle.read())

    def test_clean_minimum_passes(self) -> None:
        self.assertEqual(self._run({"dependencies": [{"name": "pyjwt", "version": "2.8.0", "vulns": []}]}), 0)


class TestRepositoryMinimums(unittest.TestCase):
    """Minimums raised in #390: these versions had fixable advisories."""

    def test_raised_minimums(self) -> None:
        root = SCRIPT.parents[2]
        ekyc = amv.minimum_pins((root / "remediate/ekyc/requirements.txt").read_text(encoding="utf-8"))
        identity = amv.minimum_pins((root / "remediate/identity/python/requirements.txt").read_text(encoding="utf-8"))
        self.assertIn("cryptography==50.0.0", ekyc)
        self.assertIn("cryptography==50.0.0", identity)
        self.assertIn("pyjwt==2.15.0", identity)


if __name__ == "__main__":
    unittest.main()
