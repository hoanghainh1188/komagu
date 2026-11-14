#!/usr/bin/env python3
"""Tests for Path Traversal (CWE-22) and SSRF (CWE-918) LSA support (Issue #395)."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

KIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KIT / "scripts"))

from find_path_ssrf import find_path_ssrf  # noqa: E402
from findings_to_sarif import to_sarif  # noqa: E402
from lsa_common import load_config  # noqa: E402


class TestPathTraversalAndSSRF(unittest.TestCase):
    """Verify Tier 1 pre-scan and SARIF export for path_traversal and ssrf."""

    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="komagu_path_ssrf_")).resolve()
        self.cfg = load_config(None)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_detects_vulnerable_and_skips_sanitized(self) -> None:
        (self.temp_dir / "files.js").write_text(
            "const fs = require('fs');\n"
            "app.get('/download', (req, res) => {\n"
            "  fs.readFile('/var/data/' + req.query.file, () => {});\n"
            "});\n"
            "app.get('/safe-download', (req, res) => {\n"
            "  const safe = path.basename(req.query.file);\n"
            "  fs.readFile('/var/data/' + safe, () => {});\n"
            "});\n",
            encoding="utf-8",
        )
        (self.temp_dir / "webhook.py").write_text(
            "import requests\n"
            "def send_webhook(request):\n"
            "    target_url = request.args.get('url')\n"
            "    return requests.post(target_url, json={'ok': True})\n"
            "def health():\n"
            "    return requests.get('https://status.example.com/ping')\n",
            encoding="utf-8",
        )

        res = find_path_ssrf(self.temp_dir, self.cfg)
        self.assertEqual(res["summary"]["path_traversal"], 1)
        self.assertEqual(res["summary"]["ssrf"], 1)
        cats = {c["category"]: c for c in res["candidates"]}
        self.assertEqual(cats["path_traversal"]["cwe"], "CWE-22")
        self.assertEqual(cats["path_traversal"]["line"], 3)
        self.assertEqual(cats["ssrf"]["cwe"], "CWE-918")
        self.assertEqual(cats["ssrf"]["line"], 4)

    def test_sarif_export_supports_path_traversal_and_ssrf(self) -> None:
        findings = [
            {
                "finding_id": "PATH-01",
                "category": "path_traversal",
                "severity": "high",
                "confidence": "high",
                "status": "confirmed",
                "title": "Arbitrary file read via ?file=",
                "cwe": ["CWE-22"],
                "location": {"file": "files.js", "start_line": 3},
            },
            {
                "finding_id": "SSRF-01",
                "category": "ssrf",
                "severity": "high",
                "confidence": "high",
                "status": "confirmed",
                "title": "Unvalidated webhook URL",
                "cwe": ["CWE-918"],
                "location": {"file": "webhook.py", "start_line": 4},
            },
        ]
        sarif = to_sarif({"findings": findings}, target_dir=self.temp_dir)
        results = sarif["runs"][0]["results"]
        self.assertEqual(len(results), 2)
        rule_ids = {r["ruleId"] for r in results}
        self.assertIn("lsa/path_traversal/general", rule_ids)
        self.assertIn("lsa/ssrf/general", rule_ids)


if __name__ == "__main__":
    unittest.main()
