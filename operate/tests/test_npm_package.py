#!/usr/bin/env python3
"""Automated verification tests for Komainu npm package & npx launcher (Issue #59)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_JSON = REPO_ROOT / "package.json"
BIN_KOMAINU_JS = REPO_ROOT / "bin" / "komainu.js"
WORKFLOW_FILE = REPO_ROOT / ".github" / "workflows" / "npm-publish.yml"


class TestNPMPackage(unittest.TestCase):
    """Test suite verifying npmjs package metadata and Node.js launcher bridge."""

    def test_package_json_structure(self) -> None:
        """package.json must exist, be valid JSON, and define required bin and files metadata."""
        self.assertTrue(PACKAGE_JSON.is_file(), f"package.json not found at {PACKAGE_JSON}")
        data = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))

        self.assertEqual(data.get("name"), "komainu-guard")
        self.assertIn("version", data)
        self.assertEqual(data.get("bin", {}).get("komainu"), "bin/komainu.js")
        self.assertEqual(data.get("bin", {}).get("komainu-guard"), "bin/komainu.js")
        self.assertEqual(data.get("license"), "Apache-2.0")

        # Whitelisted files must include platform modules
        files = data.get("files", [])
        for req_dir in ("bin/", "assess/", "operate/", "remediate/", "contracts/", "examples/"):
            self.assertIn(req_dir, files, f"Missing required directory {req_dir} in files array")

    def test_bin_komainu_js_permissions_and_shebang(self) -> None:
        """bin/komainu.js must be executable and have Node.js shebang."""
        self.assertTrue(BIN_KOMAINU_JS.is_file(), f"Launcher not found at {BIN_KOMAINU_JS}")
        self.assertTrue(BIN_KOMAINU_JS.stat().st_mode & 0o111 != 0, "bin/komainu.js is not executable")

        first_line = BIN_KOMAINU_JS.read_text(encoding="utf-8").splitlines()[0]
        self.assertEqual(first_line, "#!/usr/bin/env node")

    def test_node_launcher_execution_delegates_to_cli(self) -> None:
        """Executing node bin/komainu.js must forward arguments to Python CLI."""
        node_bin = shutil.which("node")
        if not node_bin:
            self.skipTest("Node.js runtime not installed on host")

        # Test --version
        res_v = subprocess.run([node_bin, str(BIN_KOMAINU_JS), "--version"], capture_output=True, text=True)
        self.assertEqual(res_v.returncode, 0)
        self.assertIn("komainu v", res_v.stdout)

        # Test --help
        res_h = subprocess.run([node_bin, str(BIN_KOMAINU_JS), "--help"], capture_output=True, text=True)
        self.assertEqual(res_h.returncode, 0)
        self.assertIn("scan", res_h.stdout)
        self.assertIn("protect", res_h.stdout)
        self.assertIn("test", res_h.stdout)
        self.assertIn("demo", res_h.stdout)

    def test_node_launcher_error_on_missing_python(self) -> None:
        """Launcher must show friendly error with Docker fallback if Python is missing."""
        node_bin = shutil.which("node")
        if not node_bin:
            self.skipTest("Node.js runtime not installed on host")

        env = os.environ.copy()
        env["PYTHON_BIN"] = "/nonexistent/python3/binary"

        res = subprocess.run([node_bin, str(BIN_KOMAINU_JS), "--version"], env=env, capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Python 3.8+ is required", res.stderr)
        self.assertIn("docker run", res.stderr)

    def test_npm_publish_workflow_configuration(self) -> None:
        """Workflow .github/workflows/npm-publish.yml must be hardened with OIDC trusted publishing and environment protection."""
        self.assertTrue(WORKFLOW_FILE.is_file(), f"Workflow not found at {WORKFLOW_FILE}")
        content = WORKFLOW_FILE.read_text(encoding="utf-8")

        self.assertIn("npm publish --access public", content)
        self.assertIn("id-token: write", content)
        self.assertIn("environment: npm-release", content)
        self.assertIn("npm@11.5.1", content)
        self.assertNotIn("secrets.NPM_TOKEN", content)


if __name__ == "__main__":
    unittest.main()
