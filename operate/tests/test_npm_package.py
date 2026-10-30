#!/usr/bin/env python3
"""Automated verification tests for Komagu npm package & npx launcher (Issue #59)."""

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
BIN_KOMAGU_JS = REPO_ROOT / "bin" / "komagu.js"
BIN_LEGACY_JS = REPO_ROOT / "bin" / "komainu-legacy.js"
WORKFLOW_FILE = REPO_ROOT / ".github" / "workflows" / "npm-publish.yml"
RELEASE_PLEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release-please.yml"
RELEASE_PLEASE_CONFIG = REPO_ROOT / "release-please-config.json"
RELEASE_PLEASE_MANIFEST = REPO_ROOT / ".release-please-manifest.json"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
CLI_INIT = REPO_ROOT / "operate" / "cli" / "__init__.py"


class TestNPMPackage(unittest.TestCase):
    """Test suite verifying npmjs package metadata and Node.js launcher bridge."""

    def test_package_json_structure(self) -> None:
        """package.json must exist, be valid JSON, and define required bin and files metadata."""
        self.assertTrue(PACKAGE_JSON.is_file(), f"package.json not found at {PACKAGE_JSON}")
        data = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))

        self.assertEqual(data.get("name"), "@hoanghainh/komagu")
        self.assertEqual(data.get("publishConfig", {}).get("access"), "public")
        self.assertIn("version", data)
        self.assertEqual(data.get("bin", {}).get("komagu"), "bin/komagu.js")
        # Deprecated pre-rename aliases (#290)
        self.assertEqual(data.get("bin", {}).get("komainu"), "bin/komainu-legacy.js")
        self.assertEqual(data.get("bin", {}).get("komainu-guard"), "bin/komainu-legacy.js")
        self.assertEqual(data.get("license"), "Apache-2.0")

        # Whitelisted files must include platform modules
        files = data.get("files", [])
        for req_dir in ("bin/", "assess/", "operate/", "remediate/", "contracts/", "examples/"):
            self.assertIn(req_dir, files, f"Missing required directory {req_dir} in files array")

    def test_bin_komagu_js_permissions_and_shebang(self) -> None:
        """bin/komagu.js must be executable and have Node.js shebang."""
        self.assertTrue(BIN_KOMAGU_JS.is_file(), f"Launcher not found at {BIN_KOMAGU_JS}")
        self.assertTrue(BIN_KOMAGU_JS.stat().st_mode & 0o111 != 0, "bin/komagu.js is not executable")

        first_line = BIN_KOMAGU_JS.read_text(encoding="utf-8").splitlines()[0]
        self.assertEqual(first_line, "#!/usr/bin/env node")

    def test_node_launcher_execution_delegates_to_cli(self) -> None:
        """Executing node bin/komagu.js must forward arguments to Python CLI."""
        node_bin = shutil.which("node")
        if not node_bin:
            self.skipTest("Node.js runtime not installed on host")

        # Test --version
        res_v = subprocess.run([node_bin, str(BIN_KOMAGU_JS), "--version"], capture_output=True, text=True)
        self.assertEqual(res_v.returncode, 0)
        self.assertIn("komagu v", res_v.stdout)

        # Test --help
        res_h = subprocess.run([node_bin, str(BIN_KOMAGU_JS), "--help"], capture_output=True, text=True)
        self.assertEqual(res_h.returncode, 0)
        self.assertIn("scan", res_h.stdout)
        self.assertIn("protect", res_h.stdout)
        self.assertIn("test", res_h.stdout)
        self.assertIn("demo", res_h.stdout)

    def test_legacy_bin_alias_warns_and_delegates(self) -> None:
        """Deprecated komainu / komainu-guard bins must print a rename notice and still run (#290)."""
        node_bin = shutil.which("node")
        if not node_bin:
            self.skipTest("Node.js runtime not installed on host")

        self.assertTrue(BIN_LEGACY_JS.stat().st_mode & 0o111 != 0, "bin/komainu-legacy.js is not executable")
        res = subprocess.run([node_bin, str(BIN_LEGACY_JS), "--version"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("komagu v", res.stdout)
        self.assertIn("renamed to `komagu`", res.stderr)

    def test_node_launcher_error_on_missing_python(self) -> None:
        """Launcher must show friendly error with Docker fallback if Python is missing."""
        node_bin = shutil.which("node")
        if not node_bin:
            self.skipTest("Node.js runtime not installed on host")

        env = os.environ.copy()
        env["PYTHON_BIN"] = "/nonexistent/python3/binary"

        res = subprocess.run([node_bin, str(BIN_KOMAGU_JS), "--version"], env=env, capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Python 3.8+ is required", res.stderr)
        self.assertIn("docker run", res.stderr)

    def test_npm_publish_workflow_configuration(self) -> None:
        """Workflow .github/workflows/npm-publish.yml must be hardened with OIDC trusted publishing and environment protection."""
        self.assertTrue(WORKFLOW_FILE.is_file(), f"Workflow not found at {WORKFLOW_FILE}")
        content = WORKFLOW_FILE.read_text(encoding="utf-8")

        self.assertIn("npm publish --access public", content)
        # release-please publishes the GitHub Release with RELEASE_PLEASE_TOKEN so this trigger fires
        self.assertIn("release:\n    types: [published]", content)
        self.assertIn("id-token: write", content)
        self.assertIn("environment: npm-release", content)
        self.assertIn("npm@11.5.1", content)
        self.assertNotIn("secrets.NPM_TOKEN", content)

        # Issue #179: Verify fail-fast tag and package version consistency check step exists
        self.assertIn("Verify release tag matches package version", content)
        self.assertIn("${GITHUB_REF_NAME#v}", content)
        self.assertIn("operate/cli/__init__.py", content)

        # Execute the shell snippet with matching and mismatching GITHUB_REF_NAME
        bash_bin = shutil.which("bash")
        if bash_bin:
            pkg_version = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))["version"]
            step_script = content.split("Verify release tag matches package version")[1].split("run: |")[1].split("- name:")[0]
            env_ok = {**os.environ, "GITHUB_REF_NAME": f"v{pkg_version}"}
            res_ok = subprocess.run([bash_bin, "-e", "-c", step_script], cwd=REPO_ROOT, env=env_ok, capture_output=True, text=True)
            self.assertEqual(res_ok.returncode, 0, f"Version check script failed: {res_ok.stderr}")
            self.assertIn("Version consistency check passed", res_ok.stdout)

            env_bad = {**os.environ, "GITHUB_REF_NAME": "v0.0.0-mismatch"}
            res_bad = subprocess.run([bash_bin, "-e", "-c", step_script], cwd=REPO_ROOT, env=env_bad, capture_output=True, text=True)
            self.assertNotEqual(res_bad.returncode, 0)

    def test_package_ships_every_folder_komagu_init_copies(self) -> None:
        """`komagu init` copies kit folders from the repo; each top-level source must be in package.json files."""
        files = json.loads(PACKAGE_JSON.read_text(encoding="utf-8")).get("files", [])
        import importlib.util
        spec = importlib.util.spec_from_file_location("lsa_build_adapters", REPO_ROOT / "assess" / "lsa" / "adapters" / "build_adapters.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        for src in builder.COPY_DIRS.values():
            top = Path(src).resolve().relative_to(REPO_ROOT).parts[0] + "/"
            self.assertIn(top, files, f"{top} is copied by komagu init but missing from package.json files")

    def test_version_consistency_between_package_and_cli(self) -> None:
        """package.json version must match operate/cli/__init__.py __version__."""
        pkg_data = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
        pkg_version = pkg_data.get("version")

        cli_init = REPO_ROOT / "operate" / "cli" / "__init__.py"
        self.assertTrue(cli_init.is_file())
        import re
        m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', cli_init.read_text(encoding="utf-8"))
        self.assertIsNotNone(m, "Could not find __version__ in operate/cli/__init__.py")
        self.assertEqual(pkg_version, m.group(1), "package.json version does not match operate/cli/__init__.py")

    def test_release_please_configuration(self) -> None:
        """release-please must bump package.json and the CLI version, keep vX.Y.Z tags, and hide chore/ci/test."""
        config = json.loads(RELEASE_PLEASE_CONFIG.read_text(encoding="utf-8"))
        manifest = json.loads(RELEASE_PLEASE_MANIFEST.read_text(encoding="utf-8"))
        pkg_version = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))["version"]

        self.assertEqual(manifest, {".": pkg_version})
        self.assertTrue(config["include-v-in-tag"])
        self.assertFalse(config["include-component-in-tag"])

        root = config["packages"]["."]
        self.assertEqual(root["release-type"], "node")
        self.assertEqual(root["changelog-path"], "CHANGELOG.md")
        self.assertIn({"type": "generic", "path": "operate/cli/__init__.py"}, root["extra-files"])

        sections = {s["type"]: s.get("hidden", False) for s in config["changelog-sections"]}
        self.assertEqual(set(sections), {"feat", "fix", "perf", "refactor", "docs", "chore", "ci", "test"})
        self.assertEqual({t for t, hidden in sections.items() if hidden}, {"chore", "ci", "test"})

        # The generic updater only rewrites lines carrying the annotation
        version_lines = [ln for ln in CLI_INIT.read_text(encoding="utf-8").splitlines() if ln.startswith("__version__")]
        self.assertEqual(version_lines, [f'__version__ = "{pkg_version}"  # x-release-please-version'])

    def test_release_please_workflow_uses_triggering_token(self) -> None:
        """GITHUB_TOKEN releases do not trigger npm-publish.yml, so the workflow must use RELEASE_PLEASE_TOKEN."""
        content = RELEASE_PLEASE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("branches: [main]", content)
        self.assertRegex(content, r"googleapis/release-please-action@[0-9a-f]{40} # v\d")
        self.assertIn("token: ${{ secrets.RELEASE_PLEASE_TOKEN }}", content)
        self.assertNotIn("secrets.GITHUB_TOKEN", content)
        self.assertIn("config-file: release-please-config.json", content)
        self.assertIn("manifest-file: .release-please-manifest.json", content)
        self.assertNotIn("npm publish --", content)
        self.assertNotIn("id-token: write", content)

    def test_changelog_ships_in_package(self) -> None:
        """CHANGELOG.md must exist, cover the current version, and be whitelisted in package.json files."""
        files = json.loads(PACKAGE_JSON.read_text(encoding="utf-8")).get("files", [])
        self.assertIn("CHANGELOG.md", files)
        pkg_version = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))["version"]
        self.assertTrue(CHANGELOG.read_text(encoding="utf-8").startswith("# Changelog\n"))
        self.assertIn(f"## [{pkg_version}](", CHANGELOG.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
