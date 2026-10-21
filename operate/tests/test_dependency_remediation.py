#!/usr/bin/env python3
"""Unit and integration tests for automated CVE dependency manifest remediation in `komainu fix`."""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from operate.cli.main import main
from operate.devsecops.pipeline import DevSecOpsPipeline
from operate.remediator.runner import RemediationRunner
from operate.remediator.strategies import DependencyVulnerabilityRemediationStrategy
from remediate.deps.patcher import (
    CVEAdvisoryCatalog,
    DependencyManifestPatcher,
    is_version_older,
)


class TestDependencyRemediation(unittest.TestCase):
    """Test suite verifying multi-ecosystem CVE dependency patching and CLI --sca integration."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="komainu_dep_fix_")
        self.target_path = Path(self.temp_dir).resolve()
        self.patcher = DependencyManifestPatcher()

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_version_comparison_semantics(self) -> None:
        """is_version_older must accurately compare semantic versions across ecosystems."""
        self.assertTrue(is_version_older("4.17.15", "4.17.21"))
        self.assertTrue(is_version_older("^4.18.2", "4.19.2"))
        self.assertTrue(is_version_older("v0.19.0", "v0.23.0"))
        self.assertTrue(is_version_older("2.13.4", "2.13.4.2"))
        self.assertFalse(is_version_older("4.17.21", "4.17.21"))
        self.assertFalse(is_version_older("5.0.0", "4.17.21"))

    def test_patch_package_json_preserves_operators_and_formatting(self) -> None:
        """package.json patching must preserve ^, ~, or exact pins and JSON indentation."""
        pkg_file = self.target_path / "package.json"
        original = (
            '{\n'
            '  "name": "legacy-portal",\n'
            '  "dependencies": {\n'
            '    "lodash": "^4.17.15",\n'
            '    "express": "~4.18.2",\n'
            '    "minimist": "1.2.5"\n'
            '  }\n'
            '}\n'
        )
        pkg_file.write_text(original, encoding="utf-8")

        patched, res1 = self.patcher.patch_manifest(
            pkg_file,
            original,
            {"package": "lodash", "fixed_version": "4.17.21"},
        )
        self.assertTrue(res1.changed)
        self.assertIn('"lodash": "^4.17.21"', patched)
        self.assertEqual(res1.operator_preserved, "^")

        patched2, res2 = self.patcher.patch_manifest(
            pkg_file,
            patched,
            {"package": "express", "fixed_version": "4.19.2"},
        )
        self.assertTrue(res2.changed)
        self.assertIn('"express": "~4.19.2"', patched2)
        self.assertEqual(res2.operator_preserved, "~")

        patched3, res3 = self.patcher.patch_manifest(
            pkg_file,
            patched2,
            {"package": "minimist", "fixed_version": "1.2.6"},
        )
        self.assertTrue(res3.changed)
        self.assertIn('"minimist": "1.2.6"', patched3)
        self.assertEqual(res3.operator_preserved, "")

    def test_patch_requirements_txt_and_pyproject_toml(self) -> None:
        """PyPI manifests (requirements.txt and pyproject.toml) must preserve operators and comments."""
        req_file = self.target_path / "requirements.txt"
        req_content = (
            "# Core backend dependencies\n"
            "requests==2.31.0  # HTTP client\n"
            "urllib3>=2.0.2\n"
            "Flask_Cors~=3.0.10\n"
        )
        req_file.write_text(req_content, encoding="utf-8")

        patched_req, res_req = self.patcher.patch_manifest(
            req_file,
            req_content,
            {"package": "requests", "fixed_version": "2.32.0"},
        )
        self.assertTrue(res_req.changed)
        self.assertIn("requests==2.32.0  # HTTP client", patched_req)

        patched_req2, res_req2 = self.patcher.patch_manifest(
            req_file,
            patched_req,
            {"package": "urllib3", "fixed_version": "2.0.7"},
        )
        self.assertTrue(res_req2.changed)
        self.assertIn("urllib3>=2.0.7", patched_req2)

        # pyproject.toml (both PEP 621 and Poetry)
        pyproj_file = self.target_path / "pyproject.toml"
        pyproj_content = (
            '[project]\n'
            'dependencies = [\n'
            '    "cryptography>=41.0.0",\n'
            '    "jinja2==3.1.2",\n'
            ']\n\n'
            '[tool.poetry.dependencies]\n'
            'werkzeug = "^3.0.1"\n'
        )
        pyproj_file.write_text(pyproj_content, encoding="utf-8")

        p1, r1 = self.patcher.patch_manifest(
            pyproj_file,
            pyproj_content,
            {"package": "cryptography", "fixed_version": "42.0.4"},
        )
        self.assertTrue(r1.changed)
        self.assertIn('"cryptography>=42.0.4"', p1)

        p2, r2 = self.patcher.patch_manifest(
            pyproj_file,
            p1,
            {"package": "werkzeug", "fixed_version": "3.0.3"},
        )
        self.assertTrue(r2.changed)
        self.assertIn('werkzeug = "^3.0.3"', p2)

    def test_patch_csproj_inline_and_nested(self) -> None:
        """.csproj NuGet PackageReference must support both inline Version attribute and nested <Version> tag."""
        csproj_file = self.target_path / "App.csproj"
        csproj_content = (
            '<Project Sdk="Microsoft.NET.Sdk.Web">\n'
            '  <ItemGroup>\n'
            '    <PackageReference Include="Newtonsoft.Json" Version="12.0.3" />\n'
            '    <PackageReference Include="System.Text.Json">\n'
            '      <Version>8.0.1</Version>\n'
            '    </PackageReference>\n'
            '  </ItemGroup>\n'
            '</Project>\n'
        )
        csproj_file.write_text(csproj_content, encoding="utf-8")

        p1, r1 = self.patcher.patch_manifest(
            csproj_file,
            csproj_content,
            {"package": "Newtonsoft.Json", "fixed_version": "13.0.1"},
        )
        self.assertTrue(r1.changed)
        self.assertIn('<PackageReference Include="Newtonsoft.Json" Version="13.0.1" />', p1)

        p2, r2 = self.patcher.patch_manifest(
            csproj_file,
            p1,
            {"package": "System.Text.Json", "fixed_version": "8.0.4"},
        )
        self.assertTrue(r2.changed)
        self.assertIn("<Version>8.0.4</Version>", p2)

    def test_patch_pom_xml_direct_and_property(self) -> None:
        """pom.xml patching must update direct <version> tags as well as ${property} references."""
        pom_file = self.target_path / "pom.xml"
        pom_content = (
            '<project>\n'
            '  <properties>\n'
            '    <log4j.version>2.14.1</log4j.version>\n'
            '  </properties>\n'
            '  <dependencies>\n'
            '    <dependency>\n'
            '      <groupId>org.apache.logging.log4j</groupId>\n'
            '      <artifactId>log4j-core</artifactId>\n'
            '      <version>${log4j.version}</version>\n'
            '    </dependency>\n'
            '    <dependency>\n'
            '      <groupId>org.yaml</groupId>\n'
            '      <artifactId>snakeyaml</artifactId>\n'
            '      <version>1.33</version>\n'
            '    </dependency>\n'
            '  </dependencies>\n'
            '</project>\n'
        )
        pom_file.write_text(pom_content, encoding="utf-8")

        # 1. Property-backed dependency version
        p1, r1 = self.patcher.patch_manifest(
            pom_file,
            pom_content,
            {"package": "org.apache.logging.log4j:log4j-core", "fixed_version": "2.17.1"},
        )
        self.assertTrue(r1.changed)
        self.assertIn("<log4j.version>2.17.1</log4j.version>", p1)

        # 2. Direct <version> tag
        p2, r2 = self.patcher.patch_manifest(
            pom_file,
            p1,
            {"package": "org.yaml:snakeyaml", "fixed_version": "2.0"},
        )
        self.assertTrue(r2.changed)
        self.assertIn("<version>2.0</version>", p2)

    def test_patch_build_gradle_and_go_mod(self) -> None:
        """build.gradle.kts and go.mod must upgrade versions cleanly."""
        gradle_file = self.target_path / "build.gradle.kts"
        gradle_content = (
            'dependencies {\n'
            '    implementation("com.fasterxml.jackson.core:jackson-databind:2.13.1")\n'
            '}\n'
        )
        gradle_file.write_text(gradle_content, encoding="utf-8")

        pg, rg = self.patcher.patch_manifest(
            gradle_file,
            gradle_content,
            {"package": "com.fasterxml.jackson.core:jackson-databind", "fixed_version": "2.13.4.2"},
        )
        self.assertTrue(rg.changed)
        self.assertIn('implementation("com.fasterxml.jackson.core:jackson-databind:2.13.4.2")', pg)

        gomod_file = self.target_path / "go.mod"
        gomod_content = (
            "module example.com/legacy\n\n"
            "go 1.21\n\n"
            "require (\n"
            "\tgolang.org/x/net v0.17.0\n"
            ")\n"
        )
        gomod_file.write_text(gomod_content, encoding="utf-8")

        pm, rm = self.patcher.patch_manifest(
            gomod_file,
            gomod_content,
            {"package": "golang.org/x/net", "fixed_version": "v0.23.0"},
        )
        self.assertTrue(rm.changed)
        self.assertIn("\tgolang.org/x/net v0.23.0\n", pm)

    def test_trivy_sarif_parsing_and_remediation(self) -> None:
        """RemediationRunner must parse Trivy SARIF reports and patch vulnerable manifests."""
        pkg_file = self.target_path / "package.json"
        pkg_file.write_text('{\n  "dependencies": {\n    "lodash": "^4.17.15"\n  }\n}\n', encoding="utf-8")

        trivy_sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Trivy"}},
                    "results": [
                        {
                            "ruleId": "CVE-2021-23337",
                            "level": "error",
                            "message": {
                                "text": "Package: lodash\nInstalled Version: 4.17.15\nVulnerability CVE-2021-23337\nSeverity: HIGH\nFixed Version: 4.17.21"
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "package.json"},
                                        "region": {"startLine": 3},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        sarif_path = self.target_path / "trivy.sarif"
        sarif_path.write_text(json.dumps(trivy_sarif), encoding="utf-8")

        runner = RemediationRunner(target_dir=self.target_path, findings_path=sarif_path, dry_run=False)
        report = runner.run()

        self.assertEqual(report.total_findings, 1)
        self.assertEqual(report.applied_count, 1)
        self.assertIn('"lodash": "^4.17.21"', pkg_file.read_text(encoding="utf-8"))

    def test_cli_fix_with_sca_flag_across_multiple_manifests(self) -> None:
        """`komainu fix <target> --sca` must scan manifests using built-in CVE catalog and apply upgrades."""
        (self.target_path / "package.json").write_text(
            '{\n  "dependencies": {\n    "lodash": "^4.17.15",\n    "express": "^4.18.2"\n  }\n}\n',
            encoding="utf-8",
        )
        (self.target_path / "requirements.txt").write_text(
            "requests==2.31.0\nurllib3>=2.0.2\n",
            encoding="utf-8",
        )

        # 1. Test dry-run with JSON output via CLI
        out_dry = io.StringIO()
        with redirect_stdout(out_dry):
            code_dry = main(["fix", str(self.target_path), "--sca", "--dry-run", "--format", "json"])
        self.assertEqual(code_dry, 0)
        dry_data = json.loads(out_dry.getvalue())
        self.assertEqual(dry_data["total_findings"], 4)
        self.assertEqual(dry_data["planned_count"], 4)
        self.assertEqual(dry_data["applied_count"], 0)

        # Verify files untouched after dry-run
        self.assertIn('"lodash": "^4.17.15"', (self.target_path / "package.json").read_text(encoding="utf-8"))

        # 2. Test in-place apply via CLI
        out_apply = io.StringIO()
        with redirect_stdout(out_apply):
            code_apply = main(["fix", str(self.target_path), "--sca", "--format", "json"])
        self.assertEqual(code_apply, 0)
        apply_data = json.loads(out_apply.getvalue())
        self.assertEqual(apply_data["applied_count"], 4)

        patched_pkg = (self.target_path / "package.json").read_text(encoding="utf-8")
        self.assertIn('"lodash": "^4.17.21"', patched_pkg)
        self.assertIn('"express": "^4.19.2"', patched_pkg)

        patched_req = (self.target_path / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn("requests==2.32.0", patched_req)
        self.assertIn("urllib3>=2.0.7", patched_req)

    def test_devsecops_sca_feeds_directly_into_komainu_fix(self) -> None:
        """DevSecOpsPipeline.run_sca() must emit sca.sarif that `komainu fix` auto-discovers and patches."""
        (self.target_path / "go.mod").write_text(
            "module app\n\ngo 1.21\n\nrequire golang.org/x/net v0.17.0\n",
            encoding="utf-8",
        )
        pipeline = DevSecOpsPipeline(target_dir=str(self.target_path))
        sca_res = pipeline.run_sca()
        self.assertGreaterEqual(sca_res["findings_count"], 1)

        # Now run RemediationRunner without explicit --findings or --sca; it auto-discovers .komainu-devsecops/sca.sarif
        runner = RemediationRunner(target_dir=self.target_path, dry_run=False)
        report = runner.run()
        self.assertEqual(report.applied_count, 1)
        self.assertIn("golang.org/x/net v0.23.0", (self.target_path / "go.mod").read_text(encoding="utf-8"))

    def test_patch_all_lockfile_formats_directly(self) -> None:
        """All 7 lockfile formats must upgrade versions and resolved URLs cleanly."""
        # 1. package-lock.json (v3 format)
        pkg_lock = self.target_path / "package-lock.json"
        pkg_lock_content = (
            '{\n'
            '  "name": "portal",\n'
            '  "lockfileVersion": 3,\n'
            '  "packages": {\n'
            '    "": {\n'
            '      "dependencies": {\n'
            '        "lodash": "^4.17.15"\n'
            '      }\n'
            '    },\n'
            '    "node_modules/lodash": {\n'
            '      "version": "4.17.15",\n'
            '      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"\n'
            '    }\n'
            '  }\n'
            '}\n'
        )
        p_npmlock, r_npmlock = self.patcher.patch_manifest(
            pkg_lock,
            pkg_lock_content,
            {"package": "lodash", "fixed_version": "4.17.21"},
        )
        self.assertTrue(r_npmlock.changed)
        self.assertIn('"version": "4.17.21"', p_npmlock)
        self.assertIn("lodash-4.17.21.tgz", p_npmlock)
        self.assertIn('"lodash": "^4.17.21"', p_npmlock)

        # 2. yarn.lock
        yarn_lock = self.target_path / "yarn.lock"
        yarn_content = (
            'lodash@^4.17.15:\n'
            '  version "4.17.15"\n'
            '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.15.tgz#b44b3662"\n'
        )
        p_yarn, r_yarn = self.patcher.patch_manifest(
            yarn_lock,
            yarn_content,
            {"package": "lodash", "fixed_version": "4.17.21"},
        )
        self.assertTrue(r_yarn.changed)
        self.assertIn('version "4.17.21"', p_yarn)
        self.assertIn("lodash-4.17.21.tgz", p_yarn)

        # 3. Pipfile.lock
        pip_lock = self.target_path / "Pipfile.lock"
        pip_content = (
            '{\n'
            '  "default": {\n'
            '    "requests": {\n'
            '      "version": "==2.31.0"\n'
            '    }\n'
            '  }\n'
            '}\n'
        )
        p_pip, r_pip = self.patcher.patch_manifest(
            pip_lock,
            pip_content,
            {"package": "requests", "fixed_version": "2.32.0"},
        )
        self.assertTrue(r_pip.changed)
        self.assertIn('"version": "==2.32.0"', p_pip)

        # 4. poetry.lock
        poetry_lock = self.target_path / "poetry.lock"
        poetry_content = (
            '[[package]]\n'
            'name = "urllib3"\n'
            'version = "2.0.2"\n'
            'description = "HTTP library"\n'
        )
        p_poet, r_poet = self.patcher.patch_manifest(
            poetry_lock,
            poetry_content,
            {"package": "urllib3", "fixed_version": "2.0.7"},
        )
        self.assertTrue(r_poet.changed)
        self.assertIn('version = "2.0.7"', p_poet)

        # 5. packages.lock.json (NuGet)
        nuget_lock = self.target_path / "packages.lock.json"
        nuget_content = (
            '{\n'
            '  "version": 1,\n'
            '  "dependencies": {\n'
            '    "net8.0": {\n'
            '      "Newtonsoft.Json": {\n'
            '        "type": "Direct",\n'
            '        "requested": "[12.0.3, )",\n'
            '        "resolved": "12.0.3"\n'
            '      }\n'
            '    }\n'
            '  }\n'
            '}\n'
        )
        p_nuget, r_nuget = self.patcher.patch_manifest(
            nuget_lock,
            nuget_content,
            {"package": "Newtonsoft.Json", "fixed_version": "13.0.1"},
        )
        self.assertTrue(r_nuget.changed)
        self.assertIn('"resolved": "13.0.1"', p_nuget)
        self.assertIn('"requested": "[13.0.1, )"', p_nuget)

        # 6. gradle.lockfile
        gradle_lock = self.target_path / "gradle.lockfile"
        gradle_lock_content = (
            "# This is a Gradle generated file for dependency locking.\n"
            "org.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,runtimeClasspath\n"
            "empty=\n"
        )
        p_grad, r_grad = self.patcher.patch_manifest(
            gradle_lock,
            gradle_lock_content,
            {"package": "org.apache.logging.log4j:log4j-core", "fixed_version": "2.17.1"},
        )
        self.assertTrue(r_grad.changed)
        self.assertIn("org.apache.logging.log4j:log4j-core:2.17.1=compileClasspath", p_grad)

        # 7. go.sum
        gosum_file = self.target_path / "go.sum"
        gosum_content = (
            "golang.org/x/net v0.17.0 h1:abc123=\n"
            "golang.org/x/net v0.17.0/go.mod h1:def456=\n"
        )
        p_gosum, r_gosum = self.patcher.patch_manifest(
            gosum_file,
            gosum_content,
            {"package": "golang.org/x/net", "fixed_version": "v0.23.0"},
        )
        self.assertTrue(r_gosum.changed)
        self.assertIn("golang.org/x/net v0.23.0 h1:abc123=", p_gosum)
        self.assertIn("golang.org/x/net v0.23.0/go.mod h1:def456=", p_gosum)

    def test_automatic_companion_lockfile_sync_on_manifest_patch(self) -> None:
        """When findings.json only references package.json or go.mod, companion lockfiles in the same dir must auto-sync."""
        (self.target_path / "package.json").write_text(
            '{\n  "dependencies": {\n    "lodash": "^4.17.15"\n  }\n}\n',
            encoding="utf-8",
        )
        (self.target_path / "package-lock.json").write_text(
            '{\n'
            '  "packages": {\n'
            '    "node_modules/lodash": {\n'
            '      "version": "4.17.15",\n'
            '      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"\n'
            '    }\n'
            '  }\n'
            '}\n',
            encoding="utf-8",
        )
        (self.target_path / "go.mod").write_text(
            "module demo\n\ngo 1.21\n\nrequire golang.org/x/net v0.17.0\n",
            encoding="utf-8",
        )
        (self.target_path / "go.sum").write_text(
            "golang.org/x/net v0.17.0 h1:xyz=\ngolang.org/x/net v0.17.0/go.mod h1:uvw=\n",
            encoding="utf-8",
        )

        # Findings report ONLY mentions package.json and go.mod
        findings_file = self.target_path / "findings.json"
        findings_file.write_text(
            json.dumps({
                "findings": [
                    {
                        "finding_id": "CVE-2021-23337",
                        "category": "dependency",
                        "package": "lodash",
                        "fixed_version": "4.17.21",
                        "location": {"file": "package.json", "start_line": 3},
                    },
                    {
                        "finding_id": "CVE-2023-45288",
                        "category": "dependency",
                        "package": "golang.org/x/net",
                        "fixed_version": "v0.23.0",
                        "location": {"file": "go.mod", "start_line": 5},
                    },
                ]
            }),
            encoding="utf-8",
        )

        runner = RemediationRunner(target_dir=self.target_path, findings_path=findings_file, dry_run=False)
        report = runner.run()

        # 2 manifest patches + 2 companion lockfile patches = 4 applied plans
        self.assertEqual(report.applied_count, 4)
        self.assertIn('"lodash": "^4.17.21"', (self.target_path / "package.json").read_text(encoding="utf-8"))
        self.assertIn("lodash-4.17.21.tgz", (self.target_path / "package-lock.json").read_text(encoding="utf-8"))
        self.assertIn("golang.org/x/net v0.23.0", (self.target_path / "go.mod").read_text(encoding="utf-8"))
        self.assertIn("golang.org/x/net v0.23.0/go.mod", (self.target_path / "go.sum").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
