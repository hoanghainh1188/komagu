#!/usr/bin/env python3
"""Unit and Acceptance Tests for Boilerplate 5: DevSecOps, SCA & SBOM Pipeline."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from operate.cli.main import main
from operate.devsecops.pipeline import DevSecOpsPipeline
from operate.devsecops.sarif_aggregator import SARIFReportAggregator
from operate.devsecops.sbom import Component, SBOMGenerator


class TestDevSecOpsPipeline(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="komagu_devsecops_test_")

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_component_purl_generation(self) -> None:
        """Verifies Package URL (purl) complies with standard formats."""
        npm_comp = Component(name="@angular/core", version="17.0.0", ecosystem="npm")
        self.assertEqual(npm_comp.purl, "pkg:npm/@angular/core@17.0.0")

        py_comp = Component(name="Flask-Cors", version="4.0.0", ecosystem="pypi")
        self.assertEqual(py_comp.purl, "pkg:pypi/flask-cors@4.0.0")

        nuget_comp = Component(name="Newtonsoft.Json", version="13.0.3", ecosystem="nuget")
        self.assertEqual(nuget_comp.purl, "pkg:nuget/Newtonsoft.Json@13.0.3")

        maven_comp = Component(name="org.springframework.boot:spring-boot", version="3.2.0", ecosystem="maven")
        self.assertEqual(maven_comp.purl, "pkg:maven/org.springframework.boot:spring-boot@3.2.0")

        go_comp = Component(name="github.com/gin-gonic/gin", version="v1.9.1", ecosystem="golang")
        self.assertEqual(go_comp.purl, "pkg:golang/github.com/gin-gonic/gin@v1.9.1")

    def test_02_sbom_generator_multi_ecosystem_discovery(self) -> None:
        """Verifies SBOM generator discovers dependencies across npm, python, and nuget."""
        # 1. Create dummy package.json
        pkg_json = os.path.join(self.temp_dir, "package.json")
        with open(pkg_json, "w", encoding="utf-8") as f:
            json.dump({"dependencies": {"express": "^4.18.2"}, "devDependencies": {"jest": "^29.5.0"}}, f)

        # 2. Create dummy requirements.txt
        req_txt = os.path.join(self.temp_dir, "requirements.txt")
        with open(req_txt, "w", encoding="utf-8") as f:
            f.write("requests==2.31.0\nurllib3>=2.0.0\n# comment line\n")

        # 3. Create dummy .csproj
        csproj = os.path.join(self.temp_dir, "Service.csproj")
        with open(csproj, "w", encoding="utf-8") as f:
            f.write('<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Dapper" Version="2.1.28" /></ItemGroup></Project>')

        gen = SBOMGenerator(root_dir=self.temp_dir, app_name="MultiApp", app_version="2.0.0")
        components = gen.scan()

        comp_names = {c.name: c for c in components}
        self.assertIn("express", comp_names)
        self.assertEqual(comp_names["express"].ecosystem, "npm")
        self.assertEqual(comp_names["express"].version, "4.18.2")

        self.assertIn("requests", comp_names)
        self.assertEqual(comp_names["requests"].ecosystem, "pypi")
        self.assertEqual(comp_names["requests"].version, "2.31.0")

        self.assertIn("Dapper", comp_names)
        self.assertEqual(comp_names["Dapper"].ecosystem, "nuget")
        self.assertEqual(comp_names["Dapper"].version, "2.1.28")

    def test_03_cyclonedx_json_structure(self) -> None:
        """Verifies generated CycloneDX SBOM conforms to v1.5 specification."""
        gen = SBOMGenerator(root_dir=self.temp_dir, app_name="DemoApp", app_version="1.0.0")
        gen.components.append(Component(name="lodash", version="4.17.21", ecosystem="npm", license_name="MIT"))

        cdx = gen.to_cyclonedx()
        self.assertEqual(cdx["bomFormat"], "CycloneDX")
        self.assertEqual(cdx["specVersion"], "1.5")
        self.assertEqual(cdx["metadata"]["component"]["name"], "DemoApp")
        self.assertEqual(len(cdx["components"]), 1)
        self.assertEqual(cdx["components"][0]["name"], "lodash")
        self.assertEqual(cdx["components"][0]["purl"], "pkg:npm/lodash@4.17.21")

    def test_04_spdx_json_structure(self) -> None:
        """Verifies generated SPDX SBOM conforms to v2.3 specification."""
        gen = SBOMGenerator(root_dir=self.temp_dir, app_name="DemoApp", app_version="1.0.0")
        gen.components.append(Component(name="pytest", version="8.0.0", ecosystem="pypi", license_name="MIT"))

        spdx = gen.to_spdx()
        self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")
        self.assertEqual(spdx["dataLicense"], "CC0-1.0")
        self.assertEqual(spdx["name"], "DemoApp-SBOM")
        self.assertTrue(len(spdx["packages"]) >= 2)  # Root package + 1 dependency
        self.assertEqual(spdx["relationships"][0]["relationshipType"], "DEPENDS_ON")

    def test_05_sarif_aggregator_deduplication(self) -> None:
        """Verifies SARIF aggregator deduplicates identical alerts and merges rules."""
        aggregator = SARIFReportAggregator()

        sarif_1 = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Scanner-A",
                            "rules": [{"id": "RULE-1", "shortDescription": {"text": "Rule 1 description"}}],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "RULE-1",
                            "level": "error",
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/App.cs"},
                                        "region": {"startLine": 42},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        # Second SARIF reporting the exact same finding at src/App.cs:42
        sarif_2 = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Scanner-B",
                            "rules": [{"id": "RULE-1", "shortDescription": {"text": "Rule 1 description"}}],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "RULE-1",
                            "level": "error",
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/App.cs"},
                                        "region": {"startLine": 42},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        count1 = aggregator.add_sarif_data(sarif_1)
        count2 = aggregator.add_sarif_data(sarif_2)

        self.assertEqual(count1, 1)
        self.assertEqual(count2, 0)  # Deduplicated!
        self.assertEqual(len(aggregator.results), 1)

        summary = aggregator.get_summary()
        self.assertEqual(summary["error"], 1)
        self.assertEqual(summary["warning"], 0)

    def test_06_native_secret_scanner_detection(self) -> None:
        """Verifies secret scanner detects private keys and tokens."""
        secret_file = os.path.join(self.temp_dir, "config.py")
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write('AWS_KEY = "AKIA1234567890ABCDEF"\n')

        pipeline = DevSecOpsPipeline(target_dir=self.temp_dir)
        res = pipeline.run_secret_detection()
        self.assertGreaterEqual(res["findings_count"], 1)

    def test_07_container_misconfiguration_scan(self) -> None:
        """Verifies container scanner flags insecure Dockerfile practices."""
        dockerfile = os.path.join(self.temp_dir, "Dockerfile")
        with open(dockerfile, "w", encoding="utf-8") as f:
            f.write("FROM node:latest\nUSER root\n")

        pipeline = DevSecOpsPipeline(target_dir=self.temp_dir)
        res = pipeline.run_container_scan()
        self.assertGreaterEqual(res["findings_count"], 2)

    def test_08_cli_devsecops_sbom_command(self) -> None:
        """Verifies CLI `komagu devsecops sbom` execution."""
        pkg_json = os.path.join(self.temp_dir, "package.json")
        with open(pkg_json, "w", encoding="utf-8") as f:
            json.dump({"dependencies": {"uuid": "^9.0.0"}}, f)

        out_sbom = os.path.join(self.temp_dir, "out-cdx.json")
        exit_code = main(["devsecops", "sbom", self.temp_dir, "--format", "cyclonedx", "-o", out_sbom])
        self.assertEqual(exit_code, 0)
        self.assertTrue(os.path.isfile(out_sbom))

        with open(out_sbom, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["bomFormat"], "CycloneDX")


if __name__ == "__main__":
    unittest.main()
