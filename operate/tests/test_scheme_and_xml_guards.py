#!/usr/bin/env python3
"""Guards behind the Bandit B310 / B314 suppressions (#385).

Each `# nosec` added for #385 relies on a check: outbound requests only use
http(s) URLs, and SBOM manifests with a DTD are not parsed.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from operate.ai.client import LLMClient
from operate.cross_user_tester.runner import CrossUserTestRunner, TestCase
from operate.devsecops.sbom import SBOMGenerator
from operate.simulate.scenarios import MetabaseZeroDayScenario, TimesCarBreachScenario

CSPROJ = '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Dapper" Version="2.1.28" /></ItemGroup></Project>'
CSPROJ_WITH_DTD = (
    '<?xml version="1.0"?>\n<!DOCTYPE Project [<!ENTITY a "aaaaaaaaaa">]>\n'
    '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="&a;" Version="1.0.0" /></ItemGroup></Project>'
)


class TestHttpOnlyUrls(unittest.TestCase):
    def test_llm_client_accepts_http_and_https(self) -> None:
        self.assertEqual(LLMClient("http://127.0.0.1:11434/v1").endpoint, "http://127.0.0.1:11434/v1/chat/completions")
        self.assertEqual(LLMClient("https://llm.example/v1/chat/completions").endpoint, "https://llm.example/v1/chat/completions")

    def test_llm_client_rejects_other_schemes(self) -> None:
        for endpoint in ("file:///etc/passwd", "ftp://host/v1", "127.0.0.1:11434/v1"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                LLMClient(endpoint)

    def test_scenarios_reject_other_schemes(self) -> None:
        for scenario in (TimesCarBreachScenario, MetabaseZeroDayScenario):
            with self.subTest(scenario=scenario.__name__), self.assertRaises(ValueError):
                scenario("file:///etc")

    def test_bearer_runner_does_not_open_other_schemes(self) -> None:
        res = CrossUserTestRunner("file://").execute_test(TestCase("t", "/etc/passwd", "GET"))
        self.assertFalse(res.is_secure or res.is_breach)
        self.assertEqual(res.status_code, 0)
        self.assertIn("http", res.error_message or "")


class TestSbomRefusesDtd(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="komagu_sbom_dtd_")
        self.addCleanup(shutil.rmtree, self.root, True)

    def _scan(self, content: str) -> list:
        with open(os.path.join(self.root, "Service.csproj"), "w", encoding="utf-8") as handle:
            handle.write(content)
        return [c.name for c in SBOMGenerator(root_dir=self.root).scan()]

    def test_plain_manifest_is_parsed(self) -> None:
        self.assertIn("Dapper", self._scan(CSPROJ))

    def test_manifest_with_dtd_is_skipped(self) -> None:
        self.assertEqual(self._scan(CSPROJ_WITH_DTD), [])


if __name__ == "__main__":
    unittest.main()
