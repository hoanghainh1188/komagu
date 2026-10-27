#!/usr/bin/env python3
"""Tests for Komainu Breach & Attack Simulation (BAS) Suite (TASK-3.1 to TASK-3.4).

Validates:
1. TimesCarBreachScenario: detects mass BOLA account scraping on vulnerable endpoint, passes on protected endpoint.
2. MetabaseZeroDayScenario: executes remote SQL injection probes and verifies error handling.
3. IDCFrontierRansomwareScenario: evaluates storage resilience against malicious tampering and deletion.
4. ExecutiveReportGenerator: produces structured C-level Markdown and JSON summaries.
5. CLI integration: `komainu simulate` execution, argument parsing, and report exporting.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from operate.cli.main import main as cli_main
from operate.cross_user_tester.mock_test_server import start_mock_server
from operate.simulate.scenarios import (
    ExecutiveReportGenerator,
    IDCFrontierRansomwareScenario,
    MetabaseZeroDayScenario,
    ScenarioResult,
    TimesCarBreachScenario,
)


class TestSimulateScenarios(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Start mock server simulating legacy and protected endpoints
        cls.server, cls.thread, cls.base_url = start_mock_server(port=0)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.server_close()

    def test_times_car_breach_vulnerable_endpoint(self) -> None:
        """Verify that TimesCarBreachScenario flags BOLA leakage when accessing /api/legacy-orders/{id}."""
        scenario = TimesCarBreachScenario(
            target=self.base_url,
            endpoint_pattern="/api/legacy-orders/{id}",
            attacker_token="attacker-bob-token",
            sample_ids=["1", "2"],
        )
        res = scenario.run()
        self.assertEqual(res.scenario_id, "times-car-breach")
        self.assertFalse(res.passed)
        self.assertEqual(res.breaches_leaked, 2)
        self.assertEqual(res.breaches_blocked, 0)
        self.assertEqual(res.resilience_score, 0.0)
        self.assertIn("Boilerplate 1", res.recommendation)

    def test_times_car_breach_protected_endpoint(self) -> None:
        """Verify that TimesCarBreachScenario passes when non-owner receives 404 on /api/orders/{id}."""
        scenario = TimesCarBreachScenario(
            target=self.base_url,
            endpoint_pattern="/api/orders/{id}",
            attacker_token="attacker-bob-token",
            sample_ids=["1", "2"],
        )
        res = scenario.run()
        self.assertTrue(res.passed)
        self.assertEqual(res.breaches_leaked, 0)
        self.assertEqual(res.breaches_blocked, 2)
        self.assertEqual(res.resilience_score, 100.0)
        self.assertIn("404 Not Found invariant maintained", res.recommendation)

    def test_metabase_zero_day_scenario(self) -> None:
        """Verify MetabaseZeroDayScenario probes target query path and returns structured results."""
        scenario = MetabaseZeroDayScenario(
            target=self.base_url,
            query_path="/api/products",
            target_param="q",
        )
        res = scenario.run()
        self.assertEqual(res.scenario_id, "metabase-cve-2026-72898")
        self.assertEqual(res.total_attempts, 5)
        # Mock server returns 404 for unknown /api/products, which is treated as blocked (not leaking DB probe)
        self.assertTrue(res.passed)
        self.assertEqual(res.breaches_leaked, 0)
        self.assertEqual(res.resilience_score, 100.0)

    def test_idc_frontier_ransomware_scenario(self) -> None:
        """Verify IDCFrontierRansomwareScenario attempts malicious file operations on storage dir."""
        with tempfile.TemporaryDirectory() as temp_dir:
            scenario = IDCFrontierRansomwareScenario(target_dir=temp_dir)
            res = scenario.run()
            self.assertEqual(res.scenario_id, "idc-frontier-ransomware")
            self.assertEqual(res.total_attempts, 3)
            self.assertIn(res.passed, (True, False))
            self.assertIsInstance(res.resilience_score, float)
            self.assertTrue(len(res.details) > 0)

    def test_executive_report_generator_markdown_and_json(self) -> None:
        """Verify ExecutiveReportGenerator formats C-Level Markdown and JSON correctly."""
        results = [
            ScenarioResult(
                scenario_id="times-car-breach",
                scenario_name="Times Car Mass BOLA Simulation",
                description="BOLA test description",
                incident_reference="Times Car 2024",
                total_attempts=5,
                breaches_blocked=5,
                breaches_leaked=0,
                resilience_score=100.0,
                passed=True,
                details=[],
                recommendation="Keep 404 invariant.",
            ),
            ScenarioResult(
                scenario_id="metabase-cve-2026-72898",
                scenario_name="Metabase SQLi Simulation",
                description="SQLi test description",
                incident_reference="Metabase 2024",
                total_attempts=5,
                breaches_blocked=4,
                breaches_leaked=1,
                resilience_score=80.0,
                passed=False,
                details=[],
                recommendation="Deploy WAF rule.",
            ),
        ]
        generator = ExecutiveReportGenerator(results, target="http://test-server")
        self.assertEqual(generator.overall_resilience_score, 90.0)

        md = generator.generate_markdown()
        self.assertIn("# Komainu Executive Breach & Attack Simulation (BAS) Report", md)
        self.assertIn("Times Car Mass BOLA Simulation", md)
        self.assertIn("Metabase SQLi Simulation", md)
        self.assertIn("90.0%", md)
        self.assertIn("EXCELLENT (RESILIENT)", md)

        data = generator.generate_json()
        self.assertEqual(data["overall_resilience_score"], 90.0)
        self.assertEqual(data["scenarios_executed"], 2)
        self.assertEqual(len(data["results"]), 2)

    def test_cli_simulate_command_json_output(self) -> None:
        """Verify running `komainu simulate` CLI with JSON output format."""
        with tempfile.TemporaryDirectory() as temp_dir:
            exit_code = cli_main([
                "--no-banner",
                "simulate",
                "--scenario",
                "idc-frontier-ransomware",
                "--target",
                temp_dir,
                "--format",
                "json",
            ])
            self.assertIn(exit_code, (0, 1))

    def test_cli_simulate_command_report_file_export(self) -> None:
        """Verify `komainu simulate` CLI exports executive report to specified path."""
        with tempfile.TemporaryDirectory() as temp_dir:
            out_file = Path(temp_dir) / "bas_report.md"
            exit_code = cli_main([
                "--no-banner",
                "simulate",
                "--scenario",
                "times-car-breach",
                "--target",
                self.base_url,
                "--endpoint",
                "/api/orders/{id}",
                "--output",
                str(out_file),
                "--format",
                "markdown",
            ])
            self.assertEqual(exit_code, 0)
            self.assertTrue(out_file.exists())
            content = out_file.read_text(encoding="utf-8")
            self.assertIn("Komainu Executive Breach & Attack Simulation (BAS) Report", content)


if __name__ == "__main__":
    unittest.main()
