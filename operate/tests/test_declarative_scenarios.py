#!/usr/bin/env python3
"""Comprehensive unit tests for Declarative Incident Scenarios (#317).

Validates:
1. bas-scenario.schema.json schema validation on built-in and custom scenarios.
2. Discovery of scenarios from files, directories, and built-ins.
3. DeclarativeScenario execution of HTTP and storage steps.
4. Governance safety gates: draft scenarios blocked without --allow-draft.
5. Destructive step safety gates: destructive steps blocked without --allow-destructive.
6. Parameter substitutions and CLI --set overrides.
7. METI SCS audit evidence generation (#271).
8. CLI commands: --list, --validate, --scenario-file, --evidence.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from operate.cli.main import main as cli_main
from operate.cross_user_tester.mock_test_server import start_mock_server
from operate.simulate.engine import (
    DeclarativeScenario,
    generate_execution_evidence,
)
from operate.simulate.loader import (
    BUILTIN_SCENARIOS_DIR,
    discover_scenarios,
    load_scenario_file,
    load_validator,
    validate_scenario,
)


class TestDeclarativeScenarios(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server, cls.thread, cls.base_url = start_mock_server(port=0)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.server_close()

    def test_schema_validates_builtin_scenarios(self) -> None:
        """All 3 built-in scenario files must strictly conform to bas-scenario.schema.json."""
        validator = load_validator("bas-scenario.schema.json")
        for sc_name in ["times-car-breach.json", "metabase-cve-2026-72898.json", "idc-frontier-ransomware.json"]:
            path = BUILTIN_SCENARIOS_DIR / sc_name
            self.assertTrue(path.is_file(), f"Missing built-in scenario: {sc_name}")
            data = load_scenario_file(path)
            errs = validator(data)
            self.assertEqual(errs, [], f"Validation errors for {sc_name}: {errs}")

    def test_schema_validation_error_on_invalid_scenario(self) -> None:
        """Validator must report missing required properties."""
        invalid_data = {
            "id": "invalid-scenario",
            "title": "Invalid",
            # missing status, version, incident, mappings, etc.
        }
        errs = validate_scenario(invalid_data)
        self.assertTrue(len(errs) > 0)
        self.assertTrue(any("required property missing" in e or "is a required property" in e for e in errs))

    def test_discovery_scenarios(self) -> None:
        """discover_scenarios must locate all built-in scenarios and custom ones."""
        scenarios = discover_scenarios(include_builtins=True)
        self.assertIn("times-car-breach", scenarios)
        self.assertIn("metabase-cve-2026-72898", scenarios)
        self.assertIn("idc-frontier-ransomware", scenarios)

        # Test custom dir discovery
        with tempfile.TemporaryDirectory() as tmp_dir:
            custom_path = Path(tmp_dir) / "custom-sc.json"
            base_sc = dict(scenarios["times-car-breach"])
            base_sc["id"] = "custom-test-scenario"
            custom_path.write_text(json.dumps(base_sc), encoding="utf-8")

            discovered = discover_scenarios(scenario_dirs=[tmp_dir], include_builtins=False)
            self.assertIn("custom-test-scenario", discovered)

    def test_draft_scenario_blocked_without_override(self) -> None:
        """Scenario with status != 'approved' must fail execution unless allow_draft is set."""
        data = dict(load_scenario_file(BUILTIN_SCENARIOS_DIR / "times-car-breach.json"))
        data["status"] = "draft"
        runner = DeclarativeScenario(data, self.base_url, allow_draft=False)
        with self.assertRaises(PermissionError):
            runner.run()

        # Overriding with allow_draft=True must succeed
        runner_override = DeclarativeScenario(data, self.base_url, allow_draft=True)
        res = runner_override.run()
        self.assertIsNotNone(res)

    def test_destructive_step_blocked_without_override(self) -> None:
        """Destructive steps must be skipped unless allow_destructive is set."""
        data = dict(load_scenario_file(BUILTIN_SCENARIOS_DIR / "times-car-breach.json"))
        data["steps"] = [dict(data["steps"][0])]
        data["steps"][0]["destructive"] = True

        runner_safe = DeclarativeScenario(data, self.base_url, allow_destructive=False)
        res_safe = runner_safe.run()
        self.assertTrue(any(d.get("skipped") for d in res_safe.details))

        runner_destr = DeclarativeScenario(data, self.base_url, allow_destructive=True)
        res_destr = runner_destr.run()
        self.assertFalse(any(d.get("skipped") for d in res_destr.details))

    def test_parameter_override_and_substitution(self) -> None:
        """Custom parameter overrides must take precedence over defaults."""
        data = load_scenario_file(BUILTIN_SCENARIOS_DIR / "times-car-breach.json")
        runner = DeclarativeScenario(
            data,
            self.base_url,
            param_overrides={
                "endpoint_pattern": "/api/orders/{id}",
                "sample_ids": ["999"],
            },
        )
        res = runner.run()
        self.assertEqual(res.total_attempts, 1)
        self.assertTrue(res.passed)

    def test_evidence_generation(self) -> None:
        """generate_execution_evidence produces complete audit record conforming to METI SCS."""
        data = load_scenario_file(BUILTIN_SCENARIOS_DIR / "times-car-breach.json")
        runner = DeclarativeScenario(data, self.base_url)
        res = runner.run()

        with tempfile.TemporaryDirectory() as tmp_dir:
            ev_path = Path(tmp_dir) / "evidence.json"
            ev = generate_execution_evidence([runner], [res], self.base_url, output_path=ev_path)
            self.assertTrue(ev_path.is_file())
            self.assertEqual(ev["evidence_type"], "breach_and_attack_simulation_audit")
            self.assertEqual(len(ev["audit_records"]), 1)
            self.assertTrue(ev["audit_records"][0]["scenario_hash"].startswith("sha256:"))

    def test_cli_list_and_validate(self) -> None:
        """Test CLI flags --list and --validate."""
        # --list
        exit_code = cli_main(["simulate", "--list"])
        self.assertEqual(exit_code, 0)

        # --validate valid
        valid_file = str(BUILTIN_SCENARIOS_DIR / "times-car-breach.json")
        exit_code = cli_main(["simulate", "--validate", valid_file])
        self.assertEqual(exit_code, 0)

        # --validate invalid
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{\"id\": \"incomplete\"}")
            inv_file = f.name
        try:
            exit_code = cli_main(["simulate", "--validate", inv_file])
            self.assertEqual(exit_code, 2)
        finally:
            os.unlink(inv_file)


if __name__ == "__main__":
    unittest.main()
