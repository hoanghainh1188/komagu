#!/usr/bin/env python3
"""SARIF input for BFLA and mass assignment in `komagu test --from-scan` and `--export-poc` (#289)."""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from operate.cli.main import main as cli_main  # noqa: E402
from operate.cross_user_tester.mock_test_server import start_mock_server  # noqa: E402
from operate.cross_user_tester.persona_matrix import generate_matrix_cases_from_findings  # noqa: E402
from operate.exploit.generator import ExploitGenerator  # noqa: E402
from operate.lsa_sarif.lsa_to_sarif import convert_findings_to_sarif  # noqa: E402
from operate.lsa_sarif.sarif_findings import findings_from_sarif  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "lsa_findings_to_sarif", PROJECT_ROOT / "assess" / "lsa" / "scripts" / "findings_to_sarif.py"
)
assert _spec and _spec.loader
lsa_findings_to_sarif = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lsa_findings_to_sarif)

ENV = {"T_USER": "user-secret-token"}

FINDINGS = {
    "findings": [
        {"finding_id": "BFLA-R-0001-1", "category": "bfla", "title": "Any user deletes accounts",
         "location": {"file": "app.py", "line": 10},
         "endpoint": {"method": "DELETE", "path": "/api/admin/users/{id}"}, "status": "confirmed",
         "consensus": {"score": 0.9}},
        {"finding_id": "MASS-M-0001-1", "category": "mass_assignment", "title": "Profile binds body",
         "location": {"file": "app.py", "line": 20},
         "endpoint": {"method": "PUT", "path": "/api/profile"},
         "attack_vector": {"fields": {"role": "admin"}, "readback": "GET /api/profile",
                           "suggested_payload": "{\"role\": \"admin\"}"},
         "status": "unverified", "consensus": {"score": 0.6}},
        {"finding_id": "BFLA-R-0002-1", "category": "bfla", "title": "Rejected one",
         "location": {"file": "app.py", "line": 30},
         "endpoint": {"method": "DELETE", "path": "/api/x"}, "status": "rejected"},
        {"finding_id": "BOLA-R-0003-1", "category": "bola", "title": "Not ours",
         "location": {"file": "app.py", "line": 40},
         "endpoint": {"method": "GET", "path": "/api/orders/{id}"}},
    ]
}


def case_key(c):
    return (c.kind, c.finding_id, c.method, c.path, c.probe_fields, c.readback)


def sarif_from_assess(doc):
    return lsa_findings_to_sarif.to_sarif(copy.deepcopy(doc), include_rejected=True)


def sarif_from_operate(doc):
    return convert_findings_to_sarif(copy.deepcopy(doc["findings"]))


class TestSarifMatrixCases(unittest.TestCase):
    def test_both_exporters_give_the_same_cases_as_findings_json(self):
        expected = [case_key(c) for c in generate_matrix_cases_from_findings(FINDINGS, "T_USER", default_id="7")]
        self.assertEqual([k[1] for k in expected], ["BFLA-R-0001-1", "MASS-M-0001-1"])
        for export in (sarif_from_assess, sarif_from_operate):
            with self.subTest(exporter=export.__name__):
                cases = generate_matrix_cases_from_findings(export(FINDINGS), "T_USER", default_id="7")
                self.assertEqual([case_key(c) for c in cases], expected)

    def test_min_consensus_applies_to_sarif(self):
        cases = generate_matrix_cases_from_findings(sarif_from_assess(FINDINGS), "T_USER", min_consensus=0.8)
        self.assertEqual([c.finding_id for c in cases], ["BFLA-R-0001-1"])

    def test_suggested_payload_is_not_written_to_sarif(self):
        text = json.dumps(sarif_from_assess(FINDINGS)) + json.dumps(sarif_from_operate(FINDINGS))
        self.assertNotIn("suggested_payload", text)

    def test_sarif_without_replay_properties_falls_back_to_rule_and_message(self):
        sarif = sarif_from_assess(FINDINGS)
        for result in sarif["runs"][0]["results"]:
            for key in ("finding_id", "category", "endpoint", "attack_vector", "consensus_score"):
                result["properties"].pop(key, None)
        findings = {f["finding_id"]: f for f in findings_from_sarif(sarif)}
        self.assertEqual(findings["BFLA-R-0001-1"]["category"], "bfla")
        self.assertEqual(findings["BFLA-R-0001-1"]["endpoint"], {"method": "DELETE", "path": "/api/admin/users/{id}"})
        cases = generate_matrix_cases_from_findings(sarif, "T_USER", default_id="7")
        mass = next(c for c in cases if c.kind == "mass_assignment")
        self.assertIn("role", mass.probe_fields)  # default probe fields without attack_vector
        self.assertEqual(mass.readback, ("GET", "/api/profile"))

    def test_owasp_tag_identifies_category_when_rule_id_does_not(self):
        sarif = sarif_from_assess(FINDINGS)
        run = sarif["runs"][0]
        renamed = {}
        for i, rule in enumerate(run["tool"]["driver"]["rules"]):
            renamed[rule["id"]] = f"custom-{i}"
            rule["id"] = f"custom-{i}"
        for result in run["results"]:
            result["ruleId"] = renamed[result["ruleId"]]
            result["properties"].pop("category", None)
        kinds = {f["finding_id"]: f["category"] for f in findings_from_sarif(sarif)}
        self.assertEqual(kinds["BFLA-R-0001-1"], "bfla")
        self.assertEqual(kinds["MASS-M-0001-1"], "mass_assignment")


class TestSarifPocExport(unittest.TestCase):
    def test_pocs_from_sarif_match_findings_json(self):
        gen = ExploitGenerator(base_url="http://127.0.0.1:1", default_resource_id="7")
        expected = {a.finding_id: (a.category, a.method, a.target_path) for a in gen.generate_from_findings_data(FINDINGS)}
        for export in (sarif_from_assess, sarif_from_operate):
            with self.subTest(exporter=export.__name__):
                arts = {a.finding_id: a for a in gen.generate_from_findings_data(export(FINDINGS))}
                self.assertEqual({k: (a.category, a.method, a.target_path) for k, a in arts.items()}, expected)
                self.assertIn('"role": "admin"', arts["MASS-M-0001-1"].python_script)
                self.assertNotIn("BFLA-R-0002-1", arts)


class TestCliFromScanSarif(unittest.TestCase):
    def setUp(self):
        self.server, _, self.base_url = start_mock_server(port=0)
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def test_from_scan_sarif_runs_bfla_and_mass_cases(self):
        scan = self.dir / "findings.sarif"
        scan.write_text(json.dumps(sarif_from_assess(FINDINGS)), encoding="utf-8")
        out = self.dir / "res.json"
        buf = io.StringIO()
        with mock.patch.dict(os.environ, ENV), redirect_stdout(buf):
            code = cli_main(["test", "--url", self.base_url, "--from-scan", str(scan),
                             "--token-env", "T_USER", "--resource-id", "7", "--output", str(out)])
        self.assertEqual(code, 1)
        report = json.loads(out.read_text(encoding="utf-8"))
        ids = {r["finding_id"] for r in report["matrix_results"] if r["is_breach"]}
        self.assertEqual(ids, {"BFLA-R-0001-1", "MASS-M-0001-1"})
        self.assertNotIn(ENV["T_USER"], out.read_text(encoding="utf-8") + buf.getvalue())


if __name__ == "__main__":
    unittest.main()
