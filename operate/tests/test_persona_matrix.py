#!/usr/bin/env python3
"""Tests for the persona matrix (komainu test suite v2, #269d).

Validates:
1. Suite v2 loading: tokens only from token_env, persona names checked.
2. BFLA cases: personas outside allow must be refused (401/403/404, --strict 404).
3. Mass assignment probe: privileged field stored -> breach; allow-list -> pass.
4. --from-scan for bfla / mass_assignment findings.
5. CLI end to end, JSON report without tokens, PoC export for the new classes.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from operate.cli.main import main as cli_main  # noqa: E402
from operate.cross_user_tester.mock_test_server import start_mock_server  # noqa: E402
from operate.cross_user_tester.persona_matrix import (  # noqa: E402
    PersonaMatrixRunner,
    SuiteError,
    format_matrix_report,
    generate_matrix_cases_from_findings,
    load_persona_suite,
)
from operate.exploit.generator import ExploitGenerator  # noqa: E402

ENV = {"T_USER": "token-user-b", "T_ADMIN": "token-admin"}
PERSONAS = {
    "anonymous": {},
    "user": {"token_env": "T_USER"},
    "admin": {"token_env": "T_ADMIN"},
}


def suite(*routes):
    return {"version": 2, "personas": PERSONAS, "routes": list(routes)}


VULN_ADMIN = {"method": "DELETE", "path": "/api/admin/users/{id}", "allow": ["admin"], "params": {"id": "7"}}
SAFE_ADMIN = {"method": "DELETE", "path": "/api/secure-admin/users/{id}", "allow": ["admin"], "params": {"id": "7"}}


def probe_route(path):
    return {
        "method": "PUT", "path": path, "allow": ["user", "admin"],
        "payload": {"name": "Probe"},
        "mass_assignment_probe": {"fields": {"role": "admin"}, "readback": f"GET {path}"},
    }


class TestSuiteLoading(unittest.TestCase):
    def test_denied_personas_only(self):
        cases = load_persona_suite(suite(VULN_ADMIN))
        self.assertEqual(sorted(c.persona.name for c in cases), ["anonymous", "user"])
        self.assertTrue(all(c.path == "/api/admin/users/7" for c in cases))
        self.assertTrue(all(c.kind == "bfla" for c in cases))

    def test_inline_token_rejected(self):
        bad = suite(VULN_ADMIN)
        bad["personas"] = {"user": {"token": "secret"}}
        with self.assertRaises(SuiteError) as ctx:
            load_persona_suite(bad)
        self.assertIn("token_env", str(ctx.exception))
        self.assertNotIn("secret", str(ctx.exception))

    def test_unknown_persona_in_allow(self):
        with self.assertRaises(SuiteError):
            load_persona_suite(suite({**VULN_ADMIN, "allow": ["root"]}))

    def test_version_required(self):
        with self.assertRaises(SuiteError):
            load_persona_suite({"personas": PERSONAS, "routes": [VULN_ADMIN]})

    def test_probe_needs_write_method(self):
        route = {**probe_route("/api/profile"), "method": "GET"}
        with self.assertRaises(SuiteError):
            load_persona_suite(suite(route))

    def test_probe_defaults_to_first_allowed_persona(self):
        cases = load_persona_suite(suite(probe_route("/api/profile")))
        probe = [c for c in cases if c.kind == "mass_assignment"]
        self.assertEqual(len(probe), 1)
        self.assertEqual(probe[0].persona.name, "user")
        self.assertEqual(probe[0].readback, ("GET", "/api/profile"))


    def test_unknown_route_key_rejected(self):
        with self.assertRaises(SuiteError) as ctx:
            load_persona_suite(suite({**VULN_ADMIN, "allowed": ["admin"]}))
        self.assertIn("allowed", str(ctx.exception))

    def test_schema_matches_loader(self):
        from operate.cross_user_tester import persona_matrix as pm
        schema = json.loads((PROJECT_ROOT / "contracts" / "schemas" / "persona-suite.schema.json").read_text())
        route = schema["properties"]["routes"]["items"]["properties"]
        self.assertEqual(set(route), pm._ROUTE_KEYS)
        self.assertEqual(set(route["mass_assignment_probe"]["properties"]), pm._PROBE_KEYS)
        self.assertEqual(set(schema["properties"]["personas"]["additionalProperties"]["properties"]), pm._PERSONA_KEYS)

    def test_cli_guide_example_loads(self):
        guide = (PROJECT_ROOT / "docs" / "cli-guide.md").read_text(encoding="utf-8")
        start = guide.index('```json\n{\n  "version": 2')
        block = guide[start + len("```json\n"):guide.index("```", start + 7)]
        cases = load_persona_suite(json.loads(block))
        self.assertEqual({c.kind for c in cases}, {"bfla", "mass_assignment"})


class TestMatrixAgainstMock(unittest.TestCase):
    def setUp(self):
        self.server, _, self.base_url = start_mock_server(port=0)
        self.runner = PersonaMatrixRunner(self.base_url, env=ENV)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def by_persona(self, results):
        return {r.case.persona.name: r for r in results}

    def test_bfla_breach_detected(self):
        res = self.by_persona(self.runner.run(load_persona_suite(suite(VULN_ADMIN))))
        self.assertTrue(res["user"].is_breach)
        self.assertTrue(res["anonymous"].is_secure)  # 401
        _, ok = format_matrix_report(list(res.values()))
        self.assertFalse(ok)

    def test_role_guard_passes(self):
        results = self.runner.run(load_persona_suite(suite(SAFE_ADMIN)))
        self.assertTrue(all(r.is_secure for r in results), [r.to_dict() for r in results])
        self.assertTrue(format_matrix_report(results)[1])

    def test_strict_rejects_403(self):
        runner = PersonaMatrixRunner(self.base_url, env=ENV, strict=True)
        res = self.by_persona(runner.run(load_persona_suite(suite(SAFE_ADMIN))))
        self.assertFalse(res["user"].is_secure)
        self.assertFalse(res["user"].is_breach)

    def test_missing_token_env_is_error(self):
        runner = PersonaMatrixRunner(self.base_url, env={})
        res = self.by_persona(runner.run(load_persona_suite(suite(SAFE_ADMIN))))
        self.assertIn("T_USER", res["user"].error_message)
        self.assertEqual(res["user"].status_code, 0)
        self.assertFalse(format_matrix_report(list(res.values()))[1])

    def test_mass_assignment_breach(self):
        cases = [c for c in load_persona_suite(suite(probe_route("/api/profile"))) if c.kind == "mass_assignment"]
        [r] = self.runner.run(cases)
        self.assertTrue(r.is_breach, r.to_dict())
        self.assertEqual(r.persisted_fields, ("role",))

    def test_mass_assignment_allowlist_passes(self):
        cases = [c for c in load_persona_suite(suite(probe_route("/api/safe-profile"))) if c.kind == "mass_assignment"]
        [r] = self.runner.run(cases)
        self.assertTrue(r.is_secure, r.to_dict())

    def test_probe_value_already_present_is_inconclusive(self):
        cases = [c for c in load_persona_suite(suite(probe_route("/api/profile"))) if c.kind == "mass_assignment"]
        self.runner.run(cases)  # first run stores role=admin
        [r] = self.runner.run(cases)
        self.assertFalse(r.is_breach)
        self.assertFalse(r.is_secure)
        self.assertIn("inconclusive", r.error_message)

    def test_result_never_contains_token(self):
        results = self.runner.run(load_persona_suite(suite(VULN_ADMIN, probe_route("/api/profile"))))
        dumped = json.dumps([r.to_dict() for r in results])
        for token in ENV.values():
            self.assertNotIn(token, dumped)


FINDINGS = {
    "findings": [
        {"finding_id": "BFLA-R-0001-1", "category": "bfla", "title": "Any user deletes accounts",
         "endpoint": {"method": "DELETE", "path": "/api/admin/users/{id}"}, "status": "confirmed"},
        {"finding_id": "MASS-M-0001-1", "category": "mass_assignment", "title": "Profile binds body",
         "endpoint": {"method": "PUT", "path": "/api/profile"},
         "attack_vector": {"fields": {"role": "admin"}, "readback": "GET /api/profile"}, "status": "unverified"},
        {"finding_id": "BFLA-R-0002-1", "category": "bfla", "title": "Rejected one",
         "endpoint": {"method": "DELETE", "path": "/api/x"}, "status": "rejected"},
        {"finding_id": "BOLA-R-0003-1", "category": "bola", "title": "Not ours",
         "endpoint": {"method": "GET", "path": "/api/orders/{id}"}},
    ]
}


class TestFromScan(unittest.TestCase):
    def test_cases_from_findings(self):
        cases = generate_matrix_cases_from_findings(FINDINGS, token_env="T_USER", default_id="7")
        self.assertEqual([(c.kind, c.finding_id) for c in cases],
                         [("bfla", "BFLA-R-0001-1"), ("mass_assignment", "MASS-M-0001-1")])
        self.assertEqual(cases[0].path, "/api/admin/users/7")
        self.assertEqual(cases[1].probe_fields, {"role": "admin"})

    def test_mass_without_fields_uses_default(self):
        f = {"finding_id": "MASS-1", "category": "mass_assignment", "endpoint": {"method": "POST|PUT", "path": "/p"}}
        [c] = generate_matrix_cases_from_findings([f], token_env="T_USER")
        self.assertEqual(c.method, "POST")
        self.assertIn("role", c.probe_fields)
        self.assertEqual(c.readback, ("GET", "/p"))


class TestCli(unittest.TestCase):
    def setUp(self):
        self.server, _, self.base_url = start_mock_server(port=0)
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def run_cli(self, argv, env=ENV):
        import os
        from unittest import mock
        buf = io.StringIO()
        with mock.patch.dict(os.environ, env), redirect_stdout(buf):
            code = cli_main(argv)
        return code, buf.getvalue()

    def write(self, name, data):
        p = self.dir / name
        p.write_text(json.dumps(data), encoding="utf-8")
        return str(p)

    def test_v2_suite_breach_exit_1(self):
        out = self.dir / "res.json"
        code, text = self.run_cli(["test", "--url", self.base_url,
                                   "--suite", self.write("s.json", suite(VULN_ADMIN, probe_route("/api/profile"))),
                                   "--output", str(out)])
        self.assertEqual(code, 1)
        report = json.loads(out.read_text())
        cats = {r["category"] for r in report["matrix_results"] if r["is_breach"]}
        self.assertEqual(cats, {"bfla", "mass_assignment"})
        for token in ENV.values():
            self.assertNotIn(token, out.read_text())
            self.assertNotIn(token, text)

    def test_v2_suite_secure_exit_0(self):
        code, _ = self.run_cli(["test", "--url", self.base_url,
                                "--suite", self.write("s.json", suite(SAFE_ADMIN, probe_route("/api/safe-profile")))])
        self.assertEqual(code, 0)

    def test_invalid_suite_exit_2(self):
        bad = suite(VULN_ADMIN)
        bad["personas"] = {"user": {"token": "x"}}
        code, _ = self.run_cli(["test", "--url", self.base_url, "--suite", self.write("s.json", bad)])
        self.assertEqual(code, 2)

    def test_from_scan_bfla_and_mass(self):
        out = self.dir / "res.json"
        code, _ = self.run_cli(["test", "--url", self.base_url, "--from-scan", self.write("f.json", FINDINGS),
                                "--token-env", "T_USER", "--resource-id", "7", "--output", str(out)])
        self.assertEqual(code, 1)
        report = json.loads(out.read_text())
        ids = {r["finding_id"] for r in report["matrix_results"] if r["is_breach"]}
        self.assertEqual(ids, {"BFLA-R-0001-1", "MASS-M-0001-1"})


class TestPocExport(unittest.TestCase):
    def test_bfla_and_mass_pocs(self):
        gen = ExploitGenerator(base_url="http://127.0.0.1:1", default_resource_id="7")
        arts = {a.finding_id: a for a in gen.generate_from_findings_data(FINDINGS)}
        self.assertEqual(arts["BFLA-R-0001-1"].category, "bfla")
        self.assertIn("/api/admin/users/7", arts["BFLA-R-0001-1"].python_script)
        self.assertEqual(arts["MASS-M-0001-1"].category, "mass_assignment")
        self.assertIn('"role": "admin"', arts["MASS-M-0001-1"].python_script)
        self.assertIn("KOMAINU_TOKEN", arts["MASS-M-0001-1"].python_script)
        self.assertNotIn("BFLA-R-0002-1", arts)
        for art in arts.values():
            compile(art.python_script, art.finding_id, "exec")


if __name__ == "__main__":
    unittest.main()
