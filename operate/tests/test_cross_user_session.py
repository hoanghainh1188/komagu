#!/usr/bin/env python3
"""komagu test on session-based Java legacy apps (#368)."""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from operate.cli.main import main as cli_main
from operate.cross_user_tester.mock_test_server import start_mock_server
from operate.cross_user_tester.runner import CrossUserTestRunner, TestCase, generate_test_cases_from_findings
from operate.cross_user_tester.session_config import SessionConfigError, read_cookie
from operate.cross_user_tester.session_http import (
    ALLOWED,
    DENIED,
    INCONCLUSIVE,
    DenialSignal,
    classify,
    decode_body,
    encode_form,
    extract_form_token,
    safe_location,
)
from operate.tests.mock_legacy_session_app import (
    ALICE_COOKIE,
    BOB_COOKIE,
    DENIED_TEXT,
    EXPIRED_COOKIE,
    TOKEN_FIELD,
    start_legacy_app,
)

READ_FINDING: Dict[str, Any] = {
    "finding_id": "BOLA-READ", "category": "bola", "title": "Order view", "status": "confirmed",
    "endpoint": {"method": "GET", "path": "/order/view.do"},
    "attack_vector": {"method": "GET", "path": "/order/view.do", "target_param": "id"},
}
WRITE_FINDING: Dict[str, Any] = {
    "finding_id": "BOLA-WRITE", "category": "bola", "title": "Order update", "status": "confirmed",
    "endpoint": {"method": "POST", "path": "/order/update.do"},
    "attack_vector": {"method": "POST", "path": "/order/update.do", "target_param": "id",
                      "suggested_payload": "id={id}&status=tampered"},
}
SIGNAL = DenialSignal(deny_status=(404,), deny_redirects=("/login.do",), deny_markers=("denied",),
                      allow_redirects=("/list.do",), allow_markers=())


class TestClassify(unittest.TestCase):
    def verdict(self, signal: DenialSignal, status: int, location: str = "", body: str = "") -> str:
        return classify(signal, status, location, body)[0]

    def test_declared_status_is_denied(self) -> None:
        self.assertEqual(self.verdict(SIGNAL, 404), DENIED)

    def test_undeclared_error_status_is_never_a_pass_or_breach(self) -> None:
        for status in (0, 400, 403, 405, 500):
            self.assertEqual(self.verdict(SIGNAL, status), INCONCLUSIVE, status)

    def test_redirects(self) -> None:
        self.assertEqual(self.verdict(SIGNAL, 302, "http://h/login.do;x=1"), DENIED)
        self.assertEqual(self.verdict(SIGNAL, 302, "/order/list.do"), ALLOWED)
        self.assertEqual(self.verdict(SIGNAL, 302, "/somewhere.do"), INCONCLUSIVE)

    def test_error_page_with_200_is_denied(self) -> None:
        self.assertEqual(self.verdict(SIGNAL, 200, body="access denied"), DENIED)

    def test_200_without_marker_is_allowed(self) -> None:
        self.assertEqual(self.verdict(SIGNAL, 200, body="order data"), ALLOWED)

    def test_allow_marker_required_when_declared(self) -> None:
        signal = DenialSignal(deny_markers=("denied",), allow_markers=("Order detail",))
        self.assertEqual(self.verdict(signal, 200, body="Order detail"), ALLOWED)
        self.assertEqual(self.verdict(signal, 200, body="validation failed"), INCONCLUSIVE)

    def test_page_matching_both_signals_is_ambiguous(self) -> None:
        signal = DenialSignal(deny_markers=("denied",), allow_markers=("Order detail",))
        self.assertEqual(self.verdict(signal, 200, body="Order detail denied"), INCONCLUSIVE)

    def test_reason_does_not_carry_session_id_from_url_rewriting(self) -> None:
        _, reason = classify(SIGNAL, 302, "/x.do;jsessionid=SECRET123?token=SECRET456", "")
        self.assertNotIn("SECRET", reason)


class TestHelpers(unittest.TestCase):
    def test_safe_location_strips_session_and_query(self) -> None:
        self.assertEqual(safe_location("http://h/a.do;jsessionid=abc?x=1"), "http://h/a.do")

    def test_decode_windows_31j_header(self) -> None:
        raw = DENIED_TEXT.encode("cp932")
        self.assertIn(DENIED_TEXT, decode_body(raw, "text/html; charset=Windows-31J"))

    def test_decode_meta_charset(self) -> None:
        raw = f'<meta charset="Shift_JIS">{DENIED_TEXT}'.encode("cp932")
        self.assertIn(DENIED_TEXT, decode_body(raw, "text/html"))

    def test_decode_undeclared_shift_jis(self) -> None:
        self.assertIn(DENIED_TEXT, decode_body(DENIED_TEXT.encode("cp932"), "text/html"))

    def test_decode_unknown_charset_falls_back(self) -> None:
        self.assertEqual(decode_body(b"abc", "text/html; charset=nope"), "abc")

    def test_extract_token_any_attribute_order(self) -> None:
        self.assertEqual(extract_form_token('<input value="T1" type="hidden" name="f">', "f"), {"f": "T1"})

    def test_extract_token_from_meta(self) -> None:
        self.assertEqual(extract_form_token('<meta name="_csrf" content="T2">', "_csrf"), {"_csrf": "T2"})

    def test_extract_struts2_sends_companion_field(self) -> None:
        html = '<input name="struts.token.name" value="token"><input name="token" value="T3">'
        self.assertEqual(extract_form_token(html, "token"), {"struts.token.name": "token", "token": "T3"})

    def test_extract_missing_token(self) -> None:
        self.assertIsNone(extract_form_token("<form></form>", "f"))

    def test_encode_form(self) -> None:
        self.assertEqual(encode_form({"a": "1 2", "b": 3}), b"a=1+2&b=3")

    def test_encode_form_rejects_nested_values(self) -> None:
        with self.assertRaises(ValueError):
            encode_form({"a": {"b": 1}})


class TestReadCookie(unittest.TestCase):
    def test_env(self) -> None:
        self.assertEqual(read_cookie("C", None, {"C": " JSESSIONID=a \n"}, "attacker"), "JSESSIONID=a")

    def test_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "c.txt"
            path.write_text("JSESSIONID=b\n", encoding="utf-8")
            os.chmod(path, 0o600)
            self.assertEqual(read_cookie(None, str(path), {}, "owner"), "JSESSIONID=b")

    def test_both_sources_rejected(self) -> None:
        with self.assertRaises(SessionConfigError):
            read_cookie("C", "/f", {"C": "a=b"}, "attacker")

    def test_unset_env_names_variable_only(self) -> None:
        with self.assertRaises(SessionConfigError) as ctx:
            read_cookie("NOPE", None, {}, "attacker")
        self.assertIn("NOPE", str(ctx.exception))

    def test_bad_values_are_rejected_without_echo(self) -> None:
        for bad in ("JSESSIONID=SECRETVALUE\r\nX: y", "SECRETVALUE"):
            with self.assertRaises(SessionConfigError) as ctx:
                read_cookie("C", None, {"C": bad}, "attacker")
            self.assertNotIn("SECRETVALUE", str(ctx.exception))


class TestFromScanRequests(unittest.TestCase):
    def test_form_action_read_puts_id_in_query(self) -> None:
        case = generate_test_cases_from_findings([READ_FINDING], default_resource_id="100")[0]
        self.assertEqual(case.path, "/order/view.do?id=100")
        self.assertEqual(case.body_format, "form")

    def test_form_action_write_puts_id_in_body(self) -> None:
        case = generate_test_cases_from_findings([WRITE_FINDING], default_resource_id="100")[0]
        self.assertEqual(case.path, "/order/update.do")
        self.assertEqual(case.body_format, "form")
        self.assertEqual(case.payload, {"id": "100", "status": "tampered"})

    def test_existing_query_is_extended(self) -> None:
        finding = {**READ_FINDING, "attack_vector": {"path": "/order.do?method=view", "target_param": "orderId"}}
        case = generate_test_cases_from_findings([finding], default_resource_id="7")[0]
        self.assertEqual(case.path, "/order.do?method=view&orderId=7")

    def test_placeholder_in_query_is_filled(self) -> None:
        finding = {**READ_FINDING, "attack_vector": {"path": "/order/view.do?id={id}"}}
        case = generate_test_cases_from_findings([finding], default_resource_id="7")[0]
        self.assertEqual(case.path, "/order/view.do?id=7")

    def test_rest_route_stays_json(self) -> None:
        finding = {"finding_id": "BOLA-API", "category": "bola", "endpoint": {"method": "PUT", "path": "/api/orders"}}
        case = generate_test_cases_from_findings([finding], default_resource_id="7")[0]
        self.assertEqual(case.path, "/api/orders/7")
        self.assertEqual(case.body_format, "json")

    def test_forced_json_keeps_rest_shape_for_do_route(self) -> None:
        case = generate_test_cases_from_findings([WRITE_FINDING], default_resource_id="7", body_format="json")[0]
        self.assertEqual(case.body_format, "json")
        self.assertEqual(case.path, "/order/update.do/7")

    def test_sarif_form_action(self) -> None:
        sarif = {"runs": [{"results": [{"ruleId": "bola.x", "message": {"text": "m"}, "properties": {
            "finding_id": "S1", "endpoint": {"method": "GET", "path": "/order/view.do"},
            "attack_vector": {"target_param": "id"}}}]}]}
        case = generate_test_cases_from_findings(sarif, default_resource_id="9")[0]
        self.assertEqual(case.path, "/order/view.do?id=9")


class SessionAppCase(unittest.TestCase):
    def setUp(self) -> None:
        self.server, self.base_url = start_legacy_app()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.scan = self.dir / "findings.json"
        self.scan.write_text(json.dumps({"findings": [READ_FINDING, WRITE_FINDING]}), encoding="utf-8")
        self.out = self.dir / "out.json"
        self.env = {"ATT_COOKIE": BOB_COOKIE, "OWN_COOKIE": ALICE_COOKIE}

    def base_args(self) -> List[str]:
        return [
            "--no-banner", "test", "--url", self.base_url, "--from-scan", str(self.scan),
            "--resource-id", "100", "--output", str(self.out),
            "--attacker-cookie-env", "ATT_COOKIE", "--owner-cookie-env", "OWN_COOKIE",
        ]

    def strict_args(self) -> List[str]:
        return self.base_args() + [
            "--strict", "--session-check", "/home.do", "--session-marker", "Welcome",
            "--deny-status", "404", "--deny-redirect", "/login.do", "--deny-marker", DENIED_TEXT,
            "--allow-redirect", "/order/list.do",
            "--csrf-page", "/order/edit.do?id=200", "--csrf-field", TOKEN_FIELD,
            "--owner-control-writes",
        ]

    def run_cli(self, args: List[str]) -> Tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, self.env), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli_main(args)
            except SystemExit as stop:
                code = int(stop.code or 0)
        return code, out.getvalue() + err.getvalue()

    def report(self) -> Dict[str, Any]:
        return json.loads(self.out.read_text(encoding="utf-8"))

    def by_finding(self) -> Dict[str, Dict[str, Any]]:
        return {r["finding_id"]: r for r in self.report()["results"]}


class TestRehearsal(SessionAppCase):
    """A vulnerable route must fail before the fix and pass after it."""

    def test_fails_before_fix(self) -> None:
        code, _ = self.run_cli(self.strict_args())
        self.assertEqual(code, 1)
        results = self.by_finding()
        self.assertTrue(results["BOLA-READ"]["is_breach"])
        self.assertTrue(results["BOLA-WRITE"]["is_breach"])
        self.assertIn(("bob", "100"), self.server.updates)

    def assert_passes_after_fix(self, denial: str) -> None:
        self.server.fixed = True
        self.server.denial = denial
        code, output = self.run_cli(self.strict_args())
        self.assertEqual(code, 0, output)
        results = self.by_finding()
        self.assertTrue(results["BOLA-READ"]["is_secure"])
        self.assertEqual(results["BOLA-READ"]["owner_control"], "passed")
        self.assertTrue(results["BOLA-WRITE"]["is_secure"])
        self.assertEqual(results["BOLA-WRITE"]["owner_control"], "passed")
        self.assertEqual(self.server.updates, [("alice", "100")])

    def test_passes_after_fix_with_200_error_page(self) -> None:
        self.assert_passes_after_fix("error_page")

    def test_passes_after_fix_with_login_redirect(self) -> None:
        self.assert_passes_after_fix("login_redirect")

    def test_passes_after_fix_with_404(self) -> None:
        self.assert_passes_after_fix("not_found")

    def test_trailing_slash_in_url(self) -> None:
        args = self.strict_args()
        args[args.index("--url") + 1] = self.base_url + "/"
        self.server.fixed = True
        code, output = self.run_cli(args)
        self.assertEqual(code, 0, output)

    def test_requests_are_session_and_form_shaped(self) -> None:
        self.run_cli(self.strict_args())
        post = next(s for s in self.server.seen if s.method == "POST")
        self.assertEqual(post.cookie, BOB_COOKIE)
        self.assertIsNone(post.authorization)
        self.assertEqual(post.content_type, "application/x-www-form-urlencoded")
        self.assertIn("id=100", post.body)
        self.assertIn("status=tampered", post.body)

    def test_login_redirect_is_not_followed(self) -> None:
        self.server.fixed = True
        self.server.denial = "login_redirect"
        self.run_cli(self.strict_args())
        self.assertFalse([s for s in self.server.seen if s.path.startswith("/login.do")])


class TestNoFalseVerdicts(SessionAppCase):
    def test_expired_attacker_session_stops_the_run(self) -> None:
        self.server.fixed = True
        self.env["ATT_COOKIE"] = EXPIRED_COOKIE
        code, output = self.run_cli(self.strict_args())
        self.assertEqual(code, 2, output)
        self.assertFalse([s for s in self.server.seen if s.path.startswith("/order/")])

    def test_expired_owner_session_stops_the_run(self) -> None:
        self.env["OWN_COOKIE"] = EXPIRED_COOKIE
        code, _ = self.run_cli(self.strict_args())
        self.assertEqual(code, 2)

    def test_session_lost_during_run_invalidates_result(self) -> None:
        self.server.fixed = True
        original = self.server.orders

        class DropsSessionAfterFirstUse(dict):
            def __init__(inner, server: Any) -> None:  # noqa: N805
                super().__init__(original)
                inner.server = server

            def get(inner, key: str, default: Any = None) -> Any:  # noqa: N805
                inner.server.sessions.pop("sess-bob-0002", None)
                return super().get(key, default)

        self.server.orders = DropsSessionAfterFirstUse(self.server)
        code, output = self.run_cli(self.strict_args())
        self.assertEqual(code, 2, output)
        self.assertFalse(self.report()["success"])

    def test_missing_record_is_not_a_pass(self) -> None:
        self.server.fixed = True
        args = self.strict_args()
        args[args.index("--resource-id") + 1] = "999"
        code, _ = self.run_cli(args)
        self.assertEqual(code, 1)
        read = self.by_finding()["BOLA-READ"]
        self.assertFalse(read["is_secure"])
        self.assertFalse(read["is_breach"])
        self.assertEqual(read["owner_control"], "failed")

    def test_missing_csrf_token_is_not_a_pass(self) -> None:
        self.server.fixed = True
        self.server.hide_token = True
        code, _ = self.run_cli(self.strict_args())
        self.assertEqual(code, 1)
        write = self.by_finding()["BOLA-WRITE"]
        self.assertFalse(write["is_secure"])
        self.assertFalse(write["is_breach"])
        self.assertIn("token", write["error_message"])
        self.assertFalse([s for s in self.server.seen if s.method == "POST"])

    def test_undeclared_redirect_is_inconclusive(self) -> None:
        args = [a for a in self.strict_args()]
        i = args.index("--allow-redirect")
        del args[i:i + 2]
        code, _ = self.run_cli(args)
        self.assertEqual(code, 1)
        write = self.by_finding()["BOLA-WRITE"]
        self.assertFalse(write["is_breach"])
        self.assertFalse(write["is_secure"])

    def test_strict_session_needs_signal_check_and_owner(self) -> None:
        full = self.strict_args()

        def without(flag: str) -> List[str]:
            i = full.index(flag)
            return full[:i] + full[i + 2:]

        no_signal = full
        for flag in ("--deny-status", "--deny-redirect", "--deny-marker"):
            i = no_signal.index(flag)
            no_signal = no_signal[:i] + no_signal[i + 2:]
        for args in (no_signal, without("--session-check"), without("--owner-cookie-env")):
            code, _ = self.run_cli(args)
            self.assertEqual(code, 2, args)
        self.assertEqual(self.server.seen, [])

    def test_strict_refused_write_without_owner_control_is_not_a_pass(self) -> None:
        self.server.fixed = True
        args = [a for a in self.strict_args() if a != "--owner-control-writes"]
        code, _ = self.run_cli(args)
        self.assertEqual(code, 1)
        write = self.by_finding()["BOLA-WRITE"]
        self.assertFalse(write["is_secure"])
        self.assertFalse(write["is_breach"])
        self.assertEqual(write["owner_control"], "skipped_write")
        self.assertIn("--owner-control-writes", write["error_message"])
        self.assertEqual(self.server.updates, [])

    def test_non_strict_refused_write_keeps_owner_data_untouched(self) -> None:
        self.server.fixed = True
        args = [a for a in self.strict_args() if a not in ("--owner-control-writes", "--strict")]
        code, output = self.run_cli(args)
        self.assertEqual(code, 0, output)
        self.assertEqual(self.by_finding()["BOLA-WRITE"]["owner_control"], "skipped_write")
        self.assertEqual(self.server.updates, [])

    def test_owner_control_uses_owner_csrf_page(self) -> None:
        self.server.fixed = True
        code, output = self.run_cli(self.strict_args() + ["--owner-csrf-page", "/order/edit.do?id=100"])
        self.assertEqual(code, 0, output)
        pages = [s for s in self.server.seen if s.path == "/order/edit.do?id=100"]
        self.assertEqual([s.cookie for s in pages], [ALICE_COOKIE])

    def test_empty_signal_value_is_config_error(self) -> None:
        for flag in ("--deny-marker", "--deny-redirect", "--allow-marker", "--allow-redirect"):
            code, _ = self.run_cli(self.strict_args() + [flag, ""])
            self.assertEqual(code, 2, flag)
        self.assertEqual(self.server.seen, [])


class TestSecrets(SessionAppCase):
    def test_cookie_cannot_be_given_as_argument(self) -> None:
        for flag in ("--attacker-cookie", "--owner-cookie"):
            code, _ = self.run_cli(["--no-banner", "test", "--url", self.base_url, flag, BOB_COOKIE])
            self.assertEqual(code, 2)

    def test_no_cookie_or_session_id_in_output_or_report(self) -> None:
        for fixed, denial in ((False, "error_page"), (True, "login_redirect")):
            self.server.fixed = fixed
            self.server.denial = denial
            args = self.strict_args()
            i = args.index("--deny-redirect")
            del args[i:i + 2]  # the redirect is reported as undeclared, with its target
            _, output = self.run_cli(args)
            text = output + self.out.read_text(encoding="utf-8")
            for secret in ("sess-bob", "sess-alice", "sess-rewritten", "jsessionid"):
                self.assertNotIn(secret, text)

    def test_cookie_file_source(self) -> None:
        path = self.dir / "bob.cookie"
        path.write_text(BOB_COOKIE + "\n", encoding="utf-8")
        os.chmod(path, 0o600)
        args = self.strict_args()
        i = args.index("--attacker-cookie-env")
        args[i:i + 2] = ["--attacker-cookie-file", str(path)]
        code, _ = self.run_cli(args)
        self.assertEqual(code, 1)
        self.assertTrue(self.by_finding()["BOLA-READ"]["is_breach"])

    def test_unset_cookie_variable_is_config_error(self) -> None:
        del self.env["ATT_COOKIE"]
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ATT_COOKIE", None)
            code, _ = self.run_cli(self.strict_args())
        self.assertEqual(code, 2)


class TestSuites(SessionAppCase):
    def write_suite(self, suite: Any) -> str:
        path = self.dir / "suite.json"
        path.write_text(json.dumps(suite), encoding="utf-8")
        return str(path)

    def suite_args(self, path: str) -> List[str]:
        return [
            "--no-banner", "test", "--url", self.base_url, "--suite", path, "--output", str(self.out),
            "--deny-marker", DENIED_TEXT, "--deny-redirect", "/login.do", "--allow-redirect", "/order/list.do",
        ]

    def test_v1_suite_form_and_csrf(self) -> None:
        suite = {"tests": [{
            "name": "update", "method": "POST", "path": "/order/update.do", "body_format": "form",
            "payload": {"id": "100"}, "csrf": {"page": "/order/edit.do?id=200", "field": TOKEN_FIELD},
        }]}
        args = self.suite_args(self.write_suite(suite)) + ["--attacker-cookie-env", "ATT_COOKIE"]
        code, _ = self.run_cli(args)
        self.assertEqual(code, 1)
        self.assertTrue(self.report()["results"][0]["is_breach"])
        self.server.fixed = True
        code, _ = self.run_cli(args)
        self.assertEqual(code, 0)

    def test_v1_suite_headers_are_sent(self) -> None:
        suite = {"tests": [{"method": "GET", "path": "/order/view.do?id=100", "headers": {"X-Trace": "1", "Authorization": "Basic abc"}}]}
        self.run_cli(self.suite_args(self.write_suite(suite)) + ["--attacker-cookie-env", "ATT_COOKIE"])
        self.assertEqual(self.server.seen[-1].authorization, "Basic abc")

    def test_v1_suite_bad_body_format_is_config_error(self) -> None:
        suite = {"tests": [{"method": "POST", "path": "/x.do", "body_format": "xml"}]}
        code, _ = self.run_cli(self.suite_args(self.write_suite(suite)))
        self.assertEqual(code, 2)
        self.assertEqual(self.server.seen, [])

    def v2_suite(self) -> Dict[str, Any]:
        return {
            "version": 2,
            "personas": {"owner": {"cookie_env": "OWN_COOKIE"}, "attacker": {"cookie_env": "ATT_COOKIE"}},
            "routes": [
                {"method": "GET", "path": "/order/view.do?id={id}", "params": {"id": "100"}, "allow": ["owner"]},
                {"method": "POST", "path": "/order/update.do", "allow": ["owner"], "body_format": "form",
                 "payload": {"id": "100"}, "csrf": {"page": "/order/edit.do?id=200", "field": TOKEN_FIELD}},
            ],
        }

    def test_v2_suite_cookie_personas(self) -> None:
        args = self.suite_args(self.write_suite(self.v2_suite()))
        code, _ = self.run_cli(args)
        self.assertEqual(code, 1)
        self.assertTrue(all(r["is_breach"] for r in self.report()["matrix_results"]))
        self.server.fixed = True
        code, _ = self.run_cli(args)
        self.assertEqual(code, 0)

    def test_v2_session_check_covers_cookie_personas(self) -> None:
        self.env["ATT_COOKIE"] = EXPIRED_COOKIE
        args = self.suite_args(self.write_suite(self.v2_suite())) + ["--session-check", "/home.do"]
        code, _ = self.run_cli(args)
        self.assertEqual(code, 2)

    def test_v2_rejects_token_and_cookie_together(self) -> None:
        suite = self.v2_suite()
        suite["personas"]["attacker"]["token_env"] = "T"
        code, _ = self.run_cli(self.suite_args(self.write_suite(suite)))
        self.assertEqual(code, 2)

    def test_v2_rejects_inline_cookie(self) -> None:
        suite = self.v2_suite()
        suite["personas"]["attacker"] = {"cookie": "JSESSIONID=x"}
        code, _ = self.run_cli(self.suite_args(self.write_suite(suite)))
        self.assertEqual(code, 2)


class TestFormWithoutSession(unittest.TestCase):
    def test_nested_form_value_is_an_error_not_a_crash(self) -> None:
        server, base_url = start_legacy_app()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        case = TestCase("t", "/order/update.do", "POST", payload={"a": {"b": 1}}, body_format="form")
        res = CrossUserTestRunner(base_url, default_attacker_token="t").execute_test(case)
        self.assertFalse(res.is_secure or res.is_breach)
        self.assertEqual(server.seen, [])

    def test_only_http_urls_are_sent(self) -> None:
        case = TestCase("t", "/etc/passwd", "GET", body_format="form")
        res = CrossUserTestRunner("file://").execute_test(case)
        self.assertFalse(res.is_secure or res.is_breach)
        self.assertIn("http", res.error_message)


class TestBearerUnchanged(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server, _, cls.base_url = start_mock_server(port=0)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.server_close()

    def test_json_body_and_404_invariant(self) -> None:
        runner = CrossUserTestRunner(self.base_url, default_attacker_token="persona-b")
        res = runner.execute_test(TestCase("t", "/api/orders/1", "PUT", payload={"a": 1}))
        self.assertTrue(res.is_secure)
        self.assertEqual(set(res.to_dict()), {
            "name", "finding_id", "consensus_score", "method", "path", "status_code",
            "is_breach", "is_secure", "duration_ms", "error_message",
        })


if __name__ == "__main__":
    unittest.main()
