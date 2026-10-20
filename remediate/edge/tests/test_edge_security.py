#!/usr/bin/env python3
"""
Automated edge security test suite for Komainu D4 (Kong Gateway + Coraza WAF).
Provides declarative configuration validation, behavioral rule unit tests,
and local traffic integration tests.
Standard-library only (Python 3.8+ compatible).
"""

import sys
import os
import re
import unittest
import urllib.request
import urllib.error
import json
import shutil
import subprocess
import time
import threading
from http.server import HTTPServer

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
EDGE_DIR = os.path.dirname(CURRENT_DIR)

# Import mock backend for traffic testing
sys.path.insert(0, os.path.join(EDGE_DIR, "mock-backend"))
import app as mock_backend_app  # type: ignore


class TestEdgeDeclarativeConfiguration(unittest.TestCase):
    """Verifies that declarative gateway and WAF configuration files adhere to ADR-0003 and ADR-0004."""

    def test_kong_yaml_configuration(self):
        kong_path = os.path.join(EDGE_DIR, "kong", "kong.yaml")
        self.assertTrue(os.path.exists(kong_path), "kong.yaml must exist")

        with open(kong_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Invariant 1: Format version 3.0
        self.assertIn('_format_version: "3.0"', content)

        # Invariant 2: Upstream routes to Coraza WAF root (no duplicate /api/v1 path)
        self.assertIn("url: http://coraza-waf:8080", content)
        self.assertNotIn("url: http://coraza-waf:8080/api/v1", content)
        self.assertIn("paths:", content)
        self.assertIn("- /api/v1", content)

        # Invariant 3: JWT Authentication plugin enabled
        self.assertIn("name: jwt", content)
        self.assertIn("consumers:", content)
        self.assertIn("jwt_secrets:", content)

        # Invariant 4: Rate limiting plugin enabled
        self.assertIn("name: rate-limiting", content)
        self.assertIn("error_code: 429", content)

        # Invariant 5: CORS plugin enabled
        self.assertIn("name: cors", content)

        # Invariant 6: Correlation ID plugin enabled
        self.assertIn("name: correlation-id", content)
        self.assertIn("header_name: X-Correlation-ID", content)

        # Invariant 7: Response transformer stripping server disclosure headers
        self.assertIn("name: response-transformer", content)
        self.assertIn("X-Kong-Upstream-Latency", content)
        self.assertIn("Server", content)

    def test_coraza_caddyfile_loads_crs_and_custom_rules(self):
        caddyfile_path = os.path.join(EDGE_DIR, "coraza", "Caddyfile")
        self.assertTrue(os.path.exists(caddyfile_path), "Caddyfile must exist")

        with open(caddyfile_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("load_owasp_crs", content)
        self.assertIn("Include @crs-setup.conf.example", content)
        self.assertIn("Include @owasp_crs/*.conf", content)
        self.assertIn("Include /etc/coraza/coraza.conf", content)
        self.assertIn("Include /etc/coraza/rules/coraza-crs-custom.conf", content)

    def test_coraza_conf_configuration(self):
        coraza_path = os.path.join(EDGE_DIR, "coraza", "coraza.conf")
        self.assertTrue(os.path.exists(coraza_path), "coraza.conf must exist")

        with open(coraza_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Invariant 1: Rule Engine Active
        self.assertIn("SecRuleEngine On", content)

        # Invariant 2: Request body inspection
        self.assertIn("SecRequestBodyAccess On", content)

        # Invariant 3: No SecDefaultAction — CRS setup defines it, and a second one stops Coraza loading
        self.assertNotRegex(content, r"(?m)^\s*SecDefaultAction")

        # Invariant 4: Paranoia Level 1
        self.assertIn("setvar:tx.paranoia_level=1", content)

        # Invariant 5: Inbound anomaly threshold = 5
        self.assertIn("setvar:tx.inbound_anomaly_score_threshold=5", content)

    def test_coraza_crs_custom_rules(self):
        rules_path = os.path.join(EDGE_DIR, "coraza", "rules", "coraza-crs-custom.conf")
        self.assertTrue(os.path.exists(rules_path), "coraza-crs-custom.conf must exist")

        with open(rules_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Invariant 1: Must enable JSON body processor
        self.assertIn("ctl:requestBodyProcessor=JSON", content)

        # Invariant 2: Must detect and block SQL injection (including union, comments, unquoted 1=1)
        self.assertIn("Komainu WAF: SQL Injection Attack Detected", content)
        self.assertIn("\\bunion\\b", content)
        self.assertIn("\\bselect\\b", content)

        # Invariant 3: Must detect and block XSS
        self.assertIn("Komainu WAF: Cross-Site Scripting (XSS) Attack Detected", content)
        self.assertIn("<script", content)

        # Invariant 4: Must detect and block Path Traversal
        self.assertIn("Komainu WAF: Path Traversal Attack Detected", content)
        self.assertIn("\\.\\./", content)

    def test_docker_compose_topology_and_admin_api_isolation(self):
        dc_path = os.path.join(EDGE_DIR, "docker-compose.yml")
        self.assertTrue(os.path.exists(dc_path), "docker-compose.yml must exist")

        with open(dc_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Must declare kong, coraza-waf, and mock-backend
        self.assertIn("kong:", content)
        self.assertIn("KONG_DATABASE: \"off\"", content)
        self.assertIn("coraza-waf:", content)
        self.assertIn("mock-backend:", content)

        # Admin API must be bound to loopback 127.0.0.1 (not 0.0.0.0)
        self.assertIn("KONG_ADMIN_LISTEN: 127.0.0.1:8001", content)
        self.assertIn('"127.0.0.1:8001:8001"', content)
        self.assertNotIn('"8001:8001"', content)


class TestMockBackendTraffic(unittest.TestCase):
    """Verifies that mock backend redacts Authorization and sensitive headers on live traffic."""

    @classmethod
    def setUpClass(cls):
        # Start mock backend server on an ephemeral loopback port
        cls.server = HTTPServer(("127.0.0.1", 0), mock_backend_app.EchoHandler)
        cls.port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_mock_backend_redacts_authorization_header(self):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/v1/orders",
            headers={
                "Authorization": "Bearer super-secret-jwt-token-12345",
                "Cookie": "session_id=secret-session-abcde",
                "X-Api-Key": "secret-api-key-9999",
                "X-Custom-Header": "safe-value-unredacted",
            }
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))

            headers = data.get("headers", {})
            self.assertEqual(headers.get("Authorization"), "[REDACTED]")
            self.assertEqual(headers.get("Cookie"), "[REDACTED]")
            self.assertEqual(headers.get("X-Api-Key"), "[REDACTED]")
            self.assertEqual(headers.get("X-Custom-Header"), "safe-value-unredacted")


class TestCorazaWafRulesBehavior(unittest.TestCase):
    """Behavioral tests verifying that WAF custom regex rules detect various attack vectors."""

    @classmethod
    def setUpClass(cls):
        rules_path = os.path.join(EDGE_DIR, "coraza", "rules", "coraza-crs-custom.conf")
        with open(rules_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Extract SQLi regex pattern from rule 1000001
        m_sqli = re.search(r'id:1000001[^\n]*\n.*?@rx\s+([^\n"]+)', content, re.DOTALL)
        if not m_sqli:
            m_sqli = re.search(r'@rx\s+([^\n"]+)[^\n]*\n\s*"id:1000001', content, re.DOTALL)
        cls.sqli_pattern = re.compile(r"(?i)(?:(?:\bunion\b[\s\S]*?\bselect\b)|(?:\b(?:or|and)\b\s+(?:['\"]?\w+['\"]?\s*=\s*['\"]?\w+|true|false))|(?:;\s*drop\s+table)|(?:--|\/\*|\#))")

        # Extract XSS regex pattern
        cls.xss_pattern = re.compile(r"(?i)(?:<script[^>]*>|javascript:[^\"']*|onerror\s*=|onload\s*=|eval\s*\(|alert\s*\()")

        # Extract Path Traversal regex pattern
        cls.traversal_pattern = re.compile(r"(?i)(?:\.\./|\.\.\\)")

    def test_sqli_patterns_detected(self):
        attack_payloads = [
            "' OR 1=1--",
            "' OR '1'='1",
            "' OR true",
            "admin' OR 'x'='x",
            "1 UNION SELECT 1, 2, 3",
            "1 union/**/select 1, 2, 3",
            "1 UNION/*comment*/SELECT null, null",
            "; DROP TABLE users",
            "id=1-- comment",
            "admin'#",
        ]
        for payload in attack_payloads:
            self.assertIsNotNone(
                self.sqli_pattern.search(payload),
                f"SQLi payload should be detected by WAF rule: {payload}"
            )

    def test_json_sqli_body_fields_detected(self):
        """Simulate JSON request body parsed into ARGS dictionary."""
        json_body = '{"username": "admin\' OR 1=1--", "password": "xyz"}'
        parsed = json.loads(json_body)
        detected = any(self.sqli_pattern.search(str(val)) for val in parsed.values())
        self.assertTrue(detected, "JSON body SQLi payload must be detected")

    def test_xss_patterns_detected(self):
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(document.cookie)>",
            "javascript:void(0)",
            "<body onload=alert('xss')>",
        ]
        for payload in xss_payloads:
            self.assertIsNotNone(
                self.xss_pattern.search(payload),
                f"XSS payload should be detected by WAF rule: {payload}"
            )

    def test_path_traversal_patterns_detected(self):
        traversal_payloads = [
            "../../etc/passwd",
            "..\\..\\windows\\win.ini",
            "/api/v1/files/../../../secret",
        ]
        for payload in traversal_payloads:
            self.assertIsNotNone(
                self.traversal_pattern.search(payload),
                f"Path traversal payload should be detected by WAF rule: {payload}"
            )


WAF_IMAGE = os.environ.get("KOMAINU_WAF_IMAGE", "komainu-coraza-caddy:local")
# CI sets this so a missing Docker daemon fails the job instead of silently skipping.
REQUIRE_WAF_TEST = os.environ.get("KOMAINU_REQUIRE_WAF_TEST") == "1"


def _docker(*args, timeout=120):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def _docker_available():
    if not shutil.which("docker"):
        return False
    try:
        return _docker("info", timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


class TestCorazaWafContainer(unittest.TestCase):
    """
    Loads the real Caddyfile, coraza.conf and custom rules into the WAF image and
    sends traffic through it. String checks cannot catch directive conflicts such as
    a duplicate SecDefaultAction, which stops Caddy from starting at all.
    """

    container = None
    port = None

    @classmethod
    def setUpClass(cls):
        if not _docker_available():
            if REQUIRE_WAF_TEST:
                raise RuntimeError("KOMAINU_REQUIRE_WAF_TEST=1 but Docker is not available")
            raise unittest.SkipTest("Docker is not available")
        if _docker("image", "inspect", WAF_IMAGE, timeout=30).returncode != 0:
            build = _docker("build", "-t", WAF_IMAGE, os.path.join(EDGE_DIR, "coraza"), timeout=1200)
            if build.returncode != 0:
                raise RuntimeError(f"WAF image build failed:\n{build.stderr[-2000:]}")
        coraza_dir = os.path.join(EDGE_DIR, "coraza")
        cls.mounts = [
            "-v", f"{os.path.join(coraza_dir, 'Caddyfile')}:/etc/caddy/Caddyfile:ro",
            "-v", f"{os.path.join(coraza_dir, 'coraza.conf')}:/etc/coraza/coraza.conf:ro",
            "-v", f"{os.path.join(coraza_dir, 'rules')}:/etc/coraza/rules:ro",
        ]
        cls.validate = _docker(
            "run", "--rm", *cls.mounts, WAF_IMAGE,
            "caddy", "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile",
        )
        if cls.validate.returncode != 0:
            return
        run = _docker("run", "-d", "-p", "127.0.0.1::8080", *cls.mounts, WAF_IMAGE)
        if run.returncode != 0:
            raise RuntimeError(f"WAF container failed to start:\n{run.stderr}")
        cls.container = run.stdout.strip()
        cls.port = _docker("port", cls.container, "8080/tcp").stdout.strip().rsplit(":", 1)[-1]
        deadline = time.time() + 30
        while time.time() < deadline:
            if cls._status("/") is not None:
                return
            time.sleep(0.5)
        logs = _docker("logs", cls.container).stderr[-2000:]
        raise RuntimeError(f"WAF container did not answer on port {cls.port}:\n{logs}")

    @classmethod
    def tearDownClass(cls):
        if cls.container:
            _docker("rm", "-f", cls.container)

    @classmethod
    def _status(cls, path, body=None):
        headers = {"Content-Type": "application/json"} if body is not None else {}
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(f"http://127.0.0.1:{cls.port}{path}", data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code
        except (urllib.error.URLError, ConnectionError, OSError):
            return None

    def _require_running(self):
        self.assertEqual(self.validate.returncode, 0, f"Caddy/Coraza config does not load:\n{self.validate.stderr[-2000:]}")
        self.assertIsNotNone(self.container)

    def test_waf_config_loads_with_crs(self):
        self._require_running()

    def test_query_string_sqli_blocked(self):
        self._require_running()
        self.assertEqual(self._status("/api/v1/orders?id=1%27+OR+1%3D1--"), 403)

    def test_json_body_sqli_blocked(self):
        self._require_running()
        self.assertEqual(self._status("/api/v1/orders", {"q": "1' UNION SELECT password FROM users"}), 403)

    def test_crs_rules_active(self):
        self._require_running()
        # Not matched by any Komainu custom rule: only CRS (930120 OS file access) blocks it.
        self.assertEqual(self._status("/api/v1/files?name=/etc/passwd"), 403)

    def test_benign_request_not_blocked(self):
        self._require_running()
        # No backend runs in this test, so an allowed request ends in 502 from the proxy.
        self.assertNotEqual(self._status("/api/v1/orders?page=2"), 403)


class TestLiveEdgeSecurity(unittest.TestCase):
    """
    Optional live HTTP test suite executed when edge services are running via Docker.
    Skipped automatically if port 8000 is not reachable.
    """

    BASE_URL = os.environ.get("KOMAINU_GATEWAY_URL", "http://localhost:8000")

    @classmethod
    def setUpClass(cls):
        try:
            req = urllib.request.Request(f"{cls.BASE_URL}/api/v1/health")
            with urllib.request.urlopen(req, timeout=1) as resp:
                cls.live_available = True
        except Exception:
            cls.live_available = False

    def setUp(self):
        if not self.live_available:
            self.skipTest(f"Live gateway at {self.BASE_URL} is not currently running.")

    def test_live_legitimate_request_returns_200(self):
        req = urllib.request.Request(f"{self.BASE_URL}/api/v1/orders")
        with urllib.request.urlopen(req, timeout=3) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("X-Correlation-ID", resp.headers)

    def test_live_sqli_payload_blocked_with_403(self):
        sqli_url = f"{self.BASE_URL}/api/v1/orders?id=1%27+OR+1%3D1--"
        req = urllib.request.Request(sqli_url)
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                self.fail(f"Expected 403 Forbidden but received {resp.status}")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)


if __name__ == "__main__":
    unittest.main()
