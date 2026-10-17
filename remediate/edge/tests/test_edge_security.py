#!/usr/bin/env python3
"""
Automated edge security test suite for Komainu D4 (Kong Gateway + Coraza WAF).
Provides both static declarative configuration validation and live HTTP integration tests.
Standard-library only (Python 3.8+ compatible).
"""

import sys
import os
import re
import unittest
import urllib.request
import urllib.error
import json
import time

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
EDGE_DIR = os.path.dirname(CURRENT_DIR)


class TestEdgeDeclarativeConfiguration(unittest.TestCase):
    """Verifies that declarative gateway and WAF configuration files adhere to ADR-0003 and ADR-0004."""

    def test_kong_yaml_configuration(self):
        kong_path = os.path.join(EDGE_DIR, "kong", "kong.yaml")
        self.assertTrue(os.path.exists(kong_path), "kong.yaml must exist")

        with open(kong_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Invariant 1: Format version 3.0
        self.assertIn('_format_version: "3.0"', content)

        # Invariant 2: Upstream routes to Coraza WAF
        self.assertIn("url: http://coraza-waf:8080/api/v1", content)
        self.assertIn("paths:", content)
        self.assertIn("- /api/v1", content)

        # Invariant 3: Rate limiting plugin enabled
        self.assertIn("name: rate-limiting", content)
        self.assertIn("error_code: 429", content)

        # Invariant 4: CORS plugin enabled
        self.assertIn("name: cors", content)

        # Invariant 5: Correlation ID plugin enabled
        self.assertIn("name: correlation-id", content)
        self.assertIn("header_name: X-Correlation-ID", content)

        # Invariant 6: Response transformer stripping server disclosure headers
        self.assertIn("name: response-transformer", content)
        self.assertIn("X-Kong-Upstream-Latency", content)
        self.assertIn("Server", content)

    def test_coraza_conf_configuration(self):
        coraza_path = os.path.join(EDGE_DIR, "coraza", "coraza.conf")
        self.assertTrue(os.path.exists(coraza_path), "coraza.conf must exist")

        with open(coraza_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Invariant 1: Rule Engine Active
        self.assertIn("SecRuleEngine On", content)

        # Invariant 2: Request body inspection
        self.assertIn("SecRequestBodyAccess On", content)

        # Invariant 3: Deny status is 403 Forbidden
        self.assertIn("deny,status:403", content)

        # Invariant 4: Paranoia Level 1
        self.assertIn("setvar:tx.paranoia_level=1", content)

        # Invariant 5: Inbound anomaly threshold = 5
        self.assertIn("setvar:tx.inbound_anomaly_score_threshold=5", content)

    def test_coraza_crs_custom_rules(self):
        rules_path = os.path.join(EDGE_DIR, "coraza", "rules", "coraza-crs-custom.conf")
        self.assertTrue(os.path.exists(rules_path), "coraza-crs-custom.conf must exist")

        with open(rules_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Must explicitly detect and block SQL injection
        self.assertIn("Komainu WAF: SQL Injection Attack Detected", content)
        self.assertIn("union\\s+select", content)
        self.assertIn("drop\\s+table", content)

        # Must explicitly detect and block XSS
        self.assertIn("Komainu WAF: Cross-Site Scripting (XSS) Attack Detected", content)
        self.assertIn("<script", content)

        # Must explicitly detect and block Path Traversal
        self.assertIn("Komainu WAF: Path Traversal Attack Detected", content)
        self.assertIn("\\.\\./", content)

    def test_docker_compose_topology(self):
        dc_path = os.path.join(EDGE_DIR, "docker-compose.yml")
        self.assertTrue(os.path.exists(dc_path), "docker-compose.yml must exist")

        with open(dc_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Must declare kong, coraza-waf, and mock-backend
        self.assertIn("kong:", content)
        self.assertIn("KONG_DATABASE: \"off\"", content)
        self.assertIn("coraza-waf:", content)
        self.assertIn("mock-backend:", content)


class TestLiveEdgeSecurity(unittest.TestCase):
    """
    Optional live HTTP test suite executed when edge services are running.
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

    def test_live_xss_payload_blocked_with_403(self):
        xss_url = f"{self.BASE_URL}/api/v1/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
        req = urllib.request.Request(xss_url)
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                self.fail(f"Expected 403 Forbidden but received {resp.status}")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)


if __name__ == "__main__":
    unittest.main()
