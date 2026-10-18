#!/usr/bin/env python3
"""
Pilot Edge Protection Verification Suite (Deliverable D4 & D6).
Executes live security abuse and transparent routing verification against the
Komainu Edge Gateway (Kong) + OWASP Coraza WAF stack.
Standard-library only (Python 3.8+ compatible).
"""

import sys
import os
import time
import urllib.request
import urllib.error
import json
import unittest

BASE_GATEWAY_URL = os.environ.get("KOMAINU_GATEWAY_URL", "http://localhost:8000")


class TestPilotEdgeProtection(unittest.TestCase):
    """Verifies that D4 Edge Gateway + WAF blocks attacks and passes legitimate traffic."""

    @classmethod
    def setUpClass(cls):
        try:
            req = urllib.request.Request(f"{BASE_GATEWAY_URL}/api/v1/health")
            with urllib.request.urlopen(req, timeout=2) as resp:
                cls.live_ready = (resp.status == 200)
        except Exception:
            cls.live_ready = False

    def setUp(self):
        if not self.live_ready:
            self.skipTest(f"Komainu Gateway at {BASE_GATEWAY_URL} is not responding.")
        # Short pause between test cases to ensure rate limit buckets do not collide
        time.sleep(0.15)

    def test_01_legitimate_traffic_passes_transparently(self):
        """Verifies legitimate API traffic routes through Kong and Coraza WAF with HTTP 200."""
        req = urllib.request.Request(f"{BASE_GATEWAY_URL}/api/v1/orders")
        with urllib.request.urlopen(req, timeout=3) as resp:
            self.assertEqual(resp.status, 200)
            headers = dict(resp.headers)
            self.assertIn("X-Correlation-ID", headers, "Kong must inject X-Correlation-ID")
            self.assertNotIn("Server", headers, "Kong response-transformer must strip Server header")
            self.assertNotIn("X-Kong-Upstream-Latency", headers, "Latency disclosure must be stripped")

    def test_02_planted_sqli_finding_inj_0001_blocked(self):
        """Verifies INJ-I-0001-1 (' OR '1'='1) query string injection is dropped at edge with HTTP 403."""
        payload_url = f"{BASE_GATEWAY_URL}/api/v1/test/legacy-search?query=%27+OR+%271%27%3D%271"
        req = urllib.request.Request(payload_url)
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                self.fail(f"Expected 403 Forbidden but received {resp.status}")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403, f"Expected 403 Forbidden but got {e.code}")

    def test_03_planted_sqli_finding_inj_0002_blocked(self):
        """Verifies INJ-I-0002-1 (UNION SELECT) query string injection is dropped at edge with HTTP 403."""
        payload_url = f"{BASE_GATEWAY_URL}/api/v1/test/legacy-search?query=%27+UNION+SELECT+1%2C2%2C3--"
        req = urllib.request.Request(payload_url)
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                self.fail(f"Expected 403 Forbidden but received {resp.status}")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403, f"Expected 403 Forbidden but got {e.code}")

    def test_04_xss_probe_blocked(self):
        """Verifies XSS payload in query parameters is dropped at edge with HTTP 403."""
        payload_url = f"{BASE_GATEWAY_URL}/api/v1/search?q=%3Cscript%3Ealert(%27pwned%27)%3C%2Fscript%3E"
        req = urllib.request.Request(payload_url)
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                self.fail(f"Expected 403 Forbidden but received {resp.status}")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403, f"Expected 403 Forbidden but got {e.code}")

    def test_05_path_traversal_probe_blocked(self):
        """Verifies path traversal payload is dropped at edge with HTTP 403."""
        payload_url = f"{BASE_GATEWAY_URL}/api/v1/documents?path=..%2f..%2fetc%2fpasswd"
        req = urllib.request.Request(payload_url)
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                self.fail(f"Expected 403 Forbidden but received {resp.status}")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403, f"Expected 403 Forbidden but got {e.code}")

    def test_06_rate_limiting_protects_against_dos_burst(self):
        """Verifies per-IP burst rate limit (10 req/s) triggers HTTP 429 Too Many Requests."""
        time.sleep(1.2)  # Clear rate-limit burst window
        status_codes = []
        for _ in range(15):
            try:
                req = urllib.request.Request(f"{BASE_GATEWAY_URL}/api/v1/health")
                with urllib.request.urlopen(req, timeout=1) as resp:
                    status_codes.append(resp.status)
            except urllib.error.HTTPError as e:
                status_codes.append(e.code)
        time.sleep(1.2)  # Cooldown
        self.assertIn(429, status_codes, "Rate limiter must reject burst with HTTP 429")


def main():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestPilotEdgeProtection)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
