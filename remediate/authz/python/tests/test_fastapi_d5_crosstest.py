"""Automated Cross-User Testing (D5) Integration with Python FastAPI Adapter.

Runs the Komagu continuous authorization verification runner (D5)
against live HTTP endpoints protected by Komagu D1/D2:
1. Protected endpoints enforce Komagu invariant: attacker gets 404 on Read/Update/Delete -> [PASS - SECURE].
2. Planted vulnerable endpoints expose BOLA: attacker gets 200 -> [FAIL - VULNERABILITY DETECTED].
"""

from __future__ import annotations

import http.server
import json
import socket
import threading
import unittest
from dataclasses import dataclass
from typing import Any, Dict, Optional

from operate.cross_user_tester.runner import CrossUserTestRunner, TestCase
from remediate.authz.python.komagu_authz.models import (
    InMemorySecurityAuditSink,
    IOwnedResource,
    OwnershipException,
    ResourceOperation,
)
from remediate.authz.python.komagu_authz.service import KomaguAuthorizationService
from remediate.identity.python.komagu_identity.oidc_validator import OidcTokenValidator


@dataclass
class Order(IOwnedResource):
    id: str
    owner_user_id: str
    tenant_id: str
    description: str
    amount: float


class MockFastApiServer(http.server.BaseHTTPRequestHandler):
    """Simulates FastAPI routing and Komagu D1/D2 dependency injection."""

    authz_service = KomaguAuthorizationService(audit_sink=InMemorySecurityAuditSink())
    validator = OidcTokenValidator(
        issuer="https://auth.komagu.test",
        audience="komagu-api",
        allow_dev_tokens=True,
    )

    # Pre-seeded test database
    orders: Dict[str, Order] = {
        "ord-101": Order("ord-101", "user-a", "tenant-komagu", "Alice Laptop", 1200.0),
        "ord-102": Order("ord-102", "user-b", "tenant-komagu", "Bob Monitor", 300.0),
    }

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Suppress console logging during test run

    def _get_auth_user(self) -> Optional[Any]:
        auth_header = self.headers.get("Authorization")
        if not auth_header:
            return None
        try:
            return self.validator.validate_token(auth_header)
        except Exception:
            return None

    def _send_json(self, status: int, data: Any) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        user = self._get_auth_user()
        if not user:
            self._send_json(401, {"detail": "Unauthorized"})
            return

        # 1. Protected endpoint with Komagu D1
        if self.path.startswith("/api/v1/orders/"):
            order_id = self.path.split("/")[-1]
            order = self.orders.get(order_id)
            if not order:
                self._send_json(404, {"detail": "Resource not found"})
                return

            try:
                self.authz_service.require_ownership(user, order, ResourceOperation.READ)
                self._send_json(200, {
                    "id": order.id,
                    "ownerUserId": order.owner_user_id,
                    "tenantId": order.tenant_id,
                    "description": order.description,
                    "amount": order.amount,
                })
            except OwnershipException:
                # Invariant: deny with 404
                self._send_json(404, {"detail": "Resource not found"})
            return

        # 2. Planted insecure endpoint (BOLA vulnerability)
        if self.path.startswith("/api/v1/insecure-orders/"):
            order_id = self.path.split("/")[-1]
            order = self.orders.get(order_id)
            if not order:
                self._send_json(404, {"detail": "Resource not found"})
                return
            # Flaw: No ownership verification! Returns data directly to any authenticated user
            self._send_json(200, {
                "id": order.id,
                "ownerUserId": order.owner_user_id,
                "tenantId": order.tenant_id,
                "description": order.description,
            })
            return

        self._send_json(404, {"detail": "Not found"})

    def do_PUT(self) -> None:
        user = self._get_auth_user()
        if not user:
            self._send_json(401, {"detail": "Unauthorized"})
            return

        if self.path.startswith("/api/v1/orders/"):
            order_id = self.path.split("/")[-1]
            order = self.orders.get(order_id)
            if not order:
                self._send_json(404, {"detail": "Resource not found"})
                return

            try:
                self.authz_service.require_ownership(user, order, ResourceOperation.UPDATE)
                self._send_json(200, {"id": order.id, "status": "Updated"})
            except OwnershipException:
                self._send_json(404, {"detail": "Resource not found"})
            return

        self._send_json(404, {"detail": "Not found"})

    def do_DELETE(self) -> None:
        user = self._get_auth_user()
        if not user:
            self._send_json(401, {"detail": "Unauthorized"})
            return

        if self.path.startswith("/api/v1/orders/"):
            order_id = self.path.split("/")[-1]
            order = self.orders.get(order_id)
            if not order:
                self._send_json(404, {"detail": "Resource not found"})
                return

            try:
                self.authz_service.require_ownership(user, order, ResourceOperation.DELETE)
                self._send_json(200, {"id": order.id, "status": "Deleted"})
            except OwnershipException:
                self._send_json(404, {"detail": "Resource not found"})
            return

        self._send_json(404, {"detail": "Not found"})


class TestFastApiD5Crosstest(unittest.TestCase):
    server: http.server.HTTPServer
    server_thread: threading.Thread
    port: int
    base_url: str

    @classmethod
    def setUpClass(cls) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]

        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.server = http.server.HTTPServer(("127.0.0.1", cls.port), MockFastApiServer)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_01_d5_runner_passes_on_remediated_fastapi_endpoints(self) -> None:
        """D5 CrossUserTestRunner against /api/v1/orders/{id} passes with zero breaches."""
        runner = CrossUserTestRunner(
            base_url=self.base_url,
            default_attacker_token="token-user-b",
        )

        test_cases = [
            TestCase("Cross-User Read", "/api/v1/orders/{id}", "GET", resource_id="ord-101"),
            TestCase("Cross-User Update", "/api/v1/orders/{id}", "PUT", resource_id="ord-101", payload={"description": "Hacked"}),
            TestCase("Cross-User Delete", "/api/v1/orders/{id}", "DELETE", resource_id="ord-101"),
        ]

        results = runner.run_suite(test_cases)
        self.assertEqual(len(results), 3)
        breaches = [r for r in results if r.is_breach]
        secures = [r for r in results if r.is_secure]
        self.assertEqual(len(breaches), 0)
        self.assertEqual(len(secures), 3)
        self.assertTrue(all(r.status_code == 404 for r in results))

    def test_02_d5_runner_detects_breach_on_insecure_endpoint(self) -> None:
        """D5 CrossUserTestRunner against /api/v1/insecure-orders/{id} flags BOLA breach."""
        runner = CrossUserTestRunner(
            base_url=self.base_url,
            default_attacker_token="token-user-b",
        )

        test_cases = [
            TestCase("Insecure Cross-User Read", "/api/v1/insecure-orders/{id}", "GET", resource_id="ord-101"),
        ]

        results = runner.run_suite(test_cases)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].is_breach)
        self.assertFalse(results[0].is_secure)
        self.assertEqual(results[0].status_code, 200)


if __name__ == "__main__":
    unittest.main()
