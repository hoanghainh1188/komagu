#!/usr/bin/env python3
"""Mock HTTP Server for Komagu Cross-User Authorization Testing.

Simulates both:
1. Vulnerable legacy endpoints (Planted BOLA / IDOR):
   Returns 200/204 to any caller regardless of ownership.
2. D1-Protected endpoints:
   Enforces tenant/user isolation: returns 404 Not Found when
   Persona B attempts to access Persona A's resource.
3. Function-level endpoints for the persona matrix:
   /api/admin/users/{id} (BFLA: any logged-in user may delete),
   /api/secure-admin/users/{id} (admin only),
   /api/profile (mass assignment: every body field is stored),
   /api/safe-profile (only name and email are stored).
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from typing import Dict, Optional, Tuple

ADMIN_TOKEN = "token-admin"
PROFILE_FIELDS = ("name", "email")


class MockAuthzHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler simulating vulnerable and secure endpoints."""

    def _get_bearer_token(self) -> Optional[str]:
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:].strip()
        return None

    def _send_json(self, status: int, data: dict) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _profile(self, token: str) -> Dict[str, object]:
        store = getattr(self.server, "profiles", None)
        if store is None:
            store = {}
            setattr(self.server, "profiles", store)
        return store.setdefault(token, {"name": "User", "email": "user@example.test", "role": "member"})

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return {}
        return body if isinstance(body, dict) else {}

    def _handle_profile(self, method: str, token: Optional[str]) -> bool:
        """Profile routes. Returns True when the path was handled."""
        path = self.path.split("?")[0]
        if path not in ("/api/profile", "/api/safe-profile"):
            return False
        if not token:
            self._send_json(401, {"error": "Login required"})
            return True
        profile = self._profile(f"{path}:{token}")
        if method == "PUT":
            body = self._read_json_body()
            if path == "/api/profile":
                profile.update(body)  # Planted mass assignment
            else:
                profile.update({k: v for k, v in body.items() if k in PROFILE_FIELDS})
        self._send_json(200, profile)
        return True

    def _handle_admin(self, token: Optional[str]) -> bool:
        """Admin user deletion. Returns True when the path was handled."""
        if not self.path.startswith(("/api/admin/users/", "/api/secure-admin/users/")):
            return False
        if not token:
            self._send_json(401, {"error": "Login required"})
        elif self.path.startswith("/api/secure-admin/") and token != ADMIN_TOKEN:
            self._send_json(403, {"error": "Admin role required"})
        else:
            self._send_no_content()  # /api/admin/ has no role check (planted BFLA)
        return True

    def _send_no_content(self) -> None:
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        token = self._get_bearer_token()
        if self._handle_profile("GET", token):
            return

        # Planted BOLA endpoint: leaking Persona A's order to anyone
        if self.path.startswith("/api/legacy-orders/"):
            order_id = self.path.split("/")[-1]
            self._send_json(200, {
                "id": order_id,
                "owner": "user_a",
                "secret_details": "Unprotected legacy order data",
            })
            return

        # D1-Protected endpoint: 404 for non-owners
        if self.path.startswith("/api/orders/"):
            order_id = self.path.split("/")[-1]
            if token == "token-user-a":
                self._send_json(200, {
                    "id": order_id,
                    "owner": "user_a",
                    "status": "active",
                })
            else:
                # Persona B or unauthenticated -> 404 Not Found (BOLA prevention)
                self._send_json(404, {"error": "Order not found"})
            return

        self._send_json(404, {"error": "Not found"})

    def do_PUT(self) -> None:
        token = self._get_bearer_token()
        if self._handle_profile("PUT", token):
            return

        if self.path.startswith("/api/legacy-orders/"):
            order_id = self.path.split("/")[-1]
            self._send_json(200, {
                "id": order_id,
                "message": "Order updated without ownership check",
            })
            return

        if self.path.startswith("/api/orders/"):
            if token == "token-user-a":
                self._send_json(200, {"message": "Order updated"})
            else:
                self._send_json(404, {"error": "Order not found"})
            return

        self._send_json(404, {"error": "Not found"})

    def do_DELETE(self) -> None:
        token = self._get_bearer_token()
        if self._handle_admin(token):
            return

        if self.path.startswith("/api/legacy-orders/"):
            # Planted BOLA: destructive action allowed cross-user
            self._send_no_content()
            return

        if self.path.startswith("/api/orders/"):
            if token == "token-user-a":
                self._send_no_content()
            else:
                self._send_json(404, {"error": "Order not found"})
            return

        self._send_json(404, {"error": "Not found"})

    def log_message(self, format: str, *args: object) -> None:
        # Suppress standard logging during automated tests
        pass


def start_mock_server(port: int = 0) -> Tuple[HTTPServer, threading.Thread, str]:
    """Start the mock server in a background thread."""
    server = HTTPServer(("127.0.0.1", port), MockAuthzHandler)
    actual_port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{actual_port}"
    return server, thread, base_url


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8089
    server = HTTPServer(("127.0.0.1", port), MockAuthzHandler)
    print(f"Mock Authz Server listening on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down mock server.")
        server.server_close()
