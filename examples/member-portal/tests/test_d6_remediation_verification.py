#!/usr/bin/env python3
"""Remediation & Continuous Authorization CI Verification for Boilerplate 1 Demo App (B1-D6).

Validates that all accepted security findings from Issue #76 (BOLA & SQLi)
are completely remediated using Komainu D1 and D3 when running in standard (remediated) mode:
1. Launches .NET 8 Member Portal Backend with ENABLE_SECURITY_TEST_VULNERABILITIES=false.
2. Validates legitimate owner (User A) can access their own orders.
3. Runs D5 cross-user test runner against /api/v1/test/legacy-orders/{id} -> verifies exit code 0 ([PASS - SECURE]).
4. Direct HTTP verification: User B (Attacker) receives 404 on GET/PUT/DELETE against User A's order.
5. Verifies legacy search parameterized query neutralizes SQL injection payload.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(CURRENT_DIR)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestRemediationVerification(unittest.TestCase):
    backend_proc: subprocess.Popen | None = None
    port: int = 0
    base_url: str = ""

    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("dotnet"):
            raise unittest.SkipTest(".NET SDK not installed on host")

        cls.port = find_free_port()
        cls.base_url = f"http://127.0.0.1:{cls.port}"

        backend_dir = os.path.join(PROJECT_ROOT, "examples", "member-portal", "backend-dotnet")
        backend_dll = os.path.join(
            backend_dir,
            "bin",
            "Debug",
            "net8.0",
            "MemberPortal.Backend.dll",
        )

        if not os.path.isfile(backend_dll):
            build_res = subprocess.run(
                ["dotnet", "build", backend_dir, "-c", "Debug"],
                capture_output=True,
                text=True,
            )
            if build_res.returncode != 0:
                raise RuntimeError(
                    f"Failed to build .NET backend:\nStdout: {build_res.stdout}\nStderr: {build_res.stderr}"
                )

        env = os.environ.copy()
        env["ASPNETCORE_URLS"] = cls.base_url
        # Explicitly run in remediated mode (default)
        env["ENABLE_SECURITY_TEST_VULNERABILITIES"] = "false"
        env["ConnectionStrings__DefaultConnection"] = f"Data Source={os.path.join(CURRENT_DIR, f'remediation_{cls.port}.db')}"

        cls.backend_proc = subprocess.Popen(
            ["dotnet", backend_dll],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Wait for backend readiness
        ready = False
        health_url = f"{cls.base_url}/api/v1/auth/personas"
        for _ in range(50):
            try:
                with urllib.request.urlopen(health_url, timeout=1.0) as resp:
                    if resp.status == 200:
                        ready = True
                        break
            except Exception:
                time.sleep(0.2)

        if not ready:
            if cls.backend_proc.poll() is not None:
                stdout, stderr = cls.backend_proc.communicate()
                raise RuntimeError(
                    f"Backend process failed to start.\nStdout: {stdout}\nStderr: {stderr}"
                )
            raise TimeoutError(f"Backend failed to respond on {health_url} within 10s")

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.backend_proc and cls.backend_proc.poll() is None:
            cls.backend_proc.terminate()
            try:
                cls.backend_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cls.backend_proc.kill()

        db_path = os.path.join(CURRENT_DIR, f"remediation_{cls.port}.db")
        if os.path.isfile(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass

    def test_01_owner_accesses_rem_legacy_order_succeeds(self) -> None:
        """Owner Alice accesses /api/v1/test/legacy-orders/ord-001 -> 200 OK."""
        url = f"{self.base_url}/api/v1/test/legacy-orders/ord-001"
        req = urllib.request.Request(
            url,
            headers={"Authorization": "Bearer token-user-a"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["id"], "ord-001")
            self.assertEqual(data["ownerUserId"], "user-a")

    def test_02_d5_runner_passes_on_remediated_legacy_orders(self) -> None:
        """D5 cross-user runner confirms BOLA findings are remediated -> exit code 0 ([PASS - SECURE])."""
        runner_script = os.path.join(
            PROJECT_ROOT, "operate", "cross_user_tester", "runner.py"
        )
        proc = subprocess.run(
            [
                sys.executable,
                runner_script,
                "--base-url",
                self.base_url,
                "--auto-crud-path",
                "/api/v1/test/legacy-orders/{id}",
                "--resource-id",
                "ord-001",
                "--attacker-token",
                "token-user-b",
            ],
            capture_output=True,
            text=True,
        )

        self.assertEqual(
            proc.returncode,
            0,
            f"Expected D5 to pass on remediated endpoint.\nOutput:\n{proc.stdout}\nStderr:\n{proc.stderr}",
        )
        self.assertIn("[PASS - SECURE]", proc.stdout)

    def test_03_attacker_direct_get_unauthorized_returns_404(self) -> None:
        """Attacker Bob (token-user-b) attempting to GET ord-001 -> 404 Not Found."""
        url = f"{self.base_url}/api/v1/test/legacy-orders/ord-001"
        req = urllib.request.Request(
            url,
            headers={"Authorization": "Bearer token-user-b"},
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 404)

    def test_04_attacker_direct_put_unauthorized_returns_404(self) -> None:
        """Attacker Bob attempting to PUT ord-001 -> 404 Not Found."""
        url = f"{self.base_url}/api/v1/test/legacy-orders/ord-001"
        payload = json.dumps({"description": "Tampered", "status": "Hacked"}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Authorization": "Bearer token-user-b",
                "Content-Type": "application/json",
            },
            method="PUT",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 404)

    def test_05_attacker_direct_delete_unauthorized_returns_404(self) -> None:
        """Attacker Bob attempting to DELETE ord-001 -> 404 Not Found."""
        url = f"{self.base_url}/api/v1/test/legacy-orders/ord-001"
        req = urllib.request.Request(
            url,
            headers={"Authorization": "Bearer token-user-b"},
            method="DELETE",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 404)

    def test_06_parameterized_search_neutralizes_sqli(self) -> None:
        """SQL injection attempt on /api/v1/test/legacy-search is safely parameterized."""
        injection_payload = "' OR '1'='1"
        query_param = urllib.parse.quote(injection_payload)
        url = f"{self.base_url}/api/v1/test/legacy-search?query={query_param}"
        req = urllib.request.Request(
            url,
            headers={"Authorization": "Bearer token-user-a"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            # When safely parameterized as LIKE '%...%', it searches for the literal string and matches nothing
            self.assertIsInstance(data, list)
            self.assertEqual(len(data), 0)


if __name__ == "__main__":
    unittest.main()
