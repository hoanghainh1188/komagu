#!/usr/bin/env python3
"""Acceptance & Integration Verification for Boilerplate 1 Demo App (B1-D6).

Validates the full chain:
1. Launches .NET 8 Member Portal Backend.
2. Runs D5 cross-user test runner against planted BOLA endpoints -> verifies failure (exit code 1).
3. Runs D5 cross-user test runner against D1 protected endpoints -> verifies clean pass (exit code 0).
4. Verifies verified owner (User A) successfully accesses own records with HTTP 200 OK.
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
import urllib.request

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(CURRENT_DIR)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestDemoAppVerification(unittest.TestCase):
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

        # Automatically build the .NET backend if the compiled artifact is missing (e.g. after git clean)
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
        env["ENABLE_SECURITY_TEST_VULNERABILITIES"] = "true"
        # Use an in-memory or temp SQLite database
        env["ConnectionStrings__DefaultConnection"] = f"Data Source={os.path.join(CURRENT_DIR, f'test_{cls.port}.db')}"

        cls.backend_proc = subprocess.Popen(
            ["dotnet", backend_dll],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Wait for backend to be ready
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

        db_path = os.path.join(CURRENT_DIR, f"test_{cls.port}.db")
        if os.path.isfile(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass

    def test_01_owner_can_access_own_order(self) -> None:
        """Alice (User A) accesses her own order (ord-001) -> 200 OK."""
        url = f"{self.base_url}/api/v1/orders/ord-001"
        req = urllib.request.Request(
            url,
            headers={"Authorization": "Bearer token-user-a"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["id"], "ord-001")
            self.assertEqual(data["ownerUserId"], "user-a")

    def test_02_d5_fails_on_planted_bola(self) -> None:
        """D5 test runner must detect planted BOLA endpoints and exit with code 1."""
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

        self.assertEqual(proc.returncode, 1, f"Expected D5 to fail on BOLA.\nOutput: {proc.stdout}")
        self.assertIn("[FAIL - BOLA BREACH]", proc.stdout)

    def test_03_d5_passes_on_d1_protected_orders(self) -> None:
        """D5 test runner must pass cleanly (exit 0) on Komagu D1-protected endpoints."""
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
                "/api/v1/orders/{id}",
                "--resource-id",
                "ord-001",
                "--attacker-token",
                "token-user-b",
            ],
            capture_output=True,
            text=True,
        )

        self.assertEqual(proc.returncode, 0, f"Expected D5 to pass on D1.\nOutput: {proc.stdout}")
        self.assertIn("[PASS - SECURE]", proc.stdout)

    def test_04_cross_tenant_attacker_blocked(self) -> None:
        """Charlie (User C, Tenant Beta) attempting to access Alice's order -> 404."""
        url = f"{self.base_url}/api/v1/orders/ord-001"
        req = urllib.request.Request(
            url,
            headers={"Authorization": "Bearer token-user-c"},
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 404)

    def test_05_safe_sort_protects_against_sqli(self) -> None:
        """Dynamic sort with injection string throws error or fails safe."""
        url = f"{self.base_url}/api/v1/orders?sort=status;DROP+TABLE+orders;--"
        req = urllib.request.Request(
            url,
            headers={"Authorization": "Bearer token-user-a"},
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        # Server must reject with 400 or 500 SecurityException, not 200
        self.assertIn(ctx.exception.code, [400, 500])


if __name__ == "__main__":
    unittest.main()
