#!/usr/bin/env python3
"""Stdio MCP server: handshake, tool catalog, and the local analysis tools (issue #393)."""

from __future__ import annotations

import io
import json
import select
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List

from operate.cli import __version__
from operate.cli.main import main
from operate.mcp.server import LATEST_PROTOCOL, PROTOCOL_VERSIONS, Session, serve
from operate.mcp.tools import INSTRUCTIONS, build_registry

REPO_ROOT = Path(__file__).resolve().parents[2]
BIN_KOMAGU = REPO_ROOT / "bin" / "komagu"
FIXTURE = REPO_ROOT / "assess" / "lsa" / "tests" / "fixtures" / "php-plain"
TOOL_NAMES = ["fix_preview", "inventory", "leak_check", "read_audit", "scan"]


def _initialize(protocol: str = "2025-06-18", request_id: int = 1) -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersion": protocol,
            "capabilities": {},
            "clientInfo": {"name": "komagu-test", "version": "0"},
        },
    }


def exchange(messages: List[Dict[str, Any]], registry=None) -> List[Dict[str, Any]]:
    """Run a session to EOF and return every JSON response."""
    stdin = io.StringIO("".join(json.dumps(message) + "\n" for message in messages))
    stdout = io.StringIO()
    session = Session(registry or build_registry(), __version__, INSTRUCTIONS)
    serve(session, stdin, stdout)
    lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
    for line in lines:
        json.loads(line)  # each response is one JSON value, with no raw newline inside it
        if "\n" in line:
            raise AssertionError(line)
    return [json.loads(line) for line in lines]


def ready_messages() -> List[Dict[str, Any]]:
    """initialize plus the initialized notification."""
    return [
        _initialize(),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]


class TestHandshake(unittest.TestCase):
    def test_supported_protocol_is_echoed(self) -> None:
        for protocol in PROTOCOL_VERSIONS:
            responses = exchange([_initialize(protocol)])
            self.assertEqual(responses[0]["result"]["protocolVersion"], protocol)
            self.assertEqual(responses[0]["result"]["serverInfo"]["name"], "komagu")
            self.assertEqual(responses[0]["result"]["serverInfo"]["version"], __version__)
            self.assertIn("fix_preview", responses[0]["result"]["instructions"])
            self.assertFalse(responses[0]["result"]["capabilities"]["tools"]["listChanged"])

    def test_unknown_protocol_falls_back_to_latest(self) -> None:
        responses = exchange([_initialize("1999-01-01")])
        self.assertEqual(responses[0]["result"]["protocolVersion"], LATEST_PROTOCOL)

    def test_second_initialize_is_rejected(self) -> None:
        responses = exchange([_initialize(request_id=1), _initialize(request_id=2)])
        self.assertEqual(responses[1]["error"]["code"], -32600)

    def test_tools_wait_until_initialized(self) -> None:
        responses = exchange(
            [
                _initialize(),
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            ]
        )
        self.assertEqual(responses[1]["error"]["message"], "Server not initialized")

    def test_initialized_notification_has_no_response(self) -> None:
        responses = exchange(ready_messages())
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0]["id"], 1)

    def test_tools_list_after_initialized(self) -> None:
        responses = exchange(
            ready_messages()
            + [{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}]
        )
        tools = responses[1]["result"]["tools"]
        self.assertEqual([tool["name"] for tool in tools], TOOL_NAMES)
        scan = next(tool for tool in tools if tool["name"] == "scan")
        self.assertIn("target", scan["inputSchema"]["properties"])
        self.assertFalse(scan["annotations"]["destructiveHint"])
        self.assertTrue(next(tool for tool in tools if tool["name"] == "read_audit")["annotations"]["readOnlyHint"])

    def test_unknown_tool_is_an_invalid_params_error(self) -> None:
        responses = exchange(
            ready_messages()
            + [
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "exploit", "arguments": {}},
                }
            ]
        )
        self.assertEqual(responses[1]["error"]["code"], -32602)
        self.assertIn("exploit", responses[1]["error"]["message"])

    def test_parse_error_and_unknown_method(self) -> None:
        stdin = io.StringIO(
            "\n"
            + "not-json\n"
            + json.dumps(_initialize())
            + "\n"
            + json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
            + "\n"
            + json.dumps({"jsonrpc": "2.0", "id": 9, "method": "resources/list"})
            + "\n"
        )
        stdout = io.StringIO()
        serve(Session(build_registry(), __version__, INSTRUCTIONS), stdin, stdout)
        responses = [json.loads(line) for line in stdout.getvalue().splitlines() if line.strip()]
        self.assertEqual(responses[0]["error"]["code"], -32700)
        self.assertIsNone(responses[0]["id"])
        self.assertEqual(responses[2]["error"]["code"], -32601)

    def test_ping_and_bad_arguments_are_tool_errors(self) -> None:
        responses = exchange(
            ready_messages()
            + [
                {"jsonrpc": "2.0", "id": "ping-1", "method": "ping"},
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "read_audit", "arguments": {}},
                },
            ]
        )
        self.assertEqual(responses[1]["id"], "ping-1")
        self.assertEqual(responses[1]["result"], {})
        self.assertTrue(responses[2]["result"]["isError"])
        self.assertIn("audit_dir", responses[2]["result"]["content"][0]["text"])


class TestTools(unittest.TestCase):
    def _call(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        responses = exchange(
            ready_messages()
            + [
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                }
            ]
        )
        self.assertNotIn("error", responses[-1])
        return responses[-1]["result"]

    def test_read_audit_lists_finding_metadata_without_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit = Path(tmp)
            (audit / "stack-profile.json").write_text(
                json.dumps({"stacks": [{"id": "php-plain"}]}),
                encoding="utf-8",
            )
            (audit / "findings.json").write_text(
                json.dumps(
                    {
                        "summary": {"total": 1, "by_severity": {"high": 1}},
                        "findings": [
                            {
                                "finding_id": "BOLA-1",
                                "category": "bola",
                                "severity": "high",
                                "title": "missing owner check",
                                "status": "new",
                                "location": {"file": "app.php", "start_line": 12},
                                "evidence": [{"snippet": "SELECT * FROM users WHERE id = " + "request"}],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = self._call("read_audit", {"audit_dir": str(audit)})
            self.assertFalse(result["isError"])
            body = result["structuredContent"]
            self.assertEqual(body["stacks"], ["php-plain"])
            self.assertEqual(body["findings"][0]["finding_id"], "BOLA-1")
            self.assertEqual(body["findings"][0]["start_line"], 12)
            self.assertNotIn("evidence", body["findings"][0])
            self.assertNotIn("SELECT", result["content"][0]["text"])

    def test_leak_check_masks_a_planted_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.md"
            secret = "hunter2hunter2"
            report.write_text(f'String password = "{secret}";\n', encoding="utf-8")
            result = self._call("leak_check", {"paths": [str(report)]})
            body = result["structuredContent"]
            self.assertEqual(body["exitCode"], 1)
            self.assertIn("redaction-pattern", [hit["detector"] for hit in body["hits"]])
            self.assertTrue(all(secret not in hit["masked"] for hit in body["hits"]))
            self.assertNotIn(secret, result["content"][0]["text"])

    def test_inventory_reports_a_shadow_route(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            routes = root / "routes.json"
            spec = root / "openapi.json"
            routes.write_text(
                json.dumps(
                    {
                        "routes": [
                            {"method": "GET", "path": "/api/users/{id}", "location": "app.py:10"},
                            {"method": "POST", "path": "/api/shadow-login", "location": "auth.py:4"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            spec.write_text(
                json.dumps({"openapi": "3.0.0", "paths": {"/api/users/{id}": {"get": {"summary": "Get user"}}}}),
                encoding="utf-8",
            )
            result = self._call("inventory", {"routes": str(routes), "openapi": str(spec)})
            body = result["structuredContent"]
            self.assertGreaterEqual(body["summary"]["shadow_count"], 1)
            self.assertTrue(any(item["path"] == "/api/shadow-login" for item in body["shadow_apis"]))

    def test_fix_preview_does_not_modify_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "app.php"
            original = "<?php echo $_GET['id'];\n"
            source.write_text(original, encoding="utf-8")
            findings = root / "findings.json"
            findings.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "finding_id": "BOLA-1",
                                "category": "bola",
                                "title": "missing owner check",
                                "location": {"file": "app.php", "start_line": 1, "end_line": 1},
                                "severity": "high",
                                "status": "new",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            result = self._call("fix_preview", {"target": str(root), "findings": str(findings)})
            body = result["structuredContent"]
            self.assertTrue(body["dry_run"])
            self.assertEqual(body["applied_count"], 0)
            self.assertFalse(body["modifiedSource"])
            self.assertEqual(source.read_text(encoding="utf-8"), original)
            self.assertFalse(any(root.glob("*.patch")))

    def test_fix_preview_rejects_an_apply_flag(self) -> None:
        result = self._call("fix_preview", {"target": ".", "apply": True})
        self.assertTrue(result["isError"])

    def test_scan_writes_an_audit_and_keeps_protocol_stdout_clean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            result = self._call(
                "scan",
                {"target": str(FIXTURE), "out": str(out), "format": "sarif", "lang": "en"},
            )
            body = result["structuredContent"]
            self.assertEqual(body["exitCode"], 0, body.get("stderrTail"))
            self.assertTrue((out / "findings.json").is_file())
            self.assertTrue((out / "findings.sarif").is_file())
            self.assertIsInstance(body["audit"]["findingsTotal"], int)
            self.assertNotIn("Komagu Security Audit Summary", result["content"][0]["text"])


class TestCli(unittest.TestCase):
    def test_mcp_without_stdio_is_a_usage_error_and_writes_nothing(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        real_out, real_err = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = stdout, stderr
            code = main(["mcp"])
        finally:
            sys.stdout, sys.stderr = real_out, real_err
        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("--stdio", stderr.getvalue())

    def test_help_documents_stdio(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(BIN_KOMAGU), "mcp", "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertIn("--stdio", completed.stdout)
        self.assertIn("dry-run", completed.stdout)

    def test_stdio_process_speaks_json_only(self) -> None:
        proc = subprocess.Popen(
            [sys.executable, str(BIN_KOMAGU), "mcp", "--stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
        err = ""
        try:
            self._send(proc, _initialize("2024-11-05"))
            first = self._recv(proc)
            self.assertTrue(first.startswith("{"), first)
            hello = json.loads(first)
            self.assertEqual(hello["result"]["protocolVersion"], "2024-11-05")
            self.assertEqual(hello["result"]["serverInfo"]["version"], __version__)
            self._send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
            self._send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            listed = json.loads(self._recv(proc))
            names = [tool["name"] for tool in listed["result"]["tools"]]
            self.assertEqual(names, TOOL_NAMES)
            proc.stdin.close()
            proc.wait(timeout=5)
            err = proc.stderr.read()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            proc.stdout.close()
            proc.stderr.close()
            if proc.stdin and not proc.stdin.closed:
                proc.stdin.close()
        self.assertEqual(proc.returncode, 0)
        self.assertIn("stdio", err)

    def _send(self, proc: subprocess.Popen, message: Dict[str, Any]) -> None:
        assert proc.stdin is not None
        proc.stdin.write(json.dumps(message) + "\n")
        proc.stdin.flush()

    def _recv(self, proc: subprocess.Popen, timeout: float = 10) -> str:
        assert proc.stdout is not None
        ready, _, _ = select.select([proc.stdout], [], [], timeout)
        if not ready:
            proc.kill()
            err = proc.stderr.read() if proc.stderr is not None else ""
            self.fail(f"timed out waiting for MCP output: {err}")
        line = proc.stdout.readline()
        self.assertTrue(line, "stdout closed")
        return line


if __name__ == "__main__":
    unittest.main()
