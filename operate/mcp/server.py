"""Newline-delimited JSON-RPC session for the Model Context Protocol.

Supported protocol revisions: 2024-11-05, 2025-03-26, and 2025-06-18.
A requested revision we implement is echoed back. Any other revision is
answered with the newest one this server implements.
"""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any, Dict, IO, Optional, TextIO

from operate.cli import __version__
from operate.mcp.tools import INSTRUCTIONS, ToolError, ToolRegistry, build_registry

JSONRPC = "2.0"
PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18")
LATEST_PROTOCOL = PROTOCOL_VERSIONS[-1]
SERVER_NAME = "komagu"
MAX_LINE_CHARS = 1_048_576
TEXT_CAP = 60_000

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


def error_response(request_id: Any, code: int, message: str) -> Dict[str, Any]:
    """JSON-RPC error object. request_id is null when the request id could not be read."""
    return {"jsonrpc": JSONRPC, "id": request_id, "error": {"code": code, "message": message}}


def success_response(request_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    """JSON-RPC result object."""
    return {"jsonrpc": JSONRPC, "id": request_id, "result": result}


def tool_result(payload: Dict[str, Any], is_error: bool) -> Dict[str, Any]:
    """MCP tools/call result. Text is the payload the client shows the model."""
    if is_error:
        text = payload.get("message", "tool error")
        return {"content": [{"type": "text", "text": text}], "isError": True}
    text = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)
    if len(text) > TEXT_CAP:
        text = text[:TEXT_CAP] + "\n…truncated"
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": payload,
        "isError": False,
    }


class Session:
    """One stdio client. Requests other than initialize and ping wait for initialized."""

    def __init__(self, registry: ToolRegistry, version: str, instructions: str) -> None:
        self.registry = registry
        self.version = version
        self.instructions = instructions
        self.initialized = False
        self.negotiated: Optional[str] = None

    def handle(self, message: Any) -> Optional[Dict[str, Any]]:
        """Return a response, or None when the message is a notification."""
        if not isinstance(message, dict):
            return error_response(None, INVALID_REQUEST, "Invalid Request")

        is_request = "id" in message
        request_id = message.get("id") if is_request else None
        if message.get("jsonrpc") != JSONRPC:
            return error_response(request_id, INVALID_REQUEST, "Invalid Request") if is_request else None

        method = message.get("method")
        if not isinstance(method, str) or not method:
            return error_response(request_id, INVALID_REQUEST, "Invalid Request") if is_request else None

        params = message.get("params", {})
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return error_response(request_id, INVALID_PARAMS, "Invalid params") if is_request else None

        if method == "initialize":
            if not is_request:
                return None
            return self._initialize(request_id, params)

        if method in ("notifications/initialized", "initialized"):
            if self.negotiated is not None:
                self.initialized = True
            return None

        if method == "ping":
            return success_response(request_id, {}) if is_request else None

        if method.startswith("notifications/"):
            return None

        if not is_request:
            return None

        if not self.initialized:
            return error_response(request_id, INVALID_REQUEST, "Server not initialized")

        if method == "tools/list":
            cursor = params.get("cursor")
            if cursor not in (None, ""):
                return error_response(request_id, INVALID_PARAMS, "Unknown cursor")
            return success_response(request_id, {"tools": self.registry.descriptors()})

        if method == "tools/call":
            return self._call_tool(request_id, params)

        if method == "logging/setLevel":
            return success_response(request_id, {})

        return error_response(request_id, METHOD_NOT_FOUND, f"Method not found: {method}")

    def _initialize(self, request_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        if self.negotiated is not None:
            return error_response(request_id, INVALID_REQUEST, "Server already initialized")
        version = params.get("protocolVersion")
        if not isinstance(version, str) or not version:
            return error_response(request_id, INVALID_PARAMS, "protocolVersion is required")
        chosen = version if version in PROTOCOL_VERSIONS else LATEST_PROTOCOL
        self.negotiated = chosen
        return success_response(
            request_id,
            {
                "protocolVersion": chosen,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": self.version},
                "instructions": self.instructions,
            },
        )

    def _call_tool(self, request_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        name = params.get("name")
        if not isinstance(name, str) or not name:
            return error_response(request_id, INVALID_PARAMS, "tool name is required")
        arguments = params.get("arguments", {})
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return error_response(request_id, INVALID_PARAMS, "arguments must be an object")
        try:
            payload = self.registry.call(name, arguments)
        except KeyError:
            return error_response(request_id, INVALID_PARAMS, f"Unknown tool: {name}")
        except ToolError as exc:
            return success_response(request_id, tool_result({"message": str(exc)}, is_error=True))
        except Exception as exc:
            traceback.print_exc(file=sys.stderr)
            return success_response(request_id, tool_result({"message": f"Tool failed: {exc}"}, is_error=True))
        return success_response(request_id, tool_result(payload, is_error=False))


def _write(stdout: TextIO, message: Dict[str, Any]) -> None:
    """One JSON object per line. ensure_ascii keeps the line free of raw separators."""
    stdout.write(json.dumps(message, ensure_ascii=True, separators=(",", ":")) + "\n")
    flush = getattr(stdout, "flush", None)
    if flush is not None:
        flush()


def serve(session: Session, stdin: IO[str], stdout: TextIO) -> None:
    """Read messages until stdin closes. Blank lines are ignored."""
    while True:
        line = stdin.readline()
        if line == "":
            return
        if len(line) > MAX_LINE_CHARS:
            _write(stdout, error_response(None, INVALID_REQUEST, "Message too large"))
            continue
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            _write(stdout, error_response(None, PARSE_ERROR, "Parse error"))
            continue
        if isinstance(message, list):
            _write(stdout, error_response(None, INVALID_REQUEST, "Batch requests are not supported"))
            continue
        response = session.handle(message)
        if response is not None:
            _write(stdout, response)


def serve_stdio() -> int:
    """Serve on process stdin and stdout. Logs go to stderr."""
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
    print("komagu mcp: serving Model Context Protocol on stdio", file=sys.stderr, flush=True)
    session = Session(build_registry(), __version__, INSTRUCTIONS)
    try:
        serve(session, sys.stdin, sys.stdout)
    except BrokenPipeError:
        return 0
    return 0
