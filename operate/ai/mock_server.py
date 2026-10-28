"""Mock OpenAI-compatible LLM Server for testing headless AI scans.

Standard-library only (Python 3.8+ compatible).
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from typing import Callable, Dict, List, Optional, Tuple


class MockLLMHandler(BaseHTTPRequestHandler):
    """Handles /chat/completions requests by returning canned or dynamic responses."""

    # Pluggable response generator: (messages, model) -> str
    response_generator: Optional[Callable[[List[Dict[str, str]], str], str]] = None
    default_response: str = "```json\n{\"status\": \"ok\"}\n```"
    received_requests: List[Dict] = []

    def log_message(self, format: str, *args: object) -> None:
        """Suppress standard HTTP server stderr logging in test output."""
        return

    def do_POST(self) -> None:
        if not self.path.endswith("/chat/completions"):
            self.send_response(404)
            self.end_headers()
            return

        content_len = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_len).decode("utf-8")
        try:
            req_data = json.loads(raw_body)
        except Exception:
            req_data = {}

        MockLLMHandler.received_requests.append(req_data)

        messages = req_data.get("messages", [])
        model = req_data.get("model", "mock-model")

        if MockLLMHandler.response_generator:
            reply_text = MockLLMHandler.response_generator(messages, model)
        else:
            reply_text = MockLLMHandler.default_response

        response_payload = {
            "id": "chatcmpl-mock-12345",
            "object": "chat.completion",
            "created": 1700000000,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": reply_text,
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150,
            },
        }

        data = json.dumps(response_payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def start_mock_llm_server(
    port: int = 0,
    response_generator: Optional[Callable[[List[Dict[str, str]], str], str]] = None,
) -> Tuple[HTTPServer, threading.Thread, str]:
    """Start the mock LLM server in a daemon thread.

    Returns:
        (server, thread, base_url)
    """
    MockLLMHandler.response_generator = response_generator
    MockLLMHandler.received_requests = []

    server = HTTPServer(("127.0.0.1", port), MockLLMHandler)
    assigned_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{assigned_port}/v1"
    return server, thread, base_url
