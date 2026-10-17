#!/usr/bin/env python3
"""
Lightweight mock upstream backend for Komainu edge security test harness.
Echoes received request headers and JSON payloads back to caller.
"""

import json
from http.server import HTTPServer, BaseHTTPRequestHandler

class EchoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self._handle_request()

    def do_POST(self):
        self._handle_request()

    def do_PUT(self):
        self._handle_request()

    def do_DELETE(self):
        self._handle_request()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def _handle_request(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else None

        response_data = {
            "status": "success",
            "message": "Request successfully reached upstream backend",
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "body": body
        }

        response_bytes = json.dumps(response_data, indent=2).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def log_message(self, format, *args):
        # Concise logging to stdout
        print(f"[MOCK-BACKEND] {self.command} {self.path} - {args[1]}")

def run(server_class=HTTPServer, handler_class=EchoHandler, port=5000):
    server_address = ("0.0.0.0", port)
    httpd = server_class(server_address, handler_class)
    print(f"Mock upstream backend listening on port {port}...")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
