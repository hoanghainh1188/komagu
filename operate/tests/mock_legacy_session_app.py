#!/usr/bin/env python3
"""Small session-based app that behaves like a JSP / Struts application.

Used to rehearse ``komagu test`` on legacy behaviour:

- login state lives in a ``JSESSIONID`` cookie;
- writes are ``application/x-www-form-urlencoded`` and need a single-use Struts token;
- a successful write answers 302 (post/redirect/get);
- a denied request is a 200 Shift_JIS error page, a 302 to login, or a 404,
  depending on ``server.denial``;
- ``server.fixed`` is the ownership check being deployed.
"""

from __future__ import annotations

import secrets
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List, NamedTuple, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

ALICE_COOKIE = "JSESSIONID=sess-alice-0001"
BOB_COOKIE = "JSESSIONID=sess-bob-0002"
EXPIRED_COOKIE = "JSESSIONID=sess-expired-0003"
TOKEN_FIELD = "org.apache.struts.taglib.html.TOKEN"
DENIED_TEXT = "アクセス権限がありません"
LOGIN_REDIRECT = "/login.do;jsessionid=sess-rewritten-url-9999"


class Seen(NamedTuple):
    method: str
    path: str
    cookie: Optional[str]
    authorization: Optional[str]
    content_type: Optional[str]
    body: str


class LegacyHandler(BaseHTTPRequestHandler):
    server: "LegacyServer"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass

    def _user(self) -> Optional[str]:
        cookie = self.headers.get("Cookie", "")
        pairs = dict(p.strip().split("=", 1) for p in cookie.split(";") if "=" in p)
        return self.server.sessions.get(pairs.get("JSESSIONID", ""))

    def _send(self, status: int, body: bytes = b"", charset: str = "UTF-8", location: Optional[str] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", f"text/html; charset={charset}")
        self.send_header("Content-Length", str(len(body)))
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(body)

    def _to_login(self) -> None:
        self._send(302, location=LOGIN_REDIRECT)

    def _deny(self) -> None:
        if self.server.denial == "login_redirect":
            self._to_login()
        elif self.server.denial == "not_found":
            self._send(404, b"<html>Not Found</html>")
        else:
            page = f"<html><body><p>{DENIED_TEXT}</p></body></html>"
            self._send(200, page.encode("cp932"), charset="Windows-31J")

    def _may_access(self, user: str, order_id: str) -> bool:
        owner = self.server.orders.get(order_id)
        if owner is None:
            return False
        return owner == user or not self.server.fixed

    def _record(self, method: str, body: str = "") -> None:
        self.server.seen.append(Seen(
            method, self.path, self.headers.get("Cookie"), self.headers.get("Authorization"),
            self.headers.get("Content-Type"), body,
        ))

    def do_GET(self) -> None:  # noqa: N802
        self._record("GET")
        url = urlsplit(self.path)
        query = parse_qs(url.query)
        if url.path == "/login.do":
            self._send(200, b"<html>Please log in</html>")
            return
        user = self._user()
        if user is None:
            self._to_login()
        elif url.path == "/home.do":
            self._send(200, f"<html>Welcome {user}</html>".encode())
        elif url.path == "/order/view.do":
            self._view(user, query.get("id", [""])[0])
        elif url.path == "/order/edit.do":
            self._edit_form(user)
        else:
            self._send(404, b"<html>No such action</html>")

    def _view(self, user: str, order_id: str) -> None:
        if not self._may_access(user, order_id):
            self._deny()
            return
        self._send(200, f"<html>Order detail {order_id}: secret-note</html>".encode())

    def _edit_form(self, user: str) -> None:
        if self.server.hide_token:
            self._send(200, b"<html><form></form></html>")
            return
        token = secrets.token_hex(8)
        self.server.tokens[user] = token
        # value before name, as some tag libraries render it.
        page = f'<html><form><input value="{token}" type="hidden" name="{TOKEN_FIELD}"></form></html>'
        self._send(200, page.encode())

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        self._record("POST", raw)
        user = self._user()
        if user is None:
            self._to_login()
            return
        if self.headers.get("Content-Type", "").split(";")[0] != "application/x-www-form-urlencoded":
            self._send(415, b"<html>Form post expected</html>")
            return
        form = parse_qs(raw)
        if urlsplit(self.path).path != "/order/update.do":
            self._send(404, b"<html>No such action</html>")
            return
        if form.get(TOKEN_FIELD, [""])[0] != self.server.tokens.pop(user, None):
            self._send(400, b"<html>Invalid token</html>")
            return
        order_id = form.get("id", [""])[0]
        if not self._may_access(user, order_id):
            self._deny()
            return
        self.server.updates.append((user, order_id))
        self._send(302, location="/order/list.do")


class LegacyServer(HTTPServer):
    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), LegacyHandler)
        self.fixed = False
        self.denial = "error_page"
        self.hide_token = False
        self.orders: Dict[str, str] = {"100": "alice", "200": "bob"}
        self.sessions: Dict[str, str] = {"sess-alice-0001": "alice", "sess-bob-0002": "bob"}
        self.tokens: Dict[str, str] = {}
        self.updates: List[Tuple[str, str]] = []
        self.seen: List[Seen] = []


def start_legacy_app() -> Tuple[LegacyServer, str]:
    server = LegacyServer()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}"
