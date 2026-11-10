"""HTTP and verdict helpers for session-based legacy apps (JSP / Struts / old Spring MVC).

Redirects are never followed here: a 302 to the login page is the answer to
evaluate, and following it would turn a refusal into a 200. Cookies and CSRF
tokens stay inside the request and are never put in a reply, reason or error.

Python standard library only.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any, Dict, List, Mapping, NamedTuple, Optional, Tuple

ALLOWED = "allowed"
DENIED = "denied"
INCONCLUSIVE = "inconclusive"

DEFAULT_DENY_STATUS = (401, 403, 404)
STRICT_DENY_STATUS = (404,)
BODY_FORMATS = ("json", "form")
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
MAX_BODY_BYTES = 1_000_000
FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"

_FORM_ACTION_SUFFIXES = (".do", ".action", ".jsp", ".jspx")
_STRUTS2_NAME_FIELD = "struts.token.name"
_CHARSET = re.compile(r"charset\s*=\s*[\"']?([A-Za-z0-9_.:-]+)", re.IGNORECASE)
# Pages labelled Shift_JIS are usually cp932 in practice, and Python has no windows-31j alias.
_CHARSET_ALIASES = {
    "windows-31j": "cp932",
    "ms932": "cp932",
    "shift_jis": "cp932",
    "shift-jis": "cp932",
    "sjis": "cp932",
    "x-sjis": "cp932",
}


class SessionConfigError(ValueError):
    """Invalid session, form or CSRF configuration. Messages never contain secret values."""


@dataclass(frozen=True)
class CsrfConfig:
    """Page to fetch and field to read. The token is fetched fresh for every write."""

    page: str
    field: str


@dataclass(frozen=True)
class DenialSignal:
    """How this application says no, and optionally how it says yes."""

    deny_status: Tuple[int, ...] = ()
    deny_redirects: Tuple[str, ...] = ()
    deny_markers: Tuple[str, ...] = ()
    allow_redirects: Tuple[str, ...] = ()
    allow_markers: Tuple[str, ...] = ()

    def declared(self) -> bool:
        return bool(self.deny_status or self.deny_redirects or self.deny_markers)


class HttpReply(NamedTuple):
    status: int
    location: str
    body: str
    error: Optional[str]


class SessionRequest(NamedTuple):
    method: str
    path: str
    cookie: Optional[str] = None
    auth_header: Optional[Tuple[str, str]] = None
    payload: Optional[Dict[str, Any]] = None
    body_format: str = "json"
    csrf: Optional[CsrfConfig] = None
    headers: Optional[Dict[str, str]] = None


def is_form_action(path: str) -> bool:
    """True for routes shaped like a Java legacy form action (/order/update.do)."""
    return path.split("?", 1)[0].lower().endswith(_FORM_ACTION_SUFFIXES)


def parse_body_format(raw: Any, where: str, default: str = "json") -> str:
    if raw is None:
        return default
    if raw not in BODY_FORMATS:
        raise SessionConfigError(f"{where}: body_format must be one of {list(BODY_FORMATS)}")
    return str(raw)


def parse_csrf(raw: Any, where: str, default: Optional[CsrfConfig] = None) -> Optional[CsrfConfig]:
    if raw is None:
        return default
    if not isinstance(raw, dict) or set(raw) != {"page", "field"}:
        raise SessionConfigError(f"{where}: csrf must be an object with 'page' and 'field'")
    page, field_name = raw["page"], raw["field"]
    if not isinstance(page, str) or not page.startswith("/") or not isinstance(field_name, str) or not field_name:
        raise SessionConfigError(f"{where}: csrf.page must start with '/' and csrf.field must be a name")
    return CsrfConfig(page=page, field=field_name)


def encode_form(payload: Mapping[str, Any]) -> bytes:
    """Encode a flat mapping as a form body. Raises ValueError on nested values."""
    for key, value in payload.items():
        if isinstance(value, dict) or (isinstance(value, list) and any(isinstance(v, (dict, list)) for v in value)):
            raise ValueError(f"form field '{key}' must be a plain value")
    return urllib.parse.urlencode(payload, doseq=True).encode("ascii")


def decode_body(raw: bytes, content_type: str) -> str:
    """Decode using the declared charset, so markers in Japanese pages can match."""
    found = _CHARSET.search(content_type or "") or _CHARSET.search(raw[:2048].decode("ascii", "ignore"))
    if found:
        name = found.group(1).lower()
        try:
            return raw.decode(_CHARSET_ALIASES.get(name, name), errors="replace")
        except LookupError:
            pass
    # Nothing usable declared: legacy Japanese pages are often cp932 with no charset at all.
    for encoding in ("utf-8", "cp932"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


class _FieldCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.fields: List[Tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        values = dict(attrs)
        name = values.get("name")
        if not name:
            return
        if tag == "input":
            self.fields.append((name, values.get("value") or ""))
        elif tag == "meta":
            self.fields.append((name, values.get("content") or ""))


def extract_form_token(html: str, field_name: str) -> Optional[Dict[str, str]]:
    """Fields to send for a token, or None when the page does not carry it.

    Struts 2 ``<s:token>`` needs a second field naming the token field, so it
    is returned too.
    """
    collector = _FieldCollector()
    collector.feed(html)
    found = dict(reversed(collector.fields))
    token = found.get(field_name)
    if not token:
        return None
    if found.get(_STRUTS2_NAME_FIELD) == field_name:
        return {_STRUTS2_NAME_FIELD: field_name, field_name: token}
    return {field_name: token}


def safe_location(location: str) -> str:
    """Redirect target fit for a report: no ;jsessionid=, query string or fragment."""
    return re.split(r"[;?#]", location, maxsplit=1)[0]


def _matches(location: str, patterns: Tuple[str, ...]) -> bool:
    # Patterns without '?' look at the path only, so /login.do?next=/list.do is not /list.do.
    return any(p in (location if "?" in p else location.split("?", 1)[0]) for p in patterns)


def _both_signals(where: str) -> str:
    return f"{where} matches both a denial and an allow signal"


def _classify_redirect(signal: DenialSignal, status: int, location: str) -> Tuple[str, str]:
    denied, allowed = _matches(location, signal.deny_redirects), _matches(location, signal.allow_redirects)
    target = safe_location(location) or "(no Location)"
    if denied and allowed:
        return INCONCLUSIVE, _both_signals(f"redirect to {target}")
    if denied:
        return DENIED, f"redirect to {target}"
    if allowed:
        return ALLOWED, f"redirect to {target}"
    return INCONCLUSIVE, f"HTTP {status} redirect to {target} is not a declared denial or allow target"


def _classify_page(signal: DenialSignal, body: str) -> Tuple[str, str]:
    denied = any(m in body for m in signal.deny_markers)
    allowed = any(m in body for m in signal.allow_markers)
    if denied and allowed:
        return INCONCLUSIVE, _both_signals("response body")
    if denied:
        return DENIED, "denial marker in response body"
    if allowed or not signal.allow_markers:
        return ALLOWED, "response served without a denial signal"
    return INCONCLUSIVE, "response body has neither a denial nor an allow marker"


def classify(signal: DenialSignal, status: int, location: str, body: str) -> Tuple[str, str]:
    """Return (verdict, reason). Anything not positively identified is inconclusive."""
    if status in signal.deny_status:
        return DENIED, f"HTTP {status} is a declared denial status"
    if 300 <= status < 400:
        return _classify_redirect(signal, status, location)
    if 200 <= status < 300:
        return _classify_page(signal, body)
    return INCONCLUSIVE, f"HTTP {status} is not a declared denial status"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _send(url: str, method: str, headers: Dict[str, str], data: Optional[bytes], timeout: float) -> HttpReply:
    if not url.lower().startswith(("http://", "https://")):
        return HttpReply(0, "", "", "base URL must be an http:// or https:// URL")
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        # The scheme is checked above.
        with opener.open(request, timeout=timeout) as resp:  # nosec B310
            raw = resp.read(MAX_BODY_BYTES)
            return HttpReply(resp.status, "", decode_body(raw, resp.headers.get("Content-Type", "")), None)
    except urllib.error.HTTPError as err:
        raw = err.read(MAX_BODY_BYTES)
        return HttpReply(
            err.code, err.headers.get("Location", ""), decode_body(raw, err.headers.get("Content-Type", "")), None
        )
    except Exception as ex:  # network errors are reported, not raised
        return HttpReply(0, "", "", f"{type(ex).__name__}: request failed")


def _base_headers(req: SessionRequest) -> Dict[str, str]:
    headers: Dict[str, str] = dict(req.headers or {})
    if req.cookie:
        headers["Cookie"] = req.cookie
    if req.auth_header:
        headers[req.auth_header[0]] = req.auth_header[1]
    return headers


def fetch_page(base_url: str, path: str, req: SessionRequest, timeout: float) -> HttpReply:
    """GET a page with the same credentials as ``req``."""
    return _send(f"{base_url}{path}", "GET", _base_headers(req), None, timeout)


def _csrf_fields(base_url: str, req: SessionRequest, timeout: float) -> Tuple[Dict[str, str], Optional[str]]:
    assert req.csrf is not None
    page = fetch_page(base_url, req.csrf.page, req, timeout)
    if page.error or not 200 <= page.status < 300:
        return {}, f"CSRF page {req.csrf.page} failed: {page.error or f'HTTP {page.status}'}"
    fields = extract_form_token(page.body, req.csrf.field)
    if fields is None:
        return {}, f"CSRF token field '{req.csrf.field}' was not found on {req.csrf.page}"
    return fields, None


def deliver(base_url: str, req: SessionRequest, timeout: float) -> HttpReply:
    """Send one request, adding a fresh CSRF token to writes when configured."""
    payload = req.payload
    if req.csrf is not None and req.method in WRITE_METHODS:
        fields, problem = _csrf_fields(base_url, req, timeout)
        if problem:
            return HttpReply(0, "", "", problem)
        payload = {**(payload or {}), **fields}

    headers = _base_headers(req)
    data: Optional[bytes] = None
    if payload is not None:
        try:
            data = encode_form(payload) if req.body_format == "form" else json.dumps(payload).encode("utf-8")
        except ValueError as err:
            return HttpReply(0, "", "", str(err))
        headers.setdefault("Content-Type", FORM_CONTENT_TYPE if req.body_format == "form" else "application/json")
    return _send(f"{base_url}{req.path}", req.method, headers, data, timeout)
