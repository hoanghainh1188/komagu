"""Operator configuration for testing session-based legacy apps.

Cookie values are read from environment variables or files only. There is
deliberately no flag that takes a cookie value, and no message repeats one.
"""

from __future__ import annotations

import argparse
import os
import stat
from dataclasses import dataclass, field
from typing import List, Mapping, Optional

from operate.cross_user_tester.session_http import (
    DEFAULT_DENY_STATUS,
    STRICT_DENY_STATUS,
    CsrfConfig,
    DenialSignal,
    SessionConfigError,
    SessionRequest,
    fetch_page,
)

__all__ = ["SessionConfigError", "SessionOptions", "read_cookie"]


@dataclass(frozen=True)
class SessionOptions:
    attacker_cookie: Optional[str] = field(default=None, repr=False)
    owner_cookie: Optional[str] = field(default=None, repr=False)
    denial: Optional[DenialSignal] = None
    owner_control_writes: bool = False
    owner_csrf_page: Optional[str] = None
    strict: bool = False
    session_check: Optional[str] = None
    session_marker: Optional[str] = None


def _validated(value: str, label: str) -> str:
    cookie = value.strip()
    if not cookie:
        raise SessionConfigError(f"{label}: the session cookie is empty")
    if "=" not in cookie or not cookie.isascii() or any(ord(c) < 32 or ord(c) == 127 for c in cookie):
        raise SessionConfigError(f"{label}: the session cookie must be one line such as NAME=VALUE; NAME2=VALUE2")
    return cookie


def read_cookie(env_name: Optional[str], file_path: Optional[str], env: Mapping[str, str], label: str) -> Optional[str]:
    """Read a persona's Cookie header value. None when no source is configured."""
    if env_name and file_path:
        raise SessionConfigError(f"{label}: use either a cookie environment variable or a cookie file, not both")
    if env_name:
        if not env.get(env_name):
            raise SessionConfigError(f"{label}: environment variable {env_name} is not set")
        return _validated(env[env_name], label)
    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                return _validated(handle.read(), label)
        except (OSError, UnicodeDecodeError) as err:
            raise SessionConfigError(f"{label}: cannot read the cookie file ({type(err).__name__})") from err
    return None


def cookie_file_is_open(file_path: Optional[str]) -> bool:
    """True when group or others can read a cookie file."""
    if not file_path or os.name != "posix":
        return False
    try:
        return bool(stat.S_IMODE(os.stat(file_path).st_mode) & 0o077)
    except OSError:
        return False


def add_session_arguments(parser: argparse.ArgumentParser) -> None:
    """Flags for session-based apps. None of them takes a secret value."""
    group = parser.add_argument_group("session-based apps (JSP / Struts / old Spring MVC)")
    group.add_argument("--attacker-cookie-env", metavar="VAR", help="Environment variable holding the attacker's Cookie value, e.g. JSESSIONID=...")
    group.add_argument("--attacker-cookie-file", metavar="PATH", help="File holding the attacker's Cookie value")
    group.add_argument("--owner-cookie-env", metavar="VAR", help="Environment variable holding the resource owner's Cookie value")
    group.add_argument("--owner-cookie-file", metavar="PATH", help="File holding the resource owner's Cookie value")
    group.add_argument("--body-format", choices=["auto", "json", "form"], default="auto",
                       help="Request body encoding. auto: form for --from-scan routes ending in .do, .action, .jsp or .jspx; otherwise JSON")
    group.add_argument("--csrf-page", metavar="PATH", help="Page the attacker can open that contains a CSRF or Struts token")
    group.add_argument("--csrf-field", metavar="NAME", help="Token field name, e.g. org.apache.struts.taglib.html.TOKEN")
    group.add_argument("--deny-status", type=int, action="append", metavar="CODE", help="Status that means refused (repeatable)")
    group.add_argument("--deny-redirect", action="append", metavar="TEXT", help="Redirect target containing TEXT means refused (repeatable)")
    group.add_argument("--deny-marker", action="append", metavar="TEXT", help="2xx body containing TEXT means refused (repeatable)")
    group.add_argument("--allow-redirect", action="append", metavar="TEXT", help="Redirect target containing TEXT means the request succeeded (repeatable)")
    group.add_argument("--allow-marker", action="append", metavar="TEXT", help="If set, a 2xx body must contain TEXT to count as served data (repeatable)")
    group.add_argument("--session-check", metavar="PATH", help="Page every session persona can open; checked before and after the run")
    group.add_argument("--session-marker", metavar="TEXT", help="Text that --session-check page must contain")
    group.add_argument("--owner-control-writes", action="store_true",
                       help="Also replay writes as the owner after a denial. This changes the owner's data. Required for --strict to pass a refused write")
    group.add_argument("--owner-csrf-page", metavar="PATH", help="Token page for the owner's replayed writes (default: --csrf-page)")


def _signal(args: argparse.Namespace) -> DenialSignal:
    fallback = STRICT_DENY_STATUS if args.strict else DEFAULT_DENY_STATUS
    texts = (args.deny_redirect or []) + (args.deny_marker or []) + (args.allow_redirect or []) + (args.allow_marker or [])
    if not all(texts):
        raise SessionConfigError("--deny-redirect, --deny-marker, --allow-redirect and --allow-marker cannot be empty")
    return DenialSignal(
        deny_status=tuple(args.deny_status or fallback),
        deny_redirects=tuple(args.deny_redirect or ()),
        deny_markers=tuple(args.deny_marker or ()),
        allow_redirects=tuple(args.allow_redirect or ()),
        allow_markers=tuple(args.allow_marker or ()),
    )


def declared_denial(args: argparse.Namespace) -> bool:
    return bool(args.deny_status or args.deny_redirect or args.deny_marker)


def strict_gaps(args: argparse.Namespace, cookie_attacker: bool, cookie_owner: bool) -> List[str]:
    """What --strict still needs to give a trustworthy verdict on a session app."""
    gaps: List[str] = []
    if not declared_denial(args):
        gaps.append("a denial signal (--deny-status, --deny-redirect or --deny-marker)")
    if not args.session_check:
        gaps.append("--session-check, so an expired session is not read as a refusal")
    if cookie_attacker and not cookie_owner:
        gaps.append("the owner's cookie, so a missing record is not read as a refusal")
    return gaps


def build_session_options(args: argparse.Namespace, env: Mapping[str, str]) -> Optional[SessionOptions]:
    """Options for this run, or None when it is an ordinary Bearer run."""
    attacker = read_cookie(args.attacker_cookie_env, args.attacker_cookie_file, env, "attacker")
    owner = read_cookie(args.owner_cookie_env, args.owner_cookie_file, env, "owner")
    if not (attacker or owner or declared_denial(args) or args.allow_redirect or args.allow_marker or args.session_check):
        return None
    if args.strict and attacker:
        gaps = strict_gaps(args, True, bool(owner))
        if gaps:
            raise SessionConfigError("--strict on a session app needs " + "; ".join(gaps))
    return SessionOptions(
        attacker_cookie=attacker,
        owner_cookie=owner,
        denial=_signal(args),
        owner_control_writes=args.owner_control_writes,
        owner_csrf_page=args.owner_csrf_page,
        strict=args.strict,
        session_check=args.session_check,
        session_marker=args.session_marker,
    )


def global_csrf(args: argparse.Namespace) -> Optional[CsrfConfig]:
    if bool(args.csrf_page) != bool(args.csrf_field):
        raise SessionConfigError("--csrf-page and --csrf-field must be given together")
    if not args.csrf_page:
        return None
    if not args.csrf_page.startswith("/"):
        raise SessionConfigError("--csrf-page must start with '/'")
    return CsrfConfig(page=args.csrf_page, field=args.csrf_field)


def check_session(
    base_url: str,
    label: str,
    cookie: str,
    path: str,
    marker: Optional[str],
    denial: Optional[DenialSignal],
    timeout: float = 10.0,
) -> Optional[str]:
    """Return why this session is unusable, or None when it is alive."""
    reply = fetch_page(base_url.rstrip("/"), path, SessionRequest("GET", path, cookie=cookie), timeout)
    if reply.error:
        return f"{label}: session check failed ({reply.error})"
    if not 200 <= reply.status < 300:
        return f"{label}: session check {path} returned HTTP {reply.status}; the session is expired or invalid"
    if denial and any(m in reply.body for m in denial.deny_markers):
        return f"{label}: session check {path} shows a denial page"
    if marker and marker not in reply.body:
        return f"{label}: session check {path} does not contain the expected text"
    return None
