#!/usr/bin/env python3
"""Tier 1 hints for broken function level authorization (BFLA, OWASP API5).

annotate_privilege() adds to each route candidate:
  privilege_hint         "privileged" (admin-like path / handler / sensitive write) or "unknown"
  privilege_reasons      why, e.g. ["path:admin", "write:users"]
  role_checks            server-side role checks that apply: {hint, line, scope: route|file}
  bfla_signals           {signal, line, hint}; signal is one of
                           no_role_check          privileged route, no server-side role check
                           role_from_request      role / admin flag read from request input
                           client_side_role_check role check only around markup (menu, link)
  needs_bfla_audit_hint  True when any signal is present

The code a route owns is its handler line (extended up over the annotations or
attributes directly above it) to the line before the next route in the same file.
Class-level annotations, router.use(...) and before_action lines above the first
route apply to every route in the file; a guard function that is only defined
there does not.

These are hints for the Tier 2 auditor, not findings. Standard-library-only (Python 3.8+).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lsa_common import read_text  # noqa: E402

PRIV_TOKENS = {
    "admin", "admins", "administrator", "administrators", "administration", "administrative",
    "manage", "management", "manager", "backoffice", "internal", "staff", "superuser", "sysadmin",
    "console", "role", "roles", "permission", "permissions", "privilege", "privileges", "acl",
    "grant", "grants", "impersonate", "impersonation", "export", "bulk", "purge",
}

SENSITIVE_WRITE_RES = [
    re.compile(r"(?i)\bdelete\s+from\s+[`\"\[]?(?:\w+\.)?(users?|accounts?|members?|roles?|permissions?|user_roles)\b"),
    re.compile(r"(?i)\binsert\s+into\s+[`\"\[]?(?:\w+\.)?(roles?|permissions?|user_roles|role_assignments)\b"),
    re.compile(r"(?i)\bupdate\s+[`\"\[]?(?:\w+\.)?(users?|accounts?|members?)[`\"\]]?\s+set\b[^;\n]{0,120}?"
               r"\b(?:role|is_?admin|admin|permissions?|privileges?|level|user_?type)\s*="),
    re.compile(r"(?i)\bupdate\s+[`\"\[]?(?:\w+\.)?(roles?|permissions?|settings|config)\b"),
]

ROLE_CHECK_RE = re.compile("|".join([
    r"@PreAuthorize|@Secured|@RolesAllowed|\bisUserInRole\b|\bIsInRole\b|\bhas(?:Any)?Role\b|\bhas(?:Any)?Authority\b",
    r"Authorize\s*\(\s*(?:Roles|Policy)\s*=",
    r"\bis_?admin\b|\bis_?super_?user\b|\bis_?staff\b|\badmin_?required\b|\broles?_required\b|\bpermission_required\b",
    r"\b(?:require|ensure|check|verify|assert)_?(?:admin|role|roles|permission|permissions)\b",
    r"\bhas_perm\b|\bauthorize!|\.admin\?|\bcan\?\s*[:(]",
    r"\brole\b['\"]?\s*\]?\s*(?:===?|!==?|<>|\beq\b|\bne\b)",
    r"Gate::(?:allows|denies|authorize)|->can\s*\(|\bcan\s*\(\s*['\"]|->authorize\s*\(",
    r"\$_SESSION\s*\[\s*['\"](?:role|is_?admin|admin|user_?role|level|privilege)['\"]\s*\]",
    r"Session\s*[\(\[]\s*\"(?:role|isadmin|is_admin|admin|level)\"|session\.(?:role|isadmin|is_admin|admin)\b",
    r"\$session->param\s*\(\s*['\"](?:role|admin)",
    r"(?:include|require)(?:_once)?\s*\(?\s*['\"](?:[^'\"]*/)?[^/'\"]*(?:admin|role|perm|acl)[^/'\"]*['\"]",
]), re.I)

_ROLE_NAMES = r"(?:role|is_?admin|isadmin|admin|user_?role|userrole|level|privilege|access_?level|user_?type)"
ROLE_FROM_REQUEST_RE = re.compile("|".join([
    r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]" + _ROLE_NAMES + r"['\"]",
    r"\breq\.(?:body|query|params|cookies|headers)\s*(?:\.|\[\s*['\"])" + _ROLE_NAMES + r"\b",
    r"\brequest\.(?:getParameter|getHeader)\s*\(\s*\"" + _ROLE_NAMES + r"\"",
    r"\bRequest(?:\.QueryString|\.Form|\.Cookies)?\s*[\(\[]\s*\"" + _ROLE_NAMES + r"\"",
    r"\brequest\.(?:args|form|cookies|values|json|GET|POST)\s*(?:\.get\s*\(|\[)\s*['\"]" + _ROLE_NAMES + r"['\"]",
    r"\bparams\s*\[\s*:" + _ROLE_NAMES + r"\s*\]",
    r"\b(?:url|form|cookie)\.(?:role|isadmin|is_admin|admin)\b",
    r"\bparam\s*\(\s*['\"]" + _ROLE_NAMES + r"['\"]",
]), re.I)

CONDITION_RE = re.compile(r"(?i)\bif\b|\?|={2,3}|!==?|<>|\bcfif\b|\bunless\b|\beq\b|\bne\b|\bwhen\b")
VIEW_RE = re.compile(
    r"(?i)<(?:a|button|li|ul|div|span|nav|form|input|option|td|tr|menu)\b|\.(?:show|hide)\s*\(|display\s*[:=]"
    r"|visible\s*=|\bhidden\b|\bv-if\b|\bng-if\b|\{\{|<c:if\b"
)
ANNOTATION_RE = re.compile(r"^\s*(?:@[A-Za-z]|\[[A-Za-z])")
APPLIED_RE = re.compile(r"^\s*(?:@[A-Za-z]|\[[A-Za-z])|\.use\s*\(|\bbefore_(?:action|filter|request)\b")


def _tokens(*parts: Optional[str]) -> List[str]:
    out: List[str] = []
    for part in parts:
        if not part:
            continue
        spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", part)
        out += [t.lower() for t in re.split(r"[^A-Za-z0-9]+", spaced) if t]
        out += [t.lower() for t in re.findall(r"back-?office", part, re.I)]
    return [t.replace("-", "") for t in out]


def is_privileged(path: str, rel: str, symbol: Optional[str], code: str) -> Tuple[bool, List[str]]:
    """Admin-like path / handler file / symbol, or a write to users, roles, permissions or settings."""
    reasons = [f"path:{t}" for t in dict.fromkeys(_tokens(path, rel, symbol)) if t in PRIV_TOKENS]
    for rx in SENSITIVE_WRITE_RES:
        for m in rx.finditer(code):
            reason = f"write:{m.group(1).lower()}"
            if reason not in reasons:
                reasons.append(reason)
    return bool(reasons), reasons


def _route_start(lines: List[str], handler_line: int) -> int:
    start = max(1, min(handler_line, len(lines)))
    while start > 1 and ANNOTATION_RE.match(lines[start - 2]):
        start -= 1
    return start


def _scan_lines(lines: List[str], first: int, last: int) -> Dict[str, List[Dict]]:
    found: Dict[str, List[Dict]] = {"server": [], "ui": [], "request": []}
    for no in range(first, last + 1):
        line = lines[no - 1]
        from_request = ROLE_FROM_REQUEST_RE.search(line)
        if from_request:
            found["request"].append({"hint": from_request.group(0)[:80], "line": no, "conditional": bool(CONDITION_RE.search(line))})
            continue
        check = ROLE_CHECK_RE.search(line)
        if check:
            kind = "ui" if VIEW_RE.search(line) else "server"
            found[kind].append({"hint": check.group(0)[:80], "line": no})
    return found


def _annotate_one(route: Dict, lines: List[str], start: int, end: int, header_end: int) -> Dict:
    found = _scan_lines(lines, start, end) if lines else {"server": [], "ui": [], "request": []}
    file_checks = []
    for no in range(1, header_end + 1):
        line = lines[no - 1]
        m = ROLE_CHECK_RE.search(line)
        if m and APPLIED_RE.search(line) and not ROLE_FROM_REQUEST_RE.search(line):
            file_checks.append({"hint": m.group(0)[:80], "line": no, "scope": "file"})
    role_checks = file_checks + [{**c, "scope": "route"} for c in found["server"]]

    code = "\n".join(lines[start - 1:end]) if lines else ""
    privileged, reasons = is_privileged(route.get("path", ""), route["handler"]["file"], route["handler"].get("symbol"), code)

    signals: List[Dict] = []
    for r in found["request"]:
        if r["conditional"] or not role_checks:
            signals.append({"signal": "role_from_request", "line": r["line"], "hint": r["hint"]})
    if privileged and not role_checks:
        if found["ui"]:
            ui = found["ui"][0]
            signals.append({"signal": "client_side_role_check", "line": ui["line"], "hint": ui["hint"]})
        else:
            signals.append({"signal": "no_role_check", "line": route["handler"]["line"], "hint": ", ".join(reasons)})

    return {
        **route,
        "privilege_hint": "privileged" if privileged else "unknown",
        "privilege_reasons": reasons,
        "role_checks": role_checks,
        "bfla_signals": signals,
        "needs_bfla_audit_hint": bool(signals),
    }


def annotate_privilege(routes: List[Dict], target: Path, config: Dict) -> List[Dict]:
    """Return copies of the route candidates with BFLA hints."""
    encodings = config["hints"]["file_encodings"]
    root = target.resolve()
    by_file: Dict[str, List[int]] = {}
    for idx, r in enumerate(routes):
        by_file.setdefault(r["handler"]["file"], []).append(idx)

    out: List[Optional[Dict]] = [None] * len(routes)
    for rel, idxs in by_file.items():
        lines: List[str] = []
        path = (root / rel).resolve()
        try:
            path.relative_to(root)
            if path.is_file():
                lines = read_text(path, encodings).splitlines()
        except (ValueError, OSError):
            lines = []
        ordered = sorted(idxs, key=lambda i: routes[i]["handler"].get("line") or 1)
        starts = [_route_start(lines, routes[i]["handler"].get("line") or 1) if lines else 1 for i in ordered]
        header_end = (starts[0] - 1) if lines else 0
        for pos, i in enumerate(ordered):
            nxt = [s for s in starts[pos + 1:] if s > starts[pos]]
            end = (nxt[0] - 1) if nxt else len(lines)
            out[i] = _annotate_one(routes[i], lines, starts[pos], end, header_end)
    return [r for r in out if r is not None]
