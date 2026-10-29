#!/usr/bin/env python3
"""Persona matrix (test suite v2) for function-level authorization testing.

Suite v2 lists personas and, for every route, the personas that are allowed
to call it. Every other persona is sent the request and must be refused:

- BFLA (OWASP API5:2023, CWE-285): a persona outside ``allow`` gets 2xx.
- Mass assignment (OWASP API3:2023, CWE-915): an allowed persona sends a
  normal write plus privileged fields; reading the object back shows that a
  privileged field was stored.

Tokens are read only from environment variables (``token_env``). They never
appear in a suite file, a result or a report.

Python standard library only.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

SUITE_VERSION = 2
DENY_STATUS = (401, 403, 404)
STRICT_DENY_STATUS = (404,)
ALLOW_STATUS = (200, 201, 202, 204)
WRITE_METHODS = ("POST", "PUT", "PATCH")
HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
DEFAULT_PROBE_FIELDS = {"role": "admin", "is_admin": True}
MAX_BODY_BYTES = 1_000_000

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PLACEHOLDER = re.compile(r"\{([A-Za-z0-9_-]+)\}|:([A-Za-z_][A-Za-z0-9_]*)")
_PERSONA_KEYS = {"token_env", "description"}
_ROUTE_KEYS = {"name", "method", "path", "params", "payload", "allow", "mass_assignment_probe"}
_PROBE_KEYS = {"fields", "persona", "readback"}


class SuiteError(ValueError):
    """Raised when a v2 suite file is invalid."""


@dataclass(frozen=True)
class Persona:
    name: str
    token_env: Optional[str] = None


@dataclass(frozen=True)
class MatrixCase:
    """One request (BFLA) or one write + readback (mass assignment)."""

    kind: str  # "bfla" | "mass_assignment"
    name: str
    persona: Persona
    method: str
    path: str
    payload: Optional[Dict[str, Any]] = None
    probe_fields: Optional[Dict[str, Any]] = None
    readback: Optional[Tuple[str, str]] = None
    finding_id: Optional[str] = None


@dataclass(frozen=True)
class MatrixResult:
    case: MatrixCase
    status_code: int
    is_breach: bool
    is_secure: bool
    duration_ms: float
    error_message: Optional[str] = None
    persisted_fields: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        c = self.case
        return {
            "name": c.name,
            "category": c.kind,
            "finding_id": c.finding_id,
            "persona": c.persona.name,
            "method": c.method,
            "path": c.path,
            "status_code": self.status_code,
            "is_breach": self.is_breach,
            "is_secure": self.is_secure,
            "persisted_fields": list(self.persisted_fields),
            "duration_ms": round(self.duration_ms, 2),
            "error_message": self.error_message,
        }


# ---------------------------------------------------------------- loading


def is_v2_suite(data: Any) -> bool:
    return isinstance(data, dict) and data.get("version") == SUITE_VERSION


def _parse_personas(raw: Any) -> Dict[str, Persona]:
    if not isinstance(raw, dict) or not raw:
        raise SuiteError("'personas' must be a non-empty object")
    personas: Dict[str, Persona] = {}
    for name, spec in raw.items():
        if not isinstance(spec, dict):
            raise SuiteError(f"persona '{name}' must be an object")
        unknown = set(spec) - _PERSONA_KEYS
        if unknown:
            raise SuiteError(
                f"persona '{name}' has unsupported keys {sorted(unknown)}; "
                "tokens must come from an environment variable named in 'token_env'"
            )
        env = spec.get("token_env")
        if env is not None and (not isinstance(env, str) or not _ENV_NAME.match(env)):
            raise SuiteError(f"persona '{name}': token_env must be an environment variable name")
        personas[name] = Persona(name=name, token_env=env)
    return personas


def _parse_readback(raw: Any, default_path: str) -> Tuple[str, str]:
    if raw is None:
        return ("GET", default_path)
    if not isinstance(raw, str) or not raw.strip():
        raise SuiteError("'readback' must be a string such as 'GET /api/profile'")
    parts = raw.split(None, 1)
    if len(parts) == 1:
        return ("GET", parts[0])
    method = parts[0].upper()
    if method not in HTTP_METHODS:
        raise SuiteError(f"readback method '{parts[0]}' is not supported")
    return (method, parts[1].strip())


def fill_path(path: str, params: Mapping[str, Any], default_id: str) -> str:
    """Replace {name} and :name placeholders from params, else with default_id."""

    def repl(m: "re.Match[str]") -> str:
        key = m.group(1) or m.group(2)
        return str(params.get(key, default_id))

    return _PLACEHOLDER.sub(repl, path)


def _route_cases(
    index: int,
    route: Any,
    personas: Dict[str, Persona],
    default_id: str,
) -> List[MatrixCase]:
    if not isinstance(route, dict):
        raise SuiteError(f"routes[{index}] must be an object")
    unknown_keys = set(route) - _ROUTE_KEYS
    if unknown_keys:
        raise SuiteError(f"routes[{index}]: unknown keys {sorted(unknown_keys)}")
    method = str(route.get("method", "GET")).upper()
    if method not in HTTP_METHODS:
        raise SuiteError(f"routes[{index}]: method '{method}' is not supported")
    raw_path = route.get("path")
    if not isinstance(raw_path, str) or not raw_path.startswith("/"):
        raise SuiteError(f"routes[{index}]: 'path' must start with '/'")
    allow = route.get("allow")
    if not isinstance(allow, list):
        raise SuiteError(f"routes[{index}]: 'allow' must be a list of persona names")
    unknown = [p for p in allow if p not in personas]
    if unknown:
        raise SuiteError(f"routes[{index}]: unknown personas in allow: {unknown}")
    params = route.get("params") or {}
    if not isinstance(params, dict):
        raise SuiteError(f"routes[{index}]: 'params' must be an object")
    payload = route.get("payload")
    if payload is not None and not isinstance(payload, dict):
        raise SuiteError(f"routes[{index}]: 'payload' must be an object")

    path = fill_path(raw_path, params, default_id)
    label = route.get("name") or f"{method} {raw_path}"
    cases = [
        MatrixCase(
            kind="bfla",
            name=f"{label} as {p.name}",
            persona=p,
            method=method,
            path=path,
            payload=payload if method in WRITE_METHODS else None,
        )
        for name, p in personas.items()
        if name not in allow
    ]

    probe = route.get("mass_assignment_probe")
    if probe is not None:
        cases.append(_probe_case(index, label, method, path, payload, probe, allow, personas, params, default_id))
    return cases


def _probe_case(
    index: int,
    label: str,
    method: str,
    path: str,
    payload: Optional[Dict[str, Any]],
    probe: Any,
    allow: List[str],
    personas: Dict[str, Persona],
    params: Mapping[str, Any],
    default_id: str,
) -> MatrixCase:
    if method not in WRITE_METHODS:
        raise SuiteError(f"routes[{index}]: mass_assignment_probe needs POST, PUT or PATCH")
    if not isinstance(probe, dict):
        raise SuiteError(f"routes[{index}]: mass_assignment_probe must be an object")
    if set(probe) - _PROBE_KEYS:
        raise SuiteError(f"routes[{index}]: mass_assignment_probe has unknown keys {sorted(set(probe) - _PROBE_KEYS)}")
    fields = probe.get("fields")
    if not isinstance(fields, dict) or not fields:
        raise SuiteError(f"routes[{index}]: mass_assignment_probe.fields must be a non-empty object")
    persona_name = probe.get("persona") or (allow[0] if allow else None)
    if persona_name not in personas:
        raise SuiteError(f"routes[{index}]: mass_assignment_probe needs a persona from allow")
    rb_method, rb_path = _parse_readback(probe.get("readback"), path)
    return MatrixCase(
        kind="mass_assignment",
        name=f"{label} mass assignment probe as {persona_name}",
        persona=personas[persona_name],
        method=method,
        path=path,
        payload=payload,
        probe_fields=dict(fields),
        readback=(rb_method, fill_path(rb_path, params, default_id)),
    )


def load_persona_suite(data: Dict[str, Any], default_id: str = "1") -> List[MatrixCase]:
    """Build matrix cases from a parsed v2 suite."""
    if not is_v2_suite(data):
        raise SuiteError(f"suite 'version' must be {SUITE_VERSION}")
    personas = _parse_personas(data.get("personas"))
    routes = data.get("routes")
    if not isinstance(routes, list) or not routes:
        raise SuiteError("'routes' must be a non-empty list")
    cases: List[MatrixCase] = []
    for i, route in enumerate(routes):
        cases.extend(_route_cases(i, route, personas, default_id))
    return cases


# ---------------------------------------------------------------- from scan


def _keep_finding(item: Dict[str, Any], min_consensus: float) -> bool:
    if str(item.get("status", "confirmed")).lower() in ("rejected", "fixed"):
        return False
    score = (item.get("consensus") or {}).get("score") if isinstance(item.get("consensus"), dict) else None
    try:
        return score is None or float(score) >= min_consensus
    except (TypeError, ValueError):
        return True


def _finding_kind(item: Dict[str, Any]) -> Optional[str]:
    cat = str(item.get("category", "")).lower()
    fid = str(item.get("finding_id", ""))
    if cat == "bfla" or fid.startswith("BFLA"):
        return "bfla"
    if cat == "mass_assignment" or fid.startswith("MASS"):
        return "mass_assignment"
    return None


def generate_matrix_cases_from_findings(
    data: Any,
    token_env: Optional[str],
    default_id: str = "12345",
    min_consensus: float = 0.0,
) -> List[MatrixCase]:
    """Turn BFLA and mass assignment findings into matrix cases.

    BFLA findings are replayed by a normal user (``token_env``) who must be
    refused. Mass assignment findings are probed by the same user with the
    privileged fields from ``attack_vector.fields`` (default: role / is_admin).
    """
    items = data if isinstance(data, list) else (data.get("findings", []) if isinstance(data, dict) else [])
    persona = Persona(name="user", token_env=token_env)
    cases: List[MatrixCase] = []
    for item in items:
        kind = _finding_kind(item)
        if kind is None or not _keep_finding(item, min_consensus):
            continue
        av = item.get("attack_vector") or {}
        ep = item.get("endpoint") or {}
        raw_path = av.get("path") or ep.get("path")
        if not raw_path:
            continue
        path = fill_path(raw_path, {}, default_id)
        methods = [m.strip().upper() for m in str(av.get("method") or ep.get("method") or "GET").split("|") if m.strip()]
        fid = str(item.get("finding_id", ""))
        title = item.get("title", path)
        if kind == "bfla":
            for m in methods:
                cases.append(MatrixCase(
                    kind="bfla", name=f"[{fid}] {title} ({m})", persona=persona,
                    method=m, path=path, payload={} if m in WRITE_METHODS else None, finding_id=fid,
                ))
            continue
        write = next((m for m in methods if m in WRITE_METHODS), None)
        if write is None:
            continue
        fields = av.get("fields") if isinstance(av.get("fields"), dict) and av.get("fields") else DEFAULT_PROBE_FIELDS
        rb_method, rb_path = _parse_readback(av.get("readback"), raw_path)
        cases.append(MatrixCase(
            kind="mass_assignment", name=f"[{fid}] {title} ({write})", persona=persona,
            method=write, path=path, payload={}, probe_fields=dict(fields),
            readback=(rb_method, fill_path(rb_path, {}, default_id)), finding_id=fid,
        ))
    return cases


# ---------------------------------------------------------------- running


def _contains_value(doc: Any, key: str, value: Any, depth: int = 0) -> bool:
    """True if key == value anywhere in doc (objects and lists, 4 levels)."""
    if depth > 4:
        return False
    if isinstance(doc, dict):
        if key in doc and doc[key] == value:
            return True
        return any(_contains_value(v, key, value, depth + 1) for v in doc.values())
    if isinstance(doc, list):
        return any(_contains_value(v, key, value, depth + 1) for v in doc)
    return False


class PersonaMatrixRunner:
    """Runs matrix cases. Tokens are resolved from env at request time."""

    def __init__(
        self,
        base_url: str,
        env: Optional[Mapping[str, str]] = None,
        strict: bool = False,
        auth_header: str = "Authorization",
        token_prefix: str = "Bearer ",
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.env = os.environ if env is None else env
        self.deny_status = STRICT_DENY_STATUS if strict else DENY_STATUS
        self.auth_header = auth_header
        self.token_prefix = token_prefix
        self.timeout = timeout

    def _token(self, persona: Persona) -> Tuple[Optional[str], Optional[str]]:
        """Return (token, error). Anonymous personas have neither."""
        if persona.token_env is None:
            return None, None
        token = self.env.get(persona.token_env)
        if not token:
            return None, f"environment variable {persona.token_env} is not set"
        return token, None

    def _send(self, method: str, path: str, token: Optional[str], body: Optional[Dict[str, Any]]) -> Tuple[int, bytes, Optional[str]]:
        headers: Dict[str, str] = {}
        if token:
            headers[self.auth_header] = f"{self.token_prefix}{token}".strip()
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(f"{self.base_url}{path}", data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read(MAX_BODY_BYTES), None
        except urllib.error.HTTPError as err:
            return err.code, err.read(MAX_BODY_BYTES), None
        except Exception as ex:  # network errors are reported, not raised
            return 0, b"", f"{type(ex).__name__}: {ex}"

    def _readback(self, case: MatrixCase, token: Optional[str]) -> Tuple[Optional[Any], Optional[str]]:
        assert case.readback is not None
        status, raw, err = self._send(case.readback[0], case.readback[1], token, None)
        if err or status not in ALLOW_STATUS:
            return None, err or f"readback {case.readback[0]} {case.readback[1]} returned HTTP {status}"
        try:
            return json.loads(raw.decode("utf-8", errors="replace")), None
        except ValueError:
            return None, "readback response is not JSON"

    def _run_bfla(self, case: MatrixCase, token: Optional[str], start: float) -> MatrixResult:
        status, _, err = self._send(case.method, case.path, token, case.payload)
        return MatrixResult(
            case=case, status_code=status,
            is_breach=status in ALLOW_STATUS, is_secure=status in self.deny_status,
            duration_ms=(time.time() - start) * 1000.0, error_message=err,
        )

    def _run_probe(self, case: MatrixCase, token: Optional[str], start: float) -> MatrixResult:
        fields = case.probe_fields or {}

        def done(status: int, breach: bool, secure: bool, err: Optional[str] = None, persisted: Tuple[str, ...] = ()) -> MatrixResult:
            return MatrixResult(case, status, breach, secure, (time.time() - start) * 1000.0, err, persisted)

        before, err = self._readback(case, token)
        if err:
            return done(0, False, False, err)
        already = [k for k, v in fields.items() if _contains_value(before, k, v)]
        if already:
            return done(0, False, False, f"inconclusive: {', '.join(already)} already has the probe value")
        body = {**(case.payload or {}), **fields}
        status, _, err = self._send(case.method, case.path, token, body)
        if err:
            return done(status, False, False, err)
        if status not in ALLOW_STATUS:
            # The write was refused (e.g. 400/422 for unknown fields): nothing stored.
            return done(status, False, True)
        after, err = self._readback(case, token)
        if err:
            return done(status, False, False, err)
        persisted = tuple(k for k, v in fields.items() if _contains_value(after, k, v))
        return done(status, bool(persisted), not persisted, None, persisted)

    def execute(self, case: MatrixCase) -> MatrixResult:
        start = time.time()
        token, err = self._token(case.persona)
        if err:
            return MatrixResult(case, 0, False, False, 0.0, err)
        if case.kind == "mass_assignment":
            return self._run_probe(case, token, start)
        return self._run_bfla(case, token, start)

    def run(self, cases: List[MatrixCase]) -> List[MatrixResult]:
        return [self.execute(c) for c in cases]


def format_matrix_report(results: List[MatrixResult], deny_status: Tuple[int, ...] = DENY_STATUS) -> Tuple[str, bool]:
    """Human-readable report and overall pass/fail."""
    lines = [
        "============================================================",
        "  KOMAINU PERSONA MATRIX REPORT (BFLA / MASS ASSIGNMENT)",
        "============================================================",
    ]
    breaches = errors = passed = 0
    for r in results:
        c = r.case
        tag = "BFLA BREACH" if c.kind == "bfla" else "MASS ASSIGNMENT"
        if r.is_breach:
            breaches += 1
            extra = f" stored {list(r.persisted_fields)}" if r.persisted_fields else ""
            lines.append(f"[FAIL - {tag}] {c.method} {c.path} as {c.persona.name} -> HTTP {r.status_code}{extra}")
        elif r.is_secure:
            passed += 1
            lines.append(f"[PASS - SECURE]      {c.method} {c.path} as {c.persona.name} -> HTTP {r.status_code}")
        else:
            errors += 1
            why = r.error_message or f"expected {list(deny_status)}"
            lines.append(f"[ERROR - UNEXPECTED] {c.method} {c.path} as {c.persona.name} -> HTTP {r.status_code} ({why})")
    lines.append("------------------------------------------------------------")
    lines.append(f"Result: {passed} Passed, {breaches} Breaches (BFLA/mass assignment), {errors} Errors")
    lines.append("============================================================")
    return "\n".join(lines), breaches == 0 and errors == 0
