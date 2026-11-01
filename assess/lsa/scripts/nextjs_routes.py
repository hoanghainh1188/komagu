"""Next.js route inventory for map_routes.py. Python 3.8+, standard library only.

Covers App Router route handlers (app/**/route.ts), dynamic server-component pages
(app/**/page.tsx), Pages Router API routes (pages/api/**), and server actions
(files that start with "use server", and inline "use server" functions).
The file path is the URL, so routes come from folder names, not from declarations.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional

from lsa_common import is_id_name, line_of, read_text

JS_EXT = r"(?:[cm]?[jt]s|[jt]sx)"
APP_FILE = re.compile(r"(?:^|/)app/(?:(.+)/)?(route|page)\." + JS_EXT + "$")
PAGES_API = re.compile(r"(?:^|/)pages/(api(?:/.+)?)\." + JS_EXT + "$")
METHODS = "GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS"
HANDLER_DECL = re.compile(r"^export\s+(?:async\s+)?function\s+(" + METHODS + r")\b|^export\s+const\s+(" + METHODS + r")\s*=", re.M)
HANDLER_REEXPORT = re.compile(r"\b\w+\s+as\s+(" + METHODS + r")\b")
TOP_LEVEL = re.compile(r"^(?:export|function|async|const|let|var|class)\b", re.M)
ACTION_EXPORT = re.compile(r"^export\s+(?:default\s+)?async\s+function\s+(\w+)\s*\(|^export\s+const\s+(\w+)\s*=\s*async\s*\(", re.M)
INLINE_ACTION = re.compile(r"\basync\s+function\s+(\w+)\s*\(|\b(?:const|let)\s+(\w+)\s*=\s*async\s*\(")
USE_SERVER_STMT = re.compile(r"\s*['\"]use server['\"]")
REQ_METHOD = re.compile(r"req\.method\s*===?\s*['\"](\w+)['\"]|case\s+['\"](" + METHODS + r")['\"]\s*:")
MIDDLEWARE_FILE = re.compile(r"^(?:src/)?(middleware|proxy)\." + JS_EXT + "$")
MATCHER = re.compile(r"matcher\s*:\s*(\[[^\]]*\]|['\"][^'\"]*['\"])")

QUERY_INPUT = re.compile(r"searchParams\??\.get(?:All)?\(\s*['\"]([\w-]+)['\"]")
FORM_INPUT = re.compile(r"\b\w*[fF]orm\w*\??\.get(?:All)?\(\s*['\"]([\w-]+)['\"]")
JSON_DESTRUCT = re.compile(r"\{([^{}]*)\}\s*=\s*(?:await\s+)?[\w.]+\.(?:json|formData)\(\)")
DESTRUCT_NAME = re.compile(r"(?:^|,)\s*(?:\.\.\.)?(\w+)")

GUARD_HINTS = [re.compile(p) for p in [
    r"\bauth\s*\(\s*\)", r"\bgetServerSession\s*\(", r"\bget(?:Session|User|Auth|CurrentUser)\s*\(", r"\bcurrentUser\s*\(",
    r"\b(?:with|require|ensure|assert)\w*(?:Auth|User|Session|Role|Permission|Admin)\w*\s*\(",
    r"\bpermission\s*:\s*['\"][^'\"]+['\"]", r"\bhas(?:Role|Permission)\s*\(",
    r"redirect\s*\(\s*['\"]/(?:login|signin|sign-in)",
]]


def route_path(folder: Optional[str], prefix: str = "") -> Optional[str]:
    """URL path for an app/ or pages/ folder; None for private (_folder) segments."""
    parts = [prefix] if prefix else []
    for seg in (folder or "").split("/"):
        if not seg or seg.startswith("@") or (seg.startswith("(") and seg.endswith(")")):
            continue  # route group or parallel-route slot: not part of the URL
        if seg.startswith("_"):
            return None
        seg = re.sub(r"^(?:\(\.+\))+", "", seg)  # interception marker (.) (..) (...)
        catch = re.fullmatch(r"\[\[?\.\.\.(\w+)\]\]?", seg)
        dyn = re.fullmatch(r"\[(\w+)\]", seg)
        parts.append("{" + catch.group(1) + "*}" if catch else "{" + dyn.group(1) + "}" if dyn else seg)
    return "/" + "/".join(p for p in parts if p)


def _close(text: str, idx: int, open_ch: str, close_ch: str) -> int:
    """Index of the bracket that closes text[idx] (or len(text))."""
    depth = 0
    for j in range(idx, len(text)):
        if text[j] == open_ch:
            depth += 1
        elif text[j] == close_ch:
            depth -= 1
            if depth == 0:
                return j
    return len(text)


def _starts_with_use_server(text: str) -> bool:
    """True when the first statement of the file is the "use server" directive (comments may come first)."""
    i, n = 0, len(text)
    while i < n:
        if text[i].isspace():
            i += 1
        elif text.startswith("//", i):
            nl = text.find("\n", i)
            i = n if nl == -1 else nl + 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
        else:
            break
    return bool(USE_SERVER_STMT.match(text, i))


def _segment_end(text: str, start: int) -> int:
    nxt = TOP_LEVEL.search(text, text.find("\n", start) + 1 if "\n" in text[start:] else len(text))
    return nxt.start() if nxt else len(text)


def _signature_params(sig: str) -> List[str]:
    """Parameter names of an action signature; FormData parameters are read through .get() instead."""
    names: List[str] = []
    depth, cur, parts = 0, "", []
    for ch in sig:
        depth += ch in "({[<"
        depth -= ch in ")}]>"
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    for part in (p.strip() for p in parts):
        if not part or re.search(r":\s*FormData\b", part):
            continue
        if part.startswith("{"):
            names += DESTRUCT_NAME.findall(part[1:_close(part, 0, "{", "}")])
        else:
            m = re.match(r"(?:\.\.\.)?(\w+)", part)
            if m:
                names.append(m.group(1))
    return names


class NextRoutes:
    def __init__(self, c, rel: str, text: str):
        self.c, self.rel, self.text = c, rel, text
        self.found = False

    def _param(self, name: str, source: str, line: Optional[int]) -> Dict:
        return {"name": name, "source": source, "line": line, "is_id_like": is_id_name(name, self.c.idp)}

    def inputs(self, path: str, body: str, base_line: int, args: Optional[List[str]] = None) -> List[Dict]:
        out = list(self.c.path_params(path)) if path.startswith("/") else []
        out += [self._param(n, "body", base_line) for n in args or []]
        for rx, src in ((QUERY_INPUT, "query"), (FORM_INPUT, "form")):
            out += [self._param(m.group(1), src, base_line + line_of(body, m.start()) - 1) for m in rx.finditer(body)]
        for m in JSON_DESTRUCT.finditer(body):
            line = base_line + line_of(body, m.start()) - 1
            out += [self._param(n, "body", line) for n in DESTRUCT_NAME.findall(m.group(1))]
        out += self.c.inputs("js", body, base_line)
        seen, dedup = set(), []
        for p in out:
            if p["name"] not in seen:
                seen.add(p["name"])
                dedup.append(p)
        return dedup

    def guards(self, body: str, base_line: int) -> List[Dict]:
        out = self.c.guards(body, base_line)
        for rx in GUARD_HINTS:
            m = rx.search(body)
            if m:
                out.append({"hint": m.group(0)[:80], "line": base_line + line_of(body, m.start()) - 1})
        seen, dedup = set(), []
        for g in sorted(out, key=lambda g: g["line"]):
            if (g["hint"], g["line"]) not in seen:
                seen.add((g["hint"], g["line"]))
                dedup.append(g)
        return dedup[:8]

    def add(self, kind: str, method: List[str], path: str, start: int, end: int, notes: str,
            symbol: Optional[str] = None, args: Optional[List[str]] = None) -> None:
        body = self.text[start:end]
        line = line_of(self.text, start)
        self.c.add(stack="node-nextjs", kind=kind, method=method, path=path,
                   handler={"file": self.rel, "line": line, "symbol": symbol},
                   id_params=self.inputs(path, body, line, args), guard_hints=self.guards(body, line),
                   data_hints=self.c.data_ops(body, line), notes=notes)
        self.found = True

    def route_handlers(self, path: str) -> None:
        decls = list(HANDLER_DECL.finditer(self.text))
        for i, m in enumerate(decls):
            end = decls[i + 1].start() if i + 1 < len(decls) else len(self.text)
            self.add("declared_route", [m.group(1) or m.group(2)], path, m.start(), end, "next.js route handler",
                     symbol=m.group(1) or m.group(2))
        if not decls:
            for m in HANDLER_REEXPORT.finditer(self.text):
                self.add("declared_route", [m.group(1)], path, 0, len(self.text), "next.js route handler (re-exported)",
                         symbol=m.group(1))

    def page(self, path: str) -> None:
        if "{" in path or QUERY_INPUT.search(self.text) or "searchParams" in self.text:
            self.add("file_endpoint", ["GET"], path, 0, len(self.text),
                     "next.js server component page: check data loaded for params/searchParams")

    def pages_api(self, folder: str) -> None:
        folder = re.sub(r"(?:^|/)index$", "", folder) or "api"
        path = route_path(folder)
        if path is None:
            return
        methods = sorted({(m.group(1) or m.group(2)).upper() for m in REQ_METHOD.finditer(self.text)}) or ["ANY"]
        self.add("declared_route", methods, path, 0, len(self.text), "next.js pages/api route")

    def server_actions(self) -> None:
        if _starts_with_use_server(self.text):
            for m in ACTION_EXPORT.finditer(self.text):
                name = m.group(1) or m.group(2)
                paren = m.end() - 1
                args = _signature_params(self.text[paren + 1:_close(self.text, paren, "(", ")")])
                self.add("declared_route", ["POST"], f"action:{self.rel}#{name}", m.start(),
                         _segment_end(self.text, m.start()), "next.js server action (callable by any client with its id)",
                         symbol=name, args=args)
            return
        for m in INLINE_ACTION.finditer(self.text):
            paren = m.end() - 1
            close = _close(self.text, paren, "(", ")")
            brace = self.text.find("{", close)
            if brace == -1 or not USE_SERVER_STMT.match(self.text, brace + 1):
                continue
            name = m.group(1) or m.group(2)
            self.add("declared_route", ["POST"], f"action:{self.rel}#{name}", m.start(),
                     _close(self.text, brace, "{", "}") + 1, "next.js inline server action (closure values are sent to the client encrypted; arguments are not trusted)",
                     symbol=name, args=_signature_params(self.text[paren + 1:close]))


def nextjs_declared(c, rel: str, text: str) -> bool:
    """Add Next.js routes found in one JS/TS file. Returns True when the file is a Next.js entry point."""
    r = NextRoutes(c, rel, text)
    am = APP_FILE.search(rel)
    if am:
        path = route_path(am.group(1))
        if path is not None:
            if am.group(2) == "route":
                r.route_handlers(path)
            else:
                r.page(path)
    pm = PAGES_API.search(rel)
    if pm:
        r.pages_api(pm.group(1))
    r.server_actions()
    return r.found or bool(am or pm)


def middleware_note(target: Path, rels: List[str], enc) -> Optional[str]:
    """Describe middleware.ts / proxy.ts (Next.js 16) so the auditor checks it covers each route."""
    for rel in rels:
        if MIDDLEWARE_FILE.match(rel):
            m = MATCHER.search(read_text(target / rel, enc))
            scope = f"matcher: {m.group(1)[:120]}" if m else "no matcher: runs on every route"
            return f"{rel} runs before this route ({scope}); confirm it enforces auth here"
    return None
