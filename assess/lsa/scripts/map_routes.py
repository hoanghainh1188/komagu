#!/usr/bin/env python3
"""Build a route/endpoint candidate list for a legacy repository (heuristic, high recall).

Usage: map_routes.py TARGET [--config audit-config.json] [--out routes.candidates.json]

The output is a *candidate* list. The route-mapper agent confirms, corrects
and completes it. Favour recall: a noisy candidate is cheap, a missed endpoint
is an unaudited endpoint.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lsa_common import (KIT_VERSION, compile_id_patterns, is_id_name, iter_source_files,  # noqa: E402
                        line_of, load_config, read_text, write_json)
from privilege import annotate_privilege  # noqa: E402

# --------------------------------------------------------------------------------------
# Input sources: (regex, group index of the parameter name, source kind)
# --------------------------------------------------------------------------------------
INPUTS: Dict[str, List[Tuple[re.Pattern, int, str]]] = {
    "php": [
        (re.compile(r"\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]"), 2, "php_super"),
        (re.compile(r"\$HTTP_(GET|POST)_VARS\s*\[\s*['\"]([^'\"]+)['\"]"), 2, "php_super"),
        (re.compile(r"\$this->input->(get|post|cookie|get_post)\s*\(\s*['\"]([^'\"]+)['\"]"), 2, "ci"),
        (re.compile(r"\$this->request->(data|params|query)\s*\[\s*['\"]([^'\"]+)['\"]"), 2, "cake"),
        (re.compile(r"(?:\$request->(?:input|get|query|post)|Input::get|Request::input)\s*\(\s*['\"]([^'\"]+)['\"]"), 1, "any"),
        (re.compile(r"\$this->_getParam\s*\(\s*['\"]([^'\"]+)['\"]"), 1, "any"),
    ],
    "java": [
        (re.compile(r"getParameter(?:Values)?\s*\(\s*\"([^\"]+)\"\s*\)"), 1, "any"),
        (re.compile(r"@RequestParam\s*\(\s*(?:value\s*=\s*|name\s*=\s*)?\"([^\"]+)\""), 1, "query"),
        (re.compile(r"@RequestParam(?:\([^)]*\))?\s+(?:final\s+)?[\w<>\[\]]+\s+(\w+)"), 1, "query"),
        (re.compile(r"@PathVariable(?:\s*\(\s*(?:value\s*=\s*|name\s*=\s*)?\"([^\"]+)\"\s*\))?\s+(?:final\s+)?[\w<>\[\]]+\s+(\w+)"), 2, "path"),
        (re.compile(r"@PathVariable(?:\s*\(\s*(?:value\s*=\s*|name\s*=\s*)?\"([^\"]+)\"\s*\))?\s+(?:val\s+|var\s+)?(\w+)\s*:\s*[\w<>?.\[\]]+"), 2, "path"),
        (re.compile(r"@RequestParam(?:\([^)]*\))?\s+(?:val\s+|var\s+)?(\w+)\s*:\s*[\w<>?.\[\]]+"), 1, "query"),
        (re.compile(r"@(?:PathParam|QueryParam|FormParam)\s*\(\s*\"([^\"]+)\"\s*\)"), 1, "any"),
        (re.compile(r"\$\{\s*param\.(\w+)\s*\}"), 1, "any"),
        (re.compile(r"public\s+void\s+set(\w+)\s*\(\s*(?:String|Long|long|Integer|int)\s+\w+\s*\)"), 1, "struts2_setter"),
    ],
    "dotnet": [
        (re.compile(r"Request\.(QueryString|Form|Params|Cookies)\s*[\[(]\s*\"([^\"]+)\"\s*[\])]"), 2, "dotnet_coll"),
        (re.compile(r"Request\s*[\[(]\s*\"([^\"]+)\"\s*[\])]"), 1, "any"),
        (re.compile(r"RouteData\.Values\s*[\[(]\s*\"([^\"]+)\""), 1, "path"),
        (re.compile(r"(?:Hidden\w*|hf\w*|hdn\w*)\.Value\b"), 0, "hidden_field"),
        (re.compile(r"CommandArgument\b"), 0, "form"),
        (re.compile(r"\b((?:txt|tb|ddl|cbo|cmb|lst|rb|chk|lbl|hid)\w*)\.(?:Text|SelectedValue|SelectedItem\.Value|Checked)\b"), 1, "form"),
    ],
    "asp": [
        (re.compile(r"Request(?:\.(QueryString|Form|Cookies))?\s*\(\s*\"([^\"]+)\"\s*\)", re.I), 2, "asp_coll"),
    ],
    "perl": [
        (re.compile(r"(?:\$\w+->)?(?:url_)?param\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"), 1, "any"),
        (re.compile(r"\$in\s*\{\s*['\"]?(\w+)['\"]?\s*\}"), 1, "any"),
        (re.compile(r"\$ENV\s*\{\s*['\"]?(QUERY_STRING|PATH_INFO)['\"]?\s*\}"), 1, "any"),
    ],
    "cfml": [
        (re.compile(r"\b(url|form|cookie)\.(\w+)", re.I), 2, "cf_scope"),
        (re.compile(r"\b(attributes|rc)\.(\w+)", re.I), 2, "any"),
    ],
    "js": [
        (re.compile(r"req\.(params|query|body|cookies)\.(\w+)"), 2, "node"),
        (re.compile(r"req\.(params|query|body|cookies)\s*\[\s*['\"](\w+)['\"]\s*\]"), 2, "node"),
    ],
    "python": [
        (re.compile(r"request\.(GET|POST|args|form|values|cookies)(?:\.get\(\s*|\[\s*)['\"](\w+)['\"]"), 2, "py"),
    ],
    "ruby": [
        (re.compile(r"params\s*\[\s*:(\w+)\s*\]"), 1, "any"),
        (re.compile(r"params\s*\[\s*['\"](\w+)['\"]\s*\]"), 1, "any"),
    ],
    "rust": [
        (re.compile(r"Path\s*<\s*([^>]+)\s*>"), 1, "path"),
        (re.compile(r"Query\s*<\s*([^>]+)\s*>"), 1, "query"),
        (re.compile(r"Json\s*<\s*([^>]+)\s*>"), 1, "body"),
        (re.compile(r"Form\s*<\s*([^>]+)\s*>"), 1, "form"),
        (re.compile(r"\.match_info\(\)\.get\(\s*\"([^\"]+)\"\s*\)"), 1, "path"),
        (re.compile(r"web::Path\s*<\s*([^>]+)\s*>"), 1, "path"),
        (re.compile(r"web::Query\s*<\s*([^>]+)\s*>"), 1, "query"),
    ],
    "go": [
        (re.compile(r"c\.(?:Param|Params)\s*\(\s*\"([^\"]+)\"\s*\)"), 1, "path"),
        (re.compile(r"c\.(?:Query|QueryParam)\s*\(\s*\"([^\"]+)\"\s*\)"), 1, "query"),
        (re.compile(r"c\.(?:PostForm|FormValue)\s*\(\s*\"([^\"]+)\"\s*\)"), 1, "form"),
        (re.compile(r"r\.(?:FormValue|PostFormValue)\s*\(\s*\"([^\"]+)\"\s*\)"), 1, "form"),
        (re.compile(r"r\.URL\.Query\(\)\.Get\s*\(\s*\"([^\"]+)\"\s*\)"), 1, "query"),
        (re.compile(r"chi\.URLParam\s*\(\s*\w+\s*,\s*\"([^\"]+)\"\s*\)"), 1, "path"),
        (re.compile(r"mux\.Vars\s*\(\s*\w+\s*\)\s*\[\s*\"([^\"]+)\"\s*\]"), 1, "path"),
    ],
}

SOURCE_MAP = {
    "GET": "query", "POST": "form", "REQUEST": "any", "COOKIE": "cookie",
    "get": "query", "post": "form", "cookie": "cookie", "get_post": "any",
    "data": "form", "params": "path", "query": "query",
    "QueryString": "query", "Form": "form", "Params": "any", "Cookies": "cookie",
    "body": "body", "cookies": "cookie", "args": "query", "form": "form", "values": "any",
    "url": "query",
}

GUARD_HINTS = [
    re.compile(p, re.I) for p in [
        r"\$_SESSION\s*\[", r"session_start\s*\(", r"(require|include)(_once)?\s*\(?\s*['\"][^'\"]*(auth|login|check|session|secure|common)[^'\"]*['\"]",
        r"check_?login|is_?logged_?in|require_?login|login_?required|ensure_?(logged_?in|authenticated)|authenticate",
        r"\[Authorize[^\]]*\]|<Authorize[^>]*>|\[AllowAnonymous\]",
        r"@PreAuthorize|@Secured|@RolesAllowed|isUserInRole|getRemoteUser|getUserPrincipal",
        r"session\.getAttribute\s*\(|Session\s*\(\s*\"|Session\s*\[\s*\"|HttpContext\.Current\.User|User\.Identity",
        r"before_(filter|action)\s+:authenticate|current_user|Auth::(user|check|id)|->middleware\s*\(\s*['\"]auth|\$this->Auth->",
        r"passport\.authenticate|req\.(user|session)\b|getAuthUser\s*\(|<cflogin|session\.user",
        r"#include\s+(file|virtual)\s*=\s*\"[^\"]*(auth|login|check|session|secure|common)[^\"]*\"",
        r"\$ENV\s*\{\s*['\"]?REMOTE_USER", r"CGI::Session",
        r"authorize\s*\(|can\s*\(|Gate::|policy|checkOwner|canAccess|isOwner|assertOwner|IsMine|ownership",
    ]
]

DATA_HINTS = [
    ("read", re.compile(r"(?i)\bselect\b[\s\S]{0,80}?\bfrom\b")),
    ("update", re.compile(r"(?i)\bupdate\s+[\w\[\].`\"]+\s+set\b")),
    ("delete", re.compile(r"(?i)\bdelete\s+(from\s+)?[\w\[\].`\"]+")),
    ("create", re.compile(r"(?i)\binsert\s+into\b")),
    ("read", re.compile(r"\b(find|findById|findOne|findByPk|get_where|getById|Find|FirstOrDefault|SingleOrDefault|load|get)\s*\(")),
    ("file_read", re.compile(r"\b(readfile|fopen|file_get_contents|fpassthru|WriteFile|TransmitFile|ReadAllBytes|FileInputStream|send_file|sendFile|res\.download|cfcontent|ADODB\.Stream|open\s*\(\s*[<]?)\b")),
]

LANG_BY_EXT = {
    ".php": "php", ".php3": "php", ".php4": "php", ".php5": "php", ".phtml": "php", ".inc": "php", ".ctp": "php",
    ".java": "java", ".jsp": "java", ".jspf": "java", ".kt": "java", ".groovy": "java",
    ".cs": "dotnet", ".vb": "dotnet", ".aspx": "dotnet", ".ascx": "dotnet", ".ashx": "dotnet", ".asmx": "dotnet", ".svc": "dotnet",
    ".cshtml": "dotnet", ".vbhtml": "dotnet",
    ".asp": "asp", ".asa": "asp",
    ".pl": "perl", ".pm": "perl", ".cgi": "perl",
    ".cfm": "cfml", ".cfc": "cfml", ".cfml": "cfml",
    ".js": "js", ".mjs": "js", ".ts": "js", ".py": "python", ".rb": "ruby",
    ".rs": "rust", ".go": "go",
}

FILE_ENDPOINT_EXTS = {".php", ".php3", ".php4", ".php5", ".phtml", ".jsp", ".aspx", ".ashx", ".asmx", ".svc",
                      ".asp", ".cgi", ".pl", ".cfm", ".cfml"}
INCLUDE_DIR_RE = re.compile(r"(^|/)(inc|incs|include|includes|lib|libs|library|classes|class|config|conf|common|core|"
                            r"functions|helpers?|models?|dao|templates?|views?|partials?|layouts?|lang|language)(/|$)", re.I)
DISPATCH_RE = {
    "php": re.compile(r"switch\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[\s*['\"](\w+)['\"]\s*\]\s*\)"),
    "asp": re.compile(r"Select\s+Case\s+(?:LCase\s*\(\s*|Trim\s*\(\s*)*Request(?:\.\w+)?\s*\(\s*\"(\w+)\"", re.I),
    "perl": re.compile(r"(?:if|elsif)\s*\(\s*(?:\$\w+->)?param\s*\(\s*['\"](\w+)['\"]\s*\)\s*eq"),
    "cfml": re.compile(r"<cfswitch\s+expression\s*=\s*\"#\s*(?:url|form|attributes)\.(\w+)\s*#\"", re.I),
}
CASE_RE = {
    "php": re.compile(r"case\s+['\"]([^'\"]+)['\"]\s*:"),
    "asp": re.compile(r"^\s*Case\s+\"([^\"]+)\"", re.I | re.M),
    "perl": re.compile(r"param\s*\(\s*['\"]\w+['\"]\s*\)\s*eq\s*['\"]([^'\"]+)['\"]"),
    "cfml": re.compile(r"<cfcase\s+value\s*=\s*\"([^\"]+)\"", re.I),
}
PATH_PARAM_RE = re.compile(r"[:{<](?:\w+:)?(\w+)[}>]?|\(\?P<(\w+)>")


class Collector:
    def __init__(self, config: Dict):
        self.config = config
        self.idp = compile_id_patterns(config)
        self.items: List[Dict] = []
        self.extra_guards = [re.compile(re.escape(h)) for h in
                             config["hints"].get("known_auth_helpers", []) + config["hints"].get("known_ownership_helpers", [])]

    def add(self, **kw) -> None:
        kw["route_id"] = f"R-{len(self.items) + 1:04d}"
        self.items.append(kw)

    # --- analysis helpers -------------------------------------------------------------
    def inputs(self, lang: str, text: str, base_line: int = 1) -> List[Dict]:
        out, seen = [], set()
        for rx, grp, kind in INPUTS.get(lang, []):
            for m in rx.finditer(text):
                if grp == 0:
                    name, src = m.group(0).split(".")[0], kind
                else:
                    name = m.group(grp) or (m.group(1) if m.lastindex and m.lastindex >= 1 else "")
                    if not name:
                        continue
                    if kind in ("php_super", "ci", "cake", "dotnet_coll", "asp_coll", "cf_scope", "node", "py"):
                        coll = m.group(1) or ""
                        src = SOURCE_MAP.get(coll, SOURCE_MAP.get(coll.capitalize(), "any")) if coll else "any"
                        if kind == "asp_coll" and not m.group(1):
                            src = "any"
                    elif kind == "struts2_setter":
                        name, src = name[0].lower() + name[1:], "any"
                    else:
                        src = kind
                key = (name, src)
                if key in seen:
                    continue
                seen.add(key)
                out.append({"name": name, "source": src, "line": base_line + line_of(text, m.start()) - 1,
                            "is_id_like": is_id_name(name, self.idp) or src in ("hidden_field",)})
        return out

    def guards(self, text: str, base_line: int = 1, limit: int = 8) -> List[Dict]:
        out = []
        for rx in GUARD_HINTS + self.extra_guards:
            m = rx.search(text)
            if m:
                out.append({"hint": m.group(0)[:80], "line": base_line + line_of(text, m.start()) - 1})
        out.sort(key=lambda g: g["line"])
        return out[:limit]

    @staticmethod
    def data_ops(text: str, base_line: int = 1, limit: int = 10) -> List[Dict]:
        out = []
        for op, rx in DATA_HINTS:
            for m in rx.finditer(text):
                out.append({"op": op, "line": base_line + line_of(text, m.start()) - 1})
                if len(out) >= limit:
                    break
        out.sort(key=lambda d: d["line"])
        dedup, seen = [], set()
        for d in out:
            if (d["op"], d["line"]) not in seen:
                seen.add((d["op"], d["line"]))
                dedup.append(d)
        return dedup[:limit]

    def path_params(self, path: str) -> List[Dict]:
        out = []
        for m in PATH_PARAM_RE.finditer(path):
            name = m.group(1) or m.group(2)
            if name and not name.isdigit():
                out.append({"name": name, "source": "path", "line": None, "is_id_like": True})
        return out


def segments(text: str, decl_rx: re.Pattern) -> List[Tuple[re.Match, int, int]]:
    """Split text into (match, start_index, end_index) blocks starting at each declaration."""
    ms = list(decl_rx.finditer(text))
    out = []
    for i, m in enumerate(ms):
        end = ms[i + 1].start() if i + 1 < len(ms) else len(text)
        out.append((m, m.start(), end))
    return out


# --------------------------------------------------------------------------------------
# Declared-route extractors
# --------------------------------------------------------------------------------------
PHP_METHOD = re.compile(r"^[ \t]*(?:(public|protected|private)\s+)?(?:static\s+)?function\s+&?(\w+)\s*\(", re.M)
JAVA_METHOD_ANN = re.compile(r"@(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|Path)\b\s*(\(([^)]*)\))?")
JAVA_HTTP_ANN = re.compile(r"@(GET|POST|PUT|DELETE|PATCH)\b")
CS_ACTION = re.compile(r"^[ \t]*public\s+(?!record\b|class\b)(?:virtual\s+|async\s+|override\s+|static\s+)*[A-Za-z0-9_<>., \[\]?]+\s+(\w+)\s*\(([^)]*)\)", re.M)
VB_ACTION = re.compile(r"^[ \t]*Public\s+(?:Overridable\s+|Async\s+)*Function\s+(\w+)\s*\(([^)]*)\)\s+As\s+[\w.(<>) ]+", re.M | re.I)
WEBMETHOD = re.compile(r"(\[WebMethod[^\]]*\]|<WebMethod[^>]*>|\[OperationContract[^\]]*\]|<OperationContract[^>]*>)[\s\S]{0,300}?"
                       r"(?:public|Public)\s+(?:[\w<>\[\]]+\s+)*?(?:Function\s+|Sub\s+)?(\w+)\s*\(", re.I)


def php_declared(c: Collector, rel: str, text: str, stacks: set) -> bool:
    found = False
    # Laravel / Slim-like route files
    for m in re.finditer(r"Route::(get|post|put|patch|delete|any|match|resource)\s*\(\s*(\[[^\]]*\]\s*,\s*)?['\"]([^'\"]+)['\"]", text):
        verb, path = m.group(1), m.group(3)
        line = line_of(text, m.start())
        end = text.find(";", m.end())
        stmt = text[m.start(): end if end > 0 else m.end() + 200]
        c.add(stack="php-laravel", kind="declared_route", method=[verb.upper()], path="/" + path.lstrip("/"),
              handler={"file": rel, "line": line, "symbol": None}, id_params=c.path_params(path),
              guard_hints=c.guards(stmt, line) + c.guards(text[:m.start()][-3000:], 1)[:2],
              data_hints=[], notes="handler is in the controller named in this route")
        found = True
    # Controller classes (CodeIgniter / CakePHP / Zend)
    cls = re.search(r"class\s+(\w+?)(Controller)?\s+extends\s+(CI_Controller|MY_Controller|\w*Controller\w*|AppController|Zend_Controller_Action)", text)
    if not cls or "Route::" in text:
        return found
    base = cls.group(1)
    is_zend = cls.group(3) == "Zend_Controller_Action"
    if cls.group(3) in ("AppController",) or (cls.group(2) and not is_zend):
        stack = "php-cakephp" if "php-cakephp" in stacks else "php-mvc"
        ctrl = re.sub(r"(?<!^)(?=[A-Z])", "_", base).lower()
    else:
        stack = "php-zend1" if is_zend else "php-codeigniter"
        ctrl = base.lower()
    for m, s, e in segments(text, PHP_METHOD):
        vis, name = m.group(1), m.group(2)
        if vis in ("private", "protected") or name.startswith("_"):
            continue
        if is_zend:
            if not name.endswith("Action"):
                continue
            name = name[:-6]
        if name in ("beforeFilter", "afterFilter", "beforeRender", "init", "preDispatch", "postDispatch", "initialize"):
            continue
        body = text[s:e]
        line = line_of(text, s)
        args = re.findall(r"\$(\w+)", body[: body.find(")") + 1])
        idps = [{"name": a, "source": "path", "line": line, "is_id_like": is_id_name(a, c.idp)} for a in args]
        c.add(stack=stack, kind="declared_route", method=["ANY"], path=f"/{ctrl}/{name}" + "".join(f"/{{{a}}}" for a in args),
              handler={"file": rel, "line": line, "symbol": f"{base}::{name}"},
              id_params=idps + c.inputs("php", body, line), guard_hints=c.guards(text[:s], 1)[:3] + c.guards(body, line),
              data_hints=c.data_ops(body, line), notes="path is convention-based")
        found = True
    return found


def java_declared(c: Collector, rel: str, text: str) -> bool:
    found = False
    cls_prefix = ""
    cm = re.search(r"@(RequestMapping|Path)\s*\(\s*(?:value\s*=\s*)?\"([^\"]*)\"[^)]*\)\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:public\s+)?(?:abstract\s+)?class", text)
    if cm:
        cls_prefix = cm.group(2)
    is_servlet = re.search(r"extends\s+HttpServlet", text)
    if is_servlet:
        ws = re.search(r"@WebServlet\s*\(\s*(?:urlPatterns\s*=\s*|value\s*=\s*)?\{?\s*\"([^\"]+)\"", text)
        for m in re.finditer(r"(?:public|protected)\s+void\s+(doGet|doPost|doPut|doDelete|service)\s*\(", text):
            start = m.start()
            nxt = re.search(r"\n\s*(?:public|protected|private)\s+[\w<>\[\]]+\s+\w+\s*\(", text[m.end():])
            body = text[start: m.end() + (nxt.start() if nxt else len(text))]
            line = line_of(text, start)
            verb = {"doGet": "GET", "doPost": "POST", "doPut": "PUT", "doDelete": "DELETE"}.get(m.group(1), "ANY")
            c.add(stack="java-servlet", kind="declared_route", method=[verb],
                  path=ws.group(1) if ws else "<see web.xml servlet-mapping>",
                  handler={"file": rel, "line": line, "symbol": m.group(1)},
                  id_params=c.inputs("java", body, line), guard_hints=c.guards(body, line),
                  data_hints=c.data_ops(body, line), notes="" if ws else "resolve path from web.xml")
            found = True
        return found
    anns = list(JAVA_METHOD_ANN.finditer(text))
    for m in anns:
        if cm and m.start() == cm.start():
            continue
        after = text[m.end(): m.end() + 600]
        # skip class-level annotation
        if re.match(r"\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:public\s+)?(?:abstract\s+)?class\b", after):
            continue
        sig = re.search(r"(?:(?:public|protected)\s+[\w<>\[\],.? ]+|fun|(?:override|suspend)\s+fun)\s+(\w+)\s*\(", after)
        if not sig:
            continue
        before = text[:m.start()]
        cls_m = list(re.finditer(r"@(?:RequestMapping|Path)\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?\"([^\"]*)\"[^)]*\)[\s\S]{0,300}?(?:class\b)", before))
        method_cls_prefix = cls_m[-1].group(1) if cls_m else cls_prefix
        args = m.group(3) or ""
        pv = re.search(r"(?:value\s*=\s*|path\s*=\s*)?\{?\s*\"([^\"]*)\"", args)
        sub = pv.group(1) if pv else ""
        verbs = re.findall(r"RequestMethod\.(\w+)", args)
        ann = m.group(1)
        if ann.endswith("Mapping") and ann != "RequestMapping":
            verbs = [ann[:-7].upper()]
        if ann == "Path":
            hv = JAVA_HTTP_ANN.search(text[max(0, m.start() - 200): m.end() + 200])
            verbs = [hv.group(1)] if hv else ["ANY"]
        path = "/" + "/".join(p.strip("/") for p in (method_cls_prefix, sub) if p.strip("/"))
        nxt = re.search(r"\n\s*@(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|Path)\b(?!Variable|Param)", text[m.end():])
        body = text[m.start(): m.end() + (nxt.start() if nxt else len(text))]
        line = line_of(text, m.start())
        c.add(stack="java-spring-mvc" if ann != "Path" else "java-jaxrs", kind="declared_route", method=verbs or ["ANY"],
              path=path, handler={"file": rel, "line": line, "symbol": sig.group(1)},
              id_params=c.path_params(path) + c.inputs("java", body, line),
              guard_hints=c.guards(text[:m.start()][-1500:], 1)[:2] + c.guards(body, line),
              data_hints=c.data_ops(body, line), notes="")
        found = True
    # Struts 1 / 2 Action classes without annotations are mapped from XML (see xml_declared)
    return found


def xml_declared(c: Collector, rel: str, text: str, class_index: Dict[str, str]) -> bool:
    found = False
    if rel.endswith("web.xml"):
        servlets = dict(re.findall(r"<servlet>\s*<servlet-name>\s*([^<]+?)\s*</servlet-name>[\s\S]*?<servlet-class>\s*([^<]+?)\s*</servlet-class>", text))
        for m in re.finditer(r"<servlet-mapping>\s*<servlet-name>\s*([^<]+?)\s*</servlet-name>\s*<url-pattern>\s*([^<]+?)\s*</url-pattern>", text):
            name, pattern = m.group(1), m.group(2)
            cls = servlets.get(name, "")
            hfile = class_index.get(cls.split(".")[-1], rel)
            c.add(stack="java-servlet", kind="declared_route", method=["ANY"], path=pattern,
                  handler={"file": hfile, "line": 1, "symbol": cls or name}, id_params=[], guard_hints=[],
                  data_hints=[], notes=f"mapped in {rel}:{line_of(text, m.start())}")
            found = True
    if "struts-config" in rel:
        for m in re.finditer(r"<action\b([^>]*)>", text):
            attrs = dict(re.findall(r"(\w+)\s*=\s*\"([^\"]*)\"", m.group(1)))
            if "path" not in attrs:
                continue
            cls = attrs.get("type", "")
            hfile = class_index.get(cls.split(".")[-1], rel)
            note = f"declared in {rel}:{line_of(text, m.start())}"
            if attrs.get("parameter"):
                note += f"; DispatchAction parameter '{attrs['parameter']}' -> one endpoint per method"
            c.add(stack="java-struts1", kind="declared_route", method=["ANY"], path=attrs["path"] + ".do",
                  handler={"file": hfile, "line": 1, "symbol": cls}, id_params=[], guard_hints=[], data_hints=[], notes=note)
            found = True
    if rel.endswith("struts.xml"):
        for pm in re.finditer(r"<package\b([^>]*)>([\s\S]*?)</package>", text):
            pattrs = dict(re.findall(r"(\w+)\s*=\s*\"([^\"]*)\"", pm.group(1)))
            ns = pattrs.get("namespace", "/").rstrip("/")
            for am in re.finditer(r"<action\b([^>]*)>", pm.group(2)):
                attrs = dict(re.findall(r"(\w+)\s*=\s*\"([^\"]*)\"", am.group(1)))
                cls = attrs.get("class", "")
                hfile = class_index.get(cls.split(".")[-1], rel)
                c.add(stack="java-struts2", kind="declared_route", method=["ANY"], path=f"{ns}/{attrs.get('name', '?')}.action",
                      handler={"file": hfile, "line": 1, "symbol": f"{cls}#{attrs.get('method', 'execute')}"},
                      id_params=[], guard_hints=[], data_hints=[],
                      notes=f"declared in {rel}:{line_of(text, pm.start() + am.start())}; action setters are inputs")
                found = True
    return found


def dotnet_declared(c: Collector, rel: str, text: str) -> bool:
    found = False
    cm = re.search(r"(?:\[ApiController\][\s\S]{0,100}?)?class\s+(\w+?)Controller\s*(?::\s*(\w+))?|Class\s+(\w+?)Controller[\s\S]{0,80}?Inherits\s+(\w+)", text, re.I)
    if cm:
        ctrl = (cm.group(1) or cm.group(3))
        base_cls = cm.group(2) or cm.group(4) or ""
        api = ("Api" in base_cls) or ("Base" in base_cls) or ("[ApiController]" in text)
        prefix_m = re.search(r"\[(?:RoutePrefix|Route)\(\s*\"([^\"]+)\"\s*\)\]", text)
        prefix = ("/" + prefix_m.group(1).strip("/").replace("[controller]", ctrl.lower())) if prefix_m else (f"/api/{ctrl.lower()}" if api else f"/{ctrl}")
        is_vb = rel.lower().endswith(".vb")
        rx = VB_ACTION if is_vb else CS_ACTION
        ctrl_body = text[cm.end():]
        class_end = ctrl_body.rfind("}")
        if class_end > 0:
            ctrl_body = ctrl_body[:class_end]
        for m, s, e in segments(ctrl_body, rx):
            name = m.group(1)
            if name in ("Dispose", "Initialize", "OnActionExecuting", "ToString", "Equals", "GetHashCode") or name == ctrl + "Controller":
                continue
            pre = ctrl_body[max(0, s - 300): s]
            attr_lines = [line.strip() for line in pre.splitlines() if line.strip().startswith("[")]
            attrs_block = " ".join(attr_lines)
            verbs = re.findall(r"Http(Get|Post|Put|Delete|Patch)", attrs_block) or (
                [v for v in ("Get", "Post", "Put", "Delete") if api and name.startswith(v)][:1]) or ["ANY"]
            http_route = re.search(r"Http(?:Get|Post|Put|Delete|Patch)\s*\(\s*\"([^\"]+)\"", attrs_block)
            route = re.search(r"Route\(\s*\"([^\"]+)\"", attrs_block)
            sub_route = route.group(1) if route else (http_route.group(1) if http_route else None)
            if sub_route:
                if sub_route.startswith("~/") or sub_route.startswith("/"):
                    path = "/" + sub_route.lstrip("~/")
                else:
                    path = f"{prefix.rstrip('/')}/{sub_route.lstrip('/')}"
            else:
                path = prefix if api else f"{prefix}/{name}"
            params = m.group(2)
            line = line_of(text, cm.end() + s)
            idps = []
            for pn in re.findall(r"(?:\b(\w+)\s+As\s+[\w.?]+)|(?:[\w<>?.\[\]]+\s+(\w+)\s*(?:=|,|$))", params):
                n = pn[0] or pn[1]
                if n and n not in ("ByVal", "ByRef", "Optional"):
                    idps.append({"name": n, "source": "any", "line": line, "is_id_like": is_id_name(n, c.idp)})
            body = ctrl_body[s:e]
            c.add(stack="dotnet-webapi" if api else "dotnet-mvc", kind="declared_route", method=[v.upper() for v in verbs],
                  path=path, handler={"file": rel, "line": line, "symbol": f"{ctrl}Controller.{name}"},
                  id_params=idps + c.inputs("dotnet", body, line),
                  guard_hints=c.guards(attrs_block, max(1, line - attrs_block.count("\n"))) + c.guards(text[: cm.end()], 1)[:2] + c.guards(body, line),
                  data_hints=c.data_ops(body, line), notes="" if (route or http_route) else ("path is convention-based" if not api else ""))
            found = True
    for m in WEBMETHOD.finditer(text):
        line = line_of(text, m.start())
        nxt = WEBMETHOD.search(text, m.end())
        body = text[m.start(): nxt.start() if nxt else len(text)]
        c.add(stack="dotnet-asmx-wcf", kind="declared_route", method=["POST"], path=f"/{rel.rsplit('/', 1)[-1].split('.')[0]}.asmx/{m.group(2)}",
              handler={"file": rel, "line": line, "symbol": m.group(2)}, id_params=c.inputs("dotnet", body, line),
              guard_hints=c.guards(body, line), data_hints=c.data_ops(body, line), notes="web/service method; check .asmx/.svc file name")
        found = True
    return found


def cfml_declared(c: Collector, rel: str, text: str) -> bool:
    found = False
    for m, s, e in segments(text, re.compile(r"<cffunction\b([^>]*)>", re.I)):
        attrs = dict((k.lower(), v) for k, v in re.findall(r"(\w+)\s*=\s*\"([^\"]*)\"", m.group(1)))
        if attrs.get("access", "").lower() != "remote":
            continue
        body = text[s:e]
        line = line_of(text, s)
        args = [{"name": a, "source": "any", "line": line, "is_id_like": is_id_name(a, c.idp)}
                for a in re.findall(r"<cfargument\s+name\s*=\s*\"(\w+)\"", body, re.I)]
        c.add(stack="coldfusion", kind="declared_route", method=["ANY"], path=f"/{rel}?method={attrs.get('name', '?')}",
              handler={"file": rel, "line": line, "symbol": attrs.get("name")}, id_params=args + c.inputs("cfml", body, line),
              guard_hints=c.guards(body, line), data_hints=c.data_ops(body, line), notes="remote CFC method")
        found = True
    return found


def js_py_rb_declared(c: Collector, rel: str, text: str, lang: str) -> bool:
    found = False
    if lang == "js":
        if "@Controller" in text or "@nestjs" in text:
            ctrl_m = re.search(r"@Controller\s*\(\s*(?:['\"]([^'\"]*)['\"])?", text)
            ctrl_prefix = ("/" + ctrl_m.group(1).strip("/")) if (ctrl_m and ctrl_m.group(1)) else ""
            for m in re.finditer(r"@(Get|Post|Put|Delete|Patch)\s*\(\s*(?:['\"]([^'\"]*)['\"])?", text):
                sub_path = m.group(2) or ""
                path = "/" + "/".join(p.strip("/") for p in (ctrl_prefix, sub_path) if p.strip("/"))
                line = line_of(text, m.start())
                c.add(stack="node-nestjs", kind="declared_route", method=[m.group(1).upper()], path=path or "/",
                      handler={"file": rel, "line": line, "symbol": None}, id_params=c.path_params(path) + c.inputs("js", text[m.start():m.start() + 400], line),
                      guard_hints=c.guards(text[m.start():m.start() + 400], line), data_hints=c.data_ops(text[m.start():m.start() + 800], line), notes="nestjs controller")
                found = True
        rx = re.compile(r"\b(app|router|\w+Router)\.(get|post|put|patch|delete|all)\s*\(\s*['\"`]([^'\"`]+)['\"`]([^)]*)")
        decls = list(rx.finditer(text))
        for i, m in enumerate(decls):
            end = decls[i + 1].start() if i + 1 < len(decls) else len(text)
            body = text[m.start():end]
            line = line_of(text, m.start())
            pre_use = c.guards(text[:m.start()], 1)[:3]
            c.add(stack="node-express", kind="declared_route", method=[m.group(2).upper()], path=m.group(3),
                  handler={"file": rel, "line": line, "symbol": None}, id_params=c.path_params(m.group(3)) + c.inputs("js", body, line),
                  guard_hints=c.guards(m.group(4), line) + pre_use, data_hints=c.data_ops(body, line),
                  notes="check app.use() order and router mount prefix")
            found = True
    elif lang == "python":
        # FastAPI
        for m in re.finditer(r"@\w+\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)['\"]", text):
            line = line_of(text, m.start())
            c.add(stack="python-fastapi", kind="declared_route", method=[m.group(1).upper()], path=m.group(2),
                  handler={"file": rel, "line": line, "symbol": None}, id_params=c.path_params(m.group(2)) + c.inputs("python", text[m.start():m.start() + 400], line),
                  guard_hints=c.guards(text[m.start():m.start() + 400], line), data_hints=c.data_ops(text[m.start():m.start() + 800], line), notes="fastapi route")
            found = True
        rx = re.compile(r"@\w+\.route\s*\(\s*['\"]([^'\"]+)['\"](?:[^)]*methods\s*=\s*\[([^\]]*)\])?")
        decls = list(rx.finditer(text))
        for i, m in enumerate(decls):
            end = decls[i + 1].start() if i + 1 < len(decls) else len(text)
            body = text[m.start():end]
            line = line_of(text, m.start())
            verbs = re.findall(r"['\"](\w+)['\"]", m.group(2) or "") or ["GET"]
            c.add(stack="python-flask", kind="declared_route", method=[v.upper() for v in verbs], path=m.group(1),
                  handler={"file": rel, "line": line, "symbol": None}, id_params=c.path_params(m.group(1)) + c.inputs("python", body, line),
                  guard_hints=c.guards(body[:400], line), data_hints=c.data_ops(body, line), notes="")
            found = True
        for m in re.finditer(r"\b(?:url|path|re_path)\s*\(\s*r?['\"]([^'\"]*)['\"]\s*,\s*([\w.]+)", text):
            line = line_of(text, m.start())
            c.add(stack="python-django", kind="declared_route", method=["ANY"], path="/" + m.group(1).lstrip("^/").rstrip("$"),
                  handler={"file": rel, "line": line, "symbol": m.group(2)}, id_params=c.path_params(m.group(1)),
                  guard_hints=[], data_hints=[], notes="handler is the view named here")
            found = True
    elif lang == "ruby" and rel.endswith("routes.rb"):
        for m in re.finditer(r"^\s*(get|post|put|patch|delete|match|resources?)\s+['\":]([^'\"\s,]+)", text, re.M):
            line = line_of(text, m.start())
            c.add(stack="ruby-rails", kind="declared_route", method=[m.group(1).upper()], path="/" + m.group(2).lstrip("/"),
                  handler={"file": rel, "line": line, "symbol": None}, id_params=c.path_params(m.group(2)),
                  guard_hints=[], data_hints=[], notes="resolve controller#action; 'resources' = 7 REST actions")
            found = True
        if re.search(r"match\s+['\"]:controller", text):
            c.add(stack="ruby-rails", kind="declared_route", method=["ANY"], path="/:controller(/:action(/:id))",
                  handler={"file": rel, "line": 1, "symbol": None}, id_params=[{"name": "id", "source": "path", "line": None, "is_id_like": True}],
                  guard_hints=[], data_hints=[], notes="catch-all route: every public controller method is reachable")
    return found


RUST_ATTR_ROUTE = re.compile(r"#\[(get|post|put|delete|patch|head|options)\s*\(\s*\"([^\"]+)\"[^\]]*\]\s*"
                             r"(?:#\[[^\]]*\]\s*)*(?:pub(?:\([\w:]+\))?\s+)?(?:async\s+)?fn\s+(\w+)")
RUST_ROCKET_FILE = re.compile(r"\brocket::|extern\s+crate\s+rocket\b|use\s+rocket\b")
AXUM_ROUTE = re.compile(r"\.route\s*\(\s*\"([^\"]+)\"\s*,")
AXUM_METHOD = re.compile(r"(?<!\w)(get|post|put|delete|patch|head|options|any)\s*\(\s*([\w:]+)\s*\)")
GO_ROUTE = re.compile(r"\b(\w+)\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any|All|Handle|HandleFunc|"
                      r"Get|Post|Put|Delete|Patch|Head|Options)\s*\(")
GO_FRAMEWORKS = [("go-gin", "github.com/gin-gonic/gin"), ("go-echo", "github.com/labstack/echo"),
                 ("go-fiber", "github.com/gofiber/fiber"), ("go-chi", "github.com/go-chi/chi"),
                 ("go-gorilla", "github.com/gorilla/mux")]
GO_PATTERN = re.compile(r"^(?:([A-Z]+)\s+)?(/\S*)$")


def call_args(text: str, open_idx: int, limit: int = 4000) -> Tuple[str, int]:
    """Return (argument text, index after the closing paren) for the call whose '(' is at open_idx."""
    depth, i, end = 0, open_idx, min(len(text), open_idx + limit)
    while i < end:
        ch = text[i]
        if ch in "\"`":
            close = text.find(ch, i + 1)
            while ch == '"' and close != -1 and text[close - 1] == "\\":
                close = text.find(ch, close + 1)
            i = close if close != -1 else end
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i], i + 1
        i += 1
    return text[open_idx + 1:end], end


def split_top(args: str) -> List[str]:
    """Split call arguments on top-level commas."""
    parts, depth, cur, quote = [], 0, [], None
    for ch in args:
        if quote:
            quote = None if ch == quote else quote
        elif ch in "\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return parts


def guards_before(c: Collector, text: str, start: int, end: int, span: int = 500) -> List[Dict]:
    ws = max(0, start - span)
    return c.guards(text[ws:end], line_of(text, ws))


def rust_declared(c: Collector, rel: str, text: str) -> bool:
    found = False
    attr_stack = "rust-rocket" if RUST_ROCKET_FILE.search(text) else "rust-actix"
    for m in RUST_ATTR_ROUTE.finditer(text):
        verb, path, fn_name = m.group(1).upper(), m.group(2), m.group(3)
        line = line_of(text, m.start())
        window = text[m.start():m.start() + 400]
        c.add(stack=attr_stack, kind="declared_route", method=[verb], path=path,
              handler={"file": rel, "line": line, "symbol": fn_name},
              id_params=c.path_params(path) + c.inputs("rust", window, line),
              guard_hints=c.guards(window, line),
              data_hints=c.data_ops(text[m.start():m.start() + 800], line),
              notes="rocket handler" if attr_stack == "rust-rocket" else "actix-web handler")
        found = True

    for m in AXUM_ROUTE.finditer(text):
        path = m.group(1)
        args, end = call_args(text, text.index("(", m.start()))
        line = line_of(text, m.start())
        for mm in AXUM_METHOD.finditer(args.split(",", 1)[1] if "," in args else ""):
            c.add(stack="rust-axum", kind="declared_route", method=[mm.group(1).upper()], path=path,
                  handler={"file": rel, "line": line, "symbol": mm.group(2)},
                  id_params=c.path_params(path),
                  guard_hints=guards_before(c, text, m.start(), m.start()),
                  data_hints=[], notes="axum router declaration")
            found = True
    return found


def go_stack(text: str, func: str) -> str:
    for stack, module in GO_FRAMEWORKS:
        if f'"{module}' in text:
            return stack
    if func in ("Handle", "HandleFunc") and '"net/http"' in text:
        return "go-nethttp"
    return "go"


def go_handler_symbol(arg: str) -> Optional[str]:
    if arg.startswith("func"):
        return None
    m = re.match(r"[\w.]+", arg)
    return m.group(0) if m else None


def go_declared(c: Collector, rel: str, text: str) -> bool:
    found = False
    for m in GO_ROUTE.finditer(text):
        args, end = call_args(text, m.end() - 1)
        parts = split_top(args)
        if len(parts) < 2 or parts[0][:1] not in "\"`" or parts[0][-1:] != parts[0][:1]:
            continue
        pm = GO_PATTERN.match(parts[0][1:-1].strip())
        if not pm:
            continue  # not an absolute route path (e.g. c.Get("key", ...), http.Get(url, ...))
        func = m.group(2)
        path = pm.group(2)
        if pm.group(1):
            methods = [pm.group(1)]
        elif func.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            methods = [func.upper()]
        else:
            mm = re.match(r"\s*\.Methods\s*\(([^)]*)\)", text[end:end + 200])
            methods = [v.upper() for v in re.findall(r"\"(\w+)\"", mm.group(1))] if mm else ["ANY"]
        stack = go_stack(text, func)
        handler_arg = parts[1] if stack == "go-echo" else parts[-1]
        line = line_of(text, m.start())
        c.add(stack=stack, kind="declared_route", method=methods or ["ANY"], path=path,
              handler={"file": rel, "line": line, "symbol": go_handler_symbol(handler_arg)},
              id_params=c.path_params(path) + c.inputs("go", args, line),
              guard_hints=guards_before(c, text, m.start(), end),
              data_hints=c.data_ops(args, line), notes="go route declaration")
        found = True
    return found


# --------------------------------------------------------------------------------------
def file_endpoint(c: Collector, rel: str, text: str, lang: str, ext: str, target: Path, enc) -> None:
    handler_rel, body = rel, text
    if ext in (".aspx", ".ashx", ".asmx", ".svc"):
        target_resolved = target.resolve()
        for cb in (rel + ".cs", rel + ".vb"):
            p = target / cb
            if p.exists() and not p.is_symlink():
                try:
                    p.resolve().relative_to(target_resolved)
                except (ValueError, RuntimeError):
                    continue
                handler_rel, body = cb, read_text(p, enc) + "\n" + text
                break
    inputs = c.inputs(lang, body)
    data = c.data_ops(body)
    if not inputs and not data and c.config["scope"].get("file_endpoints", "all") != "all":
        return
    method = ["ANY"]
    if lang == "php":
        has_get = any(i["source"] == "query" for i in inputs)
        has_post = any(i["source"] == "form" for i in inputs)
        method = (["GET"] if has_get else []) + (["POST"] if has_post else []) or ["ANY"]
    web_roots = c.config["scope"].get("web_roots") or []
    path = "/" + rel
    for wr in web_roots:
        wr = wr.strip("/") + "/"
        if rel.startswith(wr):
            path = "/" + rel[len(wr):]
    stack = {"php": "php", "java": "java-jsp", "dotnet": "dotnet-webforms" if ext in (".aspx",) else "dotnet-handlers",
             "asp": "classic-asp", "perl": "perl-cgi", "cfml": "coldfusion"}.get(lang, lang)
    if ext in (".asmx", ".svc"):
        stack = "dotnet-asmx-wcf"
    base = dict(stack=stack, kind="file_endpoint", method=method, path=path,
                handler={"file": handler_rel, "line": 1, "symbol": None}, id_params=inputs,
                guard_hints=c.guards(body), data_hints=data, notes="")
    disp = DISPATCH_RE.get(lang)
    dm = disp.search(text) if disp else None
    if dm:
        cases: Dict[str, int] = {}
        for cm in CASE_RE[lang].finditer(text, dm.start()):
            cases.setdefault(cm.group(1), line_of(text, cm.start()))
        if cases:
            for cv, cline in list(cases.items())[:40]:
                item = dict(base)
                item["handler"] = {"file": handler_rel, "line": cline, "symbol": f"case '{cv}'"}
                item["path"] = f"{path}?{dm.group(1)}={cv}"
                item["notes"] = f"dispatcher on '{dm.group(1)}' (line {line_of(text, dm.start())}), case '{cv}'"
                c.add(**item)
            return
    c.add(**base)


def _scan_route_file_batch(args: Tuple[List[Tuple[str, str]], Dict, set, str]) -> Tuple[List[Dict], Dict[str, str]]:
    file_batch, config, stack_ids, target_str = args
    target = Path(target_str)
    enc = config["hints"]["file_encodings"]
    framework_php = bool(stack_ids & {"php-codeigniter", "php-cakephp", "php-laravel", "php-zend1"})
    c = Collector(config)
    java_texts: Dict[str, str] = {}

    for p_str, rel in file_batch:
        p = Path(p_str)
        ext = p.suffix.lower()
        lang = LANG_BY_EXT.get(ext)
        if not lang or ext == ".xml":
            continue
        t = read_text(p, enc)
        if lang == "java":
            java_texts[rel] = t
        declared = False
        if lang == "php":
            declared = php_declared(c, rel, t, stack_ids)
        elif lang == "java" and ext != ".jsp":
            declared = java_declared(c, rel, t)
        elif lang == "dotnet" and ext in (".cs", ".vb"):
            if rel.lower().endswith((".aspx.cs", ".aspx.vb", ".ashx.cs", ".ashx.vb", ".asmx.cs", ".asmx.vb")):
                if not WEBMETHOD.search(t):
                    continue
            declared = dotnet_declared(c, rel, t)
        elif lang == "cfml" and ext == ".cfc":
            declared = cfml_declared(c, rel, t)
        elif lang in ("js", "python", "ruby"):
            declared = js_py_rb_declared(c, rel, t, lang)
        elif lang == "rust":
            declared = rust_declared(c, rel, t)
        elif lang == "go":
            declared = go_declared(c, rel, t)
        if declared or ext not in FILE_ENDPOINT_EXTS:
            continue
        if INCLUDE_DIR_RE.search(rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""):
            continue
        if framework_php and lang == "php" and re.search(r"(^|/)(application|system|app|vendor|routes|resources|storage|bootstrap)/", rel):
            continue
        if lang == "perl" and ext == ".pm":
            continue
        file_endpoint(c, rel, t, lang, ext, target, enc)
    return c.items, java_texts


def map_routes(target: Path, config: Dict, stack_ids: Optional[set] = None, workers: int = 0, cache: Optional[Any] = None) -> Dict:
    enc = config["hints"]["file_encodings"]
    c = Collector(config)
    files = list(iter_source_files(target, config))
    stack_ids = stack_ids or set()
    framework_php = bool(stack_ids & {"php-codeigniter", "php-cakephp", "php-laravel", "php-zend1"})
    class_index = {p.stem: rel for p, rel in files if p.suffix == ".java"}
    texts: Dict[str, str] = {}

    # 1. XML pre-pass (web.xml / struts.xml declarative mappings)
    for p, rel in files:
        if p.suffix.lower() == ".xml":
            t = read_text(p, enc)
            if "<servlet" in t or "<action" in t:
                xml_declared(c, rel, t, class_index)

    xml_items = list(c.items)

    # 2. Source file processing (with optional caching)
    non_xml_files = [(str(p), rel) for p, rel in files if p.suffix.lower() != ".xml"]
    file_routes: Dict[str, List[Dict]] = {}
    files_to_scan: List[Tuple[str, str]] = []

    if cache and getattr(cache, "enabled", False):
        for p_str, rel in non_xml_files:
            hit = cache.get_routes(rel, Path(p_str))
            if hit is not None:
                rt_items, j_text = hit
                file_routes[rel] = rt_items
                if j_text:
                    texts[rel] = j_text
            else:
                files_to_scan.append((p_str, rel))
    else:
        files_to_scan = non_xml_files

    num_to_scan = len(files_to_scan)
    effective_workers = workers if workers > 0 else (os.cpu_count() or 1)

    if num_to_scan > 0:
        new_items: List[Dict] = []
        if effective_workers <= 1 or num_to_scan < 20:
            chunk_items, chunk_java_texts = _scan_route_file_batch(
                (files_to_scan, config, stack_ids, str(target))
            )
            new_items = chunk_items
            texts.update(chunk_java_texts)
        else:
            chunk_size = max(1, (num_to_scan + effective_workers - 1) // effective_workers)
            chunks = [
                (files_to_scan[i : i + chunk_size], config, stack_ids, str(target))
                for i in range(0, num_to_scan, chunk_size)
            ]
            with concurrent.futures.ProcessPoolExecutor(max_workers=effective_workers) as executor:
                for chunk_items, chunk_java_texts in executor.map(_scan_route_file_batch, chunks):
                    new_items.extend(chunk_items)
                    texts.update(chunk_java_texts)

        for it in new_items:
            handler_file = it["handler"]["file"]
            file_routes.setdefault(handler_file, []).append(it)

        if cache and getattr(cache, "enabled", False):
            for p_str, rel in files_to_scan:
                cache.put_routes(
                    rel=rel,
                    path=Path(p_str),
                    route_items=file_routes.get(rel, []),
                    java_text=texts.get(rel),
                )

    ordered_items = list(xml_items)
    for p, rel in files:
        if rel in file_routes:
            ordered_items.extend(file_routes[rel])
    c.items = ordered_items

    # post-pass 1: routes declared in XML -> enrich from the handler class file
    for it in c.items:
        hf = it["handler"]["file"]
        if it["kind"] == "declared_route" and not it["id_params"] and hf in texts and hf.endswith(".java"):
            t = texts[hf]
            it["id_params"] = c.inputs("java", t)
            it["guard_hints"] = it["guard_hints"] or c.guards(t)
            it["data_hints"] = it["data_hints"] or c.data_ops(t)
    # post-pass 2: servlet classes without @WebServlet -> take the path from web.xml
    xml_paths = {it["handler"]["file"]: it["path"] for it in c.items
                 if it["stack"] == "java-servlet" and it["notes"].startswith("mapped in ")}
    keep = []
    for it in c.items:
        if it["path"] == "<see web.xml servlet-mapping>" and it["handler"]["file"] in xml_paths:
            it["path"] = xml_paths[it["handler"]["file"]]
            it["notes"] = "path from web.xml"
        keep.append(it)
    mapped_with_methods = {it["handler"]["file"] for it in keep if it["notes"] == "path from web.xml"}
    keep = [it for it in keep if not (it["notes"].startswith("mapped in ") and it["handler"]["file"] in mapped_with_methods)]
    for n, it in enumerate(keep, 1):
        it["route_id"] = f"R-{n:04d}"
    c.items = keep
    for it in c.items:
        it["needs_audit_hint"] = bool(any(i.get("is_id_like") for i in it["id_params"]) or it["kind"] == "declared_route")
    c.items = annotate_privilege(c.items, target, config)
    by_stack: Dict[str, int] = {}
    for it in c.items:
        by_stack[it["stack"]] = by_stack.get(it["stack"], 0) + 1
    return {"generated_by": f"lsa map_routes.py {KIT_VERSION}", "target": target.resolve().name,
            "summary": {"total": len(c.items), "by_stack": by_stack,
                        "bfla_hints": sum(1 for i in c.items if i.get("needs_bfla_audit_hint")),
                        "with_id_like_params": sum(1 for i in c.items if any(p.get("is_id_like") for p in i["id_params"]))},
            "candidates": c.items}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target")
    ap.add_argument("--config")
    ap.add_argument("--stack-profile", help="stack-profile.json from detect_stack.py")
    ap.add_argument("--out")
    ap.add_argument("--workers", "-j", type=int, default=0,
                    help="Number of worker processes for parallel scan (default: 0 = auto/cpu_count)")
    a = ap.parse_args()
    stacks = set()
    if a.stack_profile:
        with open(a.stack_profile, encoding="utf-8") as fh:
            stacks = {s["id"] for s in json.load(fh)["stacks"]}
    res = map_routes(Path(a.target), load_config(a.config), stacks, workers=a.workers)
    if a.out:
        write_json(Path(a.out), res)
    else:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
