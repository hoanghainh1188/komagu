"""Declared-route extractors for Java web stacks (web.xml, Struts 1/2, Spring XML, annotations).

Used by map_routes.py. Python 3.8+, standard library only.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from lsa_common import blank_java_comments, call_args, iter_source_files, line_of, read_text, split_top

JAVA_METHOD_ANN = re.compile(r"@(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|Path)\b")
JAVA_HTTP_ANN = re.compile(r"@(GET|POST|PUT|DELETE|PATCH)\b")
JAVA_CLASS_AFTER = re.compile(r"\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:(?:public|protected|private|abstract|final|static)\s+)*"
                              r"(?:class|interface)\b")
# The return type may follow annotations, as in: public @ResponseBody String show(
JAVA_HANDLER_SIG = re.compile(r"(?:(?:public|protected)\s+(?:@\w+(?:\([^)]*\))?\s+|(?:final|static|synchronized)\s+)*"
                              r"[\w<>\[\],.?\s]+?|fun|(?:override|suspend)\s+fun)\s+(\w+)\s*\(")
JAVA_NEXT_ANN = re.compile(r"\n\s*@(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|Path)\b(?!Variable|Param)")
STRING_LITERAL = re.compile(r"\"((?:[^\"\\]|\\.)*)\"")
JAVA_STRING_CONSTANT = re.compile(r"\bfinal\s+String\s+(\w+)\s*=\s*\"([^\"]*)\"\s*;")
SPRING_PLACEHOLDER = re.compile(r"\$\{[^}]*\}")
XML_COMMENT = re.compile(r"<!--[\s\S]*?-->")
STRUTS2_MARKER = re.compile(r"<!DOCTYPE\s+struts\b(?!-)|<struts[\s>]")
STRUTS_EXT_CONSTANT = re.compile(r"<constant\s+name=\"struts\.action\.extension\"\s+value=\"([^\"]*)\"")
STRUTS_EXT_PROPERTY = re.compile(r"^\s*struts\.action\.extension\s*[=:]\s*(\S*)", re.M)
STRUTS_MODULE_PARAM = re.compile(r"<param-name>\s*config/([^<\s]+)\s*</param-name>\s*<param-value>\s*([^<]+?)\s*</param-value>")
SPRING_BEAN = re.compile(r"<bean\b([^>]*)>")
SPRING_URL_MAPPER = re.compile(r"<bean\b[^>]*class=\"[^\"]*UrlHandlerMapping\"[^>]*>")
SPRING_URL_PROPS = re.compile(r"<props>([\s\S]*?)</props>")
SPRING_URL_PROP = re.compile(r"<prop\s+key=\"([^\"]+)\"\s*>\s*([^<]+?)\s*</prop>")
XML_ATTR = re.compile(r"(\w+)\s*=\s*\"([^\"]*)\"")

DEFAULT_ACTION_EXTENSION = "action"


def strip_xml_comments(text: str) -> str:
    """Blank XML comments out, keeping every other character at its original offset."""
    return XML_COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def build_class_index(rels: Iterable[str]) -> Dict[str, List[str]]:
    """Map a simple class name to every Java source file with that name."""
    index: Dict[str, List[str]] = {}
    for rel in rels:
        if rel.endswith(".java"):
            index.setdefault(rel.rsplit("/", 1)[-1][:-5], []).append(rel)
    return index


def resolve_class(cls: str, index: Dict[str, List[str]], default: str) -> str:
    """Find the source file of a class name, matching on the package path when one is given."""
    name = cls.split("$", 1)[0]
    candidates = index.get(name.split(".")[-1], [])
    if "." not in name:
        return candidates[0] if candidates else default
    suffix = name.replace(".", "/") + ".java"
    return next((rel for rel in candidates if rel == suffix or rel.endswith("/" + suffix)), default)


def _annotation_args(text: str, m: re.Match) -> Tuple[str, int]:
    """Return (argument text, offset after the annotation)."""
    paren = re.match(r"\s*\(", text[m.end():])
    if not paren:
        return "", m.end()
    return call_args(text, m.end() + paren.end() - 1)


def _annotation_attrs(args: str) -> Dict[str, str]:
    attrs: Dict[str, str] = {}
    for part in split_top(args):
        named = re.match(r"\s*(\w+)\s*=", part)
        if named:
            attrs[named.group(1)] = part[named.end():]
        else:
            attrs["value"] = part
    return attrs


def _literals(expr: str) -> List[str]:
    return STRING_LITERAL.findall(expr or "")


def _string_constants(text: str) -> Dict[str, str]:
    return dict(JAVA_STRING_CONSTANT.findall(text))


def _resolve_term(term: str, constants: Dict[str, str]) -> str:
    term = term.strip()
    literal = STRING_LITERAL.fullmatch(term)
    if literal:
        return literal.group(1)
    name = term.rsplit(".", 1)[-1]
    return constants.get(name, "{" + name + "}" if name else "")


def _path_values(expr: str, constants: Dict[str, str]) -> List[str]:
    """Evaluate a mapping attribute: a literal, a constant, a concatenation of both, or an array of those."""
    inner = expr.strip()
    if inner.startswith("{") and inner.endswith("}"):
        inner = inner[1:-1]
    return ["".join(_resolve_term(t, constants) for t in re.split(r"\+(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", element))
            for element in split_top(inner)]


def _mapped_paths(attrs: Dict[str, str], constants: Optional[Dict[str, str]] = None) -> List[str]:
    """Every mapped path with its required request parameters as a query string."""
    paths = _path_values(attrs.get("value", "") or attrs.get("path", ""), constants or {}) or [""]
    required = [p for p in _literals(attrs.get("params", "")) if not p.startswith("!")]
    query = "?" + "&".join(required) if required else ""
    return [p + query for p in paths]


def _join_path(prefix: str, sub: str) -> str:
    sub_path, sep, query = sub.partition("?")
    return "/" + "/".join(p.strip("/") for p in (prefix, sub_path) if p.strip("/")) + sep + query


def _class_mappings(text: str, constants: Dict[str, str]) -> List[Tuple[int, List[str]]]:
    """(offset, mapped paths) of every class-level @RequestMapping / @Path, in source order."""
    out: List[Tuple[int, List[str]]] = []
    for m in JAVA_METHOD_ANN.finditer(text):
        args, end = _annotation_args(text, m)
        if JAVA_CLASS_AFTER.match(text[end:end + 600]):
            out.append((m.start(), [p.partition("?")[0] for p in _mapped_paths(_annotation_attrs(args), constants)]))
    return out


def _servlet_declared(c, rel: str, text: str) -> bool:
    found = False
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


def java_declared(c, rel: str, raw: str) -> bool:
    text = blank_java_comments(raw)
    if re.search(r"extends\s+HttpServlet", text):
        return _servlet_declared(c, rel, text)
    found = False
    constants = _string_constants(text)
    classes = _class_mappings(text, constants)
    for m in JAVA_METHOD_ANN.finditer(text):
        args, ann_end = _annotation_args(text, m)
        after = text[ann_end: ann_end + 600]
        if JAVA_CLASS_AFTER.match(after):
            continue
        sig = JAVA_HANDLER_SIG.search(after)
        if not sig:
            continue
        attrs = _annotation_attrs(args)
        ann = m.group(1)
        verbs = re.findall(r"RequestMethod\.(\w+)", args)
        if ann.endswith("Mapping") and ann != "RequestMapping":
            verbs = [ann[:-7].upper()]
        if ann == "Path":
            hv = JAVA_HTTP_ANN.search(text[max(0, m.start() - 200): ann_end + 200])
            verbs = [hv.group(1)] if hv else ["ANY"]
        nxt = JAVA_NEXT_ANN.search(text, ann_end)
        body = text[m.start(): nxt.start() if nxt else len(text)]
        line = line_of(text, m.start())
        enclosing = [paths for offset, paths in classes if offset < m.start()]
        for prefix in (enclosing[-1] if enclosing else [""]):
            for sub in _mapped_paths(attrs, constants):
                path = _join_path(prefix, sub)
                c.add(stack="java-spring-mvc" if ann != "Path" else "java-jaxrs", kind="declared_route",
                      method=verbs or ["ANY"], path=path,
                      handler={"file": rel, "line": line, "symbol": sig.group(1)},
                      id_params=c.path_params(SPRING_PLACEHOLDER.sub("", path)) + c.inputs("java", body, line),
                      guard_hints=c.guards(text[:m.start()][-1500:], 1)[:2] + c.guards(body, line),
                      data_hints=c.data_ops(body, line), notes="")
                found = True
    # Struts 1 / 2 Action classes without annotations are mapped from XML (see xml_declared)
    return found


def struts_modules(rel: str, text: str) -> Dict[str, str]:
    """Struts 1 module prefix for every config file a web.xml assigns to a module."""
    webapp = rel.rsplit("WEB-INF/", 1)[0]
    modules: Dict[str, str] = {}
    for m in STRUTS_MODULE_PARAM.finditer(strip_xml_comments(text)):
        for value in m.group(2).split(","):
            modules[webapp + value.strip().lstrip("/")] = "/" + m.group(1)
    return modules


def struts2_action_extension(target: Path, config: Dict, xml_texts: Iterable[str], encodings: List[str]) -> str:
    """The URL extension of Struts 2 actions: struts.properties overrides constants in struts.xml."""
    value: Optional[str] = None
    for text in xml_texts:
        m = STRUTS_EXT_CONSTANT.search(strip_xml_comments(text))
        value = m.group(1) if m else value
    for path, rel in iter_source_files(target, config, exts={".properties"}):
        if rel.rsplit("/", 1)[-1] == "struts.properties":
            m = STRUTS_EXT_PROPERTY.search(read_text(path, encodings))
            value = m.group(1) if m else value
    if value is None:
        return DEFAULT_ACTION_EXTENSION
    return next((e for e in value.split(",") if e), "")


def collect_spring_beans(text: str) -> Dict[str, str]:
    """Map bean id / name to class for one Spring XML file."""
    beans: Dict[str, str] = {}
    for m in SPRING_BEAN.finditer(strip_xml_comments(text)):
        attrs = dict(XML_ATTR.findall(m.group(1)))
        if attrs.get("class"):
            for key in filter(None, (attrs.get("id"), attrs.get("name"))):
                beans[key] = attrs["class"]
    return beans


def entry_method_line(text: str, symbol: Optional[str]) -> Optional[int]:
    """Line of the method a route declared in XML dispatches to, or None when the class has no known entry method."""
    named = symbol.split("#", 1)[1] if symbol and "#" in symbol else None
    names = [re.escape(named)] if named else ["execute", "doPost", "doGet", "service", "handleRequest"]
    for name in names:
        m = re.search(rf"\b(?:public|protected)\b[^;{{}}(]*\b{name}\s*\(", text)
        if m:
            return text.count("\n", 0, m.end()) + 1
    return None


def _spring_url_mappings(c, rel: str, text: str, class_index: Dict[str, List[str]], beans: Dict[str, str]) -> bool:
    found = False
    mappers = list(SPRING_URL_MAPPER.finditer(text))
    for i, mapper in enumerate(mappers):
        # nested <bean> elements (interceptors) make </bean> useless as the end of the mapper definition
        end = mappers[i + 1].start() if i + 1 < len(mappers) else len(text)
        props = SPRING_URL_PROPS.search(text, mapper.end(), end)
        if not props:
            continue
        for m in SPRING_URL_PROP.finditer(props.group(1)):
            bean = m.group(2)
            cls = beans.get(bean, "")
            c.add(stack="java-spring-mvc", kind="declared_route", method=["ANY"], path=m.group(1),
                  handler={"file": resolve_class(cls, class_index, rel) if cls else rel, "line": 1, "symbol": cls or bean},
                  id_params=[], guard_hints=[], data_hints=[],
                  notes=f"declared in {rel}:{line_of(text, props.start(1) + m.start())}; UrlHandlerMapping bean '{bean}'")
            found = True
    return found


def _web_xml_routes(c, rel: str, text: str, class_index: Dict[str, List[str]]) -> bool:
    found = False
    servlets: Dict[str, str] = {}
    for sm in re.finditer(r"<servlet>([\s\S]*?)</servlet>", text):
        name = re.search(r"<servlet-name>\s*([^<]+?)\s*</servlet-name>", sm.group(1))
        cls = re.search(r"<servlet-class>\s*([^<]+?)\s*</servlet-class>", sm.group(1))
        if name and cls:
            servlets[name.group(1)] = cls.group(1)
    for m in re.finditer(r"<servlet-mapping>([\s\S]*?)</servlet-mapping>", text):
        name = re.search(r"<servlet-name>\s*([^<]+?)\s*</servlet-name>", m.group(1))
        if not name:
            continue
        cls = servlets.get(name.group(1), "")
        for pattern in re.findall(r"<url-pattern>\s*([^<]+?)\s*</url-pattern>", m.group(1)):
            c.add(stack="java-servlet", kind="declared_route", method=["ANY"], path=pattern,
                  handler={"file": resolve_class(cls, class_index, rel), "line": 1, "symbol": cls or name.group(1)},
                  id_params=[], guard_hints=[], data_hints=[], notes=f"mapped in {rel}:{line_of(text, m.start())}")
            found = True
    return found


def _struts1_routes(c, rel: str, text: str, class_index: Dict[str, List[str]], module: str) -> bool:
    found = False
    for m in re.finditer(r"<action\b([^>]*)>", text):
        attrs = dict(XML_ATTR.findall(m.group(1)))
        if "path" not in attrs:
            continue
        cls = attrs.get("type", "")
        note = f"declared in {rel}:{line_of(text, m.start())}"
        if attrs.get("parameter"):
            note += f"; DispatchAction parameter '{attrs['parameter']}' -> one endpoint per method"
        c.add(stack="java-struts1", kind="declared_route", method=["ANY"], path=module + attrs["path"] + ".do",
              handler={"file": resolve_class(cls, class_index, rel), "line": 1, "symbol": cls}, id_params=[],
              guard_hints=[], data_hints=[], notes=note)
        found = True
    return found


def _struts2_routes(c, rel: str, text: str, class_index: Dict[str, List[str]], extension: str) -> bool:
    found = False
    suffix = "." + extension if extension else ""
    for pm in re.finditer(r"<package\b([^>]*)>([\s\S]*?)</package>", text):
        ns = dict(XML_ATTR.findall(pm.group(1))).get("namespace", "/").rstrip("/")
        for am in re.finditer(r"<action\b([^>]*)>", pm.group(2)):
            attrs = dict(XML_ATTR.findall(am.group(1)))
            cls = attrs.get("class", "")
            c.add(stack="java-struts2", kind="declared_route", method=["ANY"], path=f"{ns}/{attrs.get('name', '?')}{suffix}",
                  handler={"file": resolve_class(cls, class_index, rel), "line": 1, "symbol": f"{cls}#{attrs.get('method', 'execute')}"},
                  id_params=[], guard_hints=[], data_hints=[],
                  notes=f"declared in {rel}:{line_of(text, pm.start(2) + am.start())}; action setters are inputs")
            found = True
    return found


def xml_declared(c, rel: str, raw: str, class_index: Dict[str, List[str]], modules: Optional[Dict[str, str]] = None,
                 beans: Optional[Dict[str, str]] = None, action_extension: str = DEFAULT_ACTION_EXTENSION) -> bool:
    """Extract every route a deployment or framework XML file declares, ignoring commented-out ones."""
    text = strip_xml_comments(raw)
    found = False
    if rel.endswith("web.xml"):
        found = _web_xml_routes(c, rel, text, class_index) or found
    if "struts-config" in rel:
        found = _struts1_routes(c, rel, text, class_index, (modules or {}).get(rel, "")) or found
    if rel.endswith("struts.xml") or STRUTS2_MARKER.search(text):
        found = _struts2_routes(c, rel, text, class_index, action_extension) or found
    if "UrlHandlerMapping" in text:
        found = _spring_url_mappings(c, rel, text, class_index, beans or {}) or found
    return found
