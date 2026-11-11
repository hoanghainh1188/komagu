"""Resolve Laravel route declarations to the controller method that handles them (#380).

`Route::post('/x', [AccountController::class, 'register'])` is found in `routes/web.php`, but the
code an auditor needs is `AccountController::register`. Without this step every Laravel route
pointed at its declaration line, so the auditors read the route file and never the controller.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from lsa_common import line_of, read_text

# [XController::class, 'method']  or  'XController@method' / 'App\Http\Controllers\XController@method'
ROUTE_ACTION = re.compile(
    r"\[\s*\\?([\w\\]+)::class\s*,\s*['\"](\w+)['\"]\s*\]"
    r"|['\"]\\?([\w\\]+)@(\w+)['\"]"
)
PHP_FUNCTION = re.compile(
    r"^[ \t]*(?:(?:public|protected|private|static|final|abstract)\s+)*function\s+&?(\w+)\s*\(", re.M)


def route_action(stmt: str) -> Optional[str]:
    """`Class@method` named by a Laravel route statement (class without namespace), or None."""
    m = ROUTE_ACTION.search(stmt)
    if not m:
        return None
    cls, method = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
    return f"{cls.rsplit(chr(92), 1)[-1]}@{method}"


def php_class_index(rels: Iterable[str]) -> Dict[str, List[str]]:
    """Map a PHP file's base name (the class name by PSR-4 convention) to every file with that name."""
    index: Dict[str, List[str]] = {}
    for rel in rels:
        if rel.endswith(".php"):
            index.setdefault(rel.rsplit("/", 1)[-1][:-4], []).append(rel)
    return index


def find_method(text: str, cls: str, method: str) -> Optional[Tuple[int, int]]:
    """(start, end) offsets of `method` in class `cls`, or None when the class or method is absent."""
    if not re.search(rf"\bclass\s+{re.escape(cls)}\b", text):
        return None
    starts = list(PHP_FUNCTION.finditer(text))
    for i, m in enumerate(starts):
        if m.group(1) == method:
            end = starts[i + 1].start() if i + 1 < len(starts) else len(text)
            return m.start(), end
    return None


def _merge(existing: List[Dict[str, Any]], extra: List[Dict[str, Any]],
           key: Callable[[Dict[str, Any]], Any]) -> List[Dict[str, Any]]:
    seen = {key(d) for d in existing}
    return existing + [d for d in extra if key(d) not in seen]


def _locate(index: Dict[str, List[str]], texts: Dict[str, str], target: Path, enc: Any,
            cls: str, method: str) -> Optional[Tuple[str, int, int]]:
    for rel in index.get(cls, []):
        if rel not in texts:
            texts[rel] = read_text(target / rel, enc)
        span = find_method(texts[rel], cls, method)
        if span:
            return rel, span[0], span[1]
    return None


def resolve_laravel_handlers(items: List[Dict[str, Any]], target: Path, enc: Any, collector: Any,
                             rels: Iterable[str]) -> List[Dict[str, Any]]:
    """Return items with Laravel routes pointed at their controller method, when it can be found.

    Inputs, guard hints and data hints from the method body are added to those taken from the route
    statement. A route whose controller or method is not in the repo keeps its declaration.
    """
    index = php_class_index(rels)
    texts: Dict[str, str] = {}
    out: List[Dict[str, Any]] = []
    for it in items:
        symbol = (it.get("handler") or {}).get("symbol") or ""
        found = (_locate(index, texts, target, enc, *symbol.split("@", 1))
                 if it.get("stack") == "php-laravel" and "@" in symbol else None)
        if not found:
            out.append(it)
            continue
        rel, start, end = found
        line = line_of(texts[rel], start)
        body = texts[rel][start:end]
        out.append({
            **it,
            "handler": {"file": rel, "line": line, "symbol": symbol},
            "id_params": _merge(list(it.get("id_params") or []), collector.inputs("php", body, line),
                                lambda d: (d.get("name"), d.get("source"))),
            "guard_hints": _merge(list(it.get("guard_hints") or []), collector.guards(body, line),
                                  lambda d: d.get("hint")),
            "data_hints": _merge(list(it.get("data_hints") or []), collector.data_ops(body, line),
                                 lambda d: (d.get("op"), d.get("line"))),
            "notes": f"declared in {it['handler']['file']}:{it['handler']['line']}",
        })
    return out
