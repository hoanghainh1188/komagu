"""Shared helpers for the LSA pre-scan scripts. Python 3.8+, standard library only."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

KIT_VERSION = (Path(__file__).resolve().parent.parent / "VERSION").read_text().strip() \
    if (Path(__file__).resolve().parent.parent / "VERSION").exists() else "0.0.0"

DEFAULT_CONFIG: Dict = {
    "scope": {
        "include": [],
        "exclude": ["vendor/", "node_modules/", "bower_components/", "packages/", "bin/", "obj/",
                    "target/", "build/", "dist/", ".git/", ".svn/", ".hg/", "test/", "tests/", "spec/", "docs/",
                    "*.min.js", "*jquery*.js"],
        "web_roots": [],
        "file_endpoints": "all",
        "max_file_kb": 1024,
    },
    "hints": {
        "owner_columns": ["user_id", "owner_id", "created_by", "member_id", "customer_id",
                          "company_id", "tenant_id", "shop_id", "branch_id"],
        "id_param_patterns": [r"^id$", r"_id$", r"Id$", r"ID$", r"^no$", r"_no$", r"^code$", r"^key$",
                              r"^uid$", r"^oid$", r"^file(name)?$", r"^path$", r"^seq$"],
        "known_auth_helpers": [],
        "known_ownership_helpers": [],
        "file_encodings": ["utf-8", "cp932", "euc_jp", "latin-1"],
    },
    "batch": {"max_endpoints": 15, "max_injection_candidates": 25},
    "parallel": {"max_agents": 4},
    "report": {"language": "en", "min_severity": "low"},
}

SOURCE_EXTS = {
    ".php", ".php3", ".php4", ".php5", ".phtml", ".inc", ".ctp",
    ".java", ".jsp", ".jspf", ".xml", ".kt", ".groovy",
    ".cs", ".vb", ".aspx", ".ascx", ".ashx", ".asmx", ".svc", ".master", ".asax", ".config", ".cshtml", ".vbhtml",
    ".asp", ".asa",
    ".pl", ".pm", ".cgi",
    ".cfm", ".cfc", ".cfml",
    ".js", ".mjs", ".ts", ".py", ".rb", ".erb", ".sql",
}


def deep_merge(base: Dict, override: Dict) -> Dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if k.startswith("_"):
            continue
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: Optional[str]) -> Dict:
    if not path:
        return json.loads(json.dumps(DEFAULT_CONFIG))
    with open(path, encoding="utf-8") as fh:
        return deep_merge(DEFAULT_CONFIG, json.load(fh))


def read_text(path: Path, encodings: List[str]) -> str:
    data = path.read_bytes()
    for enc in encodings:
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", errors="replace")


def _excluded(rel: str, excludes: List[str]) -> bool:
    rel_slash = rel.replace(os.sep, "/") + ("/" if not rel.endswith("/") else "")
    for ex in excludes:
        ex = ex.replace("\\", "/")
        if ex.endswith("/"):
            if rel_slash.startswith(ex) or ("/" + ex) in ("/" + rel_slash):
                return True
        elif re.fullmatch(ex.replace(".", r"\.").replace("*", ".*"), rel.replace(os.sep, "/")):
            return True
    return False


def iter_source_files(root: Path, config: Dict, exts: Optional[set] = None) -> Iterator[Tuple[Path, str]]:
    """Yield (absolute path, relative posix path) for source files in scope."""
    exts = exts or SOURCE_EXTS
    excludes = config["scope"].get("exclude", [])
    includes = config["scope"].get("include", [])
    max_bytes = int(config["scope"].get("max_file_kb", 1024)) * 1024
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        dirnames[:] = sorted(d for d in dirnames
                             if not _excluded((rel_dir + "/" + d if rel_dir else d) + "/", excludes))
        for name in sorted(filenames):
            p = Path(dirpath) / name
            rel = (rel_dir + "/" + name) if rel_dir else name
            if p.suffix.lower() not in exts:
                continue
            if includes and not any(rel.startswith(i.rstrip("/")) for i in includes):
                continue
            if _excluded(rel, excludes):
                continue
            try:
                if p.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            yield p, rel


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def compile_id_patterns(config: Dict) -> List[re.Pattern]:
    return [re.compile(p) for p in config["hints"]["id_param_patterns"]]


def is_id_name(name: str, patterns: List[re.Pattern]) -> bool:
    return any(p.search(name) for p in patterns)


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def read_json(path: Path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def snippet(lines: List[str], lineno: int, max_len: int = 220) -> str:
    s = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""
    return s if len(s) <= max_len else s[: max_len - 3] + "..."


SECRET_RE = re.compile(r"(?i)(password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*['\"][^'\"]{4,}['\"]")


def redact(s: str) -> str:
    return SECRET_RE.sub(lambda m: m.group(1) + "=[REDACTED]", s)
