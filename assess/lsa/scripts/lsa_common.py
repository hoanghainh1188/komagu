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
                    # framework build output and caches
                    ".next/", ".nuxt/", ".output/", ".svelte-kit/", ".vercel/", ".netlify/", ".turbo/",
                    ".parcel-cache/", ".cache/", "out/", "storybook-static/",
                    # test and coverage output
                    "coverage/", "test-results/", "playwright-report/", ".nyc_output/",
                    # Python environments and caches
                    "__pycache__/", ".venv/", "venv/", ".tox/", ".mypy_cache/", ".pytest_cache/",
                    "*.min.js", "*jquery*.js", "*.map"],
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
    "batch": {"max_endpoints": 15, "max_injection_candidates": 25, "max_privilege_items": 20},
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
    ".js", ".mjs", ".cjs", ".mts", ".ts", ".tsx", ".jsx", ".py", ".rb", ".erb", ".sql",
    ".rs", ".go", ".toml", ".mod",
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


# Default exclude names that are also ordinary Java package and web directory names
AMBIGUOUS_DIR_EXCLUDES = {"vendor/", "packages/", "bin/", "obj/", "target/", "build/", "dist/",
                          "test/", "tests/", "spec/", "docs/", "out/"}
JAVA_PACKAGE_ROOT = re.compile(r"(?:^|/)src/main/java/|(?:^|/)(?=(?:com|org|net|jp|vn|cn|kr|de|fr|uk|io|edu|gov|biz|info)/[\w-]+/)")
JAVA_WEB_ROOT = re.compile(r"(?:^|/)(?:src/main/webapp|WebContent|WebRoot|webapp)/")
JAVA_TREE_EXTS = (".java", ".kt", ".groovy", ".jsp", ".xml")


def _inside_java_tree(rel_slash: str, index: int, is_dir: bool) -> bool:
    """True when the directory at `index` is a package inside a Java source tree or a directory under a web root."""
    name = rel_slash.rstrip("/")
    package_root = JAVA_PACKAGE_ROOT.search(rel_slash)
    if package_root and package_root.start() <= index and (is_dir or name.endswith(JAVA_TREE_EXTS)):
        return True
    web_root = JAVA_WEB_ROOT.search(rel_slash)
    return bool(web_root and web_root.start() <= index and (is_dir or name.endswith(".jsp")))


def _excluded(rel: str, excludes: List[str]) -> bool:
    is_dir = rel.endswith("/")
    rel_slash = rel.replace(os.sep, "/") + ("" if is_dir else "/")
    for ex in excludes:
        ex = ex.replace("\\", "/")
        if ex.endswith("/"):
            index = ("/" + rel_slash).find("/" + ex)
            if index != -1 and not (ex in AMBIGUOUS_DIR_EXCLUDES and _inside_java_tree(rel_slash, index, is_dir)):
                return True
        elif re.fullmatch(ex.replace(".", r"\.").replace("*", ".*"), rel.replace(os.sep, "/")):
            return True
    return False


def iter_source_files(root: Path, config: Dict, exts: Optional[set] = None) -> Iterator[Tuple[Path, str]]:
    """Yield (absolute path, relative posix path) for source files in scope."""
    exts = exts or SOURCE_EXTS
    excludes = config["scope"].get("exclude", [])
    includes = config["scope"].get("include", [])
    # Diff mode: an explicit file list (an empty list means nothing to scan)
    only_files = config["scope"].get("only_files")
    only = set(only_files) if only_files is not None else None
    max_bytes = int(config["scope"].get("max_file_kb", 1024)) * 1024
    root_resolved = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        # Skip symlinked directories and excluded directories
        dirnames[:] = sorted(d for d in dirnames
                             if not (Path(dirpath) / d).is_symlink()
                             and not _excluded((rel_dir + "/" + d if rel_dir else d) + "/", excludes))
        for name in sorted(filenames):
            p = Path(dirpath) / name
            # Skip symlinks and ensure path resolves within root
            if p.is_symlink():
                continue
            try:
                p.resolve().relative_to(root_resolved)
            except (ValueError, RuntimeError):
                continue
            rel = (rel_dir + "/" + name) if rel_dir else name
            if p.suffix.lower() not in exts:
                continue
            if includes and not any(rel.startswith(i.rstrip("/")) for i in includes):
                continue
            if only is not None and rel not in only:
                continue
            if _excluded(rel, excludes):
                continue
            try:
                if p.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            yield p, rel


JAVA_COMMENT = re.compile(r"(?m:^[ \t]*)(?:/\*[\s\S]*?\*/|//[^\n]*)")


def blank_java_comments(text: str) -> str:
    """Blank whole-line Java comments, keeping every other character at its original offset."""
    return JAVA_COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


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


from redaction import redact, redact_lines  # noqa: E402,F401  (re-exported for the Tier 1 scripts)
