"""Code context for the headless agents: snippets, server-side includes and bound model classes.

Standard-library only (Python 3.8+ compatible).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional


def _read_snippet(target_dir: Path, rel_file: str, line: int, radius: int = 15) -> str:
    """Read a window of code around target line from the audited repository."""
    full_path = target_dir / rel_file
    if not full_path.is_file():
        return f"[File not found: {rel_file}]"
    try:
        lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(0, line - radius - 1)
        end = min(len(lines), line + radius)
        numbered = [f"{i + 1:4d} | {lines[i]}" for i in range(start, end)]
        return "\n".join(numbered)
    except Exception as e:
        return f"[Error reading {rel_file}: {e}]"


# Server-side includes whose content a verifier must see to judge a control (PHP, Classic ASP, ColdFusion)
_INCLUDE_RE = re.compile(
    r"(?:require|include)(?:_once)?\s*\(?\s*['\"]([^'\"]+)['\"]"
    r"|<!--\s*#include\s+(?:file|virtual)\s*=\s*\"([^\"]+)\""
    r"|<cfinclude\s+template\s*=\s*\"([^\"]+)\"",
    re.IGNORECASE,
)


def _included_files(target_dir: Path, rel_file: str) -> List[str]:
    """Repository-relative paths of files that rel_file includes, if they exist."""
    target_dir = target_dir.resolve()
    path = target_dir / rel_file
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    found: List[str] = []
    for m in _INCLUDE_RE.finditer(text):
        ref = next(g for g in m.groups() if g)
        candidate = (path.parent / ref).resolve()
        try:
            rel = str(candidate.relative_to(target_dir))
        except ValueError:
            continue
        if candidate.is_file() and rel not in found:
            found.append(rel)
    return found


_MODEL_EXTENSIONS = (".java", ".cs", ".vb", ".php", ".py", ".js", ".ts", ".rb", ".cfc")
_NEW_OBJECT_RE = re.compile(r"\bnew\s+([A-Z][A-Za-z0-9_]*)\s*\(")


def _model_source(target_dir: Path, name: Optional[str], near_file: str = "", near_line: int = 1) -> Optional[Dict[str, Any]]:
    """Definition of the bound model class, so the privilege auditor can see its fields (#319).

    name is the Tier 1 binding target; when it is unknown, the first `new Foo(` near the binding is used.
    """
    if not name and near_file:
        m = _NEW_OBJECT_RE.search(_read_snippet(target_dir, near_file, near_line, radius=4))
        name = m.group(1) if m else None
    if not name or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        return None
    class_re = re.compile(rf"\bclass\s+{name}\b")
    # same application and language as the binding: a Node route must not pick up a PHP model of the same name
    suffix = Path(near_file).suffix.lower()
    suffixes = (suffix,) if suffix in _MODEL_EXTENSIONS else _MODEL_EXTENSIONS
    parts = Path(near_file).parts
    root = target_dir / parts[0] if len(parts) > 1 and (target_dir / parts[0]).is_dir() else target_dir
    for path in sorted(root.rglob("*")):
        if path.suffix.lower() not in suffixes or not path.is_file():
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for i, text in enumerate(lines):
            if class_re.search(text):
                rel = str(path.relative_to(target_dir))
                return {"class": name, "file": rel, "code": _read_snippet(target_dir, rel, i + 16, radius=15)}
    return {"class": name, "file": None, "code": "[definition not found in the repository]"}


def _verification_context(target_dir: Path, finding: Dict[str, Any]) -> Dict[str, Any]:
    """Code the verifier needs: the finding's site, its file header, evidence lines and included files."""
    loc = finding.get("location") or {}
    rel = str(loc.get("file") or "")
    line = int(loc.get("start_line") or 1)
    ctx: Dict[str, Any] = {"location": _read_snippet(target_dir, rel, line, radius=20)}
    if line > 40:
        ctx["file_header"] = _read_snippet(target_dir, rel, 13, radius=12)
    others = []
    for ev in finding.get("evidence") or []:
        if isinstance(ev, dict) and ev.get("file") and ev.get("file") != rel:
            others.append({"file": ev["file"], "code": _read_snippet(target_dir, str(ev["file"]), int(ev.get("line") or 1), radius=6)})
    if others:
        ctx["evidence"] = others[:3]
    includes = [{"file": inc, "code": _read_snippet(target_dir, inc, 30, radius=30)} for inc in _included_files(target_dir, rel)[:3]]
    if includes:
        ctx["included_files"] = includes
    return ctx
