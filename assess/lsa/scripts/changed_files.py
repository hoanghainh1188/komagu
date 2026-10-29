#!/usr/bin/env python3
"""Pick the files a PR diff scan must look at.

1. git_changed_files: files changed since the merge base with BASE_REF
   (committed, staged, unstaged, untracked and deleted), relative to TARGET.
2. select_files: the changed files that are in scan scope, plus in-scope files
   that reference a changed file one level deep:
     - any file naming it (include 'inc/db.php', web.xml, templates)
     - class languages (Java, Kotlin, Groovy, C#, VB): the class name
     - module languages (JS/TS, Python, Ruby): import / require of the module

Indirect changes deeper than one level (a helper of a helper) are not followed;
run a full scan on a schedule as well.

Standard-library-only (Python 3.8+).
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lsa_common import SOURCE_EXTS, iter_source_files, read_text  # noqa: E402

CLASS_EXTS = {".java", ".kt", ".groovy", ".cs", ".vb"}
MODULE_EXTS = {".js", ".mjs", ".ts", ".py", ".rb"}


class ChangedFilesError(Exception):
    """git is unavailable, TARGET is not in a work tree, or BASE_REF is unknown."""


def _git(target: Path, *args: str) -> str:
    try:
        res = subprocess.run(["git", "-C", str(target), *args], capture_output=True, text=True)
    except OSError as exc:
        raise ChangedFilesError(f"git is not available: {exc}") from exc
    if res.returncode != 0:
        raise ChangedFilesError(res.stderr.strip() or f"git {' '.join(args)} failed")
    return res.stdout


def git_changed_files(target: Path, base_ref: str) -> List[str]:
    """Return sorted posix paths, relative to target, changed since merge-base(base_ref, HEAD)."""
    if not base_ref or base_ref.startswith("-"):
        raise ChangedFilesError(f"invalid base ref: {base_ref!r}")
    _git(target, "rev-parse", "--is-inside-work-tree")
    try:
        merge_base = _git(target, "merge-base", base_ref, "HEAD").strip()
    except ChangedFilesError as exc:
        raise ChangedFilesError(f"cannot find merge base with '{base_ref}': {exc}") from exc
    tracked = _git(target, "diff", "--name-only", "--relative", "-z", merge_base, "--").split("\0")
    untracked = _git(target, "ls-files", "--others", "--exclude-standard", "-z").split("\0")
    return sorted({p for p in tracked + untracked if p})


def _reference_pattern(rel: str) -> Optional[str]:
    path = PurePosixPath(rel)
    if path.suffix.lower() not in SOURCE_EXTS:
        return None
    stem = re.escape(path.stem)
    parts = [r"(?<![\w.-])" + re.escape(path.name) + r"(?![\w-])"]
    if path.suffix.lower() in CLASS_EXTS:
        parts.append(r"\b" + stem + r"\b")
    if path.suffix.lower() in MODULE_EXTS:
        parts.append(r"[/'\".]" + stem + r"(?=['\"\s;,)]|$)")
        parts.append(r"\b(?:import|from)\s+" + stem + r"\b")
    return "|".join(parts)


def select_files(target: Path, changed: List[str], config: Dict) -> List[str]:
    """Return sorted in-scope files to scan for this diff."""
    scope_cfg = {**config, "scope": {k: v for k, v in config["scope"].items() if k != "only_files"}}
    in_scope = {rel: path for path, rel in iter_source_files(target, scope_cfg)}
    selected = {rel for rel in changed if rel in in_scope}
    patterns = [p for p in (_reference_pattern(rel) for rel in changed) if p]
    if not patterns:
        return sorted(selected)
    referrer = re.compile("|".join(f"(?:{p})" for p in patterns), re.MULTILINE)
    encodings = config["hints"]["file_encodings"]
    for rel, path in in_scope.items():
        if rel in selected:
            continue
        try:
            if referrer.search(read_text(path, encodings)):
                selected.add(rel)
        except OSError:
            continue
    return sorted(selected)
