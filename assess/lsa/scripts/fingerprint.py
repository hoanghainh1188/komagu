#!/usr/bin/env python3
"""Stable, line-independent finding fingerprints (kfp1).

A fingerprint identifies the same issue across scans so baselines and
suppressions keep working when code moves. It hashes only deterministic facts:

  category | subtype | METHOD normalized_path | file | normalized sink code | ordinal

Line numbers, finding ids and LLM-written text are never part of it.

Standard-library-only (Python 3.8+).
"""
from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lsa_common import DEFAULT_CONFIG, read_text  # noqa: E402

PREFIX = "kfp1:"
SEP = "\x1f"

_PATH_PARAM_RES = (
    re.compile(r"\{[^/}]*\}"),  # /orders/{id}
    re.compile(r"<[^/>]*>"),  # Flask /orders/<int:id>
    re.compile(r"(?<=/):[A-Za-z_][A-Za-z0-9_]*"),  # Express /orders/:orderId
    re.compile(r"(?<=/)[0-9]+(?=/|$)"),  # concrete ids /orders/123
)
_LINE_COMMENT_RE = re.compile(r"(^|\s)(//|#|--).*$")
_NUMBER_RE = re.compile(r"\b\d+(?:\.\d+)?\b")
_WS_RE = re.compile(r"\s+")


def normalize_path(method: str, path: str) -> str:
    """Upper-case the method and replace every path parameter style with {}."""
    for pattern in _PATH_PARAM_RES:
        path = pattern.sub("{}", path)
    return f"{method.upper()} {path}".strip()


def normalize_code(line: str) -> str:
    """Drop trailing line comments, numeric literals and all whitespace."""
    line = _LINE_COMMENT_RE.sub("", line)
    line = _NUMBER_RE.sub("0", line)
    return _WS_RE.sub("", line)


def _normalize_file(rel: str) -> str:
    rel = rel.replace("\\", "/")
    while rel.startswith("./"):
        rel = rel[2:]
    return rel


def _evidence_code(finding: Dict) -> str:
    loc = finding.get("location") or {}
    evidence = [e for e in finding.get("evidence") or [] if isinstance(e, dict)]
    for e in evidence:
        if e.get("line") == loc.get("start_line") and _normalize_file(e.get("file", "")) == _normalize_file(loc.get("file", "")):
            return e.get("code") or ""
    return (evidence[0].get("code") or "") if evidence else ""


def _material(finding: Dict, source_line: Optional[str]) -> str:
    endpoint = finding.get("endpoint") or {}
    code = source_line if source_line is not None else _evidence_code(finding)
    return SEP.join([
        finding.get("category", ""),
        finding.get("subtype", ""),
        normalize_path(endpoint.get("method", ""), endpoint.get("path", "")),
        _normalize_file((finding.get("location") or {}).get("file", "")),
        normalize_code(code),
    ])


def _hash(material: str, ordinal: int) -> str:
    if ordinal:
        material = f"{material}{SEP}{ordinal}"
    return PREFIX + hashlib.sha256(material.encode("utf-8")).hexdigest()


def compute_fingerprint(finding: Dict, source_line: Optional[str] = None, ordinal: int = 0) -> str:
    """Fingerprint one finding; ordinal separates identical sinks in the same file."""
    return _hash(_material(finding, source_line), ordinal)


class _SourceReader:
    """Reads sink lines from the target tree, refusing paths that escape it."""

    def __init__(self, target_dir: Optional[Path]) -> None:
        self.root = target_dir.resolve() if target_dir else None
        self.cache: Dict[str, Optional[List[str]]] = {}
        self.encodings = DEFAULT_CONFIG["hints"]["file_encodings"]

    def line(self, rel: str, lineno: int) -> Optional[str]:
        lines = self._lines(rel)
        if lines is None or not 0 < lineno <= len(lines):
            return None
        return lines[lineno - 1]

    def _lines(self, rel: str) -> Optional[List[str]]:
        if self.root is None or not rel:
            return None
        if rel not in self.cache:
            self.cache[rel] = None
            path = (self.root / rel).resolve()
            try:
                path.relative_to(self.root)
                if path.is_file():
                    self.cache[rel] = read_text(path, self.encodings).splitlines()
            except (ValueError, OSError):
                pass
        return self.cache[rel]


def assign_fingerprints(findings: List[Dict], target_dir: Optional[Path]) -> List[Dict]:
    """Return copies of the findings with a kfp1 fingerprint set on each."""
    reader = _SourceReader(target_dir)
    materials: List[Tuple[str, int]] = []
    for idx, f in enumerate(findings):
        loc = f.get("location") or {}
        source_line = reader.line(loc.get("file", ""), loc.get("start_line") or 0)
        materials.append((_material(f, source_line), idx))

    def position(item: Tuple[str, int]) -> Tuple[str, int, int]:
        loc = findings[item[1]].get("location") or {}
        return (loc.get("file", ""), loc.get("start_line") or 0, item[1])

    ordinals: Dict[int, int] = {}
    seen: Dict[str, int] = {}
    for material, idx in sorted(materials, key=position):
        ordinals[idx] = seen.get(material, 0)
        seen[material] = ordinals[idx] + 1

    return [{**f, "fingerprint": _hash(materials[idx][0], ordinals[idx])} for idx, f in enumerate(findings)]
