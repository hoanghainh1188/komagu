"""Anchor model-written finding locations to the Tier 1 routes and candidates they refer to (#319).

Small local models judge the right route or candidate but often write a wrong or non-existent path
into the finding (Evaluation Run 4: `routes.js`, `app.py`, `dotnet-mvc/...`). Tier 1 already knows
where every route handler and query / binding candidate is, so the location comes from there.

Rules:
- route findings (`route_id`): the file is the route handler's file; the model's line is kept when
  it falls inside the handler span (handler line up to the next route in the same file, or the end
  of the file), otherwise the handler line is used.
- candidate findings (`candidate_id`): file and line are the candidate's.
- evidence entries are re-pointed the same way; entries whose file does not exist and cannot be
  re-pointed are dropped.
- findings with an unknown `route_id` / `candidate_id` keep their location, get `confidence: low`
  and are reported as unanchored.

Standard-library only (Python 3.8+ compatible).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CANDIDATE_FILES = ("injection.candidates.json", "mass-assignment.candidates.json")


@dataclass(frozen=True)
class Anchor:
    file: str
    line: int
    end_line: Optional[int]  # last line of the handler span; None for an exact candidate site


@dataclass
class AnchorReport:
    moved: List[str] = field(default_factory=list)
    unanchored: List[str] = field(default_factory=list)


def _read(path: Path) -> Dict[str, Any]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


def _line_count(target_dir: Path, rel_file: str) -> int:
    try:
        return len((target_dir / rel_file).read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return 0


def load_anchors(out_dir: Path, target_dir: Path) -> Dict[str, Anchor]:
    """route_id / candidate_id -> Anchor, from OUT/routes/*.json and the Tier 1 candidate files."""
    handlers: List[Tuple[str, int, str]] = []
    for path in sorted((out_dir / "routes").glob("*.json")):
        for route in _read(path).get("routes") or []:
            if not isinstance(route, dict):
                continue
            handler = route.get("handler") or {}
            if route.get("route_id") and handler.get("file") and isinstance(handler.get("line"), int):
                handlers.append((handler["file"], handler["line"], route["route_id"]))

    anchors: Dict[str, Anchor] = {}
    for rel_file, line, route_id in handlers:
        later = sorted(ln for f, ln, _ in handlers if f == rel_file and ln > line)
        end = later[0] - 1 if later else max(_line_count(target_dir, rel_file), line)
        anchors[route_id] = Anchor(rel_file, line, end)

    for name in CANDIDATE_FILES:
        for cand in _read(out_dir / name).get("candidates") or []:
            if isinstance(cand, dict) and cand.get("candidate_id") and cand.get("file") and isinstance(cand.get("line"), int):
                anchors[cand["candidate_id"]] = Anchor(cand["file"], cand["line"], None)
    return anchors


def _anchored_line(anchor: Anchor, line: Any) -> int:
    if anchor.end_line is None or not isinstance(line, int):
        return anchor.line
    return line if anchor.line <= line <= anchor.end_line else anchor.line


def _repoint_evidence(evidence: Any, anchor: Anchor, target_dir: Path) -> List[Dict[str, Any]]:
    kept = []
    for ev in evidence if isinstance(evidence, list) else []:
        if not isinstance(ev, dict):
            continue
        rel = str(ev.get("file") or "")
        if rel == anchor.file or (rel and (target_dir / rel).is_file()):
            kept.append(ev)
        elif anchor.end_line is not None and isinstance(ev.get("line"), int) and anchor.line <= ev["line"] <= anchor.end_line:
            kept.append({**ev, "file": anchor.file})
    return kept or [{"file": anchor.file, "line": anchor.line, "why": "Location taken from the Tier 1 inventory"}]


def anchor_finding(finding: Dict[str, Any], anchors: Dict[str, Anchor], target_dir: Path) -> Tuple[Dict[str, Any], Optional[bool]]:
    """Return (finding with Tier 1 location, moved?); moved is None when the finding has no known anchor."""
    key = finding.get("route_id") or finding.get("candidate_id")
    anchor = anchors.get(key) if key else None
    if anchor is None:
        return {**finding, "confidence": "low"}, None
    loc = finding.get("location") if isinstance(finding.get("location"), dict) else {}
    # a wrong path with a line inside the handler span is most likely the right line in the wrong file
    new_loc = {**loc, "file": anchor.file, "start_line": _anchored_line(anchor, loc.get("start_line"))}
    if anchor.end_line is None:
        new_loc.pop("end_line", None)
    moved = (loc.get("file"), loc.get("start_line")) != (new_loc["file"], new_loc["start_line"])
    evidence = _repoint_evidence(finding.get("evidence"), anchor, target_dir)
    return {**finding, "location": new_loc, "evidence": evidence}, moved


def anchor_findings(findings: List[Dict[str, Any]], anchors: Dict[str, Anchor], target_dir: Path,
                    report: AnchorReport) -> List[Dict[str, Any]]:
    out = []
    for f in findings:
        if not isinstance(f, dict):
            out.append(f)
            continue
        anchored, moved = anchor_finding(f, anchors, target_dir)
        if moved is None:
            report.unanchored.append(str(f.get("finding_id")))
        elif moved:
            report.moved.append(str(f.get("finding_id")))
        out.append(anchored)
    return out
