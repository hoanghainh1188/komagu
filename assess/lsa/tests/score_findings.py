#!/usr/bin/env python3
"""Score an agent run (OUT/findings.json) against ground-truth.json from build_eval_repo.py.

Usage: python3 tests/score_findings.py GROUND_TRUTH OUT [--tolerance 3]

A vulnerable truth item is found (TP) when an active finding (status != rejected) has the
same category (sql_injection and nosql_injection are treated as one group), and the truth
line is within --tolerance lines of the finding location or of any evidence line in the same file.
A safe truth item hit by an active finding counts as a false positive (FP-safe).

--verdicts adds a verdict-level score for bfla and mass_assignment: a truth item counts as found when
the privilege auditor judged the route or candidate that contains it "vulnerable" or "needs_review",
whatever file and line the model then wrote into the finding. Routes cover their handler line up to
the next inventoried route in the same file; mass assignment candidates match their exact line.
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def group(cat: str) -> str:
    return "injection" if cat in ("sql_injection", "nosql_injection") else cat


def hits(finding: dict, item: dict, tol: int) -> bool:
    if group(finding["category"]) != group(item["category"]):
        return False
    locs = [(finding["location"]["file"], finding["location"]["start_line"], finding["location"].get("end_line") or finding["location"]["start_line"])]
    locs += [(e["file"], e["line"], e["line"]) for e in finding.get("evidence", [])]
    for f, s, e in locs:
        if f.endswith(item["file"]) or item["file"].endswith(f):
            if s - tol <= item["line"] <= e + tol:
                return True
    return False


FLAGGED = ("vulnerable", "needs_review")


def _same_file(a: str, b: str) -> bool:
    return bool(a) and bool(b) and (a.endswith(b) or b.endswith(a))


def _route_for(item: dict, routes: List[Tuple[str, int, str]]) -> Optional[str]:
    """route_id whose handler span (handler line .. next route in the file) contains the truth line."""
    in_file = sorted((line, rid) for f, line, rid in routes if _same_file(f, item["file"]) and line <= item["line"])
    return in_file[-1][1] if in_file else None


def verdict_scores(out: Path, truth: List[dict]) -> Dict[str, dict]:
    routes: List[Tuple[str, int, str]] = []
    for p in glob.glob(str(out / "routes" / "*.json")):
        for r in json.loads(Path(p).read_text()).get("routes", []):
            h = r.get("handler") or {}
            if h.get("file") and isinstance(h.get("line"), int):
                routes.append((h["file"], h["line"], r.get("route_id")))
    cands_path = out / "mass-assignment.candidates.json"
    cands = json.loads(cands_path.read_text()).get("candidates", []) if cands_path.is_file() else []
    route_v: Dict[str, str] = {}
    cand_v: Dict[str, str] = {}
    for p in glob.glob(str(out / "findings" / "priv-*.json")):
        doc = json.loads(Path(p).read_text())
        route_v.update({v.get("route_id"): v.get("verdict") for v in doc.get("privilege_route_verdicts", []) if isinstance(v, dict)})
        cand_v.update({v.get("candidate_id"): v.get("verdict") for v in doc.get("candidate_verdicts", []) if isinstance(v, dict)})

    def flagged(item: dict) -> bool:
        if item["category"] == "bfla":
            return route_v.get(_route_for(item, routes)) in FLAGGED
        return any(_same_file(c.get("file", ""), item["file"]) and c.get("line") == item["line"]
                   and cand_v.get(c.get("candidate_id")) in FLAGGED for c in cands)

    rows = {}
    for cat in ("bfla", "mass_assignment"):
        vul = [t for t in truth if t["category"] == cat and t["vulnerable"]]
        safe = [t for t in truth if t["category"] == cat and not t["vulnerable"]]
        if not vul:
            continue
        found = [t for t in vul if flagged(t)]
        rows[cat] = {"truth_vulnerable": len(vul), "found": len(found), "recall": round(len(found) / len(vul), 3),
                     "flagged_safe": [f"{t['file']}:{t['line']}" for t in safe if flagged(t)],
                     "missed": [f"{t['file']}:{t['line']}" for t in vul if t not in found]}
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("ground_truth")
    ap.add_argument("out")
    ap.add_argument("--tolerance", type=int, default=3)
    ap.add_argument("--verdicts", action="store_true", help="also score bfla / mass_assignment by auditor verdicts")
    a = ap.parse_args()
    truth = json.loads(Path(a.ground_truth).read_text())["items"]
    # fixture paths are relative to tests/fixtures; eval repo keeps the same layout
    allf = json.loads((Path(a.out) / "findings.json").read_text())["findings"]
    findings = [f for f in allf if f["status"] not in ("rejected", "needs_review")]
    needs_review = [f["finding_id"] for f in allf if f["status"] == "needs_review"]
    rows = {}
    matched_findings = set()
    present = {group(t["category"]) for t in truth}
    for g in [g for g in ("bola", "injection", "bfla", "mass_assignment") if g in present]:
        vul = [t for t in truth if group(t["category"]) == g and t["vulnerable"]]
        safe = [t for t in truth if group(t["category"]) == g and not t["vulnerable"]]
        tp = 0
        missed = []
        for t in vul:
            ok = [f["finding_id"] for f in findings if hits(f, t, a.tolerance)]
            if ok:
                tp += 1
                matched_findings.update(ok)
            else:
                missed.append(f"{t['file']}:{t['line']}")
        # a finding on a safe line is a false positive only if it does not also explain a vulnerable item
        fp_safe = [f"{t['file']}:{t['line']}" for t in safe
                   if any(hits(f, t, 0) and not any(hits(f, v, 0) for v in vul) for f in findings)]
        rows[g] = {"truth_vulnerable": len(vul), "found": tp, "recall": round(tp / len(vul), 3) if vul else None,
                   "false_positive_on_safe_code": fp_safe, "missed": missed}
    g_findings = [f for f in findings]
    unmatched = [f["finding_id"] for f in g_findings if f["finding_id"] not in matched_findings]
    precision = round(len(matched_findings) / len(g_findings), 3) if g_findings else None
    report = {"per_category": rows, "active_findings": len(g_findings), "matched_findings": len(matched_findings),
              "precision": precision, "unmatched_findings": unmatched,
              "needs_review_not_scored": needs_review}
    if a.verdicts:
        report["verdict_level"] = verdict_scores(Path(a.out), truth)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
