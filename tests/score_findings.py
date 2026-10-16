#!/usr/bin/env python3
"""Score an agent run (OUT/findings.json) against ground-truth.json from build_eval_repo.py.

Usage: python3 tests/score_findings.py GROUND_TRUTH OUT [--tolerance 3]

A vulnerable truth item is found (TP) when an active finding (status != rejected) has the
same category (sql_injection and nosql_injection are treated as one group), and the truth
line is within --tolerance lines of the finding location or of any evidence line in the same file.
A safe truth item hit by an active finding counts as a false positive (FP-safe).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("ground_truth")
    ap.add_argument("out")
    ap.add_argument("--tolerance", type=int, default=3)
    a = ap.parse_args()
    truth = json.loads(Path(a.ground_truth).read_text())["items"]
    # fixture paths are relative to tests/fixtures; eval repo keeps the same layout
    allf = json.loads((Path(a.out) / "findings.json").read_text())["findings"]
    findings = [f for f in allf if f["status"] not in ("rejected", "needs_review")]
    needs_review = [f["finding_id"] for f in allf if f["status"] == "needs_review"]
    rows = {}
    matched_findings = set()
    for g in ("bola", "injection"):
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
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
