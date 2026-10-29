#!/usr/bin/env python3
"""Compare a scan against a baseline and gate CI on new findings.

Usage:
  baseline.py OUT [--target-dir PATH] [--baseline PATH] [--update-baseline]
                  [--suppressions PATH] [--diff-scope OUT/diff-scope.json]
                  [--fail-on none|new|any] [--fail-severity info|low|medium|high|critical]

Steps:
  1. Assign kfp1 fingerprints to every finding in OUT/findings.json and attach
     approved, unexpired suppressions (suppressed findings never fail the gate).
  2. Classify active findings as new / unchanged / regressed against the
     baseline (baseline.json or a previous SARIF); list baseline entries that
     are no longer found as fixed. Write OUT/baseline-diff.json.
  3. With --update-baseline, write the updated baseline (default OUT/baseline.json).
  4. Exit 1 when --fail-on trips, 2 on usage or baseline errors, else 0.

Standard-library-only (Python 3.8+).
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fingerprint import assign_fingerprints  # noqa: E402
from lsa_common import read_json, write_json  # noqa: E402
from suppressions import SuppressionError, apply_suppressions, load_suppressions  # noqa: E402
from trend import append_history, mttr_by_severity, snapshot  # noqa: E402

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
FAIL_ON = ("none", "new", "any")
SARIF_FINGERPRINT_KEY = "komainu/v1"


class BaselineError(Exception):
    """The baseline file is missing, unreadable or in an unknown format."""


@dataclass(frozen=True)
class BaselineDiff:
    findings: List[Dict]
    fixed: List[Dict]
    counts: Dict[str, int]


def _is_active(finding: Dict) -> bool:
    return finding.get("status") != "rejected"


def _entries_from_sarif(doc: Dict) -> Dict[str, Dict]:
    entries: Dict[str, Dict] = {}
    for run in doc.get("runs") or []:
        for result in run.get("results") or []:
            fp = (result.get("partialFingerprints") or {}).get(SARIF_FINGERPRINT_KEY)
            if not fp:
                continue
            props = result.get("properties") or {}
            locations = result.get("locations") or [{}]
            uri = ((locations[0].get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")
            entries[fp] = {
                "file": uri or "",
                "fingerprint": fp,
                "first_seen": None,
                "last_seen": None,
                "state": "open",
                "fixed_at": None,
                "severity": props.get("severity", "medium"),
                "category": (result.get("ruleId") or "").split("/")[1] if (result.get("ruleId") or "").count("/") >= 2 else "",
            }
    return entries


def load_baseline(path: Path) -> Dict[str, Dict]:
    """Load baseline entries keyed by fingerprint from baseline.json or SARIF."""
    try:
        doc = read_json(path)
    except FileNotFoundError as exc:
        raise BaselineError(f"baseline not found: {path}") from exc
    except (OSError, ValueError) as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from exc
    if isinstance(doc, dict) and isinstance(doc.get("entries"), list):
        return {e["fingerprint"]: dict(e) for e in doc["entries"] if isinstance(e, dict) and e.get("fingerprint")}
    if isinstance(doc, dict) and isinstance(doc.get("runs"), list):
        return _entries_from_sarif(doc)
    raise BaselineError(f"{path} is neither a Komainu baseline nor a SARIF file")


def load_history(path: Path) -> List[Dict]:
    """Scan history stored in a baseline.json; SARIF baselines have none."""
    doc = read_json(path)
    history = doc.get("history") if isinstance(doc, dict) and isinstance(doc.get("entries"), list) else None
    return [h for h in history if isinstance(h, dict)] if isinstance(history, list) else []


def compare(findings: List[Dict], entries: Dict[str, Dict], scope: Optional[Set[str]] = None) -> BaselineDiff:
    """Annotate findings with baseline_state and list fixed baseline entries.

    With a scope (diff mode), only entries in scanned files can be fixed: an
    unscanned file says nothing about whether its findings still exist.
    """
    annotated: List[Dict] = []
    seen = set()
    counts = {"new": 0, "unchanged": 0, "regressed": 0, "fixed": 0}
    for f in findings:
        copy = {k: v for k, v in f.items() if k != "baseline_state"}
        if _is_active(f):
            fp = f.get("fingerprint")
            entry = entries.get(fp) if fp else None
            if entry is None:
                state = "new"
            elif entry.get("state") == "fixed":
                state = "regressed"
            else:
                state = "unchanged"
            copy["baseline_state"] = state
            counts[state] += 1
            if fp:
                seen.add(fp)
        annotated.append(copy)
    fixed = [
        dict(e) for fp, e in sorted(entries.items())
        if e.get("state") != "fixed" and fp not in seen and (scope is None or e.get("file") in scope)
    ]
    counts["fixed"] = len(fixed)
    return BaselineDiff(findings=annotated, fixed=fixed, counts=counts)


def update_baseline(
    entries: Dict[str, Dict], diff: BaselineDiff, today: str, history: Optional[List[Dict]] = None
) -> Dict:
    """Return a new baseline document; the input entries are not modified."""
    updated = {fp: dict(e) for fp, e in entries.items()}
    for f in diff.findings:
        fp = f.get("fingerprint")
        if not fp or "baseline_state" not in f:
            continue
        entry = updated.get(fp, {"fingerprint": fp, "first_seen": today})
        entry.update({
            "last_seen": today,
            "state": "open",
            "fixed_at": None,
            "severity": f.get("severity", "medium"),
            "category": f.get("category", ""),
            "title": f.get("title", ""),
            "file": (f.get("location") or {}).get("file", ""),
        })
        updated[fp] = entry
    for e in diff.fixed:
        updated[e["fingerprint"]] = {**updated[e["fingerprint"]], "state": "fixed", "fixed_at": today}
    doc = {"version": 1, "updated": today, "entries": [updated[fp] for fp in sorted(updated)]}
    if history is not None:
        doc["history"] = history
    return doc


def gate(findings: List[Dict], fail_on: str, fail_severity: str) -> List[Dict]:
    """Return the findings that make CI fail under the given policy."""
    if fail_on == "none":
        return []
    states = ("new", "regressed") if fail_on == "new" else ("new", "regressed", "unchanged")
    threshold = SEVERITY_RANK[fail_severity]
    return [
        f for f in findings
        if _is_active(f)
        and not f.get("suppression")
        and f.get("baseline_state") in states
        and SEVERITY_RANK.get(f.get("severity", "medium"), 2) >= threshold
    ]


def _parse_args(argv: Optional[List[str]]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Fingerprint findings, compare with a baseline and gate CI.")
    ap.add_argument("out", help="LSA output directory containing findings.json")
    ap.add_argument("--target-dir", help="Scanned source tree (improves fingerprint stability)")
    ap.add_argument("--baseline", help="Previous baseline.json or SARIF file")
    ap.add_argument("--update-baseline", action="store_true",
                    help="Write the updated baseline to --baseline (default OUT/baseline.json)")
    ap.add_argument("--suppressions", help="Approved suppressions JSON (see suppressions.py)")
    ap.add_argument("--diff-scope", help="diff-scope.json from run_prescan.py --diff; limits which entries can be fixed")
    ap.add_argument("--fail-on", choices=FAIL_ON, default="none")
    ap.add_argument("--fail-severity", choices=list(SEVERITY_RANK), default="low")
    ap.add_argument("--today", default=datetime.date.today().isoformat(), help=argparse.SUPPRESS)
    return ap.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    out = Path(args.out)
    findings_file = out / "findings.json"
    if not findings_file.is_file():
        print(f"error: {findings_file} not found", file=sys.stderr)
        return 2

    entries: Dict[str, Dict] = {}
    history: List[Dict] = []
    baseline_path = Path(args.baseline) if args.baseline else None
    if baseline_path and (baseline_path.exists() or not args.update_baseline):
        try:
            entries = load_baseline(baseline_path)
            history = load_history(baseline_path)
        except BaselineError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    rules = []
    if args.suppressions:
        try:
            rules = load_suppressions(Path(args.suppressions))
        except SuppressionError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    doc = read_json(findings_file)
    target = Path(args.target_dir) if args.target_dir else None
    suppressed = apply_suppressions(assign_fingerprints(doc.get("findings") or [], target), rules, args.today)
    scope = None
    if args.diff_scope:
        try:
            scope = set(read_json(Path(args.diff_scope))["selected"])
        except (OSError, ValueError, KeyError, TypeError) as exc:
            print(f"error: cannot read diff scope {args.diff_scope}: {exc}", file=sys.stderr)
            return 2
    diff = compare(suppressed.findings, entries, scope)
    counts = {**diff.counts, "suppressed": sum(1 for f in diff.findings if f.get("suppression"))}
    # A diff scan sees only part of the tree, so it must not add a point to the trend
    if scope is None:
        history = append_history(history, snapshot(counts, diff.findings, args.today))
    updated = update_baseline(entries, diff, args.today, history)
    write_json(findings_file, {**doc, "findings": diff.findings})
    write_json(out / "baseline-diff.json", {
        "generated": args.today,
        "baseline": str(baseline_path) if baseline_path else None,
        "counts": counts,
        "new": [f.get("finding_id") for f in diff.findings if f.get("baseline_state") == "new"],
        "regressed": [f.get("finding_id") for f in diff.findings if f.get("baseline_state") == "regressed"],
        "fixed": diff.fixed,
        "expired_suppressions": [s.to_dict() for s in suppressed.expired],
        "unused_suppressions": [s.to_dict() for s in suppressed.unused],
        "trend": {"history": history, "mttr": mttr_by_severity(updated["entries"])},
    })

    if args.update_baseline:
        write_json(baseline_path or out / "baseline.json", updated)

    print(f"baseline: {counts['new']} new, {counts['unchanged']} unchanged, {counts['regressed']} regressed, "
          f"{counts['fixed']} fixed, {counts['suppressed']} suppressed")
    for s in suppressed.expired:
        print(f"warning: suppression for {s.fingerprint} expired on {s.expires} (approved by {s.approved_by})")
    for s in suppressed.unused:
        print(f"warning: suppression for {s.fingerprint} matched no finding; remove it if the issue is fixed")
    tripped = gate(diff.findings, args.fail_on, args.fail_severity)
    if tripped:
        print(f"gate: {len(tripped)} finding(s) fail --fail-on {args.fail_on} --fail-severity {args.fail_severity}")
        for f in tripped:
            print(f"  - {f.get('finding_id')} [{f.get('severity')}] {f.get('baseline_state')}: {f.get('title', '')}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
