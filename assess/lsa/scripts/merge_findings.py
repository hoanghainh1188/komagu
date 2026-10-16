#!/usr/bin/env python3
"""Merge agent outputs into routes.json and findings.json, validate them, and check coverage.

Usage: merge_findings.py OUT

Reads:
  OUT/routes/*.json                         (route-mapper outputs)
  OUT/findings/bola-*.json, inj-*.json      (auditor outputs)
  OUT/findings/verified-*.json              (verifier outputs)
Writes:
  OUT/routes.json, OUT/findings.json, OUT/coverage.json
Exit code 1 when validation errors or coverage gaps exist (details in coverage.json).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lsa_common import KIT_VERSION, read_json, write_json  # noqa: E402

KIT = Path(__file__).resolve().parent.parent
# Generated bundles carry schemas/ next to scripts/; in the source repo they live in <repo>/contracts/schemas.
SCHEMAS = KIT / "schemas" if (KIT / "schemas").is_dir() else KIT.parent.parent / "contracts" / "schemas"
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def load_validator(schema_name: str):
    schema = read_json(SCHEMAS / schema_name)
    try:
        import jsonschema  # optional; old versions lack Draft 2020-12, the kit schemas also validate as Draft 7
        cls = getattr(jsonschema, "Draft202012Validator", None) or getattr(jsonschema, "Draft7Validator")
        if cls.__name__ != "Draft202012Validator":
            schema = {k: val for k, val in schema.items() if k != "$schema"}
        v = cls(schema)
        return lambda obj: [f"{'/'.join(map(str, e.path))}: {e.message}" for e in v.iter_errors(obj)]
    except (ImportError, AttributeError):
        req = schema.get("required", [])
        props = schema.get("properties", {})

        def basic(obj):
            errs = [f"missing required field '{k}'" for k in req if k not in obj]
            for k, spec in props.items():
                if k in obj and "enum" in spec and obj[k] not in spec["enum"]:
                    errs.append(f"{k}: '{obj[k]}' not in {spec['enum']}")
            return errs
        return basic


def extract_json(path: Path):
    """Accept a raw JSON file or a markdown file with a ```json fenced block."""
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"```json\s*(\{[\s\S]*?\})\s*```", text)
        if m:
            return json.loads(m.group(1))
        raise


def merge_routes(out: Path, errors: List[str]) -> Tuple[Dict, Dict]:
    rdir = out / "routes"
    merged = {"routes": [], "rejected": []}
    validate = load_validator("route-inventory.schema.json")
    if rdir.is_dir():
        for p in sorted(rdir.glob("*.json")):
            try:
                doc = extract_json(p)
            except Exception as e:  # noqa: BLE001
                errors.append(f"{p.name}: invalid JSON ({e})")
                continue
            for e in validate(doc):
                errors.append(f"{p.name}: {e}")
            merged["routes"].extend(doc.get("routes", []))
            merged["rejected"].extend(doc.get("rejected", []))
    cov = {}
    cand_path = out / "routes.candidates.json"
    if cand_path.exists() and rdir.is_dir():
        cands = {c["route_id"] for c in read_json(cand_path)["candidates"]}
        seen = {r["route_id"] for r in merged["routes"]} | {r["route_id"] for r in merged["rejected"]}
        base_seen = {re.sub(r"-x\d+$", "", s) for s in seen}
        missing = sorted(cands - base_seen)
        cov = {"route_candidates": len(cands), "inventoried": len(merged["routes"]), "rejected": len(merged["rejected"]),
               "missing_from_inventory": missing}
    merged["generated_by"] = f"lsa merge_findings.py {KIT_VERSION}"
    return merged, cov


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out")
    a = ap.parse_args()
    out = Path(a.out)
    errors: List[str] = []
    routes, cov = merge_routes(out, errors)
    if routes["routes"] or routes["rejected"]:
        write_json(out / "routes.json", routes)

    validate = load_validator("finding.schema.json")
    findings: Dict[str, Dict] = {}
    verifs: Dict[str, Dict] = {}
    route_verdicts, cand_verdicts = {}, {}
    new_issues: List[Dict] = []
    oos_notes: List[str] = []
    fdir = out / "findings"
    for p in sorted(fdir.glob("*.json")) if fdir.is_dir() else []:
        try:
            doc = extract_json(p)
        except Exception as e:  # noqa: BLE001
            errors.append(f"{p.name}: invalid JSON ({e})")
            continue
        if "verifications" in doc:
            for e in load_validator("verification.schema.json")(doc):
                errors.append(f"{p.name}: {e}")
        for v in doc.get("verifications", []):
            verifs[v["finding_id"]] = v
        new_issues.extend(dict(i, source=p.name) for i in doc.get("new_issues", []))
        oos_notes.extend(f"{p.name}: {n}" for n in doc.get("out_of_scope_notes", []) if n)
        for rv in doc.get("route_verdicts", []):
            route_verdicts[rv["route_id"]] = rv
        for cv in doc.get("candidate_verdicts", []):
            cand_verdicts[cv["candidate_id"]] = cv
        for f in doc.get("findings", []):
            errs = validate(f)
            if errs:
                errors.extend(f"{p.name}:{f.get('finding_id', '?')}: {e}" for e in errs)
                continue
            fid = f["finding_id"]
            if fid in findings:
                errors.append(f"duplicate finding_id {fid} in {p.name}")
                continue
            f["_source"] = p.name
            findings[fid] = f

    # de-duplicate the same issue reported twice (same category + file + start line)
    by_loc: Dict[Tuple, str] = {}
    duplicates = []
    for fid, f in sorted(findings.items(), key=lambda kv: SEV_ORDER.get(kv[1]["severity"], 9)):
        key = (f["category"], f["location"]["file"], f["location"]["start_line"])
        if key in by_loc:
            duplicates.append({"kept": by_loc[key], "dropped": fid})
            continue
        by_loc[key] = fid
    for d in duplicates:
        findings.pop(d["dropped"], None)

    # apply verification
    unverified = []
    for fid, f in findings.items():
        v = verifs.get(fid)
        if not v:
            unverified.append(fid)
            continue
        f["verification"] = {k: v.get(k) for k in ("verdict", "reason_code", "checked", "control_found", "notes",
                                                   "suggested_subtype", "suggested_cwe")}
        f["status"] = v["verdict"]
        if v.get("severity"):
            f["severity"] = v["severity"]
        if v.get("confidence"):
            f["confidence"] = v["confidence"]

    # coverage of audit verdicts
    if (out / "routes.json").exists():
        need = [r["route_id"] for r in read_json(out / "routes.json")["routes"] if r.get("needs_bola_audit")]
        cov["bola_routes_to_audit"] = len(need)
        cov["bola_routes_without_verdict"] = sorted(set(need) - set(route_verdicts))
    if (out / "injection.candidates.json").exists():
        ic = [c["candidate_id"] for c in read_json(out / "injection.candidates.json")["candidates"]]
        cov["injection_candidates"] = len(ic)
        cov["injection_candidates_without_verdict"] = sorted(set(ic) - set(cand_verdicts))
    cov["findings_without_verification"] = sorted(unverified)
    cov["duplicates_removed"] = duplicates
    cov["validation_errors"] = errors
    cov["new_issues_from_verifier"] = new_issues
    cov["out_of_scope_notes"] = oos_notes

    active = [f for f in findings.values() if f["status"] != "rejected"]
    summary = {
        "total_reported": len(findings),
        "active": len(active),
        "rejected_by_verifier": sum(1 for f in findings.values() if f["status"] == "rejected"),
        "by_severity": {s: sum(1 for f in active if f["severity"] == s) for s in SEV_ORDER},
        "by_category": {c: sum(1 for f in active if f["category"] == c) for c in ("bola", "sql_injection", "nosql_injection")},
        "by_status": {s: sum(1 for f in findings.values() if f["status"] == s)
                      for s in ("unverified", "confirmed", "likely", "rejected", "needs_review")},
    }
    ordered = sorted(findings.values(), key=lambda f: (f["status"] == "rejected", SEV_ORDER.get(f["severity"], 9), f["finding_id"]))
    for f in ordered:
        f.pop("_source", None)
    write_json(out / "findings.json", {"generated_by": f"lsa merge_findings.py {KIT_VERSION}", "summary": summary, "findings": ordered})
    write_json(out / "coverage.json", cov)
    gaps = any(cov.get(k) for k in ("missing_from_inventory", "bola_routes_without_verdict",
                                    "injection_candidates_without_verdict", "validation_errors",
                                    "new_issues_from_verifier"))
    print(json.dumps({"summary": summary, "coverage_gaps": gaps}, indent=2))
    return 1 if gaps else 0


if __name__ == "__main__":
    sys.exit(main())
