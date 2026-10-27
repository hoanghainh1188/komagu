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


def _resolve_ref(root_schema: dict, ref: str) -> dict:
    """Resolve a local JSON schema $ref pointer like #/$defs/loc."""
    if ref.startswith("#/"):
        curr = root_schema
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(curr, dict) and part in curr:
                curr = curr[part]
            else:
                return {}
        return curr if isinstance(curr, dict) else {}
    return {}


def _check_type(instance, expected_type: str) -> bool:
    """Validate python instance type against JSON schema type."""
    if expected_type == "string":
        return isinstance(instance, str)
    if expected_type == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if expected_type == "number":
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)
    if expected_type == "boolean":
        return isinstance(instance, bool)
    if expected_type == "object":
        return isinstance(instance, dict)
    if expected_type == "array":
        return isinstance(instance, list)
    if expected_type == "null":
        return instance is None
    return True


def _validate_node(instance, schema: dict, root_schema: dict, path: str, errors: List[str]) -> None:
    """Recursively validate instance against JSON schema in pure Python stdlib."""
    if not isinstance(schema, dict):
        return
    if "$ref" in schema:
        resolved = _resolve_ref(root_schema, schema["$ref"])
        _validate_node(instance, resolved, root_schema, path, errors)
        return

    # Check type
    if "type" in schema:
        st = schema["type"]
        allowed = [st] if isinstance(st, str) else (st if isinstance(st, list) else [])
        if not any(_check_type(instance, t) for t in allowed):
            errors.append(f"{path or '<root>'}: expected {allowed}, got {type(instance).__name__}")
            return

    # Check enum
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path or '<root>'}: '{instance}' not in {schema['enum']}")

    # String checks
    if isinstance(instance, str):
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errors.append(f"{path or '<root>'}: '{instance}' does not match pattern '{schema['pattern']}'")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(f"{path or '<root>'}: length {len(instance)} exceeds maxLength {schema['maxLength']}")

    # Number checks
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path or '<root>'}: {instance} is less than minimum {schema['minimum']}")

    # Array checks
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{path or '<root>'}: item count {len(instance)} less than minItems {schema['minItems']}")
        if "items" in schema and isinstance(schema["items"], dict):
            item_schema = schema["items"]
            for idx, item in enumerate(instance):
                subpath = f"{path}[{idx}]" if path else f"[{idx}]"
                _validate_node(item, item_schema, root_schema, subpath, errors)

    # Object checks
    if isinstance(instance, dict):
        if "required" in schema and isinstance(schema["required"], list):
            for req in schema["required"]:
                if req not in instance:
                    subpath = f"{path}.{req}" if path else req
                    errors.append(f"{subpath}: missing required field '{req}'")
        if "properties" in schema and isinstance(schema["properties"], dict):
            for prop_name, prop_schema in schema["properties"].items():
                if prop_name in instance:
                    subpath = f"{path}.{prop_name}" if path else prop_name
                    _validate_node(instance[prop_name], prop_schema, root_schema, subpath, errors)


def load_validator(schema_name: str):
    schema = read_json(SCHEMAS / schema_name)
    try:
        import jsonschema  # optional; old versions lack Draft 2020-12, the kit schemas also validate as Draft 7
        cls = getattr(jsonschema, "Draft202012Validator", None) or getattr(jsonschema, "Draft7Validator")
        if cls.__name__ != "Draft202012Validator":
            schema_clean = {k: val for k, val in schema.items() if k != "$schema"}
        else:
            schema_clean = schema
        v = cls(schema_clean)
        return lambda obj: [f"{'/'.join(map(str, e.path))}: {e.message}" for e in v.iter_errors(obj)]
    except (ImportError, AttributeError):
        def fallback(obj):
            errs: List[str] = []
            _validate_node(obj, schema, schema, "", errs)
            return errs
        return fallback


def extract_json(path: Path):
    """Accept a raw JSON file or a markdown file with a ```json fenced block."""
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"```json\s*(\{[\s\S]*?\}|\[[\s\S]*?\])\s*```", text)
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
            if not isinstance(doc, dict):
                errors.append(f"{p.name}: expected JSON object, got {type(doc).__name__}")
                continue
            for e in validate(doc):
                errors.append(f"{p.name}: {e}")
            for r in doc.get("routes", []) if isinstance(doc.get("routes"), list) else []:
                if isinstance(r, dict) and "route_id" in r:
                    merged["routes"].append(r)
                else:
                    errors.append(f"{p.name}: malformed route item in inventory")
            for rj in doc.get("rejected", []) if isinstance(doc.get("rejected"), list) else []:
                if isinstance(rj, dict) and "route_id" in rj:
                    merged["rejected"].append(rj)
                else:
                    errors.append(f"{p.name}: malformed rejected route item in inventory")
    cov = {}
    cand_path = out / "routes.candidates.json"
    if cand_path.exists():
        cands_doc = read_json(cand_path)
        cands_list = cands_doc.get("candidates", []) if isinstance(cands_doc, dict) else []
        cands = {c["route_id"] for c in cands_list if isinstance(c, dict) and "route_id" in c}
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

    # Clear stale outputs across runs
    (out / "routes.json").unlink(missing_ok=True)
    (out / "findings.json").unlink(missing_ok=True)
    (out / "coverage.json").unlink(missing_ok=True)

    routes, cov = merge_routes(out, errors)
    # Always write routes.json so downstream tools have valid JSON
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
        if not isinstance(doc, dict):
            errors.append(f"{p.name}: expected JSON object, got {type(doc).__name__}")
            continue

        if "verifications" in doc:
            for e in load_validator("verification.schema.json")(doc):
                errors.append(f"{p.name}: {e}")

        for v in doc.get("verifications", []) if isinstance(doc.get("verifications"), list) else []:
            if not isinstance(v, dict):
                errors.append(f"{p.name}: verification item is not an object ({type(v).__name__})")
                continue
            vid = v.get("finding_id")
            if not vid:
                errors.append(f"{p.name}: verification missing finding_id")
                continue
            verifs[vid] = v

        for i in doc.get("new_issues", []) if isinstance(doc.get("new_issues"), list) else []:
            if isinstance(i, dict):
                new_issues.append(dict(i, source=p.name))
            else:
                errors.append(f"{p.name}: malformed new_issues item ({type(i).__name__})")

        for n in doc.get("out_of_scope_notes", []) if isinstance(doc.get("out_of_scope_notes"), list) else []:
            if isinstance(n, str) and n.strip():
                oos_notes.append(f"{p.name}: {n.strip()}")

        for rv in doc.get("route_verdicts", []) if isinstance(doc.get("route_verdicts"), list) else []:
            if not isinstance(rv, dict) or "route_id" not in rv:
                errors.append(f"{p.name}: malformed route_verdict item (missing route_id)")
                continue
            route_verdicts[rv["route_id"]] = rv

        for cv in doc.get("candidate_verdicts", []) if isinstance(doc.get("candidate_verdicts"), list) else []:
            if not isinstance(cv, dict) or "candidate_id" not in cv:
                errors.append(f"{p.name}: malformed candidate_verdict item (missing candidate_id)")
                continue
            cand_verdicts[cv["candidate_id"]] = cv

        for f in doc.get("findings", []) if isinstance(doc.get("findings"), list) else []:
            if not isinstance(f, dict):
                errors.append(f"{p.name}: finding item is not an object ({type(f).__name__})")
                continue
            errs = validate(f)
            if errs:
                errors.extend(f"{p.name}:{f.get('finding_id', '?')}: {e}" for e in errs)
                continue
            fid = f.get("finding_id")
            if not fid:
                errors.append(f"{p.name}: finding missing finding_id")
                continue
            if fid in findings:
                errors.append(f"duplicate finding_id {fid} in {p.name}")
                continue
            f["_source"] = p.name
            findings[fid] = f

    # 1. apply verification first
    unverified = []
    for fid, f in findings.items():
        v = verifs.get(fid)
        if not v:
            unverified.append(fid)
            continue
        f["verification"] = {k: v.get(k) for k in ("verdict", "reason_code", "checked", "control_found", "notes",
                                                   "suggested_subtype", "suggested_cwe")}
        f["status"] = v.get("verdict", f.get("status", "unverified"))
        if v.get("severity"):
            f["severity"] = v["severity"]
        if v.get("confidence"):
            f["confidence"] = v["confidence"]
        if v.get("consensus"):
            f["consensus"] = v["consensus"]
        if v.get("attack_vector"):
            f["attack_vector"] = v["attack_vector"]

    # 2. de-duplicate findings: prefer non-rejected findings, then higher severity, confidence, fid
    # Dedupe key includes (category, subtype, route_id, file, start_line)
    CONF_ORDER = {"high": 0, "medium": 1, "low": 2}
    def _finding_sort_key(item: Tuple[str, Dict]):
        fid, f = item
        is_rejected = 1 if f.get("status") == "rejected" else 0
        sev = SEV_ORDER.get(f.get("severity"), 9)
        conf = CONF_ORDER.get(f.get("confidence"), 9)
        return (is_rejected, sev, conf, fid)

    by_loc: Dict[Tuple, str] = {}
    duplicates = []
    for fid, f in sorted(findings.items(), key=_finding_sort_key):
        loc = f.get("location") or {}
        key = (f.get("category"), f.get("subtype"), f.get("route_id"), loc.get("file"), loc.get("start_line"))
        if key in by_loc:
            duplicates.append({"kept": by_loc[key], "dropped": fid})
            continue
        by_loc[key] = fid

    for d in duplicates:
        findings.pop(d["dropped"], None)

    # Filter unverified list to exclude dropped duplicates
    unverified = [fid for fid in unverified if fid in findings]

    # coverage of audit verdicts
    if (out / "routes.json").exists():
        need = [r["route_id"] for r in read_json(out / "routes.json").get("routes", []) if isinstance(r, dict) and r.get("needs_bola_audit")]
        cov["bola_routes_to_audit"] = len(need)
        cov["bola_routes_without_verdict"] = sorted(set(need) - set(route_verdicts))
    if (out / "injection.candidates.json").exists():
        ic_doc = read_json(out / "injection.candidates.json")
        ic_list = ic_doc.get("candidates", []) if isinstance(ic_doc, dict) else []
        ic = [c["candidate_id"] for c in ic_list if isinstance(c, dict) and "candidate_id" in c]
        cov["injection_candidates"] = len(ic)
        cov["injection_candidates_without_verdict"] = sorted(set(ic) - set(cand_verdicts))
    cov["findings_without_verification"] = sorted(unverified)
    cov["duplicates_removed"] = duplicates
    cov["validation_errors"] = errors
    cov["new_issues_from_verifier"] = new_issues
    cov["out_of_scope_notes"] = oos_notes

    active = [f for f in findings.values() if f.get("status") != "rejected"]
    summary = {
        "total_reported": len(findings),
        "active": len(active),
        "rejected_by_verifier": sum(1 for f in findings.values() if f.get("status") == "rejected"),
        "by_severity": {s: sum(1 for f in active if f.get("severity") == s) for s in SEV_ORDER},
        "by_category": {c: sum(1 for f in active if f.get("category") == c) for c in ("bola", "sql_injection", "nosql_injection")},
        "by_status": {s: sum(1 for f in findings.values() if f.get("status") == s)
                      for s in ("unverified", "confirmed", "likely", "rejected", "needs_review")},
    }
    ordered = sorted(findings.values(), key=lambda f: (f.get("status") == "rejected", SEV_ORDER.get(f.get("severity"), 9), f.get("finding_id", "")))
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
