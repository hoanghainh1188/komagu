"""Write a minimal finding for every flagged auditor verdict the model left without one (#323).

Small local models sometimes judge a route or candidate correctly ("vulnerable" / "needs_review")
but write no finding for it (Evaluation Run 5, run A: four mass assignment candidates). Those count
as missed although the judgment was right, so a finding is generated from the verdict and the
Tier 1 record it refers to:
- category and subtype come from the record (`category_hint` / `subtype_hint` / `subtype`), or the
  phase's default;
- location is the record's handler or candidate site (the runner then anchors it like any finding);
- `confidence: low`, `status: unverified` (the verifier judges it like any finding), and `impact`
  names the verdict it was generated from.

Standard-library only (Python 3.8+ compatible).
"""

from __future__ import annotations

from typing import Any, Dict, List

FLAGGED = ("vulnerable", "needs_review")
# Valid subtypes per category (finding.schema.json); the first one is the default
SUBTYPES = {
    "bola": ["missing_ownership_check", "ownership_check_bypassable", "id_from_request_used_as_identity",
             "no_authentication", "parent_checked_child_not", "check_result_ignored"],
    "sql_injection": ["string_concatenation", "string_interpolation", "format_string", "template_placeholder",
                      "dynamic_identifier", "second_order", "stored_procedure_dynamic_sql"],
    "nosql_injection": ["operator_injection", "js_injection", "string_concatenation", "string_interpolation"],
    "bfla": ["missing_role_check", "role_from_request", "client_side_role_check"],
    "mass_assignment": ["whole_object_binding", "privileged_field_writable"],
}
DEFAULT_CWE = {"bola": ["CWE-284"], "bfla": ["CWE-285"], "mass_assignment": ["CWE-915"],
               "sql_injection": ["CWE-89"], "nosql_injection": ["CWE-943"]}
PREFIX = {"bola": "BOLA", "sql_injection": "INJ", "nosql_injection": "INJ", "bfla": "BFLA", "mass_assignment": "MASS"}
LABEL = {"bola": "Missing ownership check", "sql_injection": "SQL injection", "nosql_injection": "NoSQL injection",
         "bfla": "Missing role check", "mass_assignment": "Mass assignment"}
RECOMMENDATION = {
    "bola": "Bind the object lookup to the current user or tenant, or check ownership before using it.",
    "sql_injection": "Use parameterized queries; allow-list any dynamic identifier.",
    "nosql_injection": "Pass typed values to the query; reject operator objects and server-side JavaScript.",
    "bfla": "Check the caller's role on the server before the privileged action.",
    "mass_assignment": "Bind only an explicit allow-list of fields; never bind role, owner or balance fields.",
}


def _category(record: Dict[str, Any], default: str) -> str:
    hint = record.get("category_hint")
    return hint if hint in SUBTYPES else default


def _subtype(record: Dict[str, Any], category: str) -> str:
    hints = str(record.get("subtype_hint") or record.get("subtype") or "").split("|")
    return next((h for h in hints if h in SUBTYPES[category]), SUBTYPES[category][0])


def _site(record: Dict[str, Any]) -> Dict[str, Any]:
    """file / start_line of a route handler or a candidate."""
    handler = record.get("handler") if isinstance(record.get("handler"), dict) else {}
    loc = record.get("location") if isinstance(record.get("location"), dict) else {}
    line = handler.get("line") or record.get("line") or loc.get("start_line")
    return {"file": handler.get("file") or record.get("file") or loc.get("file") or "unknown",
            "start_line": line if isinstance(line, int) else 1}


def _finding(key: str, record_id: str, verdict: str, record: Dict[str, Any], default_category: str) -> Dict[str, Any]:
    category = _category(record, default_category)
    site = _site(record)
    finding = {
        "finding_id": f"{PREFIX[category]}-{record_id}-verdict",
        "category": category,
        "subtype": _subtype(record, category),
        "title": f"{LABEL[category]} at {site['file']}:{site['start_line']} (from auditor verdict)",
        key: record_id,
        "location": site,
        "evidence": [{"file": site["file"], "line": site["start_line"],
                      "why": f"The auditor judged this {'route' if key == 'route_id' else 'candidate'} '{verdict}' but wrote no finding"}],
        "impact": f"Generated from the auditor's '{verdict}' verdict; the model wrote no finding for it.",
        "severity": "medium",
        "confidence": "low",
        "cwe": list(DEFAULT_CWE[category]),
        "recommendation": RECOMMENDATION[category],
        # the verifier (phase 5) decides; the original verdict is kept in impact
        "status": "unverified",
    }
    if key == "route_id" and record.get("path"):
        method = record.get("method")
        finding["endpoint"] = {"method": method[0] if isinstance(method, list) and method else method or "GET",
                               "path": record["path"]}
    return finding


def verdict_findings(verdicts: Any, findings: List[Dict[str, Any]], key: str,
                     records: Dict[str, Dict[str, Any]], default_category: str) -> List[Dict[str, Any]]:
    """Findings for flagged verdicts (by `key`: route_id or candidate_id) that no finding covers.

    A verdict is covered by a finding that carries its id in `key`, that the verdict lists in
    `finding_ids`, or whose finding_id names the record (`BFLA-R-0001-1`). Verdicts whose id is not a
    known Tier 1 record are skipped: they cannot be located.
    """
    dicts = [f for f in findings if isinstance(f, dict)]
    covered = {f.get(key) for f in dicts}
    finding_ids = {str(f.get("finding_id")) for f in dicts}
    out: List[Dict[str, Any]] = []
    for v in verdicts if isinstance(verdicts, list) else []:
        if not isinstance(v, dict) or v.get("verdict") not in FLAGGED:
            continue
        record_id = v.get(key)
        listed = v.get("finding_ids") if isinstance(v.get("finding_ids"), list) else []
        if (record_id in covered or record_id not in records or finding_ids.intersection(map(str, listed))
                or any(f"-{record_id}-" in f"{fid}-" for fid in finding_ids)):
            continue
        covered.add(record_id)
        out.append(_finding(key, record_id, v["verdict"], records[record_id], default_category))
    return out
