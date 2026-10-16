#!/usr/bin/env python3
"""Convert OUT/findings.json to SARIF 2.1.0 (for GitHub / GitLab code scanning).

Usage: findings_to_sarif.py OUT [--include-rejected]
Writes OUT/findings.sarif
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lsa_common import KIT_VERSION, read_json, write_json  # noqa: E402

LEVEL = {"critical": ("error", "9.5"), "high": ("error", "8.0"), "medium": ("warning", "5.5"),
         "low": ("note", "3.0"), "info": ("note", "1.0")}
RULE_TEXT = {
    "bola": ("Broken object level authorization (BOLA/IDOR)",
             "The endpoint accesses an object selected by a request-controlled identifier without binding the access to the current user or tenant."),
    "sql_injection": ("SQL/HQL query built from untrusted input",
                      "A query string is built by concatenation, interpolation or formatting with request-controlled data."),
    "nosql_injection": ("NoSQL query built from untrusted input",
                        "A NoSQL filter or server-side script is built from request-controlled data."),
}


def to_sarif(doc: dict, include_rejected: bool) -> dict:
    rules, results, rule_idx = [], [], {}
    for f in doc["findings"]:
        if f["status"] == "rejected" and not include_rejected:
            continue
        rid = f"lsa/{f['category']}/{f['subtype']}"
        if rid not in rule_idx:
            name, desc = RULE_TEXT[f["category"]]
            rule_idx[rid] = len(rules)
            rules.append({
                "id": rid, "name": f"{f['category']}.{f['subtype']}",
                "shortDescription": {"text": f"{name} — {f['subtype'].replace('_', ' ')}"},
                "fullDescription": {"text": desc},
                "properties": {"tags": ["security"] + f.get("cwe", []) + f.get("owasp", [])},
            })
        level, sec = LEVEL.get(f["severity"], ("warning", "5.0"))
        loc = f["location"]
        region = {"startLine": loc["start_line"]}
        if loc.get("end_line") and loc["end_line"] >= loc["start_line"]:
            region["endLine"] = loc["end_line"]
        msg = f["title"]
        if f.get("endpoint"):
            msg += f" [{f['endpoint'].get('method', '')} {f['endpoint'].get('path', '')}]"
        msg += f" — {f.get('recommendation', '')}"
        results.append({
            "ruleId": rid, "ruleIndex": rule_idx[rid], "level": level,
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": loc["file"], "uriBaseId": "SRCROOT"}, "region": region}}],
            "relatedLocations": [
                {"id": i + 1, "message": {"text": e["why"]},
                 "physicalLocation": {"artifactLocation": {"uri": e["file"], "uriBaseId": "SRCROOT"}, "region": {"startLine": e["line"]}}}
                for i, e in enumerate(f.get("evidence", []))
            ],
            "partialFingerprints": {"lsaFindingId": f["finding_id"]},
            "properties": {"security-severity": sec, "severity": f["severity"], "confidence": f["confidence"],
                           "status": f["status"], "cwe": f.get("cwe", [])},
        })
        rules[rule_idx[rid]]["properties"]["security-severity"] = max(
            rules[rule_idx[rid]]["properties"].get("security-severity", "0"), sec, key=float)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "LSA Legacy Security Audit (AI-assisted)", "version": KIT_VERSION,
                                      "informationUri": "https://owasp.org/API-Security/", "rules": rules}},
                  "results": results}],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out")
    ap.add_argument("--include-rejected", action="store_true")
    a = ap.parse_args()
    out = Path(a.out)
    sarif = to_sarif(read_json(out / "findings.json"), a.include_rejected)
    write_json(out / "findings.sarif", sarif)
    print(f"wrote {out / 'findings.sarif'} ({len(sarif['runs'][0]['results'])} results)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
