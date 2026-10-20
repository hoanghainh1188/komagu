#!/usr/bin/env python3
"""Convert OUT/findings.json to OASIS SARIF 2.1.0 format.

Compatible with GitHub Advanced Security (Code Scanning), GitLab Security Dashboard,
SonarQube, and other DevSecOps platforms.

Usage:
  findings_to_sarif.py OUT [--include-rejected] [--target-dir <path>] [--sarif-out <path>]

Standard-library-only (Python 3.8+).
"""
from __future__ import annotations

import argparse
import datetime
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lsa_common import KIT_VERSION, read_json, write_json  # noqa: E402

LEVEL = {
    "critical": ("error", "9.5"),
    "high": ("error", "8.0"),
    "medium": ("warning", "5.5"),
    "low": ("note", "3.0"),
    "info": ("note", "1.0"),
}

RULE_TEXT = {
    "bola": (
        "Broken object level authorization (BOLA/IDOR)",
        "The endpoint accesses an object selected by a request-controlled identifier without binding the access to the current user or tenant.",
    ),
    "sql_injection": (
        "SQL/HQL query built from untrusted input",
        "A query string is built by concatenation, interpolation or formatting with request-controlled data.",
    ),
    "nosql_injection": (
        "NoSQL query built from untrusted input",
        "A NoSQL filter or server-side script is built from request-controlled data.",
    ),
}

CWE_TAXONOMY_DEFS: Dict[str, Dict[str, str]] = {
    "CWE-639": {
        "id": "CWE-639",
        "name": "Authorization Bypass Through User-Controlled Key",
        "shortDescription": "Broken Object Level Authorization (BOLA/IDOR)",
        "helpUri": "https://cwe.mitre.org/data/definitions/639.html",
    },
    "CWE-89": {
        "id": "CWE-89",
        "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "shortDescription": "SQL Injection",
        "helpUri": "https://cwe.mitre.org/data/definitions/89.html",
    },
    "CWE-943": {
        "id": "CWE-943",
        "name": "Improper Neutralization of Special Elements in Data Query Logic",
        "shortDescription": "NoSQL Injection",
        "helpUri": "https://cwe.mitre.org/data/definitions/943.html",
    },
    "CWE-285": {
        "id": "CWE-285",
        "name": "Improper Authorization",
        "shortDescription": "Improper Authorization",
        "helpUri": "https://cwe.mitre.org/data/definitions/285.html",
    },
    "CWE-284": {
        "id": "CWE-284",
        "name": "Improper Access Control",
        "shortDescription": "Improper Access Control",
        "helpUri": "https://cwe.mitre.org/data/definitions/284.html",
    },
    "CWE-20": {
        "id": "CWE-20",
        "name": "Improper Input Validation",
        "shortDescription": "Improper Input Validation",
        "helpUri": "https://cwe.mitre.org/data/definitions/20.html",
    },
}

OWASP_TAGS = {
    "bola": [
        "external/owasp/a01-2021-broken-access-control",
        "OWASP:A01:2021-Broken Access Control",
        "OWASP-API1:2023-BOLA",
    ],
    "sql_injection": [
        "external/owasp/a03-2021-injection",
        "OWASP:A03:2021-Injection",
        "OWASP-API8:2023-Security Misconfiguration",
    ],
    "nosql_injection": [
        "external/owasp/a03-2021-injection",
        "OWASP:A03:2021-Injection",
        "OWASP-API8:2023-Security Misconfiguration",
    ],
}


def normalize_cwe_id(cwe_val: Any) -> str:
    """Normalize numeric or prefixed CWE ID to standard 'CWE-XXX' format."""
    s = str(cwe_val).strip()
    if s.upper().startswith("CWE-"):
        return s.upper()
    if s.isdigit():
        return f"CWE-{s}"
    return s


def extract_snippet(
    target_dir: Optional[Path],
    rel_file: str,
    start_line: int,
    end_line: Optional[int] = None,
    evidence: Optional[List[Dict[str, Any]]] = None,
) -> Optional[str]:
    """Safely extract source code snippet from target repository or fallback to evidence."""
    if target_dir:
        try:
            target_path = target_dir.resolve()
            candidate_file = (target_path / rel_file).resolve()
            # Guard against path traversal
            try:
                candidate_file.relative_to(target_path)
            except ValueError:
                candidate_file = None

            if candidate_file and candidate_file.is_file():
                with open(candidate_file, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                s_idx = max(0, start_line - 1)
                e_idx = end_line if (end_line and end_line >= start_line) else start_line
                e_idx = min(len(lines), e_idx)
                if s_idx < len(lines):
                    snippet = "".join(lines[s_idx:e_idx]).rstrip("\r\n")
                    if snippet:
                        return snippet
        except Exception:
            pass

    # Fallback to evidence code if source file cannot be read
    if evidence:
        for ev in evidence:
            if ev.get("code"):
                return str(ev["code"]).strip()

    return None


def to_sarif(
    doc: dict,
    include_rejected: bool = False,
    target_dir: Optional[Path] = None,
    start_time: Optional[datetime.datetime] = None,
    end_time: Optional[datetime.datetime] = None,
) -> dict:
    """Convert findings dictionary to OASIS SARIF v2.1.0 document."""
    rules: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []
    rule_idx: Dict[str, int] = {}
    taxa_map: Dict[str, Dict[str, Any]] = {}

    findings = doc.get("findings", [])

    # Pre-collect all CWEs to construct taxa
    for f in findings:
        if f.get("status") == "rejected" and not include_rejected:
            continue
        cwe_list = f.get("cwe", [])
        if isinstance(cwe_list, (str, int)):
            cwe_list = [cwe_list]
        for raw_cwe in cwe_list:
            norm_cwe = normalize_cwe_id(raw_cwe)
            if norm_cwe not in taxa_map:
                if norm_cwe in CWE_TAXONOMY_DEFS:
                    defn = CWE_TAXONOMY_DEFS[norm_cwe]
                    taxa_map[norm_cwe] = {
                        "id": defn["id"],
                        "name": defn["name"],
                        "shortDescription": {"text": defn["shortDescription"]},
                        "helpUri": defn["helpUri"],
                    }
                else:
                    cwe_num = norm_cwe.replace("CWE-", "")
                    taxa_map[norm_cwe] = {
                        "id": norm_cwe,
                        "name": norm_cwe,
                        "shortDescription": {"text": f"Common Weakness Enumeration {norm_cwe}"},
                        "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
                    }

    taxa_list = list(taxa_map.values())
    taxa_index_map = {t["id"]: i for i, t in enumerate(taxa_list)}

    for f in findings:
        if f.get("status") == "rejected" and not include_rejected:
            continue

        category = f.get("category", "bola")
        subtype = f.get("subtype", "general")
        rid = f"lsa/{category}/{subtype}"

        raw_cwes = f.get("cwe", [])
        if isinstance(raw_cwes, (str, int)):
            raw_cwes = [raw_cwes]
        norm_cwes = [normalize_cwe_id(c) for c in raw_cwes]

        if rid not in rule_idx:
            name, desc = RULE_TEXT.get(category, (f"Security Finding ({category})", "Security vulnerability violating invariants."))
            rule_idx[rid] = len(rules)

            # Build GitHub and OWASP tags
            rule_tags = ["security"]
            for c in norm_cwes:
                rule_tags.append(f"external/cwe/{c.lower()}")
                if c not in rule_tags:
                    rule_tags.append(c)
            for ot in OWASP_TAGS.get(category, []):
                if ot not in rule_tags:
                    rule_tags.append(ot)
            for ot in f.get("owasp", []):
                if ot not in rule_tags:
                    rule_tags.append(ot)

            # Build relationships to CWE taxonomy
            relationships = []
            for c in norm_cwes:
                if c in taxa_index_map:
                    relationships.append({
                        "target": {
                            "id": c,
                            "index": taxa_index_map[c],
                            "toolComponent": {"name": "CWE", "index": 0},
                        },
                        "kinds": ["superset"],
                    })

            rules.append({
                "id": rid,
                "name": f"{category}.{subtype}",
                "shortDescription": {"text": f"{name} — {subtype.replace('_', ' ')}"},
                "fullDescription": {"text": desc},
                "relationships": relationships,
                "properties": {
                    "tags": rule_tags,
                    "precision": "high",
                    "problem.severity": "error" if f.get("severity") in ("critical", "high") else "warning",
                },
            })

        level, sec = LEVEL.get(f.get("severity", "medium"), ("warning", "5.0"))
        loc = f.get("location", {})
        start_line = loc.get("start_line", 1)
        end_line = loc.get("end_line", start_line)

        region: Dict[str, Any] = {"startLine": start_line}
        if end_line and end_line >= start_line:
            region["endLine"] = end_line

        # Extract code snippet
        snippet_text = extract_snippet(target_dir, loc.get("file", ""), start_line, end_line, f.get("evidence"))
        if snippet_text:
            region["snippet"] = {"text": snippet_text}

        msg = f.get("title", "Security finding")
        if f.get("endpoint"):
            msg += f" [{f['endpoint'].get('method', '')} {f['endpoint'].get('path', '')}]"
        if f.get("recommendation"):
            msg += f" — {f['recommendation']}"

        related_locations = []
        for i, e in enumerate(f.get("evidence", [])):
            ev_region: Dict[str, Any] = {"startLine": e.get("line", 1)}
            if e.get("code"):
                ev_region["snippet"] = {"text": e["code"]}
            related_locations.append({
                "id": i + 1,
                "message": {"text": e.get("why", "Supporting evidence")},
                "physicalLocation": {
                    "artifactLocation": {"uri": e.get("file", loc.get("file", "")), "uriBaseId": "SRCROOT"},
                    "region": ev_region,
                },
            })

        result_taxa = []
        for c in norm_cwes:
            if c in taxa_index_map:
                result_taxa.append({
                    "id": c,
                    "index": taxa_index_map[c],
                    "toolComponent": {"name": "CWE", "index": 0},
                })

        result_item: Dict[str, Any] = {
            "ruleId": rid,
            "ruleIndex": rule_idx[rid],
            "level": level,
            "message": {"text": msg},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": loc.get("file", ""), "uriBaseId": "SRCROOT"},
                        "region": region,
                    }
                }
            ],
            "relatedLocations": related_locations,
            "partialFingerprints": {"lsaFindingId": f.get("finding_id", f"LSA-{len(results)+1}")},
            "taxa": result_taxa,
            "properties": {
                "security-severity": sec,
                "severity": f.get("severity", "medium"),
                "confidence": f.get("confidence", "high"),
                "status": f.get("status", "unverified"),
                "cwe": norm_cwes,
            },
        }
        results.append(result_item)

        # Update rule security-severity score (maximum encountered)
        curr_score = rules[rule_idx[rid]]["properties"].get("security-severity", "0")
        rules[rule_idx[rid]]["properties"]["security-severity"] = max(curr_score, sec, key=float)

    start_iso = (start_time or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso = (end_time or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")

    driver: Dict[str, Any] = {
        "name": "Komainu LSA Security Audit",
        "version": KIT_VERSION,
        "informationUri": "https://github.com/hoanghainh1188/komainu",
        "rules": rules,
        "supportedTaxonomies": [{"name": "CWE", "index": 0}],
    }

    run_obj: Dict[str, Any] = {
        "tool": {"driver": driver},
        "taxonomies": [
            {
                "name": "CWE",
                "version": "4.13",
                "organization": "MITRE",
                "shortDescription": {"text": "Common Weakness Enumeration"},
                "informationUri": "https://cwe.mitre.org/data/definitions/",
                "taxa": taxa_list,
            }
        ],
        "invocations": [
            {
                "executionSuccessful": True,
                "startTimeUtc": start_iso,
                "endTimeUtc": end_iso,
                "toolExecutionNotifications": [],
            }
        ],
        "results": results,
    }

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run_obj],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out", help="Path to audit OUT directory containing findings.json")
    ap.add_argument("--include-rejected", action="store_true", help="Include rejected findings in SARIF output")
    ap.add_argument("--target-dir", "-s", help="Path to scanned repository root for code snippet extraction")
    ap.add_argument("--sarif-out", "-o", help="Explicit SARIF output file path (default: OUT/findings.sarif)")
    a = ap.parse_args()

    out = Path(a.out)
    target_dir = Path(a.target_dir).resolve() if a.target_dir else None
    findings_file = out / "findings.json"

    if not findings_file.is_file():
        print(f"Error: findings.json not found in {out}", file=sys.stderr)
        return 1

    t0 = datetime.datetime.now(datetime.timezone.utc)
    findings_doc = read_json(findings_file)
    t1 = datetime.datetime.now(datetime.timezone.utc)

    sarif = to_sarif(
        findings_doc,
        include_rejected=a.include_rejected,
        target_dir=target_dir,
        start_time=t0,
        end_time=t1,
    )

    out_file = Path(a.sarif_out).resolve() if a.sarif_out else (out / "findings.sarif")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    write_json(out_file, sarif)

    count = len(sarif["runs"][0]["results"])
    print(f"wrote {out_file} ({count} results)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
