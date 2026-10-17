#!/usr/bin/env python3
"""LSA-to-SARIF Converter.

Converts Komainu LSA (Legacy Security Audit) findings into OASIS SARIF v2.1.0
format for integration with GitHub Code Scanning, GitLab Security Dashboard,
and other standard DevSecOps reporting tools.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

RULE_METADATA = {
    "bola": {
        "name": "BrokenObjectLevelAuthorization",
        "title": "Broken Object Level Authorization (BOLA / IDOR)",
        "default_cwe": 639,
        "help_uri": "https://cwe.mitre.org/data/definitions/639.html",
        "tags": ["security", "cwe-639", "owasp-api1", "authorization"],
    },
    "sql_injection": {
        "name": "SqlInjection",
        "title": "Improper Neutralization of Special Elements in SQL Command (SQL Injection)",
        "default_cwe": 89,
        "help_uri": "https://cwe.mitre.org/data/definitions/89.html",
        "tags": ["security", "cwe-89", "owasp-a03", "injection"],
    },
    "nosql_injection": {
        "name": "NoSqlInjection",
        "title": "Improper Neutralization of Special Elements in NoSQL Command",
        "default_cwe": 943,
        "help_uri": "https://cwe.mitre.org/data/definitions/943.html",
        "tags": ["security", "cwe-943", "owasp-a03", "injection"],
    },
}


def _get_rule_id(category: str, cwe: int) -> str:
    cat_prefix = "BOLA" if category == "bola" else "INJ"
    return f"KOMAINU-{cat_prefix}-CWE{cwe}"


def convert_findings_to_sarif(
    findings: List[Dict[str, Any]],
    tool_version: str = "0.1.0",
) -> Dict[str, Any]:
    """Convert a list of Komainu LSA findings to SARIF v2.1.0 dict."""
    rules_dict: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for finding in findings:
        category = finding.get("category", "bola")
        cwe = finding.get("cwe") or RULE_METADATA.get(category, {}).get("default_cwe", 639)
        rule_id = _get_rule_id(category, cwe)

        if rule_id not in rules_dict:
            meta = RULE_METADATA.get(category, {
                "name": f"SecurityVulnerability_{category}",
                "title": f"Security Finding ({category})",
                "default_cwe": cwe,
                "help_uri": f"https://cwe.mitre.org/data/definitions/{cwe}.html",
                "tags": ["security", f"cwe-{cwe}"],
            })
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": meta["name"],
                "shortDescription": {"text": meta["title"]},
                "fullDescription": {
                    "text": (
                        f"Komainu LSA identified a {meta['title']} vulnerability "
                        f"violating object isolation or query parameterization invariants."
                    )
                },
                "defaultConfiguration": {"level": "error"},
                "helpUri": meta["help_uri"],
                "properties": {
                    "tags": meta["tags"],
                    "precision": "high",
                    "problem.severity": "error",
                },
            }

        severity = finding.get("severity", "high")
        level = SEVERITY_TO_SARIF_LEVEL.get(severity, "error")

        location = finding.get("location", {})
        file_path = location.get("file", "unknown")
        start_line = location.get("start_line", 1)
        end_line = location.get("end_line", start_line)

        title = finding.get("title", "Security Finding")
        rec = finding.get("recommendation", "")
        scenario = finding.get("attack_scenario", "")
        message_text = f"{title}. {scenario} Recommendation: {rec}".strip()

        sarif_location = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": file_path,
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {
                    "startLine": start_line,
                    "endLine": end_line,
                },
            }
        }

        # Build related locations from evidence if present
        related_locations = []
        for idx, ev in enumerate(finding.get("evidence", [])):
            ev_file = ev.get("file", file_path)
            ev_line = ev.get("line", start_line)
            ev_why = ev.get("why", "Evidence line")
            related_locations.append({
                "id": idx + 1,
                "message": {"text": ev_why},
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": ev_file,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": ev_line,
                        "endLine": ev_line,
                    },
                },
            })

        result_item: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message_text},
            "locations": [sarif_location],
            "properties": {
                "finding_id": finding.get("finding_id"),
                "category": category,
                "subtype": finding.get("subtype"),
                "severity": severity,
                "confidence": finding.get("confidence"),
                "cwe": cwe,
                "status": finding.get("status", "new"),
            },
        }

        if related_locations:
            result_item["relatedLocations"] = related_locations

        results.append(result_item)

    sarif_output: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Komainu LSA",
                        "semanticVersion": tool_version,
                        "informationUri": "https://github.com/hoanghainh1188/komainu",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    return sarif_output


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert Komainu LSA findings to OASIS SARIF v2.1.0 format"
    )
    parser.add_argument(
        "-i", "--input", required=True, help="Input findings.json file path (or '-' for stdin)"
    )
    parser.add_argument(
        "-o", "--output", help="Output SARIF file path (default: stdout)"
    )
    parser.add_argument(
        "--tool-version", default="0.1.0", help="Komainu tool version (default: 0.1.0)"
    )

    args = parser.parse_args()

    if args.input == "-":
        raw_data = sys.stdin.read()
    else:
        with open(args.input, "r", encoding="utf-8") as f:
            raw_data = f.read()

    data = json.loads(raw_data)
    findings = data if isinstance(data, list) else data.get("findings", [])

    sarif = convert_findings_to_sarif(findings, tool_version=args.tool_version)
    output_json = json.dumps(sarif, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_json)
            f.write("\n")
    else:
        print(output_json)


if __name__ == "__main__":
    main()
