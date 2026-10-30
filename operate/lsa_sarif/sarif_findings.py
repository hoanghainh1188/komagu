#!/usr/bin/env python3
"""Read LSA SARIF results back as findings.json-style entries (#289).

`komagu test --from-scan` and `--export-poc` work on findings.json entries. This lets them take
the SARIF that `komagu scan` writes instead. Both LSA exporters (assess/lsa/scripts/findings_to_sarif.py
and operate/lsa_sarif/lsa_to_sarif.py) put finding_id, category, endpoint, attack_vector and
consensus_score in each result's properties; older SARIF without them falls back to the rule id,
the OWASP rule tags and the "[METHOD /path]" part of the message.

Python standard library only.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# OWASP API Top 10 rule tags written by findings_to_sarif.py, for SARIF whose ruleId has no category
_TAG_CATEGORY = {
    "owasp-api1:2023-bola": "bola",
    "owasp-api5:2023-bfla": "bfla",
    "owasp-api3:2023-bopla": "mass_assignment",
}
# Rule id prefixes written by operate/lsa_sarif/lsa_to_sarif.py (KOMAINU-<PREFIX>-CWE<n>)
_LEGACY_PREFIX_CATEGORY = {"BOLA": "bola", "BFLA": "bfla", "MASS": "mass_assignment", "INJ": "sql_injection"}
_ENDPOINT_IN_MESSAGE = re.compile(r"\[(GET|POST|PUT|PATCH|DELETE)(?:\|[A-Z]+)*\s+(/[^\]\s]*)\]")


def is_sarif(data: Any) -> bool:
    return isinstance(data, dict) and isinstance(data.get("runs"), list)


def _rule_tags(run: Dict[str, Any]) -> Dict[str, List[str]]:
    rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
    return {
        str(r.get("id", "")): [str(t).lower() for t in ((r.get("properties") or {}).get("tags") or [])]
        for r in rules
        if isinstance(r, dict)
    }


def _category(rule_id: str, props: Dict[str, Any], tags: List[str]) -> Optional[str]:
    if props.get("category"):
        return str(props["category"]).lower()
    if rule_id.startswith("lsa/"):
        parts = rule_id.split("/")
        if len(parts) > 1 and parts[1]:
            return parts[1].lower()
    m = re.match(r"(?:KOMAINU|KOMAGU)-([A-Z]+)-", rule_id)
    if m and m.group(1) in _LEGACY_PREFIX_CATEGORY:
        return _LEGACY_PREFIX_CATEGORY[m.group(1)]
    for tag in tags:
        if tag in _TAG_CATEGORY:
            return _TAG_CATEGORY[tag]
    return None


def findings_from_sarif(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return one findings.json-style dict per SARIF result that names an endpoint."""
    findings: List[Dict[str, Any]] = []
    for run in data.get("runs") or []:
        if not isinstance(run, dict):
            continue
        tags_by_rule = _rule_tags(run)
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId", ""))
            props = result.get("properties") or {}
            category = _category(rule_id, props, tags_by_rule.get(rule_id, []))
            if category is None:
                continue
            message = str((result.get("message") or {}).get("text", ""))
            endpoint = props.get("endpoint") if isinstance(props.get("endpoint"), dict) else None
            if not endpoint:
                m = _ENDPOINT_IN_MESSAGE.search(message)
                endpoint = {"method": m.group(1), "path": m.group(2)} if m else None
            attack_vector = props.get("attack_vector") if isinstance(props.get("attack_vector"), dict) else None
            if not endpoint and not (attack_vector and attack_vector.get("path")):
                continue
            finding_id = props.get("finding_id") or (result.get("partialFingerprints") or {}).get("lsaFindingId") or rule_id
            finding: Dict[str, Any] = {
                "finding_id": str(finding_id),
                "category": category,
                "title": message.split(" [", 1)[0] or rule_id,
                "status": props.get("status", "confirmed"),
            }
            if endpoint:
                finding["endpoint"] = dict(endpoint)
            if attack_vector:
                finding["attack_vector"] = dict(attack_vector)
            if isinstance(props.get("consensus_score"), (int, float)):
                finding["consensus"] = {"score": props["consensus_score"]}
            findings.append(finding)
    return findings
