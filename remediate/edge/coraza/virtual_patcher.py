#!/usr/bin/env python3
"""Automated Virtual Patcher for OWASP Coraza WAF & ModSecurity (TASK-2.2).

Translates confirmed LSA findings (BOLA & SQLi) into deterministic,
production-ready SecRule configurations for instant Day-2 edge protection.

Rule tags stay 'komainu-*' after the rename so existing WAF log alerts still match (#290).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


class VirtualPatcher:
    """Generates OWASP Coraza / ModSecurity SecRule virtual patches from LSA findings."""

    def __init__(self, start_rule_id: int = 1100001) -> None:
        self.current_rule_id = start_rule_id

    def _sanitize_regex_path(self, path: str) -> str:
        """Convert a parameterized endpoint path like /api/orders/{id} into a regex."""
        p = path.strip()
        # Replace placeholders with regex pattern matching IDs
        p = re.sub(r"\{[a-zA-Z0-9_-]*(?:id|ID)[a-zA-Z0-9_-]*\}", r"[a-zA-Z0-9_\\-\\.]+", p)
        p = re.sub(r":([a-zA-Z0-9_-]*(?:id|ID)[a-zA-Z0-9_-]*)", r"[a-zA-Z0-9_\\-\\.]+", p)
        if "{id}" in p:
            p = p.replace("{id}", r"[a-zA-Z0-9_\\-\\.]+")

        # Escape special regex chars except brackets already placed
        clean_parts = []
        for part in re.split(r"(\[a-zA-Z0-9_\\-\\.]+)", p):
            if part == r"[a-zA-Z0-9_\\-\\.]+":
                clean_parts.append(part)
            else:
                clean_parts.append(re.escape(part))

        regex = "".join(clean_parts)
        if not regex.startswith("^"):
            regex = "^" + regex
        return regex

    def generate_sqli_rule(self, finding: Dict[str, Any]) -> str:
        """Generate a targeted ModSecurity SecRule for SQL Injection finding."""
        rule_id = self.current_rule_id
        self.current_rule_id += 1

        finding_id = finding.get("finding_id", "INJ-FINDING")
        title = finding.get("title", "SQL Injection on endpoint")

        av = finding.get("attack_vector") or {}
        ep = finding.get("endpoint") or {}
        path = av.get("path") or ep.get("path") or "/api"
        method = av.get("method") or ep.get("method") or "GET"

        path_regex = self._sanitize_regex_path(path)

        rule = f"""# ==============================================================================
# Komagu Virtual Patch: {finding_id}
# Vulnerability: SQL Injection (CWE-89)
# Title: {title}
# Target Endpoint: {method} {path}
# ==============================================================================
SecRule REQUEST_URI "@rx {path_regex}" \\
  "id:{rule_id},\\
   phase:2,\\
   deny,\\
   status:403,\\
   t:urlDecodeUni,\\
   t:lowercase,\\
   msg:'Komagu Virtual Patch: SQL Injection blocked on {path}',\\
   logdata:'Matched Data: %{{TX.0}}',\\
   severity:'CRITICAL',\\
   tag:'komainu-virtual-patch',\\
   tag:'komainu-sqli',\\
   tag:'{finding_id}',\\
   setvar:'tx.sql_injection_score=+5',\\
   setvar:'tx.inbound_anomaly_score_exceeded=1',\\
   chain"
  SecRule ARGS|REQUEST_BODY "@rx (?i)(?:(?:\\bunion\\b[\\s\\S]*?\\bselect\\b)|(?:\\b(?:or|and)\\b\\s+(?:(?:\\d+\\s*=\\s*\\d+)|(?:['\"][^'\"]+['\"]\\s*=\\s*['\"]?[^'\"\\s]+)|true\\b|false\\b))|(?:;\\s*(?:drop|alter|truncate|delete)\\s+table\\b)|(?:\\-\\-(?:[\\s+\\r\\n\\t]|$))|(?:\\/\\*[\\s\\S]*?\\*\\/)|(?:['\"`]\\s*#|#\\s+))" \\
    "t:urlDecodeUni,\\
     t:lowercase"
"""
        return rule

    def generate_bola_rule(self, finding: Dict[str, Any]) -> str:
        """Generate a targeted ModSecurity SecRule enforcing authentication on BOLA route."""
        rule_id = self.current_rule_id
        self.current_rule_id += 1

        finding_id = finding.get("finding_id", "BOLA-FINDING")
        title = finding.get("title", "BOLA / IDOR on endpoint")

        av = finding.get("attack_vector") or {}
        ep = finding.get("endpoint") or {}
        path = av.get("path") or ep.get("path") or "/api/orders/{id}"
        method = av.get("method") or ep.get("method") or "GET"

        path_regex = self._sanitize_regex_path(path)

        rule = f"""# ==============================================================================
# Komagu Virtual Patch: {finding_id}
# Vulnerability: Broken Object Level Authorization (CWE-639)
# Title: {title}
# Target Endpoint: {method} {path}
# ==============================================================================
SecRule REQUEST_URI "@rx {path_regex}" \\
  "id:{rule_id},\\
   phase:1,\\
   deny,\\
   status:404,\\
   t:urlDecodeUni,\\
   msg:'Komagu Virtual Patch: Missing Authorization Token on BOLA Endpoint {path}',\\
   severity:'CRITICAL',\\
   tag:'komainu-virtual-patch',\\
   tag:'komainu-bola',\\
   tag:'{finding_id}',\\
   chain"
  SecRule &REQUEST_HEADERS:Authorization "@eq 0"
"""
        return rule

    def generate_patches_from_findings(
        self,
        findings_data: Union[Dict[str, Any], List[Dict[str, Any]]],
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """Synthesize all SecRules from findings document."""
        items = findings_data if isinstance(findings_data, list) else findings_data.get("findings", [])
        rules: List[str] = [
            "# ==============================================================================",
            "# Komagu Automated Virtual Patching Configuration for OWASP Coraza WAF",
            "# Generated automatically from verified LSA audit findings.",
            "# Inbound requests matching known attack signatures on these routes are blocked.",
            "# ==============================================================================",
            "",
        ]
        manifest: List[Dict[str, Any]] = []

        for item in items:
            cat = str(item.get("category", "")).lower()
            fid = str(item.get("finding_id", ""))
            status = str(item.get("status", "confirmed")).lower()

            if status in ("rejected", "fixed"):
                continue

            if cat == "bola" or fid.startswith("BOLA"):
                rule_text = self.generate_bola_rule(item)
                rules.append(rule_text)
                manifest.append({
                    "finding_id": fid,
                    "category": "bola",
                    "rule_id": self.current_rule_id - 1,
                    "endpoint": item.get("endpoint", {}).get("path", ""),
                })
            elif cat in ("sql_injection", "nosql_injection") or fid.startswith("INJ"):
                rule_text = self.generate_sqli_rule(item)
                rules.append(rule_text)
                manifest.append({
                    "finding_id": fid,
                    "category": "sql_injection",
                    "rule_id": self.current_rule_id - 1,
                    "endpoint": item.get("endpoint", {}).get("path", ""),
                })

        return "\n".join(rules), manifest

    def patch_to_file(
        self,
        scan_data_or_path: Union[str, Path, Dict[str, Any], List[Dict[str, Any]]],
        output_file: Union[str, Path],
    ) -> Tuple[Path, List[Dict[str, Any]]]:
        """Generate virtual patch rules and write them directly to file."""
        data = scan_data_or_path
        if isinstance(scan_data_or_path, (str, Path)):
            p = Path(scan_data_or_path).resolve()
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)

        rules_text, manifest = self.generate_patches_from_findings(data)
        out_p = Path(output_file).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(rules_text, encoding="utf-8")
        return out_p, manifest
