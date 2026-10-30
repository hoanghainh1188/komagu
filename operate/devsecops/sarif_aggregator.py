#!/usr/bin/env python3
"""Unified SARIF Aggregator & Deduplication Engine.

Merges multi-source SARIF reports (SAST, Secrets, SCA, Container, LSA) into
a single, unified OASIS SARIF v2.1.0 document suitable for GitHub Security
tab and GitLab Security Dashboard ingestion.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple

SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)


class SARIFReportAggregator:
    """Aggregates multiple SARIF files into a unified, deduplicated SARIF report."""

    def __init__(self, suite_name: str = "Komagu DevSecOps Security Gate"):
        self.suite_name = suite_name
        self.rules: Dict[str, Dict[str, Any]] = {}
        self.results: List[Dict[str, Any]] = []
        self._seen_findings: set[Tuple[str, str, int]] = set()

    def add_sarif_file(self, file_path: str, source_tag: Optional[str] = None) -> int:
        """Parse and ingest a SARIF file from disk. Returns count of new results added."""
        if not os.path.isfile(file_path):
            return 0
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return self.add_sarif_data(data, source_tag=source_tag or os.path.basename(file_path))
        except Exception:
            return 0

    def add_sarif_data(self, sarif_dict: Dict[str, Any], source_tag: str = "scanner") -> int:
        """Ingest in-memory SARIF dictionary."""
        runs = sarif_dict.get("runs", [])
        added_count = 0

        for run in runs:
            # 1. Harvest rules from driver
            tool = run.get("tool", {})
            driver = tool.get("driver", {})
            driver_rules = driver.get("rules", [])
            for r in driver_rules:
                r_id = r.get("id")
                if r_id and r_id not in self.rules:
                    self.rules[r_id] = r

            # 2. Ingest results
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "UNKNOWN-RULE")
                locations = result.get("locations", [])
                uri = "unknown"
                line = 0
                if locations:
                    phys = locations[0].get("physicalLocation", {})
                    art = phys.get("artifactLocation", {})
                    uri = art.get("uri", "unknown")
                    region = phys.get("region", {})
                    line = region.get("startLine", 0)

                # Deduplication key: (rule_id, normalized_uri, line)
                norm_uri = os.path.normpath(uri).lstrip("./")
                dedup_key = (rule_id, norm_uri, line)
                if dedup_key in self._seen_findings:
                    continue

                self._seen_findings.add(dedup_key)

                # Enrich result properties with source tag
                props = result.setdefault("properties", {})
                props["komagu_source"] = source_tag

                self.results.append(result)
                added_count += 1

        return added_count

    def get_summary(self) -> Dict[str, int]:
        """Return counts by SARIF severity level."""
        summary = {"error": 0, "warning": 0, "note": 0, "total": len(self.results)}
        for r in self.results:
            level = r.get("level", "warning")
            if level in summary:
                summary[level] += 1
            else:
                summary["warning"] += 1
        return summary

    def to_sarif(self) -> Dict[str, Any]:
        """Construct the combined OASIS SARIF v2.1.0 document."""
        return {
            "$schema": SARIF_SCHEMA_URI,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Komagu DevSecOps Pipeline",
                            "organization": "Komagu Security",
                            "semanticVersion": "1.0.0",
                            "informationUri": "https://github.com/hoanghainh1188/komainu",
                            "rules": list(self.rules.values()),
                        }
                    },
                    "results": self.results,
                }
            ],
        }

    def save(self, output_path: str) -> str:
        """Write combined SARIF document to disk."""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.to_sarif(), f, indent=2)
        return os.path.abspath(output_path)
