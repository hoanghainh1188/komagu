#!/usr/bin/env python3
"""Merge SARIF files so that each tool appears as a single run.

GitHub code scanning rejects uploads that contain several runs of the same
tool under one category. Roslyn writes one SARIF file per project, so the
runs are merged here. Standard library only (Python 3.8+).

Usage: merge_sarif.py OUTPUT INPUT [INPUT ...]
"""
import json
import sys


def _strip_indexes(node):
    """Drop index pointers that become invalid once rules/artifacts are merged."""
    if isinstance(node, dict):
        node.pop("ruleIndex", None)
        location = node.get("artifactLocation")
        if isinstance(location, dict):
            location.pop("index", None)
        for value in node.values():
            _strip_indexes(value)
    elif isinstance(node, list):
        for item in node:
            _strip_indexes(item)


def merge(paths):
    merged_runs = {}
    for path in paths:
        with open(path, encoding="utf-8-sig") as handle:
            document = json.load(handle)
        for run in document.get("runs", []):
            driver = run.get("tool", {}).get("driver", {})
            name = driver.get("name", "unknown")
            results = run.get("results", [])
            _strip_indexes(results)
            if name not in merged_runs:
                merged_runs[name] = {
                    "tool": {"driver": dict(driver, rules=[])},
                    "results": [],
                    "_rule_ids": set(),
                }
            target = merged_runs[name]
            for rule in driver.get("rules", []):
                rule_id = rule.get("id")
                if rule_id not in target["_rule_ids"]:
                    target["_rule_ids"].add(rule_id)
                    target["tool"]["driver"]["rules"].append(rule)
            target["results"].extend(results)

    runs = []
    for run in merged_runs.values():
        run.pop("_rule_ids")
        runs.append(run)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }


def main(argv):
    if len(argv) < 3:
        sys.stderr.write(__doc__)
        return 2
    output, inputs = argv[1], argv[2:]
    document = merge(inputs)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
    total = sum(len(run["results"]) for run in document["runs"])
    print("merged %d file(s) into %s: %d result(s)" % (len(inputs), output, total))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
