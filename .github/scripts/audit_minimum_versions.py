#!/usr/bin/env python3
"""Audit the lowest version each requirements file allows.

`pip-audit -r requirements.txt` resolves `>=` ranges to the newest release,
which already contains every fix. A client that keeps an older version still
satisfies the range, so this script audits the minimum instead: each
`name>=X` or `name==X` line becomes `name==X` and is checked with pip-audit.

Exit 1 when a minimum has a vulnerability with a fixed version (raise the
minimum to fix it). Vulnerabilities without a fixed version are listed only.
Standard library only (Python 3.8+); pip-audit must be on PATH.

Usage: audit_minimum_versions.py [--summary FILE] REQUIREMENTS [REQUIREMENTS ...]
"""
import argparse
import json
import os
import re
import subprocess  # nosec B404  # runs the pip-audit CLI with fixed arguments
import sys
import tempfile
from typing import Dict, List, Optional, Tuple

REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(>=|==)\s*([0-9][A-Za-z0-9.!+_-]*)")


def minimum_pins(text: str) -> List[str]:
    """`name==X` for each `name>=X` / `name==X` line; other lines are ignored."""
    pins = []
    for line in text.splitlines():
        match = REQUIREMENT.match(line.split("#", 1)[0])
        if match:
            name, _, version = match.groups()
            pins.append(f"{name}=={version}")
    return pins


def classify(report: Dict) -> Tuple[List[str], List[str]]:
    """Split pip-audit JSON into (fixable, unfixable) lines, one per advisory."""
    fixable, unfixable = [], []
    for dep in report.get("dependencies", []):
        seen = set()
        for vuln in dep.get("vulns", []):
            if vuln["id"] in seen:
                continue
            seen.add(vuln["id"])
            label = f"{dep['name']} {dep['version']}: {vuln['id']}"
            if vuln.get("fix_versions"):
                fixable.append(f"{label} (fixed in {', '.join(vuln['fix_versions'])})")
            else:
                unfixable.append(f"{label} (no fixed version)")
    return fixable, unfixable


def audit(pins: List[str]) -> Dict:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "minimums.txt")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(pins) + "\n")
        proc = subprocess.run(  # nosec B603 B607  # fixed pip-audit arguments, no shell
            ["pip-audit", "-r", path, "--no-deps", "--disable-pip", "--progress-spinner", "off", "-f", "json"],
            capture_output=True, text=True, check=False,
        )
    # pip-audit exits 1 when it finds vulnerabilities; only a missing report is an error.
    if not proc.stdout.strip():
        raise RuntimeError(proc.stderr.strip() or f"pip-audit exited {proc.returncode} without a report")
    return json.loads(proc.stdout)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--summary", help="Markdown file to append the report to (e.g. $GITHUB_STEP_SUMMARY)")
    parser.add_argument("requirements", nargs="+")
    args = parser.parse_args(argv)

    lines = ["## Minimum allowed versions (pip-audit)"]
    failed = False
    for req in args.requirements:
        with open(req, encoding="utf-8") as handle:
            pins = minimum_pins(handle.read())
        lines.append(f"### `{req}`: {', '.join(pins) or 'no versioned requirement'}")
        if not pins:
            continue
        fixable, unfixable = classify(audit(pins))
        for item in fixable:
            lines.append(f"- FAIL {item}")
            print(f"::error file={req}::{item}: raise the minimum version")
        lines.extend(f"- note {item}" for item in unfixable)
        if not fixable and not unfixable:
            lines.append("- no known vulnerability")
        failed = failed or bool(fixable)

    report = "\n".join(lines) + "\n"
    print(report)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write(report)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
