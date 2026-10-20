"""Command: komainu scan - End-to-end legacy security audit."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

from operate.cli.ui import (
    BOLD,
    CYAN,
    GREEN,
    RED,
    YELLOW,
    color,
    print_summary_table,
    step,
    step_fail,
    step_info,
    step_ok,
    step_warn,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
LSA_SCRIPTS = REPO_ROOT / "assess" / "lsa" / "scripts"


def register_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Register the scan subcommand parser."""
    parser = subparsers.add_parser(
        "scan",
        help="Run security audit on target legacy codebase (deterministic pre-scan & reports)",
        description="Executes stack detection, endpoint inventory, injection analysis, and report generation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan current directory and generate bilingual HTML & Markdown reports
  komainu scan .

  # Scan a legacy codebase with Japanese reports and custom output folder
  komainu scan /path/to/legacy-php --out ./audit-results --lang ja --format html

  # Scan and generate all artifact formats (SARIF, Markdown, interactive HTML dashboard)
  komainu scan /path/to/app --format all --project "Core Banking Migration"
""",
    )
    parser.add_argument("target", help="Path to the target source code repository to audit")
    parser.add_argument(
        "--out",
        "-o",
        dest="out_dir",
        help="Output directory for audit artifacts (default: ./komainu-out)",
    )
    parser.add_argument(
        "--lang",
        choices=["en", "ja", "all"],
        default="all",
        help="Report language: en (English), ja (Japanese), or all (default: all)",
    )
    parser.add_argument(
        "--format",
        choices=["md", "html", "sarif", "all"],
        default="all",
        help="Output format: md, html, sarif, or all (default: all)",
    )
    parser.add_argument(
        "--project",
        "-p",
        help="Project name displayed on reports (default: folder name of target)",
    )
    parser.add_argument(
        "--config",
        "-c",
        help="Optional custom audit configuration file (audit-config.json)",
    )
    parser.add_argument(
        "--workers",
        "-j",
        type=int,
        default=0,
        help="Number of parallel worker processes for pre-scan (default: 0 = auto/cpu_count)",
    )
    parser.set_defaults(func=execute_scan)


def execute_scan(args: argparse.Namespace) -> int:
    """Execute the end-to-end scan pipeline."""
    target_path = Path(args.target).resolve()
    if not target_path.exists() or not target_path.is_dir():
        step_fail(f"Target directory does not exist or is not a directory: {target_path}")
        return 2

    project_name = args.project or target_path.name
    out_dir = Path(args.out_dir).resolve() if args.out_dir else (Path.cwd() / "komainu-out")
    out_dir.mkdir(parents=True, exist_ok=True)

    step(f"Scanning target repository {color(str(target_path), BOLD)}")
    step_info(f"Audit output directory: {out_dir}")

    # 1. Deterministic Pre-scan
    prescan_script = LSA_SCRIPTS / "run_prescan.py"
    cmd = [sys.executable, str(prescan_script), str(target_path), str(out_dir)]
    if args.config:
        cmd.extend(["--config", args.config])
    if getattr(args, "workers", 0):
        cmd.extend(["--workers", str(args.workers)])

    step("Executing Phase 1: Deterministic Pre-scan")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        step_fail("Pre-scan failed")
        print(res.stderr or res.stdout, file=sys.stderr)
        return 1
    step_ok("Pre-scan completed (stack profile, route candidates, injection candidates)")

    # Read pre-scan metadata
    prof_file = out_dir / "stack-profile.json"
    cov_file = out_dir / "coverage.json"
    rc_file = out_dir / "routes.candidates.json"
    ic_file = out_dir / "injection.candidates.json"

    stacks = []
    if prof_file.is_file():
        try:
            prof_data = json.loads(prof_file.read_text(encoding="utf-8"))
            stacks = [s["id"] for s in prof_data.get("stacks", [])]
        except Exception:
            pass

    route_candidates_count = 0
    if rc_file.is_file():
        try:
            route_candidates_count = len(json.loads(rc_file.read_text(encoding="utf-8")).get("candidates", []))
        except Exception:
            pass

    injection_candidates_count = 0
    if ic_file.is_file():
        try:
            injection_candidates_count = len(json.loads(ic_file.read_text(encoding="utf-8")).get("candidates", []))
        except Exception:
            pass

    if not cov_file.is_file():
        initial_cov = {
            "route_candidates": route_candidates_count,
            "inventoried": route_candidates_count,
            "bola_routes_to_audit": route_candidates_count,
            "injection_candidates": injection_candidates_count,
        }
        cov_file.write_text(json.dumps(initial_cov, indent=2), encoding="utf-8")

    cov = {}
    if cov_file.is_file():
        try:
            cov = json.loads(cov_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    # 2. Check for findings / merge findings
    findings_file = out_dir / "findings.json"
    findings_dir = out_dir / "findings"
    if findings_dir.is_dir() and any(findings_dir.glob("*.json")):
        step("Merging agent findings and validating schemas")
        merge_script = LSA_SCRIPTS / "merge_findings.py"
        res_merge = subprocess.run([sys.executable, str(merge_script), str(out_dir)], capture_output=True, text=True)
        if res_merge.returncode == 0:
            step_ok("Merged findings validated")
        else:
            step_warn(f"Findings merge note: {res_merge.stderr.strip() or res_merge.stdout.strip()}")

    # If findings.json still doesn't exist, create a clean initial scaffold
    if not findings_file.is_file():
        initial_findings = {
            "$schema": "https://raw.githubusercontent.com/hoanghainh1188/komainu/main/contracts/schemas/finding.schema.json",
            "findings": [],
            "summary": {
                "total": 0,
                "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "by_category": {"bola": 0, "sql_injection": 0, "nosql_injection": 0},
                "by_status": {
                    "new": 0,
                    "confirmed": 0,
                    "needs_review": 0,
                    "disputed": 0,
                    "fixed": 0,
                    "suppressed": 0,
                    "unverified": 0,
                    "rejected": 0,
                },
            },
        }
        findings_file.write_text(json.dumps(initial_findings, indent=2), encoding="utf-8")

    # 3. Export to SARIF if requested
    sarif_file = out_dir / "findings.sarif"
    if args.format in ("sarif", "all"):
        step("Generating SARIF v2.1.0 report")
        sarif_script = LSA_SCRIPTS / "findings_to_sarif.py"
        res_sarif = subprocess.run([sys.executable, str(sarif_script), str(out_dir)], capture_output=True, text=True)
        if res_sarif.returncode == 0:
            step_ok(f"Generated {sarif_file.name}")
        else:
            step_warn(f"SARIF generator note: {res_sarif.stderr.strip()}")

    # 4. Render reports
    if args.format in ("md", "html", "all"):
        step("Rendering bilingual Markdown & interactive HTML dashboard")
        render_script = LSA_SCRIPTS / "render_report.py"
        render_cmd = [
            sys.executable,
            str(render_script),
            str(out_dir),
            "--project",
            project_name,
            "--lang",
            args.lang,
            "--format",
            args.format if args.format in ("md", "html") else "all",
        ]
        res_render = subprocess.run(render_cmd, capture_output=True, text=True)
        if res_render.returncode == 0:
            step_ok("Generated security reports")
        else:
            step_fail("Report rendering failed")
            print(res_render.stderr, file=sys.stderr)
            return 1

    # Read summary for terminal report
    findings_data = json.loads(findings_file.read_text(encoding="utf-8"))
    summary = findings_data.get("summary", {})
    by_sev = summary.get("by_severity", {})

    crit_cnt = by_sev.get("critical", 0)
    high_cnt = by_sev.get("high", 0)
    med_cnt = by_sev.get("medium", 0)
    low_cnt = by_sev.get("low", 0)

    summary_rows = [
        ("Project", project_name),
        ("Target Directory", str(target_path)),
        ("Detected Stacks", ", ".join(stacks) or "None"),
        ("Endpoints Inventoried", str(cov.get("inventoried", 0))),
        ("Injection Candidates", str(cov.get("injection_candidates", 0))),
        (
            "Findings (Active)",
            f"{color(str(crit_cnt) + ' Critical', RED, BOLD)}, "
            f"{color(str(high_cnt) + ' High', YELLOW, BOLD)}, "
            f"{med_cnt} Med, {low_cnt} Low",
        ),
        ("HTML Dashboard", str(out_dir / "report.html")),
        ("Markdown Report", str(out_dir / "report.md")),
        ("SARIF 2.1.0", str(sarif_file)),
    ]

    print_summary_table(
        title="Komainu Security Audit Summary",
        rows=summary_rows,
        footer="Open report.html in any browser for interactive charts & remediation patches.",
    )

    return 0
