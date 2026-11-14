"""Command: komagu fix - Automated security vulnerability remediation and guard injection."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from operate.ai.client import REASONING_EFFORTS
from operate.remediator.ai_fixer import AITier2Fixer

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
from operate.remediator.runner import RemediationRunner


def register_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Register the fix subcommand parser."""
    parser = subparsers.add_parser(
        "fix",
        help="Apply automated code remediations, security guards, and CVE dependency patches",
        description="Analyzes security findings (BOLA, SQLi, and SCA/CVE dependencies) and generates or applies automated fixes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry-run remediation against current repository using default findings.json
  komagu fix . --dry-run

  # Automatically scan manifest files for vulnerable dependencies (CVEs) and patch versions
  komagu fix . --sca

  # Apply fixes from a specific findings report or SARIF file
  komagu fix /path/to/legacy-app --findings ./komagu-out/findings.json

  # Generate unified patch file without modifying source code directly
  komagu fix . --sca --dry-run -p ./security-fixes.patch

  # Output machine-readable JSON remediation report
  komagu fix . --sca --format json
""",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Path to the target codebase to remediate (default: current directory)",
    )
    parser.add_argument(
        "--findings",
        "-f",
        dest="findings_path",
        help="Path to findings.json or SARIF report (default: auto-detected under target/komagu-out)",
    )
    parser.add_argument(
        "--sca",
        action="store_true",
        help="Automatically scan manifest files (package.json, requirements.txt, pyproject.toml, .csproj, pom.xml, build.gradle, go.mod) for CVE vulnerabilities and upgrade versions",
    )
    parser.add_argument(
        "--osv",
        action="store_true",
        help="Query the OSV.dev API in addition to the built-in offline CVE advisory catalog when --sca is enabled",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview unified diffs and generated patches without modifying target files on disk",
    )
    parser.add_argument(
        "--output-patch",
        "-p",
        dest="output_patch",
        help="Path to save all generated unified diffs as a .patch file",
    )
    parser.add_argument(
        "--format",
        choices=["summary", "json", "diff"],
        default="summary",
        help="Output format: summary table (default), json, or diff",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Enable Tier 2 AI-assisted multi-line fix fallback with verification gate when deterministic patchers cannot rewrite a finding",
    )
    parser.add_argument(
        "--ai-endpoint",
        default=os.environ.get("KOMAGU_AI_ENDPOINT", "http://localhost:11434/v1"),
        help="OpenAI-compatible /v1 endpoint for --ai fixes (default: $KOMAGU_AI_ENDPOINT or http://localhost:11434/v1)",
    )
    parser.add_argument(
        "--ai-model",
        default=os.environ.get("KOMAGU_AI_MODEL", "llama3.1"),
        help="Model name for --ai fixes (default: $KOMAGU_AI_MODEL or llama3.1)",
    )
    parser.add_argument(
        "--ai-api-key",
        default=os.environ.get("KOMAGU_AI_API_KEY") or os.environ.get("OPENAI_API_KEY"),
        help="API key for --ai endpoint (default: $KOMAGU_AI_API_KEY or $OPENAI_API_KEY)",
    )
    parser.add_argument(
        "--ai-timeout",
        type=int,
        default=120,
        help="Timeout in seconds per --ai LLM request (default: 120)",
    )
    parser.add_argument(
        "--ai-reasoning-effort",
        choices=REASONING_EFFORTS,
        default=None,
        help="Reasoning effort passed to OpenAI-compatible endpoint (default: not sent)",
    )
    parser.set_defaults(func=run_fix)


def run_fix(args: argparse.Namespace) -> int:
    """Execute the fix command."""
    target_path = Path(args.target).resolve()

    if not target_path.exists():
        step_fail(f"Target path does not exist: {target_path}")
        return 1

    ai_fixer = None
    if getattr(args, "ai", False):
        ai_fixer = AITier2Fixer(
            endpoint=args.ai_endpoint,
            model=args.ai_model,
            api_key=args.ai_api_key,
            timeout=args.ai_timeout,
            reasoning_effort=args.ai_reasoning_effort,
        )

    runner = RemediationRunner(
        target_dir=target_path,
        findings_path=args.findings_path,
        dry_run=args.dry_run,
        output_patch=args.output_patch,
        scan_sca=getattr(args, "sca", False),
        query_osv=getattr(args, "osv", False),
        ai_fixer=ai_fixer,
    )

    mode_label = "DRY-RUN (Simulated)" if args.dry_run else "APPLY (In-place)"
    if args.format != "json":
        step(f"[1/2] Analyzing security findings in {mode_label} mode")

    try:
        report = runner.run()
    except FileNotFoundError as e:
        step_fail(str(e))
        return 1
    except Exception as e:
        step_fail(f"Failed to execute remediation: {str(e)}")
        return 1

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
        return 0

    if args.format == "diff":
        for plan in report.plans:
            if plan.diff:
                print(plan.diff)
            else:
                # stderr keeps stdout a valid patch; without this a run with only manual fixes prints nothing
                print(f"[{plan.status.upper()}] {plan.finding_id} {plan.target_file}:{plan.start_line} - {plan.reason}",
                      file=sys.stderr)
        return 0

    step("[2/2] Remediation execution completed")

    # Print itemized findings
    step_info("Remediated findings breakdown:")
    for plan in report.plans:
        status_color = (
            GREEN
            if plan.status in ("applied", "planned")
            else YELLOW
            if plan.status in ("skipped", "needs manual fix")
            else RED
        )
        status_text = color(f"[{plan.status.upper()}]", status_color, BOLD)
        print(f"  • {status_text} {plan.finding_id} ({plan.category}) -> {plan.target_file}:{plan.start_line} - {plan.reason}")

    # Render summary card
    summary_rows = [
        ("Mode", mode_label),
        ("Total findings processed", str(report.total_findings)),
    ]
    if args.dry_run:
        summary_rows.append(("Patches planned", str(report.planned_count)))
        summary_rows.append(("Patches applied", "0 (dry-run)"))
    else:
        summary_rows.append(("Patches applied", str(report.applied_count)))

    if report.manual_fix_count > 0:
        summary_rows.append(("Needs manual fix", str(report.manual_fix_count)))
    summary_rows.append(("Skipped", str(report.skipped_count)))
    summary_rows.append(("Errors", str(report.error_count)))

    if report.patch_file:
        summary_rows.append(("Patch file exported", report.patch_file))

    print_summary_table(f"Komagu Remediation Summary", summary_rows)

    if args.dry_run and report.planned_count > 0:
        step_info("Run without --dry-run to apply changes directly to the codebase.")

    return 0 if report.error_count == 0 else 1
