"""Command: komainu fix - Automated security vulnerability remediation and guard injection."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

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
        help="Apply automated code remediations and security guards from LSA findings",
        description="Analyzes security findings (BOLA, SQLi) and generates or applies automated fixes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry-run remediation against current repository using default findings.json
  komainu fix . --dry-run

  # Apply fixes from a specific findings report
  komainu fix /path/to/legacy-app --findings ./komainu-out/findings.json

  # Generate unified patch file without modifying source code directly
  komainu fix . --findings findings.json --dry-run -p ./security-fixes.patch

  # Output machine-readable JSON remediation report
  komainu fix . --format json
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
        help="Path to findings.json or SARIF report (default: auto-detected under target/komainu-out)",
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
    parser.set_defaults(func=run_fix)


def run_fix(args: argparse.Namespace) -> int:
    """Execute the fix command."""
    target_path = Path(args.target).resolve()

    if not target_path.exists():
        step_fail(f"Target path does not exist: {target_path}")
        return 1

    runner = RemediationRunner(
        target_dir=target_path,
        findings_path=args.findings_path,
        dry_run=args.dry_run,
        output_patch=args.output_patch,
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

    print_summary_table(f"Komainu Remediation Summary", summary_rows)

    if args.dry_run and report.planned_count > 0:
        step_info("Run without --dry-run to apply changes directly to the codebase.")

    return 0 if report.error_count == 0 else 1
