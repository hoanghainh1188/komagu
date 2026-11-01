"""Command: komagu evidence - METI SCS ★3/★4 & NIST CSF 2.0 Evidence Pack Bundler (#271)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

from governance.scs.pack import EvidencePackBuilder
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


def register_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Register the evidence subcommand parser."""
    parser = subparsers.add_parser(
        "evidence",
        help="Generate METI Supply Chain Security (SCS ★3/★4) evidence pack and gap report",
        description="Bundles technical audit artifacts into a timestamped, cryptographically hashed evidence pack (ZIP + JSON manifest) with Japanese/English gap reports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate METI SCS evidence pack from default audit output directory (OUT/)
  komagu evidence --audit-dir OUT --output-dir ./meti-evidence

  # Generate evidence pack specifying project and system names
  komagu evidence \
    --audit-dir OUT \
    --project "FinTech Core Banking" \
    --system "Staging API Cluster" \
    --output-dir ./audit-pack

  # Enforce minimum readiness rating (e.g. fail CI if SCS-★3-READY is not met)
  komagu evidence --audit-dir OUT --require-tier 3
""",
    )
    parser.add_argument(
        "--audit-dir",
        "-d",
        action="append",
        dest="audit_dirs",
        metavar="DIR",
        help="Path to directory containing audit outputs (e.g. OUT/, findings.sarif, sbom.json). Repeatable.",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        default="./evidence-pack",
        help="Directory to save evidence-pack.zip, evidence-manifest.json, and gap reports (default: ./evidence-pack)",
    )
    parser.add_argument(
        "--project",
        default="Target Modernization System",
        help="Project or organization name (default: Target Modernization System)",
    )
    parser.add_argument(
        "--system",
        default="Production Architecture",
        help="Target system or environment name (default: Production Architecture)",
    )
    parser.add_argument(
        "--require-tier",
        type=int,
        choices=[3, 4],
        help="Fail with exit code 1 if evaluated readiness does not meet the specified star tier (3 or 4)",
    )
    parser.set_defaults(func=execute_evidence)


def execute_evidence(args: argparse.Namespace) -> int:
    """Execute evidence pack generation and gap analysis."""
    audit_dirs = args.audit_dirs or ["OUT", "audit-out", "delivery/pilot/audit-out", "."]

    step(f"Assembling METI SCS Evidence Pack for {color(args.project, BOLD)} ({args.system})")
    step_info(f"Scanning audit source directories: {', '.join(audit_dirs)}")

    builder = EvidencePackBuilder(
        audit_dirs=audit_dirs,
        project_name=args.project,
        target_system=args.system,
    )

    artifacts = builder.discover_artifacts()
    step_info(f"Discovered {len(artifacts)} audit artifacts across directories")

    evaluated_controls, readiness = builder.evaluate_controls(artifacts)
    rating = readiness["rating"]
    score = readiness["compliance_percentage"]

    # Build ZIP and reports
    zip_path, manifest_path, gap_ja, gap_en = builder.build_pack(args.output_dir)

    step_ok(f"Generated Evidence Manifest: {manifest_path}")
    step_ok(f"Generated Japanese Gap Report: {gap_ja}")
    step_ok(f"Generated English Gap Report: {gap_en}")
    step_ok(f"Packaged Signed ZIP Archive: {zip_path}")

    # Display Executive Summary Table
    rating_color = GREEN if "READY" in rating else (YELLOW if rating == "GAP-IDENTIFIED" else RED)
    summary_rows = [
        ("Project Name", args.project),
        ("Target System", args.system),
        ("Total SCS Controls Evaluated", str(readiness["total_controls"])),
        ("Technically Covered Controls", color(str(readiness["covered_controls"]), GREEN, BOLD)),
        ("Partial / Organizational", color(str(readiness["partial_controls"]), YELLOW)),
        ("Compliance Score", color(f"{score}%", rating_color, BOLD)),
        ("METI SCS Readiness Rating", color(rating, rating_color, BOLD)),
    ]

    print_summary_table(
        title="METI Supply Chain Security (SCS ★3/★4) Assessment Summary",
        rows=summary_rows,
        footer="Evidence pack ready for submission to prime contractor / accredited auditor."
    )

    # Gating enforcement if requested
    if args.require_tier:
        if args.require_tier == 4 and rating != "SCS-★4-READY":
            step_fail(f"Quality Gate Failed: Required SCS-★4-READY, evaluated as {rating} ({score}%)")
            return 1
        elif args.require_tier == 3 and rating not in ("SCS-★3-READY", "SCS-★4-READY"):
            step_fail(f"Quality Gate Failed: Required SCS-★3-READY, evaluated as {rating} ({score}%)")
            return 1

    return 0
