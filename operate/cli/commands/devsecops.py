"""Command: komainu devsecops - DevSecOps, SCA & SBOM Supply Chain Security Pipeline."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, List

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
from operate.devsecops.pipeline import DevSecOpsPipeline
from operate.devsecops.sarif_aggregator import SARIFReportAggregator
from operate.devsecops.sbom import SBOMGenerator


def register_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Register the devsecops subcommand parser."""
    parser = subparsers.add_parser(
        "devsecops",
        help="DevSecOps, SCA & SBOM Supply Chain Security Pipeline",
        description="Coordinates SAST, secret detection, dependency scanning, SBOM export, and unified SARIF reporting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run full DevSecOps scan and generate unified SARIF and SBOMs
  komainu devsecops run .

  # Generate CycloneDX 1.5 JSON SBOM for an application
  komainu devsecops sbom . --format cyclonedx -o ./sbom.json

  # Generate SPDX 2.3 JSON SBOM
  komainu devsecops sbom . --format spdx -o ./spdx-sbom.json

  # Merge multiple SARIF reports into unified GitHub Code Scanning report
  komainu devsecops merge-sarif --inputs sast.sarif sca.sarif -o unified.sarif
""",
    )

    action_subparsers = parser.add_subparsers(
        title="DevSecOps Actions",
        dest="action",
        metavar="<action>",
    )

    # 1. Action: run
    run_parser = action_subparsers.add_parser(
        "run",
        help="Execute full multi-stage DevSecOps pipeline",
        description="Executes SAST, secret detection, SCA dependency review, SBOM export, and container scanning.",
    )
    run_parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target project directory to analyze (default: current directory)",
    )
    run_parser.add_argument(
        "--output-dir",
        "-o",
        default=".komainu-devsecops",
        help="Output directory for reports (default: .komainu-devsecops)",
    )
    run_parser.add_argument(
        "--app-name",
        default="Application",
        help="Application name for SBOM identification",
    )
    run_parser.add_argument(
        "--app-version",
        default="1.0.0",
        help="Application version for SBOM identification",
    )

    # 2. Action: sbom
    sbom_parser = action_subparsers.add_parser(
        "sbom",
        help="Generate compliant CycloneDX v1.5 or SPDX v2.3 SBOM",
        description="Discovers dependencies across Python, Node.js, .NET, Java/Kotlin, and Go manifests.",
    )
    sbom_parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target project directory (default: current directory)",
    )
    sbom_parser.add_argument(
        "--format",
        "-f",
        choices=["cyclonedx", "spdx"],
        default="cyclonedx",
        help="SBOM specification standard (default: cyclonedx)",
    )
    sbom_parser.add_argument(
        "--output",
        "-o",
        default="sbom.json",
        help="Output file path (default: sbom.json)",
    )
    sbom_parser.add_argument(
        "--app-name",
        default="Application",
        help="Application name for metadata",
    )
    sbom_parser.add_argument(
        "--app-version",
        default="1.0.0",
        help="Application version for metadata",
    )

    # 3. Action: merge-sarif
    merge_parser = action_subparsers.add_parser(
        "merge-sarif",
        help="Merge multiple SARIF security reports into unified format",
        description="Aggregates and deduplicates SARIF 2.1.0 findings from different scanning tools.",
    )
    merge_parser.add_argument(
        "--inputs",
        "-i",
        nargs="+",
        required=True,
        help="Input SARIF file paths to merge",
    )
    merge_parser.add_argument(
        "--output",
        "-o",
        required=True,
        help="Output file path for merged SARIF document",
    )

    parser.set_defaults(func=handle_devsecops_command)


def handle_devsecops_command(args: argparse.Namespace) -> int:
    """Dispatch DevSecOps CLI commands."""
    action = getattr(args, "action", None)
    if not action or action == "run":
        return _handle_run(args)
    elif action == "sbom":
        return _handle_sbom(args)
    elif action == "merge-sarif":
        return _handle_merge_sarif(args)
    return 0


def _handle_run(args: argparse.Namespace) -> int:
    target_path = Path(getattr(args, "target", ".")).resolve()
    output_dir = Path(getattr(args, "output_dir", ".komainu-devsecops")).resolve()
    app_name = getattr(args, "app_name", "Application")
    app_version = getattr(args, "app_version", "1.0.0")

    step(f"[1/5] Initializing DevSecOps Pipeline on: {target_path}")
    pipeline = DevSecOpsPipeline(target_dir=str(target_path), output_dir=str(output_dir))

    step("[2/5] Scanning for hardcoded secrets and credentials")
    sec_res = pipeline.run_secret_detection()
    step_ok(f"Secret scan completed ({sec_res.get('engine', 'native')}): {sec_res.get('findings_count', 0)} findings")

    step("[3/5] Executing SAST and SCA dependency analysis")
    sast_res = pipeline.run_sast()
    sca_res = pipeline.run_sca()
    step_ok(f"SAST analysis: {sast_res.get('findings_count', 0)} findings | SCA analysis: {sca_res.get('findings_count', 0)} findings")

    step("[4/5] Generating software supply chain SBOMs (CycloneDX 1.5 & SPDX 2.3)")
    sbom_res = pipeline.run_sbom_export(app_name=app_name, app_version=app_version)
    step_ok(f"SBOM export completed: {sbom_res.get('components_discovered', 0)} components cataloged")

    step("[5/5] Evaluating container hardening and aggregating SARIF reports")
    c_res = pipeline.run_container_scan()
    sarif_path = os.path.join(str(output_dir), "komainu-devsecops.sarif")
    pipeline.aggregator.save(sarif_path)
    summary = pipeline.aggregator.get_summary()

    print("\n" + color("─── DevSecOps Security Gate Summary ───", CYAN, BOLD))
    print(f"  • Total Findings:   {summary['total']}")
    print(f"  • Errors (Blockers): {color(str(summary['error']), RED if summary['error'] > 0 else GREEN, BOLD)}")
    print(f"  • Warnings:          {color(str(summary['warning']), YELLOW if summary['warning'] > 0 else GREEN)}")
    print(f"  • Notes / Info:      {summary['note']}")
    print(f"  • Unified SARIF:     {sarif_path}")
    print(f"  • CycloneDX SBOM:    {sbom_res.get('cyclonedx_sbom')}")
    print(f"  • SPDX SBOM:         {sbom_res.get('spdx_sbom')}\n")

    if summary["error"] > 0:
        step_warn(f"DevSecOps gate detected {summary['error']} critical/high alerts.")
        return 1

    step_ok("DevSecOps pipeline passed with 0 blocking errors.")
    return 0


def _handle_sbom(args: argparse.Namespace) -> int:
    target_path = Path(getattr(args, "target", ".")).resolve()
    fmt = getattr(args, "format", "cyclonedx")
    out_file = getattr(args, "output", "sbom.json")
    app_name = getattr(args, "app_name", "Application")
    app_version = getattr(args, "app_version", "1.0.0")

    step(f"[1/2] Scanning project dependencies in: {target_path}")
    gen = SBOMGenerator(root_dir=str(target_path), app_name=app_name, app_version=app_version)
    comps = gen.scan()
    step_info(f"Discovered {len(comps)} external components across manifests")

    step(f"[2/2] Exporting {fmt.upper()} compliant SBOM to {out_file}")
    saved_path = gen.save(out_file, format_type=fmt)
    step_ok(f"SBOM successfully generated: {saved_path}")
    return 0


def _handle_merge_sarif(args: argparse.Namespace) -> int:
    inputs = getattr(args, "inputs", [])
    output = getattr(args, "output", "merged.sarif")

    step(f"[1/2] Merging {len(inputs)} SARIF reports")
    aggregator = SARIFReportAggregator()
    total_added = 0
    for file_path in inputs:
        added = aggregator.add_sarif_file(file_path)
        step_info(f"Loaded {added} findings from {file_path}")
        total_added += added

    step(f"[2/2] Saving deduplicated SARIF report to: {output}")
    aggregator.save(output)
    summary = aggregator.get_summary()
    step_ok(f"Combined SARIF saved: {len(aggregator.results)} total findings (Errors: {summary['error']}, Warnings: {summary['warning']})")
    return 0
