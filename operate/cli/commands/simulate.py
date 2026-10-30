"""Command: komagu simulate - Empirical Breach & Attack Simulation (BAS)."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
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
from operate.simulate.scenarios import (
    ExecutiveReportGenerator,
    IDCFrontierRansomwareScenario,
    MetabaseZeroDayScenario,
    ScenarioResult,
    TimesCarBreachScenario,
)


def register_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Register the simulate subcommand parser."""
    parser = subparsers.add_parser(
        "simulate",
        help="Execute empirical Breach & Attack Simulation (BAS) scenarios",
        description="Simulates landmark enterprise cyber attacks (Times Car, Metabase Zero-Day, IDC Frontier).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all simulated attack scenarios against a target staging API
  komagu simulate --target http://localhost:5001

  # Simulate the Times Car mass IDOR harvesting attack specifically
  komagu simulate --scenario times-car-breach --target http://staging-api:8000

  # Simulate Metabase unauthenticated SQL injection probe
  komagu simulate --scenario metabase-cve-2026-72898 --target http://localhost:5001

  # Simulate IDC Frontier ransomware immutable storage attack
  komagu simulate --scenario idc-frontier-ransomware --target /tmp/backup-dir

  # Export Executive C-Level Report for Board of Directors
  komagu simulate --target http://localhost:5001 --output ./executive-bas-report.md --format markdown
""",
    )
    parser.add_argument(
        "--scenario",
        "-s",
        default="all",
        choices=["all", "times-car-breach", "metabase-cve-2026-72898", "idc-frontier-ransomware"],
        help="Attack scenario to execute (default: all)",
    )
    parser.add_argument(
        "--target",
        "-t",
        default="http://localhost:5001",
        help="Target API base URL or storage path (default: http://localhost:5001)",
    )
    parser.add_argument(
        "--endpoint",
        help="Custom endpoint path pattern for BOLA scenario (default: /api/legacy-orders/{id})",
    )
    parser.add_argument(
        "--param",
        default="q",
        help="Target query parameter for SQLi scenario (default: q)",
    )
    parser.add_argument(
        "--token",
        default="mock-attacker-bob-token",
        help="Attacker bearer token for cross-user impersonation",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file path for detailed executive report",
    )
    parser.add_argument(
        "--format",
        default="table",
        choices=["table", "markdown", "json"],
        help="Report output format (default: table)",
    )
    parser.set_defaults(func=execute_simulate)


def execute_simulate(args: argparse.Namespace) -> int:
    """Execute Breach & Attack Simulation scenarios."""
    step(f"Initializing Komagu Breach & Attack Simulation against {color(args.target, BOLD)}")

    results: List[ScenarioResult] = []
    scenarios_to_run = [args.scenario] if args.scenario != "all" else [
        "times-car-breach",
        "metabase-cve-2026-72898",
        "idc-frontier-ransomware",
    ]

    for sc in scenarios_to_run:
        if sc == "times-car-breach":
            ep = args.endpoint or "/api/legacy-orders/{id}"
            step_info(f"Launching Scenario: Times Car Mass BOLA/IDOR Harvesting ({ep})")
            runner = TimesCarBreachScenario(
                target=args.target,
                endpoint_pattern=ep,
                attacker_token=args.token,
            )
            res = runner.run()
            results.append(res)
            if res.passed:
                step_ok(f"Times Car Simulation: {res.resilience_score}% resilient (0 breaches)")
            else:
                step_fail(f"Times Car Simulation: {res.breaches_leaked} data leaks detected ({res.resilience_score}% resilient)")

        elif sc == "metabase-cve-2026-72898":
            ep = args.endpoint or "/api/products"
            step_info(f"Launching Scenario: Metabase Zero-Day SQLi Simulation ({ep}?{args.param}=...)")
            runner = MetabaseZeroDayScenario(
                target=args.target,
                query_path=ep,
                target_param=args.param,
            )
            res = runner.run()
            results.append(res)
            if res.passed:
                step_ok(f"Metabase Zero-Day Simulation: {res.resilience_score}% resilient (All SQLi probes blocked)")
            else:
                step_fail(f"Metabase Zero-Day Simulation: SQLi probes unhandled ({res.resilience_score}% resilient)")

        elif sc == "idc-frontier-ransomware":
            # A fresh private dir, not a fixed /tmp path another local user could pre-create or symlink
            storage_path = (
                args.target if not args.target.startswith("http") else tempfile.mkdtemp(prefix="komagu-backup-sim-")
            )
            step_info(f"Launching Scenario: IDC Frontier Cloud Storage Ransomware Simulation ({storage_path})")
            runner = IDCFrontierRansomwareScenario(target_dir=storage_path)
            res = runner.run()
            results.append(res)
            if res.passed:
                step_ok(f"IDC Frontier Simulation: {res.resilience_score}% resilient (WORM lock enforced)")
            else:
                step_warn(f"IDC Frontier Simulation: Writable storage ({res.resilience_score}% resilient)")

    generator = ExecutiveReportGenerator(results, args.target)
    overall_score = generator.overall_resilience_score
    overall_passed = all(r.passed for r in results)

    # Format CLI Summary Table
    summary_rows = []
    for r in results:
        v_color = GREEN if r.passed else RED
        v_text = color(f"{r.resilience_score}% ({r.breaches_blocked}/{r.total_attempts} Blocked)", v_color, BOLD)
        summary_rows.append((r.scenario_name, v_text))

    score_color = GREEN if overall_score >= 90 else (YELLOW if overall_score >= 50 else RED)
    summary_rows.append((
        "Platform Resilience Index",
        color(f"{overall_score}% ({'RESILIENT' if overall_passed else 'EXPOSURE DETECTED'})", score_color, BOLD),
    ))

    print_summary_table(
        title="Breach & Attack Simulation (BAS) Executive Summary",
        rows=summary_rows,
        footer="Empirical simulation against landmark real-world enterprise breaches.",
    )

    # Save output if requested
    if args.output or args.format in ("markdown", "json"):
        if args.format == "json":
            out_content = json.dumps(generator.generate_json(), indent=2)
        else:
            out_content = generator.generate_markdown()

        if args.output:
            out_path = Path(args.output).resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(out_content, encoding="utf-8")
            step_ok(f"Saved Executive Simulation Report to {out_path}")
        elif args.format != "table":
            print(out_content)

    return 0 if overall_passed else 1
