"""Command: komagu simulate - Empirical Breach & Attack Simulation (BAS) (#317)."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

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
from operate.simulate.engine import (
    DeclarativeScenario,
    generate_execution_evidence,
)
from operate.simulate.loader import (
    discover_scenarios,
    load_scenario_file,
    validate_scenario,
)
from operate.simulate.scenarios import (
    ExecutiveReportGenerator,
    ScenarioResult,
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
  # List all discovered attack scenarios
  komagu simulate --list

  # Validate a custom declarative scenario JSON against bas-scenario.schema.json
  komagu simulate --validate ./custom-scenario.json

  # Run all simulated attack scenarios against a target staging API
  komagu simulate --target http://localhost:5001

  # Simulate the Times Car mass IDOR harvesting attack specifically
  komagu simulate --scenario times-car-breach --target http://staging-api:8000

  # Run a custom scenario file with parameter override
  komagu simulate --scenario-file ./my-scenario.json --set endpoint_pattern=/api/v2/items/{id}

  # Export Executive C-Level Report and METI SCS audit evidence
  komagu simulate --target http://localhost:5001 --output ./bas-report.md --evidence ./bas-evidence.json
""",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available built-in and discovered scenarios",
    )
    parser.add_argument(
        "--validate",
        metavar="PATH",
        help="Validate a scenario JSON file against schema and exit",
    )
    parser.add_argument(
        "--scenario",
        "-s",
        default="all",
        help="Attack scenario ID to execute, or 'all' (default: all)",
    )
    parser.add_argument(
        "--scenario-file",
        action="append",
        dest="scenario_files",
        metavar="PATH",
        help="Path to custom scenario file (repeatable)",
    )
    parser.add_argument(
        "--scenario-dir",
        action="append",
        dest="scenario_dirs",
        metavar="DIR",
        help="Path to directory containing scenario files (repeatable)",
    )
    parser.add_argument(
        "--set",
        action="append",
        dest="param_sets",
        metavar="KEY=VALUE",
        help="Override scenario parameter (repeatable, e.g. --set token=secret)",
    )
    parser.add_argument(
        "--allow-draft",
        action="store_true",
        help="Allow execution of scenarios with status != 'approved'",
    )
    parser.add_argument(
        "--allow-destructive",
        action="store_true",
        help="Allow execution of steps marked destructive: true",
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
        "--evidence",
        help="Output file path for METI SCS / ISO 27001 audit evidence JSON (#271)",
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
    # Mode 1: Validate scenario file
    if args.validate:
        v_path = Path(args.validate).resolve()
        if not v_path.is_file():
            step_fail(f"Scenario file not found: {v_path}")
            return 2
        try:
            doc = json.loads(v_path.read_text(encoding="utf-8"))
        except Exception as ex:
            step_fail(f"Invalid JSON in {v_path}: {ex}")
            return 2

        errs = validate_scenario(doc)
        if errs:
            step_fail(f"Scenario {v_path.name} failed schema validation:")
            for err in errs:
                print(f"  • {err}")
            return 2
        step_ok(f"Scenario {color(doc.get('id', v_path.name), BOLD)} is valid ({doc.get('status', 'draft')})")
        return 0

    # Discover all scenarios
    scenarios_map = discover_scenarios(
        scenario_files=args.scenario_files,
        scenario_dirs=args.scenario_dirs,
        include_builtins=True,
    )

    # Mode 2: List scenarios
    if args.list:
        step("Discovered Breach & Attack Simulation (BAS) Scenarios:")
        rows = []
        for sid, sc in sorted(scenarios_map.items()):
            status = sc.get("status", "draft")
            status_color = GREEN if status == "approved" else (YELLOW if status == "draft" else RED)
            date_str = sc.get("incident", {}).get("date", "-")
            title = sc.get("title", sid)
            rows.append((f"{color(sid, BOLD)} (v{sc.get('version', '1.0.0')})", f"[{color(status, status_color)}] {title} ({date_str})"))

        print_summary_table(
            title="Available BAS Scenarios",
            rows=rows,
            footer="Execute with: komagu simulate --scenario <id> --target <url>"
        )
        return 0

    # Mode 3: Run simulation
    step(f"Initializing Komagu Breach & Attack Simulation against {color(args.target, BOLD)}")

    # Parse --set parameter overrides
    overrides: Dict[str, Any] = {}
    if args.param_sets:
        for p_set in args.param_sets:
            if "=" in p_set:
                k, v = p_set.split("=", 1)
                overrides[k.strip()] = v.strip()

    # Legacy CLI flag bridges
    if args.endpoint:
        overrides["endpoint_pattern"] = args.endpoint
        overrides["query_path"] = args.endpoint
    if args.param:
        overrides["target_param"] = args.param
    if args.token:
        overrides["attacker_token"] = args.token

    if args.scenario == "all":
        scenarios_to_run = list(scenarios_map.keys())
    else:
        if args.scenario not in scenarios_map:
            step_fail(f"Unknown scenario ID: '{args.scenario}'. Use --list to view available scenarios.")
            return 2
        scenarios_to_run = [args.scenario]

    results: List[ScenarioResult] = []
    runners: List[DeclarativeScenario] = []

    for sid in scenarios_to_run:
        sc_data = scenarios_map.get(sid)
        if not sc_data:
            continue

        step_info(f"Launching Scenario: {sc_data.get('title', sid)} ({sid})")

        # Handle local dir target if needed for idc-frontier-ransomware
        eff_target = args.target
        if sid == "idc-frontier-ransomware" and args.target.startswith("http"):
            eff_target = tempfile.mkdtemp(prefix="komagu-backup-sim-")
            overrides["target_dir"] = eff_target

        try:
            runner = DeclarativeScenario(
                scenario_data=sc_data,
                target=eff_target,
                param_overrides=overrides,
                allow_draft=args.allow_draft,
                allow_destructive=args.allow_destructive,
            )
            runners.append(runner)
            res = runner.run()
            results.append(res)

            if res.passed:
                step_ok(f"{sc_data.get('title', sid)}: {res.resilience_score}% resilient (0 breaches)")
            else:
                step_fail(f"{sc_data.get('title', sid)}: {res.breaches_leaked} data leaks detected ({res.resilience_score}% resilient)")
        except PermissionError as p_err:
            step_warn(f"Skipping {sid}: {p_err}")

    if not results:
        step_fail("No scenarios were executed.")
        return 1

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

    # Generate METI SCS audit evidence JSON if requested
    if args.evidence:
        generate_execution_evidence(runners, results, args.target, output_path=args.evidence)
        step_ok(f"Saved METI SCS Audit Evidence to {color(args.evidence, BOLD)}")

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
