"""Command: komainu test - Cross-user BOLA/IDOR continuous verification."""

from __future__ import annotations

import argparse
import json
import os
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
from operate.cross_user_tester.runner import (
    CrossUserTestRunner,
    format_report,
    generate_crud_test_cases,
    load_suite_from_file,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SUITE = REPO_ROOT / "operate" / "tests" / "test_suite.json"


def register_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Register the test subcommand parser."""
    parser = subparsers.add_parser(
        "test",
        help="Execute continuous cross-user authorization tests against an API",
        description="Enforces Komainu BOLA/IDOR security invariants (attacker access MUST return 404 Not Found).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test auto-generated CRUD BOLA cases against local API
  komainu test --url http://localhost:5001 --auto-crud /api/members

  # Run custom test suite with strict 404 enforcement
  komainu test --url http://staging.internal:8000 --suite ./test_suite.json --strict

  # Run tests with custom attacker token and save report
  komainu test --url http://localhost:5001 --token "jwt-persona-b" --output ./results.json
""",
    )
    parser.add_argument(
        "--url",
        "-u",
        dest="base_url",
        default="http://localhost:5001",
        help="Base URL of the target API under test (default: http://localhost:5001)",
    )
    parser.add_argument(
        "--suite",
        "-s",
        help="Path to JSON test suite file (defaults to operate/tests/test_suite.json if exists)",
    )
    parser.add_argument(
        "--auto-crud",
        help="Auto-generate CRUD BOLA test cases for resource path (e.g. /api/members)",
    )
    parser.add_argument(
        "--resource-id",
        default="12345",
        help="Resource ID to target in auto-generated test cases (default: 12345)",
    )
    parser.add_argument(
        "--token",
        dest="attacker_token",
        default="mock-attacker-token-user-b",
        help="Bearer token for Attacker persona (Persona B)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Path to save detailed JSON test results",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Enforce strict 404 requirement (reject 401/403 which leak resource existence)",
    )
    parser.set_defaults(func=execute_test)


def execute_test(args: argparse.Namespace) -> int:
    """Execute cross-user authorization verification."""
    step(f"Initializing cross-user security test runner against {color(args.base_url, BOLD)}")

    tests: List[Any] = []

    # 1. Load from test suite if specified or default exists
    suite_path = Path(args.suite).resolve() if args.suite else (DEFAULT_SUITE if DEFAULT_SUITE.is_file() else None)
    if suite_path and suite_path.is_file():
        step_info(f"Loading test suite from {suite_path.name}")
        try:
            tests.extend(load_suite_from_file(str(suite_path)))
        except Exception as e:
            step_warn(f"Could not load test suite {suite_path}: {e}")

    # 2. Auto-generate CRUD cases if requested or if no suite cases were loaded
    if args.auto_crud or not tests:
        crud_path = args.auto_crud or "/api/members"
        step_info(f"Generating CRUD test cases for resource: {crud_path}")
        tests.extend(
            generate_crud_test_cases(
                resource_path=crud_path,
                resource_id=args.resource_id,
                attacker_token=args.attacker_token,
            )
        )

    runner = CrossUserTestRunner(
        base_url=args.base_url,
        default_attacker_token=args.attacker_token,
    )

    step(f"Executing {len(tests)} cross-user authorization test cases")
    results = runner.run_suite(tests)
    report_text, success = format_report(results, args.base_url)

    print()
    print(report_text)

    # Save output if requested
    if args.output:
        out_path = Path(args.output).resolve()
        report_data = {
            "base_url": args.base_url,
            "total": len(results),
            "success": success,
            "results": [r.to_dict() for r in results],
        }
        out_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
        step_ok(f"Saved test report to {out_path}")

    passed_count = sum(1 for r in results if r.is_secure)
    failed_count = len(results) - passed_count

    rows = [
        ("Base URL", args.base_url),
        ("Total Cases", str(len(results))),
        ("Passed (404 Invariant)", color(f"{passed_count} Passed", GREEN, BOLD)),
        ("Failed (BOLA Breach)", color(f"{failed_count} Failed", RED, BOLD) if failed_count else "0 Failed"),
        ("Result", color("PASSED (SECURE)", GREEN, BOLD) if success else color("FAILED (VULNERABLE)", RED, BOLD)),
    ]

    print_summary_table(
        title="Cross-User Authorization Test Summary",
        rows=rows,
        footer="Komainu invariant: cross-user resource access MUST return HTTP 404.",
    )

    return 0 if success else 1
