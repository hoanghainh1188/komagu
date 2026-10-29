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
from operate.cross_user_tester.persona_matrix import (
    DENY_STATUS,
    STRICT_DENY_STATUS,
    MatrixCase,
    PersonaMatrixRunner,
    SuiteError,
    format_matrix_report,
    generate_matrix_cases_from_findings,
    is_v2_suite,
    load_persona_suite,
)
from operate.cross_user_tester.runner import (
    CrossUserTestRunner,
    format_report,
    generate_crud_test_cases,
    generate_test_cases_from_findings,
    load_suite_from_file,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SUITE = REPO_ROOT / "operate" / "tests" / "test_suite.json"
# --token is passed to persona-matrix cases through this private env entry.
CLI_TOKEN_ENV = "KOMAINU_CLI_TOKEN"


def register_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Register the test subcommand parser."""
    parser = subparsers.add_parser(
        "test",
        help="Execute continuous cross-user authorization tests against an API",
        description="Enforces Komainu BOLA/IDOR security invariants (attacker access MUST return 404 Not Found).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Ingest LSA findings and verify only findings with >= 80% AI Consensus
  komainu test --url http://staging.internal:8000 --from-scan ./findings.json --min-consensus 0.8

  # Verify findings and export reproducible Python & cURL exploit PoC scripts
  komainu test --url http://localhost:5001 --from-scan ./findings.json --export-poc ./pocs

  # Test auto-generated CRUD BOLA cases against local API
  komainu test --url http://localhost:5001 --auto-crud /api/members

  # Run custom test suite with strict 404 enforcement
  komainu test --url http://staging.internal:8000 --suite ./test_suite.json --strict

  # Run tests with custom attacker token and save report
  komainu test --url http://localhost:5001 --token "jwt-persona-b" --output ./results.json

  # Persona matrix (suite "version": 2): BFLA and mass assignment checks
  KOMAINU_TOKEN_USER=... KOMAINU_TOKEN_ADMIN=... komainu test --url http://staging:8000 --suite ./personas.json

Documentation:
  See docs/cli-guide.md#34-komainu-test--offensive-exploit-verification--bola-invariant-testing
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
        "--from-scan",
        dest="from_scan",
        help="Path to findings.json or SARIF output from komainu scan to generate attack test cases",
    )
    parser.add_argument(
        "--min-consensus",
        dest="min_consensus",
        type=float,
        default=0.0,
        help="Minimum AI consensus score threshold (0.0 to 1.0) to include a finding (default: 0.0)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Enforce strict 404 requirement (reject 401/403 which leak resource existence)",
    )
    parser.add_argument(
        "--token-env",
        dest="token_env",
        help="Environment variable holding a normal user's token, used for BFLA and "
             "mass assignment findings from --from-scan (default: the --token value)",
    )
    parser.add_argument(
        "--export-poc",
        dest="export_poc",
        help="Directory path to export standalone executable Python and cURL exploit PoC scripts",
    )
    parser.set_defaults(func=execute_test)



def execute_test(args: argparse.Namespace) -> int:
    """Execute cross-user authorization verification."""
    step(f"Initializing cross-user security test runner against {color(args.base_url, BOLD)}")

    tests: List[Any] = []
    matrix_cases: List[MatrixCase] = []

    # 1. Ingest from scan output if provided
    if getattr(args, "from_scan", None):
        scan_file = Path(args.from_scan).resolve()
        if not scan_file.is_file():
            step_fail(f"Scan file not found: {scan_file}")
            return 1
        step_info(f"Ingesting findings from scan file: {scan_file.name}")
        min_c = getattr(args, "min_consensus", 0.0) or 0.0
        scan_cases = generate_test_cases_from_findings(
            scan_data_or_path=scan_file,
            default_resource_id=args.resource_id,
            attacker_token=args.attacker_token,
            min_consensus_score=min_c,
        )
        step_info(f"Synthesized {len(scan_cases)} active verification cases from scan findings")
        tests.extend(scan_cases)
        matrix_cases.extend(_matrix_cases_from_scan(scan_file, args, min_c))

        # Export PoC exploits if requested
        if getattr(args, "export_poc", None):
            from operate.exploit.generator import ExploitGenerator
            gen = ExploitGenerator(
                base_url=args.base_url,
                default_resource_id=args.resource_id,
                attacker_token=args.attacker_token,
            )
            pocs = gen.export_all_to_dir(scan_file, args.export_poc)
            step_ok(f"Exported {len(pocs)} standalone exploit scripts to: {args.export_poc}")


    # 2. Load from test suite if specified or default exists
    suite_path = Path(args.suite).resolve() if args.suite else (DEFAULT_SUITE if DEFAULT_SUITE.is_file() and not getattr(args, "from_scan", None) else None)
    if suite_path and suite_path.is_file():
        step_info(f"Loading test suite from {suite_path.name}")
        try:
            suite_data = json.loads(suite_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            step_fail(f"Could not read test suite {suite_path}: {e}")
            return 2
        if is_v2_suite(suite_data):
            try:
                matrix_cases.extend(load_persona_suite(suite_data, default_id=args.resource_id))
            except SuiteError as e:
                step_fail(f"Invalid persona suite {suite_path.name}: {e}")
                return 2
            step_info(f"Persona matrix: {len(matrix_cases)} BFLA / mass assignment cases")
        else:
            try:
                tests.extend(load_suite_from_file(str(suite_path)))
            except Exception as e:
                step_warn(f"Could not load test suite {suite_path}: {e}")

    # 3. Auto-generate CRUD cases if explicitly requested or if no cases were loaded
    if args.auto_crud or (not tests and not matrix_cases):
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

    results = []
    success = True
    if tests:
        step(f"Executing {len(tests)} cross-user authorization test cases")
        results = runner.run_suite(tests)
        report_text, success = format_report(results, args.base_url)
        print()
        print(report_text)

    matrix_results = _run_matrix(matrix_cases, args)
    if matrix_results:
        matrix_text, matrix_ok = format_matrix_report(
            matrix_results, STRICT_DENY_STATUS if args.strict else DENY_STATUS
        )
        print()
        print(matrix_text)
        success = success and matrix_ok

    # Save output if requested
    if args.output:
        out_path = Path(args.output).resolve()
        report_data = {
            "base_url": args.base_url,
            "total": len(results) + len(matrix_results),
            "success": success,
            "results": [r.to_dict() for r in results],
            "matrix_results": [r.to_dict() for r in matrix_results],
        }
        out_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
        step_ok(f"Saved test report to {out_path}")

    all_results = list(results) + list(matrix_results)
    passed_count = sum(1 for r in all_results if r.is_secure)
    failed_count = len(all_results) - passed_count

    rows = [
        ("Base URL", args.base_url),
        ("Total Cases", str(len(all_results))),
        ("Passed (Access Refused)", color(f"{passed_count} Passed", GREEN, BOLD)),
        ("Failed (Breach or Error)", color(f"{failed_count} Failed", RED, BOLD) if failed_count else "0 Failed"),
        ("Result", color("PASSED (SECURE)", GREEN, BOLD) if success else color("FAILED (VULNERABLE)", RED, BOLD)),
    ]

    print_summary_table(
        title="Cross-User Authorization Test Summary",
        rows=rows,
        footer="Komainu invariant: cross-user access MUST return 404; lower personas MUST be refused.",
    )

    if getattr(args, "from_scan", None) and results:
        exploit_rows = []
        for r in results:
            tc = r.test_case
            f_id = getattr(tc, "finding_id", None) or "-"
            c_score_str = f"{tc.consensus_score:.2f}" if getattr(tc, "consensus_score", None) is not None else "N/A"
            if r.is_breach:
                verdict = color("CONFIRMED BREACH (EXPLOITABLE)", RED, BOLD)
            elif r.is_secure:
                verdict = color("PROTECTED (404 INVARIANT)", GREEN, BOLD)
            else:
                verdict = color(f"UNEXPECTED HTTP {r.status_code}", YELLOW)
            exploit_rows.append((f"{f_id} [{tc.method} {tc.path}]", f"Consensus: {c_score_str} | Verdict: {verdict}"))

        print_summary_table(
            title="Multi-AI Consensus vs Active Exploit Verification",
            rows=exploit_rows,
            footer="Offensive Verification: Green = 404 Enforced, Red = Active BOLA Breach Confirmed.",
        )

    return 0 if success else 1


def _matrix_cases_from_scan(scan_file: Path, args: argparse.Namespace, min_consensus: float) -> List[MatrixCase]:
    """BFLA and mass assignment findings from findings.json (SARIF is not read here)."""
    try:
        data = json.loads(scan_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    token_env = getattr(args, "token_env", None) or CLI_TOKEN_ENV
    cases = generate_matrix_cases_from_findings(
        data, token_env=token_env, default_id=args.resource_id, min_consensus=min_consensus
    )
    if cases:
        step_info(f"Synthesized {len(cases)} BFLA / mass assignment cases from scan findings")
    return cases


def _run_matrix(cases: List[MatrixCase], args: argparse.Namespace) -> List[Any]:
    if not cases:
        return []
    env: Dict[str, str] = dict(os.environ)
    if args.attacker_token:
        env.setdefault(CLI_TOKEN_ENV, args.attacker_token)
    step(f"Executing {len(cases)} persona matrix cases")
    return PersonaMatrixRunner(args.base_url, env=env, strict=args.strict).run(cases)
