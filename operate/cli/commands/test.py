"""Command: komagu test - Cross-user BOLA/IDOR continuous verification."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

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
from operate.cross_user_tester.session_config import (
    SessionOptions,
    add_session_arguments,
    build_session_options,
    check_session,
    cookie_file_is_open,
    global_csrf,
    read_cookie,
    strict_gaps,
)
from operate.cross_user_tester.session_http import SessionConfigError
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
CLI_TOKEN_ENV = "KOMAGU_CLI_TOKEN"
# The attacker's cookie reaches persona-matrix cases the same way, in a private copy of the environment.
CLI_COOKIE_ENV = "KOMAGU_CLI_COOKIE"


def register_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Register the test subcommand parser."""
    parser = subparsers.add_parser(
        "test",
        help="Execute continuous cross-user authorization tests against an API",
        description="Enforces Komagu BOLA/IDOR security invariants (attacker access MUST return 404 Not Found).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Ingest LSA findings and verify only findings with >= 80% AI Consensus
  komagu test --url http://staging.internal:8000 --from-scan ./findings.json --min-consensus 0.8

  # Verify findings and export reproducible Python & cURL exploit PoC scripts
  komagu test --url http://localhost:5001 --from-scan ./findings.json --export-poc ./pocs

  # Test auto-generated CRUD BOLA cases against local API
  komagu test --url http://localhost:5001 --auto-crud /api/members

  # Run custom test suite with strict 404 enforcement
  komagu test --url http://staging.internal:8000 --suite ./test_suite.json --strict

  # Run tests with custom attacker token and save report
  komagu test --url http://localhost:5001 --token "jwt-persona-b" --output ./results.json

  # Persona matrix (suite "version": 2): BFLA and mass assignment checks
  KOMAGU_TOKEN_USER=... KOMAGU_TOKEN_ADMIN=... komagu test --url http://staging:8000 --suite ./personas.json

  # Session-based Java app (JSP / Struts): cookies from the environment, declared denial signal
  ATTACKER_COOKIE=... OWNER_COOKIE=... komagu test --url http://test:8080 --from-scan ./findings.json --strict \\
    --attacker-cookie-env ATTACKER_COOKIE --owner-cookie-env OWNER_COOKIE \\
    --session-check /home.do --deny-status 404 --deny-redirect /login.do

Documentation:
  See docs/cli-guide.md#34-komagu-test--offensive-exploit-verification-bola-invariant--persona-matrix
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
        help="Path to findings.json or SARIF output from komagu scan to generate attack test cases",
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
        help="Enforce strict 404 requirement (reject 401/403 which leak resource existence). "
             "With session cookies, also requires a declared denial signal, --session-check and the owner's cookie",
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
    add_session_arguments(parser)
    parser.set_defaults(func=execute_test)



def execute_test(args: argparse.Namespace) -> int:
    """Execute cross-user authorization verification."""
    step(f"Initializing cross-user security test runner against {color(args.base_url, BOLD)}")

    tests: List[Any] = []
    matrix_cases: List[MatrixCase] = []

    try:
        session = build_session_options(args, os.environ)
        csrf = global_csrf(args)
    except SessionConfigError as e:
        step_fail(str(e))
        return 2
    for cookie_file in (args.attacker_cookie_file, args.owner_cookie_file):
        if cookie_file_is_open(cookie_file):
            step_warn("A cookie file can be read by other users; restrict it with chmod 600")
    # A session run sends the cookie only; the --token default must not go with it.
    attacker_token = None if session and session.attacker_cookie else args.attacker_token
    suite_body_format = "form" if args.body_format == "form" else "json"

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
            attacker_token=attacker_token,
            min_consensus_score=min_c,
            body_format=args.body_format,
            csrf=csrf,
        )
        step_info(f"Synthesized {len(scan_cases)} active verification cases from scan findings")
        tests.extend(scan_cases)
        matrix_cases.extend(_matrix_cases_from_scan(scan_file, args, min_c, session, csrf))

        # Export PoC exploits if requested
        if getattr(args, "export_poc", None):
            if session and session.attacker_cookie:
                step_warn("--export-poc writes Bearer scripts; they do not carry the session cookie")
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
                matrix_cases.extend(load_persona_suite(
                    suite_data, default_id=args.resource_id,
                    default_body_format=suite_body_format, default_csrf=csrf,
                ))
            except (SuiteError, SessionConfigError) as e:
                step_fail(f"Invalid persona suite {suite_path.name}: {e}")
                return 2
            step_info(f"Persona matrix: {len(matrix_cases)} BFLA / mass assignment cases")
        else:
            try:
                tests.extend(load_suite_from_file(str(suite_path), suite_body_format, csrf))
            except SessionConfigError as e:
                step_fail(f"Invalid test suite {suite_path.name}: {e}")
                return 2
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
                attacker_token=attacker_token,
                body_format=suite_body_format,
                csrf=csrf,
            )
        )


    runner = CrossUserTestRunner(
        base_url=args.base_url,
        default_attacker_token=attacker_token,
        session=session,
    )

    has_cookie_personas = any(c.persona.cookie_env or c.persona.cookie_file for c in matrix_cases)
    if args.strict and has_cookie_personas:
        gaps = strict_gaps(args, False, False)
        if gaps:
            step_fail("--strict on a session app needs " + "; ".join(gaps))
            return 2
    problem = _session_problem(args, session, matrix_cases, os.environ)
    if problem:
        step_fail(f"{problem}. No test was sent.")
        return 2

    results = []
    success = True
    if tests:
        step(f"Executing {len(tests)} cross-user authorization test cases")
        results = runner.run_suite(tests)
        report_text, success = format_report(results, args.base_url)
        print()
        print(report_text)

    try:
        matrix_results = _run_matrix(matrix_cases, args, session)
    except ValueError as e:
        step_fail(str(e))
        return 2
    if matrix_results:
        matrix_text, matrix_ok = format_matrix_report(
            matrix_results, STRICT_DENY_STATUS if args.strict else DENY_STATUS
        )
        print()
        print(matrix_text)
        success = success and matrix_ok

    # A session lost during the run turns refusals into login redirects: the verdicts cannot be trusted.
    lost_session = _session_problem(args, session, matrix_cases, os.environ)
    if lost_session:
        step_fail(f"{lost_session} after the run. The results below are not valid.")
        success = False

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
        if lost_session:
            report_data["session_check"] = "failed_after_run"
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
        footer="Komagu invariant: cross-user access MUST return 404; lower personas MUST be refused.",
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
                verdict = color("PROTECTED (DENIAL SIGNAL)" if session else "PROTECTED (404 INVARIANT)", GREEN, BOLD)
            else:
                verdict = color(f"UNEXPECTED HTTP {r.status_code}", YELLOW)
            exploit_rows.append((f"{f_id} [{tc.method} {tc.path}]", f"Consensus: {c_score_str} | Verdict: {verdict}"))

        print_summary_table(
            title="Multi-AI Consensus vs Active Exploit Verification",
            rows=exploit_rows,
            footer="Offensive Verification: Green = 404 Enforced, Red = Active BOLA Breach Confirmed.",
        )

    if lost_session:
        return 2
    return 0 if success else 1


def _session_targets(
    session: Optional[SessionOptions],
    cases: List[MatrixCase],
    env: Mapping[str, str],
) -> List[Tuple[str, str]]:
    """(label, cookie) for every session persona in this run."""
    targets: List[Tuple[str, str]] = []
    if session and session.attacker_cookie:
        targets.append(("attacker", session.attacker_cookie))
    if session and session.owner_cookie:
        targets.append(("owner", session.owner_cookie))
    for persona in {c.persona for c in cases if c.persona.cookie_env != CLI_COOKIE_ENV}:
        cookie = read_cookie(persona.cookie_env, persona.cookie_file, env, persona.name)
        if cookie:
            targets.append((persona.name, cookie))
    return targets


def _session_problem(
    args: argparse.Namespace,
    session: Optional[SessionOptions],
    cases: List[MatrixCase],
    env: Mapping[str, str],
) -> Optional[str]:
    """Why a session persona cannot be used, or None when all are alive."""
    if session is None or not session.session_check:
        return None
    try:
        targets = _session_targets(session, cases, env)
    except SessionConfigError as err:
        return str(err)
    for label, cookie in targets:
        problem = check_session(args.base_url, label, cookie, session.session_check, session.session_marker, session.denial)
        if problem:
            return problem
    return None


def _matrix_cases_from_scan(
    scan_file: Path,
    args: argparse.Namespace,
    min_consensus: float,
    session: Optional[SessionOptions],
    csrf: Optional[Any],
) -> List[MatrixCase]:
    """BFLA and mass assignment findings from findings.json or SARIF."""
    try:
        data = json.loads(scan_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    token_env = getattr(args, "token_env", None) or CLI_TOKEN_ENV
    cookie_env = CLI_COOKIE_ENV if session and session.attacker_cookie else None
    cases = generate_matrix_cases_from_findings(
        data, token_env=token_env, default_id=args.resource_id, min_consensus=min_consensus,
        cookie_env=cookie_env, body_format=args.body_format, csrf=csrf,
    )
    if cases:
        step_info(f"Synthesized {len(cases)} BFLA / mass assignment cases from scan findings")
    return cases


def _run_matrix(cases: List[MatrixCase], args: argparse.Namespace, session: Optional[SessionOptions]) -> List[Any]:
    if not cases:
        return []
    env: Dict[str, str] = dict(os.environ)
    if args.attacker_token:
        env.setdefault(CLI_TOKEN_ENV, args.attacker_token)
    if session and session.attacker_cookie:
        env[CLI_COOKIE_ENV] = session.attacker_cookie
    step(f"Executing {len(cases)} persona matrix cases")
    denial = session.denial if session else None
    return PersonaMatrixRunner(args.base_url, env=env, strict=args.strict, denial=denial).run(cases)
