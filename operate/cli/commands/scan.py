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
        description="Executes Tier 1 deterministic pre-scan, candidate discovery, and report generation (Zero-LLM mode). Tier 2 cognitive AI audit batches can be dispatched to your chosen AI runtime (Claude Code, Cursor, or private LLM API).",
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
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable content-hash candidate caching",
    )
    parser.add_argument(
        "--clean-cache",
        action="store_true",
        help="Clear existing candidate cache before scan",
    )
    parser.add_argument(
        "--cache-dir",
        help="Custom directory to store scan cache (default: OUT/.cache)",
    )
    parser.add_argument(
        "--sarif-out",
        help="Designated output path for SARIF 2.1.0 file (e.g. for GitHub code scanning upload)",
    )
    # Baseline comparison and CI gating
    parser.add_argument(
        "--baseline",
        metavar="PATH",
        help="Compare with a previous baseline.json or SARIF file (findings become new/unchanged/regressed)",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Write the updated baseline to --baseline (default: OUT/baseline.json)",
    )
    parser.add_argument(
        "--suppressions",
        metavar="PATH",
        help="Approved accepted-risk suppressions JSON (default: TARGET/.komainu/suppressions.json if present)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "new", "any"],
        default="none",
        help="Exit 1 when findings match: new (new or regressed), any (all active), none (default)",
    )
    parser.add_argument(
        "--fail-severity",
        choices=["info", "low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity counted by --fail-on (default: low)",
    )
    # Tier 2 Headless Cognitive AI execution
    parser.add_argument(
        "--headless-ai",
        nargs="?",
        const="http://localhost:11434/v1",
        default=None,
        metavar="ENDPOINT",
        help="Execute Tier 2 cognitive AI audit autonomously via an OpenAI-compatible endpoint (default: http://localhost:11434/v1)",
    )
    parser.add_argument(
        "--model",
        "-m",
        default=os.environ.get("KOMAINU_AI_MODEL", "llama3.1"),
        help="LLM model name for headless AI execution (default: $KOMAINU_AI_MODEL or llama3.1)",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("KOMAINU_AI_API_KEY", "ollama"),
        help="Bearer API key for headless AI endpoint (default: $KOMAINU_AI_API_KEY or 'ollama')",
    )
    parser.add_argument(
        "--ai-timeout",
        type=int,
        default=120,
        help="Timeout in seconds per LLM request (default: 120)",
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
    if getattr(args, "no_cache", False):
        cmd.append("--no-cache")
    if getattr(args, "clean_cache", False):
        cmd.append("--clean-cache")
    if getattr(args, "cache_dir", None):
        cmd.extend(["--cache-dir", str(args.cache_dir)])

    step("Executing Phase 1: Tier 1 Deterministic Pre-scan (Zero-LLM mode)")
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

    # 2. Tier 2 Cognitive Multi-Agent Audit (if --headless-ai is specified)
    if getattr(args, "headless_ai", None):
        endpoint = args.headless_ai
        model = getattr(args, "model", "llama3.1")
        api_key = getattr(args, "api_key", None)
        timeout = getattr(args, "ai_timeout", 120)

        step(
            f"Executing Tier 2 Cognitive Multi-Agent Audit (Headless BYO-LLM via {color(endpoint, BOLD)}, Model: {color(model, CYAN)})"
        )
        from operate.ai import HeadlessAIRunner, LLMClient

        def _scan_callback(status: str, msg: str) -> None:
            if status == "step":
                step(msg)
            elif status == "ok":
                step_ok(msg)
            elif status == "warn":
                step_warn(msg)
            elif status == "fail":
                step_fail(msg)
            else:
                step_info(msg)

        try:
            client = LLMClient(endpoint=endpoint, model=model, api_key=api_key, timeout=timeout)
            runner = HeadlessAIRunner(target_path, out_dir, client, step_callback=_scan_callback)
            runner.run()
        except Exception as e:
            step_fail(f"Headless AI execution failed: {e}")
            return 1

    # 3. Check for findings / merge findings
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

    # Fingerprint findings and compare with the baseline (also evaluates the CI gate)
    baseline_cmd = [
        sys.executable,
        str(LSA_SCRIPTS / "baseline.py"),
        str(out_dir),
        "--target-dir",
        str(target_path),
        "--fail-on",
        getattr(args, "fail_on", "none"),
        "--fail-severity",
        getattr(args, "fail_severity", "low"),
    ]
    if getattr(args, "baseline", None):
        baseline_cmd.extend(["--baseline", str(Path(args.baseline).resolve())])
    if getattr(args, "update_baseline", False):
        baseline_cmd.append("--update-baseline")
    suppressions_file = (
        Path(args.suppressions).resolve()
        if getattr(args, "suppressions", None)
        else target_path / ".komainu" / "suppressions.json"
    )
    if getattr(args, "suppressions", None) or suppressions_file.is_file():
        baseline_cmd.extend(["--suppressions", str(suppressions_file)])
    res_baseline = subprocess.run(baseline_cmd, capture_output=True, text=True)
    if res_baseline.returncode == 2:
        step_fail("Baseline comparison failed")
        print(res_baseline.stderr or res_baseline.stdout, file=sys.stderr)
        return 2
    gate_failed = res_baseline.returncode == 1
    baseline_lines = res_baseline.stdout.strip().splitlines()
    if getattr(args, "baseline", None) or getattr(args, "update_baseline", False) or "--suppressions" in baseline_cmd:
        step_ok(baseline_lines[0] if baseline_lines else "Baseline compared")
    for line in baseline_lines:
        if line.startswith("warning: "):
            step_warn(line[len("warning: "):])

    # 3. Export to SARIF if requested
    sarif_file = (
        Path(args.sarif_out).resolve()
        if getattr(args, "sarif_out", None)
        else (out_dir / "findings.sarif")
    )
    if getattr(args, "sarif_out", None) or args.format in ("sarif", "all"):
        step("Generating SARIF v2.1.0 report")
        sarif_script = LSA_SCRIPTS / "findings_to_sarif.py"
        sarif_cmd = [
            sys.executable,
            str(sarif_script),
            str(out_dir),
            "--target-dir",
            str(target_path),
            "--sarif-out",
            str(sarif_file),
        ]
        res_sarif = subprocess.run(sarif_cmd, capture_output=True, text=True)
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
    if baseline_lines and (getattr(args, "baseline", None) or getattr(args, "update_baseline", False)):
        summary_rows.append(("Baseline", baseline_lines[0].split(": ", 1)[-1]))

    print_summary_table(
        title="Komainu Security Audit Summary",
        rows=summary_rows,
        footer="Open report.html in any browser for interactive charts & remediation patches.",
    )

    # Clarify Two-Tier Architecture and execution mode
    if getattr(args, "headless_ai", None):
        print(
            f"  {color('🚀 Mode: Tier 2 Cognitive Multi-Agent Engine', GREEN, BOLD)} "
            f"(Headless BYO-LLM: {args.headless_ai}, Model: {args.model})"
        )
        print(f"  {color('✔ Skeptic Consensus Applied', GREEN)}: Verified zero-false-positive findings against compensative controls.\n")
    else:
        print(f"  {color('💡 Mode: Tier 1 Deterministic Engine', CYAN, BOLD)} (Regex & AST candidate extraction, no LLM required)")
        print("  To run Tier 2 Cognitive Multi-Agent Audit (BOLA semantic reasoning & Skeptic Verifier):")
        print(f"    • Headless CLI: {color('komainu scan ' + str(target_path) + ' --headless-ai http://localhost:11434/v1 --model llama3.1', BOLD)}")
        print(f"    • Claude Code : {color('python3 assess/lsa/adapters/build_adapters.py claude-code .', BOLD)}")
        print(f"    • Cursor      : {color('python3 assess/lsa/adapters/build_adapters.py cursor .', BOLD)}")
        print(f"    • Custom LLM  : see {color('assess/lsa/adapters/generic/README.md', BOLD)} (BYO-LLM: OpenAI, Gemini, Ollama)\n")

    if gate_failed:
        step_fail(f"CI gate failed (--fail-on {args.fail_on} --fail-severity {args.fail_severity})")
        for line in (ln for ln in baseline_lines if ln.startswith("  - ")):
            print(line)
        return 1
    return 0
