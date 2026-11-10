"""Command: komagu leak-check - find secrets that reached pilot outputs (runbook §9)."""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from typing import Tuple

from operate.devsecops.leak_check import CanaryFileError, ScanResult, load_canaries, scan_paths


def register_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Register the leak-check subcommand parser."""
    parser = subparsers.add_parser(
        "leak-check",
        help="Scan ai-raw/, findings and reports for leaked secrets and client canary strings",
        description=(
            "Checks audit output for secrets the redaction step missed. Values are always masked in the report. "
            "Exit codes: 0 clean, 1 suspected leak, 2 incomplete scan or bad input."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  komagu leak-check ~/pilot/out --canary-file ~/pilot/canaries.txt
  komagu leak-check ~/pilot/out/ai-raw ~/pilot/out/report.md --format json > ~/pilot/leak-check.json
""",
    )
    parser.add_argument("paths", nargs="+", metavar="PATH", help="Output directories or files to scan")
    parser.add_argument(
        "--canary-file",
        help="UTF-8 file with one client-provided canary string per line; keep it outside the repository",
    )
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Report format (default: text)")
    parser.set_defaults(func=run)


def _print_text(result: ScanResult) -> None:
    for hit in result.hits:
        print(f"{hit.path}:{hit.line}: {hit.detector}: {hit.rule}: {hit.masked}")
    for path, reason in result.unscanned:
        print(f"NOT SCANNED {path}: {reason}")
    print(
        f"leak-check: {len(result.hits)} suspected leak(s), {result.files_scanned} file(s) scanned, "
        f"{len(result.unscanned)} not scanned, {result.canaries_loaded} canary string(s)"
    )


def _print_json(result: ScanResult) -> None:
    report = {
        "exitCode": result.exit_code,
        "filesScanned": result.files_scanned,
        "canariesLoaded": result.canaries_loaded,
        "hits": [dataclasses.asdict(hit) for hit in result.hits],
        "notScanned": [{"path": path, "reason": reason} for path, reason in result.unscanned],
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))


def run(args: argparse.Namespace) -> int:
    """Run the scan and return its exit code."""
    canaries: Tuple[str, ...] = ()
    if args.canary_file is not None:
        try:
            canaries = load_canaries(args.canary_file)
        except CanaryFileError as exc:
            print(f"leak-check: {exc}", file=sys.stderr)
            return 2
    result = scan_paths(args.paths, canaries)
    if args.format == "json":
        _print_json(result)
    else:
        _print_text(result)
    return result.exit_code
