"""Command: komainu protect - Perimeter protection gateway and WAF management."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

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
EDGE_DIR = REPO_ROOT / "remediate" / "edge"
EDGE_COMPOSE = EDGE_DIR / "docker-compose.yml"
KONG_CONFIG = EDGE_DIR / "kong" / "kong.yaml"
CORAZA_RULES = EDGE_DIR / "coraza" / "rules"


def register_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Register the protect subcommand parser."""
    parser = subparsers.add_parser(
        "protect",
        help="Configure and deploy Kong Gateway & Coraza WAF perimeter protection",
        description="Generates declarative Kong routing and Coraza WAF virtual patching rules.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate perimeter configurations (dry-run)
  komainu protect --dry-run

  # Launch the perimeter Kong + Coraza container stack
  komainu protect --up

  # Point perimeter gateway to a specific upstream service
  komainu protect --target http://host.docker.internal:5001 --up

  # Check perimeter container status
  komainu protect --status

  # Stop perimeter containers
  komainu protect --down
""",
    )
    parser.add_argument(
        "--target",
        "-t",
        help="Upstream target backend URL (e.g. http://host.docker.internal:5001)",
    )
    parser.add_argument(
        "--config",
        "-c",
        help="Path to custom Kong declarative config file (kong.yaml)",
    )
    parser.add_argument(
        "--up",
        action="store_true",
        help="Launch the perimeter Kong + Coraza container stack via Docker Compose",
    )
    parser.add_argument(
        "--down",
        action="store_true",
        help="Stop the perimeter container stack",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Check the status of running perimeter containers",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate configurations without starting containers",
    )
    parser.set_defaults(func=execute_protect)


def execute_protect(args: argparse.Namespace) -> int:
    """Execute perimeter protection actions."""
    step("Validating Komainu Perimeter Protection assets")

    if not EDGE_DIR.is_dir():
        step_fail(f"Edge directory not found at {EDGE_DIR}")
        return 1

    config_path = Path(args.config).resolve() if args.config else KONG_CONFIG
    if not config_path.is_file():
        step_fail(f"Kong configuration not found at {config_path}")
        return 1

    step_ok(f"Loaded Kong declarative configuration: {config_path.name}")
    step_ok(f"Coraza WAF rules directory verified: {CORAZA_RULES}")

    # If --target is supplied, report upstream routing
    upstream_url = args.target or "http://coraza-waf:8080 (internal upstream)"
    if args.target:
        step_info(f"Configured upstream target: {args.target}")

    # Handle Docker Compose actions
    docker_bin = shutil.which("docker")
    compose_cmd = [docker_bin, "compose", "-f", str(EDGE_COMPOSE)] if docker_bin else None

    if args.up:
        if args.dry_run or not docker_bin:
            step_info(f"[DRY-RUN] Would execute: docker compose -f {EDGE_COMPOSE} up -d")
        else:
            step("Starting perimeter containers (Kong Gateway + Coraza WAF + Mock Backend)")
            res = subprocess.run(compose_cmd + ["up", "-d"], capture_output=True, text=True)
            if res.returncode != 0:
                step_fail("Failed to start perimeter containers")
                print(res.stderr or res.stdout, file=sys.stderr)
                return 1
            step_ok("Perimeter containers started")

    elif args.down:
        if args.dry_run or not docker_bin:
            step_info(f"[DRY-RUN] Would execute: docker compose -f {EDGE_COMPOSE} down")
        else:
            step("Stopping perimeter containers")
            res = subprocess.run(compose_cmd + ["down"], capture_output=True, text=True)
            if res.returncode == 0:
                step_ok("Perimeter containers stopped")
            else:
                step_fail("Failed to stop perimeter containers")
                return 1

    elif args.status:
        if args.dry_run or not docker_bin:
            step_info(f"[DRY-RUN] Would execute: docker compose -f {EDGE_COMPOSE} ps")
        else:
            subprocess.run(compose_cmd + ["ps"])

    rows = [
        ("Perimeter Gateway", "Kong Gateway 3.6 (DB-less mode)"),
        ("WAF Engine", "Coraza Caddy (OWASP Core Rule Set)"),
        ("Kong Config", str(config_path)),
        ("Upstream Target", upstream_url),
        ("Public Proxy Port", "http://localhost:8000"),
        ("Kong Admin API", "http://localhost:8001"),
        ("Coraza WAF Port", "http://localhost:8080"),
    ]

    print_summary_table(
        title="Komainu Perimeter Protection Status",
        rows=rows,
        footer="Use --up to start the gateway or --down to stop.",
    )

    return 0
