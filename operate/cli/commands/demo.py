"""Command: komagu demo - Reference Member Portal environment management."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List

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
DEMO_DIR = REPO_ROOT / "examples" / "member-portal"
DEMO_COMPOSE = DEMO_DIR / "docker-compose.yml"


def register_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Register the demo subcommand parser."""
    parser = subparsers.add_parser(
        "demo",
        help="Manage the reference Member Portal demo application (Docker Compose)",
        description="Spins up the full-stack modernization reference demo (PostgreSQL, .NET / Spring Boot, React).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start the Member Portal demo with .NET Core 8 backend
  komagu demo --backend dotnet --up

  # Start the Member Portal demo with Spring Boot 3 backend
  komagu demo --backend spring --up

  # Check status of running demo containers
  komagu demo --status

  # Stop and clean up demo containers
  komagu demo --down
""",
    )
    parser.add_argument(
        "--backend",
        choices=["dotnet", "spring", "all"],
        default="dotnet",
        help="Backend stack to run: dotnet (.NET Core 8), spring (Spring Boot 3), or all (default: dotnet)",
    )
    parser.add_argument(
        "--up",
        action="store_true",
        help="Start demo services in background (default action)",
    )
    parser.add_argument(
        "--down",
        action="store_true",
        help="Stop and remove demo containers",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show status of demo containers",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print docker compose commands without executing them",
    )
    parser.set_defaults(func=execute_demo)


def execute_demo(args: argparse.Namespace) -> int:
    """Execute demo environment lifecycle commands."""
    step("Validating Komagu Member Portal Demo assets")

    if not DEMO_COMPOSE.is_file():
        step_fail(f"Demo docker-compose.yml not found at {DEMO_COMPOSE}")
        return 1

    docker_bin = shutil.which("docker")
    compose_base = [docker_bin, "compose", "-f", str(DEMO_COMPOSE)] if docker_bin else None

    # Determine services
    services: List[str] = ["postgres"]
    if args.backend in ("dotnet", "all"):
        services.append("backend-dotnet")
    if args.backend in ("spring", "all"):
        services.append("backend-spring")
    services.append("frontend")

    action = "down" if args.down else ("status" if args.status else "up")

    if action == "up":
        step(f"Starting Member Portal demo with {args.backend} backend ({', '.join(services)})")
        if args.dry_run or not docker_bin:
            step_info(f"[DRY-RUN] Would execute: docker compose -f {DEMO_COMPOSE} up -d {' '.join(services)}")
        else:
            res = subprocess.run(compose_base + ["up", "-d"] + services, capture_output=True, text=True)
            if res.returncode != 0:
                step_fail("Failed to start demo containers")
                print(res.stderr or res.stdout, file=sys.stderr)
                return 1
            step_ok("Demo containers started")

    elif action == "down":
        step("Stopping Member Portal demo containers")
        if args.dry_run or not docker_bin:
            step_info(f"[DRY-RUN] Would execute: docker compose -f {DEMO_COMPOSE} down")
        else:
            res = subprocess.run(compose_base + ["down"], capture_output=True, text=True)
            if res.returncode == 0:
                step_ok("Demo containers stopped")
            else:
                step_fail("Failed to stop demo containers")
                return 1

    elif action == "status":
        step("Checking demo container status")
        if args.dry_run or not docker_bin:
            step_info(f"[DRY-RUN] Would execute: docker compose -f {DEMO_COMPOSE} ps")
        else:
            subprocess.run(compose_base + ["ps"])

    rows = [
        ("Demo Stack", f"Member Portal ({args.backend})"),
        ("Compose File", str(DEMO_COMPOSE)),
        ("Frontend Web App", "http://localhost:3000"),
        (".NET Backend API", "http://localhost:5001" if args.backend in ("dotnet", "all") else "Disabled"),
        ("Spring Boot API", "http://localhost:5002" if args.backend in ("spring", "all") else "Disabled"),
        ("PostgreSQL Database", "localhost:5432 (user: komagu, db: member_portal)"),
    ]

    print_summary_table(
        title="Member Portal Reference Demo Status",
        rows=rows,
        footer="Use --down to stop the demo or komagu test --url http://localhost:5001 to run tests.",
    )

    return 0
