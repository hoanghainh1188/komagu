"""Inventory subcommand: compare code routes, OpenAPI spec, and gateway traffic to find Shadow/Zombie APIs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from operate.cli.ui import color, print_summary_table, step, step_fail, step_info, step_ok, step_warn
from operate.inventory.api_inventory import (
    diff_api_inventory,
    load_code_routes,
    load_openapi_spec,
    load_traffic_log,
)


def register_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Register the inventory subcommand parser."""
    parser = subparsers.add_parser(
        "inventory",
        help="Reconcile code routes, OpenAPI spec, and gateway traffic to detect Shadow and Zombie APIs",
        description="Detects Shadow APIs (undocumented code/traffic) and Zombie APIs (deprecated routes still active).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Reconcile LSA code routes against the published OpenAPI spec
  komagu inventory --routes OUT/routes.json --openapi openapi.json

  # Include Kong Gateway traffic log to spot Zombie APIs and active Shadow endpoints
  komagu inventory --routes OUT/routes.json --openapi openapi.json --traffic-log /var/log/kong/access.log

  # CI gate: fail if any undocumented Shadow API is detected
  komagu inventory --routes OUT/routes.json --openapi openapi.json --fail-on-shadow

  # Output machine-readable JSON diff to a custom path
  komagu inventory --routes OUT/routes.json --openapi openapi.json --out OUT/api-diff.json
""",
    )
    parser.add_argument(
        "--routes",
        "-r",
        type=Path,
        required=True,
        help="Path to code routes JSON (e.g. OUT/routes.json or routes.candidates.json from LSA)",
    )
    parser.add_argument(
        "--openapi",
        "-s",
        type=Path,
        required=True,
        help="Path to OpenAPI / Swagger JSON or YAML specification",
    )
    parser.add_argument(
        "--traffic-log",
        "--kong-log",
        "-t",
        type=Path,
        default=None,
        help="Path to Kong HTTP-Log (JSON lines) or NGINX Combined access log",
    )
    parser.add_argument(
        "--out",
        "-o",
        type=Path,
        default=None,
        help="Path to write the api-inventory-diff.json output (defaults to OUT/api-inventory-diff.json)",
    )
    parser.add_argument(
        "--fail-on-shadow",
        action="store_true",
        help="Exit with non-zero code if any shadow API is detected",
    )
    parser.add_argument(
        "--fail-on-zombie",
        action="store_true",
        help="Exit with non-zero code if any zombie API is detected",
    )
    parser.set_defaults(func=run_inventory)


def run_inventory(args: argparse.Namespace) -> int:
    """Execute API inventory reconciliation."""
    routes_file = Path(args.routes).resolve()
    openapi_file = Path(args.openapi).resolve()
    traffic_file = Path(args.traffic_log).resolve() if args.traffic_log else None

    if not routes_file.is_file():
        step_fail(f"Routes file not found: {routes_file}")
        return 2

    if not openapi_file.is_file():
        step_fail(f"OpenAPI spec file not found: {openapi_file}")
        return 2

    step("Parsing routes extracted from source code")
    code_routes = load_code_routes(routes_file)
    step_ok(f"Loaded {len(code_routes)} endpoints from code routes")

    step("Parsing OpenAPI specification")
    spec_endpoints = load_openapi_spec(openapi_file)
    step_ok(f"Loaded {len(spec_endpoints)} endpoints from OpenAPI specification")

    traffic_data = {}
    if traffic_file:
        if not traffic_file.is_file():
            step_warn(f"Traffic log file not found: {traffic_file} (skipping traffic analysis)")
        else:
            step("Analyzing gateway traffic log (Kong / NGINX)")
            traffic_data = load_traffic_log(traffic_file)
            total_hits = sum(t["traffic_hits"] for t in traffic_data.values())
            step_ok(f"Parsed {len(traffic_data)} active endpoints ({total_hits} total requests) from traffic log")

    step("Reconciling API inventories across 3 surfaces")
    diff_doc = diff_api_inventory(
        code_routes=code_routes,
        spec_endpoints=spec_endpoints,
        traffic_data=traffic_data,
        routes_file_name=routes_file.name,
        openapi_file_name=openapi_file.name,
        traffic_file_name=traffic_file.name if traffic_file else None,
    )

    s = diff_doc["summary"]
    shadow_count = s["shadow_count"]
    zombie_count = s["zombie_count"]
    missing_count = s["missing_code_count"]
    dormant_count = s["dormant_count"]

    # Determine output file path
    out_file = args.out
    if not out_file:
        out_dir = routes_file.parent
        out_file = out_dir / "api-inventory-diff.json"

    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(diff_doc, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    step_ok(f"Saved inventory diff to {out_file}")

    # Display summary card
    c_yellow_bold = "\033[33m\033[1m"
    c_red_bold = "\033[31m\033[1m"
    c_green = "\033[32m"
    c_bold = "\033[1m"

    summary_rows = [
        ("Code Routes Discovered", str(s["total_code_routes"])),
        ("OpenAPI Endpoints Documented", str(s["total_spec_endpoints"])),
        ("Gateway Traffic Endpoints", str(s["total_traffic_endpoints"])),
        ("Shadow APIs (Undocumented)", color(str(shadow_count), c_yellow_bold if shadow_count > 0 else c_green)),
        ("Zombie APIs (Deprecated Active)", color(str(zombie_count), c_red_bold if zombie_count > 0 else c_green)),
        ("Documented Missing in Code", str(missing_count)),
        ("Dormant Code Endpoints", str(dormant_count)),
    ]
    print_summary_table(
        "API Inventory Reconciliation Summary",
        summary_rows,
        footer="Shadow APIs expose undocumented attack surface; Zombie APIs must be retired."
    )

    if shadow_count > 0:
        print("  " + color("⚠ Detected Shadow APIs (Top 5):", "\033[33m", c_bold))
        for sh in diff_doc["shadow_apis"][:5]:
            hits = f"({sh['traffic_hits']} traffic hits)" if sh["traffic_hits"] > 0 else ""
            norm_str = color(sh["normalized"], c_bold)
            disc_str = sh["discovered_in"]
            print(f"    • {norm_str} [{disc_str}] {hits}")

    if zombie_count > 0:
        print("  " + color("✖ Detected Zombie APIs (Top 5):", "\033[31m", c_bold))
        for z in diff_doc["zombie_apis"][:5]:
            norm_str = color(z["normalized"], c_bold)
            hits_str = f"{z['traffic_hits']} active traffic hits!"
            print(f"    • {norm_str} ({hits_str})")

    exit_code = 0
    if args.fail_on_shadow and shadow_count > 0:
        step_fail(f"Failing gate: {shadow_count} shadow APIs detected")
        exit_code = 1
    if args.fail_on_zombie and zombie_count > 0:
        step_fail(f"Failing gate: {zombie_count} zombie APIs detected")
        exit_code = 1

    return exit_code
