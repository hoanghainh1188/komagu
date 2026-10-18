"""Main entrypoint for the unified Komainu CLI."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from operate.cli import __version__
from operate.cli.commands import demo, protect, scan, test
from operate.cli.ui import print_banner


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="komainu",
        description="Komainu — Security-First Legacy Modernization Platform CLI.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"komainu v{__version__}",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the Komainu ASCII banner",
    )

    subparsers = parser.add_subparsers(
        title="Subcommands",
        dest="subcommand",
        metavar="<command>",
    )

    scan.register_subcommand(subparsers)
    protect.register_subcommand(subparsers)
    test.register_subcommand(subparsers)
    demo.register_subcommand(subparsers)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI execution entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "no_banner", False) and getattr(args, "subcommand", None) is not None:
        print_banner()

    if getattr(args, "subcommand", None) is None:
        print_banner()
        parser.print_help()
        return 0

    if hasattr(args, "func"):
        return args.func(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
