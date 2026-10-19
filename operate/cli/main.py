"""Main entrypoint for the unified Komainu CLI."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from operate.cli import __version__
from operate.cli.commands import demo, devsecops, protect, scan, test
from operate.cli.ui import print_banner


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="komainu",
        description="Komainu — Security-First Legacy Modernization Platform CLI.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Quick Start Workflow:
  1. Audit a legacy codebase:   komainu scan ./legacy-app --lang ja --format html
  2. Launch perimeter edge:     komainu protect --up
  3. Verify BOLA invariant:     komainu test --url http://localhost:8000
  4. Explore reference demo:    komainu demo --up
  5. Run DevSecOps & SBOM:      komainu devsecops run .

Learn more about a specific command:
  komainu help <command>
  komainu <command> --help
""",
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
    devsecops.register_subcommand(subparsers)

    help_parser = subparsers.add_parser(
        "help",
        help="Show help and usage examples for Komainu or a specific subcommand",
        description="Displays help information, workflow guide, and command examples.",
    )
    help_parser.add_argument(
        "topic",
        nargs="?",
        choices=["scan", "protect", "test", "demo", "devsecops"],
        help="Subcommand topic to display help for (scan, protect, test, demo, devsecops)",
    )

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

    if getattr(args, "subcommand", None) == "help":
        topic = getattr(args, "topic", None)
        if topic:
            sub_actions = [a for a in parser._subparsers._actions if isinstance(a, argparse._SubParsersAction)]
            if sub_actions and topic in sub_actions[0].choices:
                sub_actions[0].choices[topic].print_help()
                return 0
        parser.print_help()
        return 0

    if hasattr(args, "func"):
        return args.func(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
