"""Command: komagu mcp - zero-dependency Model Context Protocol server."""

from __future__ import annotations

import argparse
import sys


def register_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Register the mcp subcommand parser."""
    parser = subparsers.add_parser(
        "mcp",
        help="Serve Komagu analysis tools over the Model Context Protocol on stdio",
        description=(
            "Speaks MCP JSON-RPC on stdin and stdout using the Python standard library only. "
            "Tools are local: Tier 1 scan, audit summary, leak check, API inventory, and a dry-run fix preview. "
            "The preview never modifies source. Logging is written to stderr so stdout stays a protocol stream."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Cursor, Claude Code, or any MCP client that launches a stdio server
  komagu mcp --stdio

Client configuration:
  {
    "mcpServers": {
      "komagu": {
        "command": "komagu",
        "args": ["mcp", "--stdio"]
      }
    }
  }
""",
    )
    parser.add_argument(
        "--stdio",
        action="store_true",
        help="Speak newline-delimited MCP JSON-RPC on stdin/stdout (the only transport)",
    )
    parser.set_defaults(func=run_mcp)


def run_mcp(args: argparse.Namespace) -> int:
    """Start the stdio server, or reject the command when --stdio was omitted."""
    if not getattr(args, "stdio", False):
        print(
            "komagu mcp: the only transport is stdio. Run: komagu mcp --stdio",
            file=sys.stderr,
        )
        return 2
    from operate.mcp.server import serve_stdio

    return serve_stdio()
