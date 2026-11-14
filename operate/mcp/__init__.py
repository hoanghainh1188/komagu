"""Zero-dependency Model Context Protocol server for the Komagu CLI.

Python 3.8+ standard library only. Messages are newline-delimited JSON-RPC
on stdio. Nothing except protocol messages is written to stdout.
"""

from __future__ import annotations

from operate.mcp.server import serve_stdio

__all__ = ["serve_stdio"]
