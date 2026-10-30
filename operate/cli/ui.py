"""Terminal UI and output formatting helpers for Komagu CLI."""

from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

BG_RED = "\033[41m"
BG_YELLOW = "\033[43m"
BG_BLUE = "\033[44m"


def is_color_enabled() -> bool:
    """Check if stdout supports color escapes."""
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def color(text: str, *codes: str) -> str:
    """Wrap text in ANSI color codes if color is supported."""
    if not is_color_enabled():
        return text
    return f"{''.join(codes)}{text}{RESET}"


def print_banner() -> None:
    """Print the Komagu branding banner."""
    lines = [
        color("  _  __                                 ", CYAN, BOLD),
        color(" | |/ /___  _ __ ___   __ _  __ _ _   _ ", CYAN, BOLD),
        color(" | ' // _ \\| '_ ` _ \\ / _` |/ _` | | | |", CYAN, BOLD),
        color(" | . \\ (_) | | | | | | (_| | (_| | |_| |", BLUE, BOLD),
        color(" |_|\\_\\___/|_| |_| |_|\\__,_|\\__, |\\__,_|", BLUE, BOLD),
        color("                            |___/       ", BLUE, BOLD),
        color(" Legacy Modernization & Security Platform", DIM),
    ]
    print("\n".join(lines))
    print()


def step(message: str) -> None:
    """Print an in-progress pipeline step."""
    bullet = color("▶", CYAN, BOLD)
    print(f"{bullet} {message}...")


def step_ok(message: str) -> None:
    """Print a completed pipeline step."""
    check = color("✔", GREEN, BOLD)
    print(f"  {check} {message}")


def step_info(message: str) -> None:
    """Print an informational note."""
    info_tag = color("ℹ", BLUE)
    print(f"  {info_tag} {message}")


def step_warn(message: str) -> None:
    """Print a warning message."""
    warn_tag = color("⚠", YELLOW, BOLD)
    print(f"  {warn_tag} {color(message, YELLOW)}")


def step_fail(message: str) -> None:
    """Print an error message."""
    fail_tag = color("✖", RED, BOLD)
    print(f"  {fail_tag} {color(message, RED, BOLD)}")


def print_summary_table(
    title: str,
    rows: List[tuple[str, str]],
    footer: Optional[str] = None,
) -> None:
    """Print a structured summary card in ASCII."""
    max_k = max((len(k) for k, _ in rows), default=20)
    max_v = max((len(v) for _, v in rows), default=30)
    width = max(max_k + max_v + 7, len(title) + 6, 60)

    print()
    print(color(f"┌─ {title} " + "─" * (width - len(title) - 4) + "┐", CYAN, BOLD))
    for k, v in rows:
        padding = " " * (width - len(k) - len(v) - 5)
        print(f"│  {color(k, BOLD)}: {v}{padding}│")
    if footer:
        print(color("├" + "─" * (width - 2) + "┤", CYAN))
        foot_pad = " " * (width - len(footer) - 4)
        print(f"│ {color(footer, DIM)}{foot_pad} │")
    print(color("└" + "─" * (width - 2) + "┘", CYAN, BOLD))
    print()
