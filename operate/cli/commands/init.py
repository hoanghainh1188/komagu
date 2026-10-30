"""Command: komagu init - Install Tier 2 LSA agents into your AI runtime (Claude Code, Codex, Cursor, generic)."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
from types import ModuleType

from operate.cli.ui import step, step_fail, step_info, step_ok

REPO_ROOT = Path(__file__).resolve().parents[3]
ADAPTER_SCRIPT = REPO_ROOT / "assess" / "lsa" / "adapters" / "build_adapters.py"
RUNTIME_CHOICES = ["claude-code", "claude", "codex", "cursor", "generic", "openhands"]


def register_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Register the init subcommand parser."""
    parser = subparsers.add_parser(
        "init",
        help="Install the LSA audit skill and agents into your AI runtime (Claude Code, Codex, Cursor, generic)",
        description=(
            "Generates Tier 2 (BYO-LLM) files for your own AI runtime: the legacy-security-audit skill, "
            "one agent per audit role, and the shared knowledge base and schemas. "
            "Komagu makes no LLM calls itself; your runtime runs the agents."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Runtimes and generated files:
  claude-code (claude)  .claude/skills/legacy-security-audit/ + .claude/agents/lsa-*.md
  codex                 .agents/skills/legacy-security-audit/ + .codex/agents/lsa-*.toml + AGENTS.md section
  cursor                .lsa-kit/ + .cursor/rules/lsa-*.mdc
  generic (openhands)   system-prompts/*.md + contract.json + kit/

Examples:
  # Prepare an audit workspace for OpenAI Codex
  komagu init --ai codex ~/audits/acme-2026-10

  # Prepare the current folder for Claude Code
  komagu init --ai claude

  # Export prompts and a pipeline contract for a private LLM runner
  komagu init --ai generic ./lsa-bundle

DEST should be an audit workspace that contains or sits next to the code under
audit, not the customer repository itself. Re-running refreshes the generated files.
generic refuses a DEST whose contract.json, kit/ or system-prompts/ it did not generate.
""",
    )
    parser.add_argument(
        "--ai",
        required=True,
        choices=RUNTIME_CHOICES,
        type=str.lower,
        help="AI runtime to generate files for",
    )
    parser.add_argument(
        "dest",
        nargs="?",
        default=".",
        help="Audit workspace folder to write into (default: current directory; created if missing)",
    )
    parser.set_defaults(func=run_init)


def load_adapter_builder() -> ModuleType:
    """Load the stdlib-only adapter builder that ships inside the LSA kit."""
    spec = importlib.util.spec_from_file_location("komagu_lsa_build_adapters", ADAPTER_SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load adapter builder from {ADAPTER_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_init(args: argparse.Namespace) -> int:
    """Execute the init command."""
    dest = Path(args.dest).expanduser().resolve()
    if dest.exists() and not dest.is_dir():
        step_fail(f"Destination is not a directory: {dest}")
        return 1

    try:
        builder = load_adapter_builder()
        runtime = builder.resolve_runtime(args.ai)
    except (ImportError, OSError, ValueError) as e:
        step_fail(f"Cannot prepare adapter: {e}")
        return 1

    step(f"Generating {runtime} files in {dest}")
    try:
        dest.mkdir(parents=True, exist_ok=True)
        builder.build(runtime, dest)
    except (OSError, ValueError) as e:
        step_fail(f"Failed to write adapter files: {e}")
        return 1

    step_ok(f"LSA kit {builder.VERSION} installed for {runtime}")
    step_info("Tier 2 runs in your AI runtime. Check governance/usage-policy.md before sending customer code to a model.")
    return 0
