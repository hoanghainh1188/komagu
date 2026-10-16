# Adapter — Claude Code

## Install into an audit workspace

```bash
python3 adapters/build_adapters.py claude-code ~/audits/acme-2026-10
```

This creates:

- `.claude/skills/legacy-security-audit/` — the kit + `SKILL.md` (orchestrator)
- `.claude/agents/lsa-*.md` — one subagent per role (tools: Read, Grep, Glob, Write)

Put (or symlink / check out) the code under audit next to it, e.g.
`~/audits/acme-2026-10/src/`, and use `~/audits/acme-2026-10/lsa-out/` as OUT.

## Run

Start Claude Code in the workspace and ask, for example:

> Run the legacy-security-audit skill. TARGET=src, OUT=lsa-out, CONFIG=audit-config.json.

The skill runs the pre-scan, then launches the subagents phase by phase
(4a and 4b in parallel), then merges and renders the report.

## Recommended settings

- Do not give the subagents `Bash` or web tools. Only the main session runs
  the Python scripts.
- Use permission rules that deny `Edit`/`Write` under the TARGET folder.
- For customer code that may not leave the company, point Claude Code at an
  approved deployment (check the project's `llm_policy` first).
