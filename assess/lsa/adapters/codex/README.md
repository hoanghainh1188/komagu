# Adapter — OpenAI Codex

## Install into an audit workspace

```bash
komagu init --ai codex ~/audits/acme-2026-10
# or, from the kit:
python3 adapters/build_adapters.py codex ~/audits/acme-2026-10
```

This creates:

- `.agents/skills/legacy-security-audit/` — the kit + `SKILL.md` (orchestrator).
  Codex finds repo-scoped skills in `.agents/skills/` from the working
  directory up to the repository root.
- `.codex/agents/lsa-*.toml` — one project custom agent per role
  (`name`, `description`, `developer_instructions`).
- `AGENTS.md` — an LSA section between `komainu-lsa:begin` / `komainu-lsa:end`
  markers. Anything you write outside the markers is kept; re-running the
  generator only replaces the section.

Put (or symlink / check out) the code under audit next to it, e.g.
`~/audits/acme-2026-10/src/`, and use `~/audits/acme-2026-10/lsa-out/` as OUT.

## Run

Start Codex in the workspace and ask, for example:

> Run the legacy-security-audit skill. TARGET=src, OUT=lsa-out, CONFIG=audit-config.json.

The skill runs the pre-scan, then spawns the `lsa-*` custom agents phase by
phase (4a, 4b and 4c in parallel). Codex spawns subagents only when asked; the
skill asks for them. If subagents are not available, run the roles one after
another and start the verifier in a new Codex session.

## Recommended settings

- Run Codex with a sandbox that can write only the workspace, and keep the
  code under audit read-only (for example, mount or check it out read-only).
- Do not give the agents network access during the audit.
- For customer code that may not leave the company, point Codex at an
  approved model provider (check the project's `llm_policy` first).

Note: the skill folder, `.codex/agents/*.toml` fields and `AGENTS.md`
handling follow the Codex documentation at the time of writing. If your Codex
version differs, the role prompts in `.agents/skills/legacy-security-audit/prompts/`
are the source of truth.
