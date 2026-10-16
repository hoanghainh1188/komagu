# Adapter — Cursor

## Install

```bash
python3 adapters/build_adapters.py cursor ~/audits/acme-2026-10
```

This creates `.lsa-kit/` (the kit) and `.cursor/rules/lsa-*.mdc` (one rule
per role, `alwaysApply: false`, so they load only when you mention them).

## Run

1. In a terminal: `python3 .lsa-kit/scripts/run_prescan.py src lsa-out`.
2. Open a **new chat** per phase and mention the role rule, e.g.
   `@lsa-stack-detector inputs in lsa-out/, target src/`.
3. For phases 3–4, one chat per batch file (`lsa-out/batches/*.json`).
4. Verifier: always a new chat, give it only the findings file.
5. In a terminal: `merge_findings.py`, `findings_to_sarif.py`, `render_report.py`,
   then `@lsa-reporter`.

Cursor runs one agent per chat, so this is slower than runtimes with
sub-agents, but the prompts and outputs are the same.

Note: the `.mdc` rule format (front matter `description`, `globs`,
`alwaysApply`) is Cursor's project-rules format at the time of writing.
If your Cursor version differs, copy the body of each file into a rule
manually.
