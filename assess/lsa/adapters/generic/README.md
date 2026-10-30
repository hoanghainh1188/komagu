# Adapter — Any LLM API

Generate the bundle into its own folder:

```
komagu init --ai generic ./lsa-bundle
# or: python3 assess/lsa/adapters/build_adapters.py generic ./lsa-bundle
```

It writes `system-prompts/`, `kit/` and `contract.json` into that folder.
The contract carries `"generator": "komainu-lsa"`. Re-running refreshes a
bundle that has this marker. The generator refuses, before writing anything,
when the folder has a `contract.json` without the marker, or a `kit/` or
`system-prompts/` folder but no `contract.json`. This keeps a project's own
files safe. A bundle generated before the marker existed is refused too:
delete its `contract.json` (or the whole folder) and generate it again.

Minimum the runtime must provide to an agent role:

| Capability | Why |
|---|---|
| Read file (with line numbers), list directory, search text | Trace code. |
| Write file into OUT only (or return JSON in the reply) | Hand outputs to the next phase. |
| 64k+ token context recommended | Batches of ~15 endpoints with their files. |

Loop per agent phase:

```
for batch in OUT/batches/<kind>-*.json:
    system = read("system-prompts/<role>.md")
    user   = "TARGET=..., OUT=..., batch file: <path>, auth model: OUT/auth-model.md"
    run agent with tools until it writes OUT/<output path>
python3 kit/scripts/merge_findings.py OUT     # validates JSON, checks coverage
```

Retry a batch when `merge_findings.py` reports invalid JSON or missing
verdicts for it. Do not edit agent output by hand.

Budget control: `batch.max_endpoints`, `batch.max_injection_candidates`,
`parallel.max_agents` in `audit-config.json`. Log tokens per batch to
compute "tokens per endpoint" (see governance metrics).
