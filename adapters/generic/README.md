# Adapter — Any LLM API

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
