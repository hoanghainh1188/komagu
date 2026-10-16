# Adapter — OpenHands (and the company platform)

OpenHands can run each LSA role as a task with a custom prompt. Use the
**generic** adapter:

```bash
python3 adapters/build_adapters.py generic ./lsa-generic
```

- `lsa-generic/system-prompts/<role>.md` — full system prompt per role
  (shared rules + role).
- `lsa-generic/contract.json` — machine-readable pipeline: phases, inputs,
  outputs, required tools, which role needs a fresh context.
- `lsa-generic/kit/` — knowledge, schemas, scripts.

Suggested mapping:

| LSA concept | OpenHands |
|---|---|
| role system prompt | task instruction / repository microagent content |
| batch | one conversation (task) per batch |
| fresh context (verifier) | new conversation |
| read-only target | mount the repository read-only in the sandbox |

The folder and front-matter format for OpenHands repository customisation
has changed between versions. Check the OpenHands documentation of the
version you deploy before copying prompts into its customisation folder.

For the company platform, drive the pipeline from `contract.json`: run the
script phases, and for each agent phase send `system-prompts/<role>.md` as the
system prompt plus the batch file and file-read tools. Validate outputs with
`kit/scripts/merge_findings.py`.
