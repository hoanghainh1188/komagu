# Contracts

Shared data formats that join assess, remediate and operate.

| File | Used for |
|---|---|
| `schemas/stack-profile.schema.json` | Detected stack and auth model summary (LSA phase 1–2) |
| `schemas/route-inventory.schema.json` | Endpoint inventory (LSA phase 3) |
| `schemas/finding.schema.json` | Findings from any assessment tool |
| `schemas/verification.schema.json` | Verifier verdicts on findings |
| `schemas/persona-suite.schema.json` | `komainu test` suite v2: personas, allowed personas per route, mass assignment probes |

`assess/lsa/scripts/merge_findings.py` validates against these files, and
`assess/lsa/adapters/build_adapters.py` copies them into generated bundles as
`schemas/`. Changing a schema means updating the LSA role prompts, merge,
SARIF and report scripts in the same change.
