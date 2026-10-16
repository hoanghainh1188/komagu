# Komainu (狛犬)

Security-first modernization for legacy systems: **assess** what is wrong,
**remediate** it with reusable modules, and **operate** so it stays fixed.
The name and structure are explained in
[ADR-0001](docs/adr/0001-name-and-repository-structure.md).

| Path | Content | Status |
|---|---|---|
| [`assess/lsa/`](assess/lsa/README.md) | LSA — AI-assisted audit for BOLA/IDOR and string-built SQL/NoSQL queries | v0.1, usable |
| [`contracts/`](contracts/README.md) | Shared JSON Schemas (stack profile, route inventory, finding, verification) | v0.1 |
| [`governance/`](governance/usage-policy.md) | Usage policy: roles, data protection, approval gates, metrics | v0.1 |
| [`docs/`](docs/README.md) | Strategy documents (confidential) and ADRs | — |
| `remediate/`, `operate/`, `delivery/`, `examples/` | Created when their work starts (see ADR-0001) | not started |

## Quick start

```bash
python3 assess/lsa/tests/run_tests.py     # self-test of the assessment kit
```

See [`assess/lsa/README.md`](assess/lsa/README.md) for running an audit.
