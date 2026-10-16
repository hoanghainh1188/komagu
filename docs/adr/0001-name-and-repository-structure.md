# ADR-0001: Name the product Komainu and structure the repository by lifecycle

Date: 2026-10-16 · Status: accepted; structure applied 2026-10-16 (assess/lsa, contracts) · Owner: Harry

## Context

This repository started as the LSA kit (legacy security audit for BOLA/IDOR and
string-built queries). The [proposal](../modernization-boilerplates-proposal.md)
builds a long-term offer around it: assess a client's system, fix what is found,
and keep it fixed. Calling the repository `lsa-kit`, or organising it around
"boilerplates", describes only one tool or one delivery form.

## Decision

### Name: Komainu (狛犬)

Komainu are the paired guardian lion-dogs at the gate of a Shinto shrine. They
always stand as an **a–un (阿吽)** pair: one with an open mouth, one with a
closed mouth. The name fits the product in two ways:

- **The lifecycle:** *assess* (open mouth: say what is wrong) and
  *remediate / operate* (closed mouth: close the gap and keep it closed).
- **The two-person rule** in `governance/usage-policy.md`: the person who runs
  an audit never approves it, just as a shrine gate always has two guardians.

The repository will be renamed `komainu`. "LSA" stays as the name of the
assessment tool inside it.

### Structure: by lifecycle, joined by shared contracts

```text
contracts/    shared finding schema, CWE/severity taxonomy, category → fix module → verification test
assess/       find problems           (assess/lsa = the current LSA kit)
remediate/    reusable security modules (authz, edge, ekyc, resilience, tenancy)
operate/      keep problems from returning (CI templates, continuous scanning)
delivery/     playbooks, Japanese report templates, tickets, pilot metrics
examples/     demo and before/after sample systems
governance/   AI usage, approvals, client data handling
docs/         strategy/ (confidential) and adr/
```

Modules are named by capability (`authz`), not by offer number (`b1`), because
one capability can serve several offers. A folder is created only when its work
starts and its gate in the proposal has passed.

## Consequences

- Moving the kit to `assess/lsa/` changes paths in README, AGENTS.md, CLAUDE.md,
  `prompts/00-orchestrator.md` and the adapters; `tests/run_tests.py` must pass
  after the move.
- Schemas move from the kit to `contracts/`; new tools and modules must follow them.
- The open / closed / open-core decision is still open. Closed parts (client
  configs, assessment know-how) must not live here if this repository becomes public,
  and `docs/strategy/` must then be split out.
- "Komainu" is a common noun; exclusive trademark registration is unlikely.
  GitHub name, domain and Japanese trademark (J-PlatPat) checks are not done yet
  and need legal review before external use.
