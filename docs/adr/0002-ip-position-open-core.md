# ADR-0002: IP Position — Adopt Open Core Model and Draw the Open/Closed Boundary

Date: 2026-10-17 · Status: accepted · Owner: Harry (BOD)

## Context

The proposal (`docs/modernization-boilerplates-proposal.md`) and delivery plan
(`docs/boilerplate-1-delivery-plan.md`) raised the question of Intellectual Property (IP)
strategy before publishing any code or delivering to clients:
- Option A: Open Source (MIT) — builds maximum public credibility and developer trust,
  but allows competitors to reuse the modernization assets without attribution or fees.
- Option B: Closed IP — protects proprietary assets, but prevents prospective clients
  from inspecting code, creating sales friction with security-minded enterprise buyers.
- Option C: Open Core (recommended) — standardizes assessment tools and core interfaces
  in the open, while preserving commercial remediations, proprietary rules, and client delivery
  know-how as internal IP.

ADR-0001 noted that the open/closed decision was deferred and that confidential strategy
materials (`docs/`) must not be exposed if the repository is made public.

## Decision

We adopt **Option C: Open Core** as the official intellectual property strategy for Komainu.

### 1. Open / Closed Boundary Definition

| Lifecycle Component | Scope & Status | Distribution & Licensing |
|---|---|---|
| `assess/lsa/` | **Open** | Public repository under Apache 2.0 / MIT. Includes pre-scan scripts, evaluation fixtures, schema adapters, and runtime-neutral prompt templates. |
| `contracts/` | **Open** | Public schemas (stack profile, route inventory, finding, verification) to encourage ecosystem interoperability. |
| `governance/` | **Open** | Public usage policies, data privacy standards, and review-gate frameworks. |
| `remediate/` (Core interfaces) | **Open** | Public authorization abstraction layer (core interfaces, declarative attributes, policy annotations). |
| `remediate/` (Implementations) | **Closed** | Proprietary to paying clients. Includes legacy adapter implementations, automated fix generators, and enterprise IdP connectors. |
| `operate/` (Advanced rules) | **Closed** | Proprietary CI/CD pipelines, commercial threat detection feeds, and custom enterprise compliance rule sets. |
| `delivery/` | **Closed** | Internal client playbooks, Japanese report generation templates, ticket automation, and pilot performance metrics. |
| `docs/` | **Closed / Confidential** | Internal business proposals, pricing models, revenue projections, and operational delivery plans. |

### 2. Repository Visibility & Release Strategy

1. **Private during Stage 1 MVP:** The current repository (`hoanghainh1188/komagu`) remains **Private**
   throughout the development of Boilerplate 1 (Weeks 1–8) and the pilot run (Weeks 9–12).
2. **Public release split at M3 / v0.1:** When ready for external publication:
   - The public repository (`komainu`) will contain the Open Core elements (`assess/`, `contracts/`, `governance/`, public examples).
   - Confidential documents (`docs/modernization-boilerplates-proposal.md`, `docs/boilerplate-1-delivery-plan.md`) and commercial delivery assets (`delivery/`, closed fix modules) will be maintained in a separate private repository or internal team workspace.

## Consequences

- **Commercial viability:** Preserves high-margin professional service and licensing revenue while providing open verification tools that eliminate customer skepticism.
- **Clear developer guidance:** Engineering contributors know exactly which modules can be shared openly and which must remain proprietary.
- **Repository hygiene:** Confidential documentation in `docs/` is explicitly tagged as internal and will not be accidentally exposed in public channels.
