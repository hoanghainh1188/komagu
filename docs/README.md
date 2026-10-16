# Docs

Business and planning documents that sit around the LSA kit. They are **internal and confidential**: they contain business positioning and open decisions. Do not copy them into public repositories.

| Document | What it is | Status |
|---|---|---|
| [Modernization Boilerplates — Proposal](modernization-boilerplates-proposal.md) | Assessment-first modernization package for Japanese clients: context, offer, roadmap, business model, risks, decisions. Includes a client-facing summary. | Draft v0.1, not yet approved |
| [ADR-0001 — Name and repository structure](adr/0001-name-and-repository-structure.md) | Product name Komainu; repository organised by lifecycle (assess / remediate / operate) | Accepted; applied to assess/ and contracts/ |
| [Boilerplate 1 — Secure API & IAM: Delivery Plan](boilerplate-1-delivery-plan.md) | 12-week plan: scope, architecture, deliverables D1–D6, timeline, roles, pilot, acceptance criteria, risks. | Draft v0.1; 3 open questions deferred |

## How these files are maintained

- The working copies were drafted as collaborative docs on claude.ai. These Markdown files are exports from 2026-10-16.
- From now on, **this repository is the source of truth**. Change the Markdown here through pull requests, and bump the version history table at the end of each document.
- Diagrams in `images/` are PNG renders of the original diagrams. To change one, edit the picture in the source doc and re-export, or replace it with a Mermaid block.
- Sources cited in the documents were opened on 2026-10-16. Re-check them before any external use (see the Risks section of the proposal).
