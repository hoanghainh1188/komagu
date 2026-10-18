# Docs

Business and planning documents that sit around the LSA kit. They are **internal and confidential**: they contain business positioning and open decisions. Do not copy them into public repositories.

| Document | What it is | Status |
|---|---|---|
| [Modernization Boilerplates — Proposal](modernization-boilerplates-proposal.md) | Assessment-first modernization package for Japanese clients: context, offer, roadmap, business model, risks, decisions. Includes a client-facing summary. | Approved by BOD (2026-10-17) |
| [ADR-0001 — Name and repository structure](adr/0001-name-and-repository-structure.md) | Product name Komainu; repository organised by lifecycle (assess / remediate / operate) | Accepted; applied to assess/ and contracts/ |
| [ADR-0002 — IP Position: Open Core Model](adr/0002-ip-position-open-core.md) | Open Core boundary: assess/, contracts/, governance/ open; remediate/, operate/, delivery/, docs/ closed | Accepted (2026-10-17) |
| [ADR-0003 — WAF Engine Selection for D4](adr/0003-waf-engine-coraza.md) | OWASP Coraza WAF (pure Go, CRS v4, proxy-wasm / Kong sidecar) for D4 | Accepted (2026-10-17) |
| [ADR-0004 — B1 Design Review](adr/0004-b1-design-review-d1-threat-model-demo-app.md) | B1 design review: D1 public interface (.NET & Spring), request path threat model, D6 demo app scope | Accepted (2026-10-17) |
| [ADR-0005 — Effort Baseline & ROI Measurement Framework](adr/0005-effort-baseline-and-roi-measurement.md) | Dual-baseline measurement framework: IPA Japan standards + empirical D6 benchmark (75.7% savings); pilot tracking protocol | Accepted (2026-10-18); Closes #4 |
| [Boilerplate 1 — Secure API & IAM: Delivery Plan](boilerplate-1-delivery-plan.md) | 12-week plan: scope, architecture, deliverables D1–D6, timeline, roles, pilot, acceptance criteria, risks. | Updated v0.2; Milestone M1 Design Review approved |
| [Pitching Deck & Sales Enablement Kit](pitching-deck-sales-enablement-kit.md) | Comprehensive 12-slide pitch deck with speaker notes, 3-minute live demo script, executive one-pager, and Japanese enterprise FAQ. | Ready for BOD and client presentations |
| [Pilot: Client AI Processing Approval & Data Governance Protocol](pilot-client-ai-approval-consent.md) | AI code processing data governance, security guarantees (ZDR, no training), bilingual Japanese/English consent application form, and fallback system protocol for the AMS pilot. | Ready for client submission; Closes #5 |
| [Pilot: 4-Week Execution Runbook (Weeks 9–12)](pilot-execution-runbook.md) | Comprehensive step-by-step operational runbook for Weeks 9–12: kickoff, consent gate, LSA audit, Person B sign-off, Kong WAF, D1-D3 fixes, D5 CI, and ROI measurement. | Ready for execution; Closes #75 |
| [Developer Community Articles (Qiita & Zenn)](articles/README.md) | Japanese developer community articles: published Qiita hands-on quickstart and Zenn technical architecture deep-dive for `komainu-guard`. | Published & active; Closes #73 |

## How these files are maintained

- The working copies were drafted as collaborative docs on claude.ai. These Markdown files are exports from 2026-10-16.
- From now on, **this repository is the source of truth**. Change the Markdown here through pull requests, and bump the version history table at the end of each document.
- Diagrams in `images/` are PNG renders of the original diagrams. To change one, edit the picture in the source doc and re-export, or replace it with a Mermaid block.
- Sources cited in the documents were opened on 2026-10-16. Re-check them before any external use (see the Risks section of the proposal).
