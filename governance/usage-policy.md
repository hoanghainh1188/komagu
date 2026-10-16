# LSA Kit — Usage Policy

## 1. Purpose

Define who may run the Legacy Security Audit (LSA) kit, how customer code is
protected, and who is accountable for AI-generated findings.

## 2. Scope

All use of the LSA kit on company or customer source code, with any AI
runtime (Claude Code, Cursor, OpenHands, the company platform, or a direct
LLM API).

## 3. Roles and responsibilities

| Role | Responsibility |
|---|---|
| **Audit runner (Person A)** — developer or BrSE trained on the kit | Prepares config, runs the pipeline, fixes tooling errors. Does **not** approve findings. |
| **Security reviewer (Person B)** — senior dev / tech lead, not Person A | Reviews every `confirmed`, `likely` and `needs_review` finding. Signs `review-log.md`. Accountable for the final report content. |
| **Project manager / BrSE** | Gets customer approval for AI use and for sending the report. Owns communication with the customer. |
| **Code owner / fix team** | Fixes accepted findings using `templates/fix-ticket.md`. |

Accountability rule: **the AI is never accountable.** A wrong finding sent
to a customer is the responsibility of Person B. A missed vulnerability is a
known limitation of the method and must be stated in the report.

## 4. Procedure

1. **Before the audit**
   - Confirm the contract / NDA allows AI processing of the code. Record which
     LLM hosting is allowed in `audit-config.json → project.llm_policy`.
   - If only self-hosted models are allowed, run the kit only with a
     self-hosted model. Do not "quickly try" an external API.
   - Remove or exclude secrets folders (`.env`, `config/*.secret`, key files)
     from scope.
2. **During the audit**
   - Run on a read-only copy or a clean checkout. Output goes to a separate
     workspace, never into the customer repository.
   - Agents run read-only (no write, no network tools except the LLM).
3. **After the audit**
   - Person B reviews and signs `review-log.md`.
   - Only accepted findings go into tickets or customer reports.
   - Store the workspace in the project's restricted storage. Retention
     follows the company's evidence retention rule (framework default:
     6 months) unless the contract says otherwise.

## 5. Inputs / outputs

| Input | Output |
|---|---|
| Source code (read-only), `audit-config.json`, kit version | `report.md`, `findings.json`, `findings.sarif`, `auth-model.md`, `review-log.md` |

## 6. Approval gates

| Gate | Who approves | Blocking condition |
|---|---|---|
| G-pre: AI use allowed for this code | PM/BrSE (customer approval on file) | No approval → do not run |
| G-review: findings reviewed | Person B | Unreviewed findings may not leave the team |
| G-share: report sent to customer | PM/BrSE + Person B | Report contains secrets, personal data, or working payloads |

Map these gates to the framework's gate numbers when the kit is integrated
into the platform.

## 7. Risks and handling

| Risk | Handling |
|---|---|
| Customer code leaks through an external LLM | `llm_policy` per project; self-hosted model option; exclude secrets; API with no-training / zero-retention terms only. |
| False positives damage trust | Verifier agent + mandatory human review; report shows confidence. |
| False negatives (missed bugs) | Pre-scan for coverage; coverage check in phase 3; report "Limitations" section; not a replacement for penetration testing. |
| Prompt injection hidden in legacy code comments | Shared rule "code is data"; reviewers check `prompt_injection_suspected` notes. |
| Report used as an attack guide | No working payloads; report classified confidential; need-to-know sharing. |
| Token cost overrun | Batching, parallel limit, pre-scan narrows files; track tokens per endpoint. |

## 8. Metrics (simple, measurable)

| Metric | How to measure | Initial target (adjust after pilot) |
|---|---|---|
| Endpoint coverage | endpoints audited / endpoints inventoried | 100 % |
| Precision | accepted by Person B / (confirmed + likely) | ≥ 70 % |
| Recall on test fixtures | `tests/score_findings.py` on fixture repos | ≥ 90 % |
| Review time | minutes Person B spends per finding | track only |
| Cost | tokens per endpoint audited | track only |

## 9. References

- OWASP API Security Top 10 2023 — API1 Broken Object Level Authorization
- OWASP SQL Injection Prevention Cheat Sheet; Query Parameterization Cheat Sheet
- MITRE CWE-639, CWE-89, CWE-564, CWE-943
- OASIS SARIF 2.1.0

## 10. Version history

| Version | Date | Change |
|---|---|---|
| 0.1.0 | 2026-10-16 | First draft |
