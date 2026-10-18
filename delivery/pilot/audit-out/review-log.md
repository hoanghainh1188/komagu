# Human Review Log — Komainu Pilot (D6 Member Portal) — 2026-10-18

Audit run by (Person A): AI Auditor (Komainu LSA Kit v0.2.1)  
Reviewer (Person B, must not be Person A): Harry Nguyen  
Kit version: 0.2.1   Model(s) used: Gemini 2.5 Pro / Flash   LLM hosting: Google Cloud Vertex AI / Gemini API  

## Decisions

| Finding ID | AI verdict | Reviewer decision (accept / reject / change severity) | Final severity | Comment | Date |
|---|---|---|---|---|---|
| BOLA-R-0005-1 | confirmed | accept | critical | Confirmed missing ownership check on PUT /api/v1/test/legacy-orders/{id} in .NET LegacyTestController.cs:47 | 2026-10-18 |
| BOLA-R-0006-1 | confirmed | accept | critical | Confirmed missing ownership check on DELETE /api/v1/test/legacy-orders/{id} in .NET LegacyTestController.cs:69 | 2026-10-18 |
| BOLA-R-0022-1 | confirmed | accept | critical | Confirmed missing ownership check on PUT /api/v1/test/legacy-orders/{id} in Spring Controllers.kt:185 | 2026-10-18 |
| BOLA-R-0023-1 | confirmed | accept | critical | Confirmed missing ownership check on DELETE /api/v1/test/legacy-orders/{id} in Spring Controllers.kt:205 | 2026-10-18 |
| INJ-I-0001-1 | confirmed | accept | critical | Confirmed unparameterized raw SQL string interpolation in .NET LegacyTestController.cs:98 | 2026-10-18 |
| INJ-I-0002-1 | confirmed | accept | critical | Confirmed unparameterized native SQL string interpolation in Spring Controllers.kt:226 | 2026-10-18 |
| BOLA-R-0004-1 | confirmed | accept | high | Confirmed unauthenticated cross-tenant GET in .NET LegacyTestController.cs:28 | 2026-10-18 |
| BOLA-R-0021-1 | confirmed | accept | high | Confirmed unauthenticated cross-tenant GET in Spring Controllers.kt:172 | 2026-10-18 |

## Coverage sign-off

- [x] Endpoints inventoried vs. pre-scan candidates checked (no unexplained gaps, 24/24 inventoried)
- [x] All `needs_review` items assigned to a person (0 items)
- [x] Out-of-scope notes forwarded to the right owner (0 notes)
- [x] Report reviewed for secrets / personal data before sharing
- [x] Customer approval obtained before sending the report outside the company

Signature (Person B): Harry Nguyen  Date: 2026-10-18
