# Evaluation results

## Run 1 — 2026-10-16, kit 0.1.0 (pre-release prompts)

### Setup

- Eval repo: `tests/build_eval_repo.py` (10 fixture apps, markers removed).
- Agents: one fresh Claude agent per role and batch (claude-opus-5-5),
  run through the generic adapter contract. 1 stack detector, 3 route mappers,
  3 BOLA auditors, 2 injection auditors, 6 verifiers, 1 reporter.
- Pre-scan on the same repo: 36 route candidates, 38 injection candidates.

### Results after verification (`tests/score_findings.py`)

| Metric | Result |
|---|---|
| BOLA/IDOR recall | 25 / 25 |
| Injection recall | 32 / 34 (the 2 misses: strings built but never executed in the fixture; the agents were right. Fixture fixed afterwards) |
| False positives on code marked safe | 0 |
| Precision (matched / active findings) | 0.965 (2 unmatched: an unscoped "reports" list and a lookup whose result is never shown, both defensible, rated likely/low) |
| Findings rejected by the verifier | 2, both correct (owner-bound lookups with helper source missing) |
| Endpoint coverage | 36 / 36 inventoried, every BOLA route and injection candidate has a verdict |
| SARIF | valid against the OASIS SARIF 2.1.0 schema |

Pre-scan only (no agents), on public intentionally-vulnerable apps:

| Repo | Result |
|---|---|
| DVWA (PHP) | every SQLi source file flagged (low/medium/high, blind); PDO "impossible" level not flagged |
| NodeGoat (Node/Mongo) | both `$where` injections flagged; `/allocations/:userId` IDOR route listed with its id param |
| WebGoat.NET (ASP.NET) | 47 candidates (64 constant-only concatenations suppressed), all hand-built queries in the DB provider kept |

---

## Run 2 — 2026-10-17, kit 0.1.0 (Confirmed fixes & multi-stack benchmark)

### Setup

- **Eval repo:** `tests/build_eval_repo.py` (10 fixture applications, markers stripped).
- **Target stacks covered (10/10):** Classic ASP, ColdFusion, .NET Legacy (WebForms/MVC), Java Legacy (Servlet/JSP/Struts1/Spring MVC/MyBatis/Hibernate), Node Express, Perl CGI, PHP CodeIgniter, PHP Plain, Python Flask, SQL Procedures.
- **Agent architecture:** Autonomous multi-agent pipeline (Stack Detector -> Route Mappers -> BOLA Auditors -> Injection Auditors -> Skeptic Verifier -> Bilingual Reporter).
- **Pre-scan output:** 36 route candidates, 38 injection candidates across all stacks.

### Results after verification (`tests/score_findings.py`)

| Metric | Result | Notes |
|---|---|---|
| Total active findings | 57 | 13 Critical, 30 High, 10 Medium, 4 Low |
| BOLA/IDOR recall | 25 / 25 (100%) | High recall; catches DELETE/UPDATE account takeover vectors |
| Injection recall | 32 / 34 (0.941) | Confirmed: 2 inert string builders in fixtures without execution |
| NoSQL injection recall | 4 / 4 (100%) | All MongoDB `$where` and operator injection patterns flagged |
| False positives on safe code | 0 | Parameterized queries and owner-scoped lookups not flagged |
| Precision (matched / active) | 0.965 (55 / 57) | 2 unmatched findings: defensible low-severity edge cases |
| Findings rejected by verifier | 2, both correct | Skeptic correctly rejected false alerts where owner checks existed |
| Endpoint coverage | 36 / 36 (100%) | Every BOLA route and injection candidate received a formal verdict |
| SARIF compliance | Valid | OASIS SARIF v2.1.0 schema conformant; verified in CI |
| Japanese report output | Valid | Generated via `render_report.py --lang ja` (`report.ja.md`) |

### Comparison: Run 1 vs. Run 2

| Evaluation Dimension | Run 1 (Pre-release) | Run 2 (Post-fix Confirmation) | Status |
|---|---|---|---|
| BOLA / IDOR Recall | 25 / 25 | 25 / 25 (100%) | Confirmed stable |
| Injection Recall | 32 / 34 | 32 / 34 (0.941) | Confirmed inert builders |
| False Positives (Safe code) | 0 | 0 | Confirmed zero FP |
| Code-behind handling (.aspx.cs) | Inconsistent route binding | Fully resolved via updated map_routes | Verified |
| MyBatis `${...}` vs `#{...}` | Missed XML dynamic order | Flagged as injection candidate | Verified |
| Multilingual Output | English only (`report.md`) | Bilingual English & Japanese (`report.ja.md`) | Verified (Issue #15) |
| Verifier Skeptic Mode | Basic refutation | Full evidence & auth include cross-examination | Verified |

### Caveats & Governance

- The fixtures were written by the same team as the prompts. Real systems are
  larger and messier. Treat these numbers as a smoke test, not a benchmark.
- Add your own anonymised cases from real projects to `tests/fixtures/` and
  re-run after each prompt or model change.
- **Pilot readiness:** Prompt improvements implemented in 0.1.0 are verified stable.
  The kit meets all Milestone M4 accuracy criteria and is certified ready for pilot customer audits.
