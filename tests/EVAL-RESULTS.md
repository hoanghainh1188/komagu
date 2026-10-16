# Evaluation results

## Run 1 — 2026-10-16, kit 0.1.0 (pre-release prompts)

Setup

- Eval repo: `tests/build_eval_repo.py` (10 fixture apps, markers removed).
- Agents: one fresh Claude agent per role and batch (claude-opus-5-5),
  run through the generic adapter contract. 1 stack detector, 3 route mappers,
  3 BOLA auditors, 2 injection auditors, 6 verifiers, 1 reporter.
- Pre-scan on the same repo: 36 route candidates, 38 injection candidates.

Results after verification (`tests/score_findings.py`)

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

Caveats

- The fixtures were written by the same team as the prompts. Real systems are
  larger and messier. Treat these numbers as a smoke test, not a benchmark.
- Add your own anonymised cases from real projects to `tests/fixtures/` and
  re-run after each prompt or model change.
- Prompt problems reported by the agents in this run were fixed in 0.1.0
  (see CHANGELOG). A second run is needed to confirm the fixes.
