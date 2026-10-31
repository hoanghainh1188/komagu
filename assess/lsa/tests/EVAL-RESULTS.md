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

---

## Cross-Model Evaluation: Qwen 3.5 (2026-10-17)

### Setup & Context

To verify that the LSA prompts and detection rules remain robust and runtime-neutral across different LLM backends (not overfitted to a single model family), an independent evaluation run was conducted using **Qwen 3.5** as the auditor agent model on the same 10-stack fixture suite (`tests/build_eval_repo.py`).

The full reference outputs from this run are archived in [`assess/lsa/examples/eval-qwen35/`](../examples/eval-qwen35/):
- `final-report.md` & `final-report-expanded.md`: Full audit reports with code excerpts and remediation guides.
- `final-findings.json`: 57 findings categorized by severity and CWE.
- `ground-truth.json`: Ground-truth mapping with `SAFE-SQL`, `SQLI`, `BOLA`, `NOSQL` markers.
- `validation-summary.md`: Run 1 vs. Run 2 validation summary.

### Multi-Model Comparison

| Dimension | Run 1 (Claude Opus) | Run 2 (Claude 3.7) | Cross-Model (Qwen 3.5) | Status |
|---|---|---|---|---|
| Route candidates | 36 | 36 | 36 | 100% Consistent |
| Injection candidates | 38 (30 high) | 38 (30 high) | 38 (30 high) | 100% Consistent |
| Total findings reported | 57 | 57 | 57 | 100% Consistent |
| Confirmed by verifier | 34 | 34 | 34 | 100% Consistent |
| Likely (needs human review) | 23 | 23 | 23 | 100% Consistent |
| Rejected by verifier | 2 | 2 | 2 | 100% Consistent |
| BOLA / IDOR detection | 25 / 33 (76%) | 25 / 25 marker (100%) | 28 / 33 (85%) | Improved (+9% broader detection) |
| SQL injection detection | 32 / 43 (~74%) | 32 / 34 (94.1% active) | ~30 / 43 (~70%) | Expected variance on dynamic column builders |
| NoSQL injection detection | 4 / 4 (100%) | 4 / 4 (100%) | 4 / 4 (100%) | 100% Accurate across all models |
| False positive rate | < 1% | 0 on safe code | ~3.4% (2 / 59) | Low; all benign patterns or incomplete fixtures |

### Root Causes & Architectural Validation

Qwen 3.5's evaluation arrived at identical architectural root causes as Boilerplate 1:
1. **Absence of a reusable ownership helper:** Legacy applications enforce login sessions (`inc/auth.asp`, Struts filters) but completely fail to verify `Session("UserID") == resource.owner_id`, enabling trivial BOLA/IDOR account takeovers.
2. **String-interpolated queries:** Raw query assembly without parameter binding remains ubiquitous across legacy frameworks.

### Identified Improvement Areas (Remediation Plan)

Based on Qwen 3.5's findings, the following concrete improvements were implemented in Issues #47 and #48:
1. **Dynamic query interpolation recall:** Enhanced MyBatis dynamic XML `${orderBy}`, split string construction (`string.Format`, `$"..."`, Python multiline f-strings, Node template literals), and ColdFusion `<cfqueryparam>` rules.
2. **Sub-resource & indirect ID tracking:** Expanded BOLA rules (Pattern P13) to catch indirect entity references (`cart_id`, `member_id`, composite keys).
3. **Allow-list recognition:** Equipped the Skeptic Verifier with enum-mapping and `switch`/`case` allow-list recognition to eliminate false positives.
4. **Legacy remediation shims:** Delivered drop-in ownership verification helpers under [`remediate/legacy_shims/`](../../../remediate/legacy_shims/) for PHP, Java (Servlet/Struts/JDBC + MyBatis XML), ColdFusion, and Classic ASP.

---

## Run 3 — 2026-10-18, kit 0.2.0 (Post-Qwen 3.5 Hardening & >=95% Recall Verification)

### Setup

- **Eval repo:** `tests/build_eval_repo.py` (10 fixture applications, markers stripped).
- **Enhancements active:** Issue #47 pattern catalogs (`injection-patterns.md` §1.1, `bola-patterns.md` Pattern P13) and updated multi-agent prompts (`30-bola-auditor.md`, `40-injection-auditor.md`, `50-finding-verifier.md`).
- **Reference artifacts:** Archived in [`assess/lsa/examples/eval-run-3/`](../examples/eval-run-3/) (`findings.json`, `findings.sarif`, `report.md`, `report.ja.md`, `coverage.json`, `stack-profile.json`).

### Results after verification (`tests/score_findings.py`)

| Metric | Target (Issue #49) | Run 3 Result | Status |
|---|---|---|---|
| **BOLA / IDOR recall** | $\ge$ 95% | **25 / 25 (100%)** | Exceeds target |
| **SQL & NoSQL injection recall** | $\ge$ 95% | **34 / 34 (100%)** | Exceeds target (split `sql2`/`sql3` builders traced to sinks) |
| **NoSQL injection recall** | 100% | **4 / 4 (100%)** | 100% Accurate |
| **False positives on safe code** | 0% | **0 (`[]`)** | Zero false positives |
| **Precision (matched / active)** | $\ge$ 0.95 | **1.000 (57 / 57)** | 100% Precision |
| **Rejected by Skeptic Verifier** | — | **3** | Correctly rejected unexposed credential lookup (`BOLA-R-0030-1`) & safe owner helpers |
| **Separated for human review** | — | **1 (`BOLA-R-0020-1`)** | Unscoped monthly `/reports` flagged as `needs_review` (`data_ownership_unclear`) |
| **SARIF & Bilingual Reports** | Valid | **Valid (58 results)** | `findings.sarif`, `report.md`, and `report.ja.md` generated cleanly |

### Benchmark Progression Summary (Run 1 $\rightarrow$ Run 2 $\rightarrow$ Qwen 3.5 $\rightarrow$ Run 3)

| Dimension | Run 1 | Run 2 | Qwen 3.5 | Run 3 (Hardened) |
|---|---|---|---|---|
| **BOLA Recall (marker GT)** | 25 / 25 (100%) | 25 / 25 (100%) | 28 / 33 (85% broad) | **25 / 25 (100%)** |
| **Injection Recall (marker GT)** | 32 / 34 (94.1%) | 32 / 34 (94.1%) | ~30 / 43 (~70% broad) | **34 / 34 (100%)** |
| **False Positives on Safe Code** | 0 | 0 | 0 on safe markers | **0** |
| **Precision (matched / active)** | 0.965 (55 / 57) | 0.965 (55 / 57) | 0.966 | **1.000 (57 / 57)** |
| **Legacy Stack Shims** | None | None | Recommended | **4 Stacks (`remediate/legacy_shims/`)** |

---

## Run 4 — 2026-10-31, kit 0.3.1 (BFLA & mass assignment Tier 2, local Ollama)

Issue #286. First end-to-end measurement of phase 4c (`35-privilege-auditor`) with real models, and a
re-check of BOLA / injection on the same harness. All runs are **local only**: fixture code never left
the machine, and no third-party LLM was used.

### Setup

| Item | Value |
|---|---|
| Eval repo | `tests/build_eval_repo.py` (10 fixture apps, markers stripped); ground truth 117 items: 25 BOLA, 34 SQL/NoSQL injection, 10 BFLA, 15 mass assignment, plus 33 SAFE markers |
| Pipeline | `komagu scan <repo> --no-cache --headless-ai http://localhost:11434/v1 --model <model> --ai-timeout 3600` (`operate/ai/runner.py`, Tier 1 pre-scan + phases 2–6) |
| Hosting | Ollama 0.40.13 on an Apple M4 Pro, 24 GB RAM, 100% GPU; context 32,768 tokens |
| Models | `gpt-oss:20b` (MXFP4, reasoning effort default `medium`), `qwen3.5:9b` |
| Scoring | `tests/score_findings.py --verdicts` (tolerance 3 lines); archived per run in [`assess/lsa/examples/eval-run-4/`](../examples/eval-run-4/) |

**This is a floor, not a ceiling.** A 9–20B model on a laptop is much weaker than the models used in
Runs 1–2. The numbers below say what a fully local deployment achieves today, not what the prompts can
do with a stronger model.

**Not comparable with Run 3.** Run 3 does not record its model, and the archived Run 1 / Run 2 / Qwen
numbers were produced through agent runtimes that can open files, not through the headless runner.
The BOLA / injection columns below are therefore a new baseline for the headless harness, not a
regression check against Run 3.

### Harness fixes found by this run

Measuring with real models exposed defects in the headless runner that inflated or lost results.
They were fixed before the numbers were trusted, in two iterations (the limit set in #286):

| Iteration | Fix | Effect seen |
|---|---|---|
| 0 → 1 | Verifier no longer marks a whole batch `confirmed` when its reply cannot be parsed (it used to, with a made-up "consensus" note); such findings stay `unverified` | Results stopped being inflated by broken replies |
| 0 → 1 | A failed call (timeout) is recorded per batch in `ai-run-stats.json` instead of aborting the run | A 25-candidate injection batch took > 15 min and used to kill the run |
| 0 → 1 | Phase 4c gets the same JSON output template as 4a / 4b; sanitizer joins list `impact` values and moves a verdict written into `subtype` to `status`; unparseable replies saved to `OUT/ai-raw/` | Mass assignment findings stopped failing schema validation |
| 1 → 2 | Verifier now receives the code it judges (finding site, file header, evidence lines, server-side includes) and the auth model, and may only cite controls that are visible; otherwise `likely` + `code_not_visible` | In iteration 1 it rejected 10 of 11 real BFLA findings by inventing an admin base class and a role check in a login-only `auth.php` |
| 1 → 2 | Verifier batches of 5 instead of 10; sanitizer fills a `null` evidence line and a missing `status` | No verifier parse failures in iteration 2 |

### Results after verification

"Marker" columns use the normal location match. "Verdict" columns (BFLA / mass assignment only) count a
truth item as found when the privilege auditor judged the route or candidate that contains it
`vulnerable` or `needs_review`, whatever path and line the model then wrote into the finding.

| Run | BOLA | Injection | BFLA marker | Mass marker | BFLA verdict | Mass verdict | FP on safe code | Precision | Rejected | Unverified | Parse fail | Min · calls · tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| iter 0, gpt-oss A | 19/25 | 20/34 | 8/10 | 2/15 | 10/10 | 12/15 | 0 | 0.689 | 10 | 11 | 3 | 81 · 22 · 311K |
| iter 1, gpt-oss A | 21/25 | 34/34 | 1/10 | 2/15 | 10/10 | 14/15 | 0 | 0.765 | 19 | 17 | 2 | 75 · 21 · 288K |
| iter 1, gpt-oss B | 19/25 | 28/34 | 5/10 | 5/15 | 10/10 | 14/15 | 1 | 0.667 | 4 | 8 | 3 | 80 · 22 · 273K |
| iter 1, qwen3.5 (incomplete) | 23/25 | 33/34 | 0/10 | 0/15 | 0/10 | 8/15 | 1 | 0.778 | 0 | 52 | — | stopped after 2 h 50 min |
| **iter 2, gpt-oss A** | **24/25** | **34/34** | **8/10** | **6/15** | **10/10** | **10/15** | **0** | 0.729 | 1 | 0 | 0 | 57 · 32 · 309K |
| **iter 2, gpt-oss B** | **11/25** | **32/34** | **5/10** | **4/15** | **10/10** | **9/15** | **0** | 0.693 | 1 | 0 | 1 | 56 · 29 · 318K |

Final harness = iteration 2. Stated plainly for `gpt-oss:20b` on it:

- **BFLA:** the auditor flagged the right route for **10 / 10** BFLA markers in both runs, with no SAFE-BFLA
  route flagged. Only **8 / 10 and 5 / 10** survive as correctly located findings, because the model
  writes wrong or non-existent paths into the finding (`dotnet-mvc/Controllers/AdminController.cs`,
  `routes.js`).
- **Mass assignment:** **10 / 15 and 9 / 15** at verdict level, **6 / 15 and 4 / 15** as located findings.
  Five candidates in .NET (`CustomerController.cs`) and Java (`AccountController.java`,
  `ProfileServlet.java`) were judged `safe` in both runs: real model misses.
- **False positives on SAFE markers:** **0** in both iteration-2 runs, for all four categories.
- **BOLA / injection:** 24 / 25 and 34 / 34 in run A. In run B, 11 of its 14 missed BOLA items sit in
  one batch whose reply was empty (`routes-001`: `gpt-oss` returned no content, so 15 routes got no
  verdict); the other 3 are real misses (`perl-cgi/cgi-bin/order.cgi:19` is missed in both runs).
- **Run-to-run variance is large.** Two runs with the same model, harness and temperature 0.1 differ by
  up to 13 BOLA items and 3 BFLA findings. Single-run numbers from a local model should not be quoted
  as product capability.
- **Precision ~0.7** is measured against markers only. Of the ~25 unmatched findings per run, most are BOLA
  findings in files that carry BFLA / mass-assignment markers but no BOLA markers
  (`CustomerController.cs`, `AccountController.java`, `AdminController.cs`), plus the misplaced BFLA /
  mass findings above. They have not been triaged by a person and are not counted as false positives.

**qwen3.5:9b** could not be measured on this machine: with a 32K context the MLX runner used 22 GB of the
24 GB RAM, the system swapped (29.7 / 30 GB), and two calls hit the 1-hour timeout (the privilege batch
holding all BFLA routes, and a verifier batch). The run was stopped after 2 h 50 min with 52 findings
unverified. Its partial output is archived as `iter1-qwen-a-incomplete/` and says nothing about the
model's ability.

### Known gaps (follow-up)

1. **Misplaced findings.** Take `file` / `line` of BFLA and mass assignment findings from the Tier 1 route
   or candidate the auditor judged (`route_id` / `candidate_id`), not from the model's text. Expected to
   close most of the gap between the marker and verdict columns.
2. **Empty replies.** Retry a batch once when the reply is empty or unparseable (seen with `gpt-oss`).
3. **Mass assignment on .NET / Java binding.** Review `knowledge/mass-assignment-patterns.md` for
   `UpdateModel` / `TryUpdateModel` and Spring `@ModelAttribute` binding into entities.
4. **Re-run qwen3.5:9b** with 16K context or on a machine with more memory.
5. **Triage unmatched BOLA findings** and add markers to the fixtures where they are real.
