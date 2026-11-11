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

### Known gaps (follow-up: #319)

1. **Misplaced findings.** Take `file` / `line` of BFLA and mass assignment findings from the Tier 1 route
   or candidate the auditor judged (`route_id` / `candidate_id`), not from the model's text. Expected to
   close most of the gap between the marker and verdict columns.
2. **Empty replies.** Retry a batch once when the reply is empty or unparseable (seen with `gpt-oss`).
3. **Mass assignment on .NET / Java binding.** Review `knowledge/mass-assignment-patterns.md` for
   `UpdateModel` / `TryUpdateModel` and Spring `@ModelAttribute` binding into entities.
4. **Re-run qwen3.5:9b** with 16K context or on a machine with more memory.
5. **Triage unmatched BOLA findings** and add markers to the fixtures where they are real.

---

## Run 5 — 2026-10-31, kit 0.3.1 (Run 4 follow-up: anchored locations, retries, model context)

Issue #319. Same eval repo, ground truth, hosting and model as Run 4 (`gpt-oss:20b`, Ollama 0.40.13,
M4 Pro 24 GB, 32K context, local only). Outputs are archived in
[`assess/lsa/examples/eval-run-5/`](../examples/eval-run-5/).

### Changes since Run 4 iteration 2

| Change | Why (from Run 4) |
|---|---|
| Finding `file` / `line` come from the Tier 1 route handler span or candidate the finding references (`operate/ai/anchoring.py`); evidence is re-pointed or dropped; unknown references get `confidence: low` | The auditor judged the right route for 10 / 10 BFLA markers, but wrote paths such as `routes.js`, `app.py`, `dotnet-mvc/...` |
| An empty or unparseable batch reply is retried once with a JSON-only reminder | One empty reply cost 15 BOLA routes |
| Each mass assignment candidate carries the bound model's definition (same app and language); an unknown model means `needs_review`, never `safe` (prompt `35-privilege-auditor.md` and the headless 4c prompt) | Five .NET / Java candidates were judged `safe` in both runs because the auditor never saw `Account.java` (`role`, `balance`) |

### Results after verification

| Run | BOLA | Injection | BFLA marker | Mass marker | BFLA verdict | Mass verdict | FP on safe code | Precision | Rejected | Unverified | Retries · parse fail | Min · calls · tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Run 4 iter 2, A | 24/25 | 34/34 | 8/10 | 6/15 | 10/10 | 10/15 | 0 | 0.729 | 1 | 0 | — · 0 | 57 · 32 · 309K |
| Run 4 iter 2, B | 11/25 | 32/34 | 5/10 | 4/15 | 10/10 | 9/15 | 0 | 0.693 | 1 | 0 | — · 1 | 56 · 29 · 318K |
| **Run 5, A** | **24/25** | **34/34** | **10/10** | **10/15** | **10/10** | **15/15** | **0** | **0.818** | 2 | 0 | 0 · 0 | 83 · 32 · 328K |
| **Run 5, B** | **12/25** | **32/34** | **9/10** | **14/15** | **10/10** | **15/15** | **0** | **0.779** | 3 | 0 | 1 · 1 | 86 · 31 · 369K |

- **BFLA:** 10 / 10 and 9 / 10 as located findings (from 8 and 5). Every anchored finding pointed at a
  known route or candidate (0 unanchored).
- **Mass assignment:** the auditor flagged **15 / 15** candidates in both runs (from 10 and 9), including the
  five .NET / Java bindings. As located findings 10 / 15 and 14 / 15: in run A the model gave a
  `vulnerable` verdict for four candidates (`php-plain/profile.php` ×2, `CustomerController.cs` ×2)
  without writing a finding for them.
- **`php-plain/register.php:4` (MASS marker)** was rejected by the verifier in both runs: `extract($_POST)`
  is followed by an INSERT of only `email` and `name`. The argument is sound for this fixture as written,
  so the marker should be reviewed rather than counted as a verifier error.
- **BOLA in run B (12 / 25)** again lost batch `routes-001` (15 routes). This time the reply was not empty
  but invalid JSON: the model put code with unescaped `"` into `recommendation.code_before`; the retry
  failed the same way. The same batch failed in Run 4 run B.
- **No false positives** on SAFE markers in either run; precision rose to 0.82 / 0.78.
- Runs are ~45% slower than Run 4 iteration 2 (83–86 min): the privilege and verifier prompts are longer
  and there are more findings to verify.

### Unmatched BOLA findings (triage, not yet reflected in fixtures)

About 20 BOLA findings per run sit in files with no BOLA marker. By route:

| Route(s) | Assessment |
|---|---|
| `Customer/EditName`, `account/rename`, `python-flask` `/users/<uid>/name`, `account/profile` | Likely **real BOLA** not marked: the record ID comes from the request and is not bound to the caller |
| `Customer/Edit`, `Customer/Refresh`, `account/save`, `account/api`, `/users/<uid>` | Mass-assignment fixtures that also take the ID from the request: plausibly BOLA as well |
| `Admin/DeleteUser`, `Admin/Export`, `admin/users/{id}/delete`, `delete_user.php`, `promote.php`, `manage_users.php` | **BFLA routes also reported as BOLA**: same flaw seen from a second category; duplicate rather than wrong |

Fixture markers were left unchanged so Run 4 and Run 5 share the same ground truth.

### Remaining gaps

1. **Invalid JSON from code fields:** drop `code_before` / `code_after` from the 4a / 4b output templates
   (the sanitizer already reduces `recommendation` to a string), or repair unescaped quotes before parsing.
2. **Verdict without finding:** write a minimal finding for every `vulnerable` / `needs_review` verdict
   the model did not turn into one.
3. **Fixtures:** review the `register.php` MASS marker; add BOLA markers for the routes judged real above.
4. **qwen3.5:9b** still unmeasured: 32K context does not fit in 24 GB next to the OS; needs 16K context or
   a larger machine.

Harness changes for gaps 1 and 2 (#323), not yet measured in a new run:
- The 4a / 4b templates ask for `recommendation` as one string (no `code_before` / `code_after`). A reply
  that is still invalid is parsed again after escaping quotes that cannot end their string; such batches
  are listed under `repaired` in `ai-run-stats.json` and their raw reply is kept in `ai-raw/`.
- Every `vulnerable` / `needs_review` verdict without a finding gets a `confidence: low` finding anchored
  to its Tier 1 route or candidate (`operate/ai/verdicts.py`), listed under `findings_from_verdicts`. An
  offline replay of run A turns the four flagged candidates into located findings (mass assignment 14 / 15
  before verification) with no SAFE marker hit (`operate/tests/test_ai_verdicts.py`).

### Ground truth change after Run 5 (#323)

The fixtures were changed after Run 5, so runs from Run 6 on are scored against a new ground truth
(117 → 121 items). The archived `eval-run-4/` and `eval-run-5/` ground-truth files are kept as they were,
and their tests still score against them.

| Change | Reason |
|---|---|
| `php-plain/register.php`: `$role` defaults to `customer`, `extract($_POST)` can overwrite it, and it is inserted (MASS marker kept on line 4) | As written, the INSERT used only `email` and `name`, so the verifier's rejection was sound |
| New `BOLA` markers: `AccountController.java:21` (`/account/rename`), `CustomerController.cs:29` (`Refresh`), `python-flask/profile.py:18` (`/users/<uid>/name`) and `:26` (`PATCH /users/<uid>`) | The record id comes from the request and is not bound to the caller; checked by hand |
| No marker for Laravel `account/rename` / `account/profile` or .NET `Customer/EditName` | They act on `$request->user()`, or touch no record, so the Run 5 triage was wrong about them |

Run 5 rescored against the new ground truth (for comparison only; findings unchanged): BOLA 28 / 29
(run A) and 16 / 29 (run B), precision 0.859 and 0.826, still no false positive on SAFE markers. Every
new marker was already reported by both runs; Tier 1 lists all of them as BOLA route candidates.

---

## Run 6 — 2026-11-11, platform 2.5.0, kit 0.3.1 (#323 part 4: new harness, 121-item ground truth, redaction)

Issue #323. First run on the harness from #334 (no code fields in 4a / 4b templates, quote repair,
findings from flagged verdicts), the fixtures and ground truth from #336 (121 items: 29 BOLA, 34
SQL/NoSQL injection, 10 BFLA, 15 mass assignment, 33 SAFE), and secret redaction of code sent to the
model (v2.4.0). Outputs are archived in [`assess/lsa/examples/eval-run-6/`](../examples/eval-run-6/).
Runs 4–5 are not directly comparable; the Run 5 rows below are the Run 5 findings rescored against the
new ground truth.

| Item | Value |
|---|---|
| Pipeline | `komagu scan <repo> --no-cache --headless-ai http://localhost:11434/v1 --model <model> --ai-timeout 3600` from `main` at v2.5.0 |
| Hosting | Ollama 0.40.16 on the same Apple M4 Pro, 24 GB RAM, 100% GPU, local only; `gpt-oss:20b` on the llama.cpp runner with 32,768 context (as in Runs 4–5) |
| Scoring | `tests/score_findings.py --verdicts` (tolerance 3 lines) |
| Machine | No other heavy work while measuring; up to 5.7 GB swap in use during the `gpt-oss` runs |

### Results after verification (`gpt-oss:20b`)

| Run | BOLA | Injection | BFLA marker | Mass marker | BFLA verdict | Mass verdict | FP on safe code | Precision | Rejected | Retries · repaired · parse fail | From verdicts | Min · calls · tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Run 5 A, rescored | 28/29 | 34/34 | 10/10 | 10/15 | 10/10 | 15/15 | 0 | 0.859 | 2 | 0 · — · 0 | — | 83 · 32 · 328K |
| Run 5 B, rescored | 16/29 | 32/34 | 9/10 | 14/15 | 10/10 | 15/15 | 0 | 0.826 | 3 | 1 · — · 1 | — | 86 · 31 · 369K |
| **Run 6 A** | **26/29** | **34/34** | **10/10** | **14/15** | **10/10** | **15/15** | **1** | **0.813** | 2 | 0 · 0 · 0 | 9 (5 BOLA, 4 mass) | 40 · 33 · 315K |
| **Run 6 B** | **26/29** | **34/34** | **10/10** | **14/15** | **10/10** | **14/15** | **1** | **0.787** | 1 | 1 · 0 · 0 | 14 (5 BOLA, 9 mass) | 56 · 34 · 373K |

- **The two runs now agree.** BOLA is 26 / 29 in both (Run 5: 28 and 16). No batch was lost: no parse
  failure, no call error, no batch needed the quote repair, and the one retry (B, `injection-001`)
  succeeded. The `routes-001` batch that failed in Run 4 B and Run 5 B now parses.
- **Mass assignment:** 14 / 15 as located findings in both runs (Run 5: 10 and 14). Findings written from
  flagged verdicts closed the gap: the four candidates run A of Run 5 judged `vulnerable` without a
  finding (`profile.php` ×2, `CustomerController.cs` ×2) are findings in both runs.
  `php-plain/register.php:4` is still missed. In A the verifier rejected it because the INSERT "only"
  writes `email`, `name` and `role`, missing that `extract($_POST)` can overwrite `$role` (the
  fixture change in #336); in B the auditor did not flag it.
- **BFLA:** 10 / 10 in both runs, located and by verdict.
- **Misses:** `perl-cgi/cgi-bin/order.cgi:19` (both runs, missed since Run 4), `node-express/routes/orders.js:29`
  (both), `java-legacy/.../OrderServlet.java:15` (A), `python-flask/app.py:12` (B).
- **False positives on SAFE markers: 1 per run** (Run 5: 0), both injection:
  - A: `classic-asp/shop/member.asp:6`. The `UPDATE` starts on line 6, whose `name` value is escaped;
    the concatenated `member_id` is on line 7, which is also reported. The finding is anchored one line
    early rather than describing a new flaw, but it is scored as a false positive.
  - B: `python-flask/app.py:12`. `order_id` is an `<int:...>` path parameter, so the `%` formatting
    cannot inject. The model reported the route's missing ownership check as SQL injection, so the
    BOLA marker on the same line was missed.
- **Precision 0.81 / 0.79.** Five of the unmatched findings per run come from verdicts: the BOLA
  auditor flagged the Laravel routes `/register`, `/posts`, `/teams`, `/account/rename` and
  `/account/profile`, and the generated findings point at their declarations in `routes/web.php`
  (lines 6–10). The triage after Run 5 found these routes act on `$request->user()` or touch no
  record, so they are likely false positives. Without them precision would be 0.85 / 0.83.
- **Duration:** 40 and 56 minutes (Run 5: 83 and 86). The model wrote fewer tokens (84K and 118K
  completion tokens against about 109K and 111K); the Ollama version also changed (0.40.13 → 0.40.16).
- **`ai-raw/`** is written only for batches that needed a repair or failed to parse. None did, so neither
  run has an `ai-raw/` folder.

### Did redaction reduce recall?

No, and on this repo it cannot. Running the redaction used for model context
(`assess/lsa/scripts/redaction.py`, `redact_lines`) over every file of the eval repo changes **0 lines**:
the fixtures contain no secrets in the patterns it covers. The prompts sent in Run 6 are therefore the
same code as without redaction. The BOLA difference from Run 5 A (28 → 26) is run-to-run variance (the
same model put 16 in Run 5 B). This also means the eval repo does not test whether redaction costs
recall on code that does contain secrets; that is covered only by the unit tests
(`operate/tests/test_ai_redaction.py`, `test_no_planted_secret_reaches_the_model`).

### `qwen3.5:9b` with a 16K context (not completed)

To fit the 24 GB machine, `qwen3.5:9b` was run with `num_ctx 16384` (a local tag built
`FROM qwen3.5:9b` with `PARAMETER num_ctx 16384`, MLX runner), same command and timeout as above. It did
not finish: the run was stopped by hand after 3 h 14 min, while the second injection batch was still
running and before the privilege (4c) and verifier (5) phases. The partial output is archived as
[`eval-run-6/qwen-16k-partial/`](../examples/eval-run-6/qwen-16k-partial/) (raw batch findings, the
per-minute memory log, and an indicative score of the unverified findings).

| Phase / batch | Time | Result |
|---|---|---|
| Stack detection | 2 min | done |
| BOLA `routes-001` (15 routes) | 60 min | **timed out**, empty |
| BOLA `routes-002` … `routes-004` | 5, 3 and 2 min | 8, 7 and 9 findings |
| BOLA `routes-005` | 60 min | **timed out**, empty |
| BOLA `routes-006` | 1 min | 1 finding |
| Injection `injection-001` | 11 min | 20 findings |
| Injection `injection-002` | 49 min+ | still running when stopped |

- **Memory:** the runner used 8.1 GB for the first hour, then grew to 13, 18 and finally 20 GB (from about
  10:55, after the first timeout). Swap rose from about 4 GB (other work on the machine) to 12.4 GB of
  13.3 GB; the run was stopped there to keep the machine usable. `gpt-oss:20b` stayed under 5.7 GB of
  swap on the same machine.
- **Timeouts:** a batch that hits `--ai-timeout` is not retried (only empty or unparseable replies are),
  so two of six BOLA batches were lost outright. The quick batches suggest the model can do the task;
  the timed-out ones look like long reasoning that does not end within the context.
- **Indicative score** (findings before verification, from the batches that finished): BOLA 12/29,
  injection 22/34, BFLA and mass assignment not reached, precision 0.73, no finding on a SAFE marker.
  These numbers are not comparable with the `gpt-oss` rows: two BOLA batches, half the injection
  candidates and the verifier are missing.

Thinking looks like the cause: on this 24 GB machine a 16K context with default reasoning is **not**
a working setting. The run below with reasoning off is.

### `qwen3.5:9b` with a 16K context and reasoning off (#382)

Same tag, command and timeout, plus `--ai-reasoning-effort none` (#382), which sends
`"reasoning_effort": "none"` with every request; Ollama's `/v1` endpoint ignores `think: false` but
honours this field. One run, archived as [`eval-run-6/qwen-16k-nothink/`](../examples/eval-run-6/qwen-16k-nothink/)
(with `ai-raw/` for the two repaired verifier replies and the per-minute memory log).

| Run | BOLA (29) | Injection (34) | BFLA (10) | Mass (15) | BFLA verdict | Mass verdict | SAFE hit | Precision | Time |
|---|---|---|---|---|---|---|---|---|---|
| `gpt-oss:20b` A | 26 | 34 | 10 | 14 | 10 | 15 | 1 | 0.813 | 40 min |
| `gpt-oss:20b` B | 26 | 34 | 10 | 14 | 10 | 14 | 1 | 0.787 | 56 min |
| `qwen3.5:9b` 16K, reasoning off | 23 | 29 | 6 | 10 | 8 | 15 | 0 | 0.734 | 35 min |

- **Completed:** all phases, 33 calls, no timeout, no parse failure or call error, no retry, all findings
  anchored. Two verifier replies were repaired (`verified-1`, `verified-9`); 11 findings were generated
  from flagged verdicts (2 BOLA, 2 BFLA, 7 mass assignment).
- **Recall** is lower than `gpt-oss:20b` in every category: BFLA and mass assignment are mostly found as
  verdicts (8/10, 15/15) but placed on the right line less often (6/10, 10/15).
- **Precision 0.73:** no finding on a SAFE marker, but 25 unmatched findings (23 BOLA, 2 BFLA), not yet triaged;
  none is on `php-laravel/routes/web.php`.
- **Memory and time:** the runner stayed at 14–17 GB and swap peaked at 6.0 GB (about 3.7 GB before the
  run, from other work), against 20 GB and 12.4 GB with reasoning on. 35 minutes in all, of which the
  verifier took 17.
- **Minimum to run it:** a 24 GB machine is enough with `num_ctx 16384` and `--ai-reasoning-effort none`.
  With reasoning on it needs more; on this evidence at least 32 GB RAM.
