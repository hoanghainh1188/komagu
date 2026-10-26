# Changelog

## 0.2.3 — 2026-10-26

Runtime adapters (#244).

- **Codex Adapter:** `build_adapters.py codex DEST` generates a repo-scoped skill in `.agents/skills/legacy-security-audit/`, one custom agent per role in `.codex/agents/lsa-*.toml`, and an idempotent LSA section in `AGENTS.md` that keeps user content outside its markers.
- **`komainu init --ai <runtime> [DEST]`:** CLI entry point for the adapter generators (`claude-code`/`claude`, `codex`, `cursor`, `generic`/`openhands`). No LLM SDKs or network calls (ADR-0006).
- **Builder API:** `build(runtime, dest)` and `resolve_runtime(name)` shared by the script and the CLI; unknown runtimes exit with code 2.
- **Packaging:** `governance/` now ships in the npm package and Docker image, since every adapter bundles the usage policy.

## 0.2.2 — 2026-10-19

Finding merge and security hardening (#115).

- **Verification-First Deduplication:** Verification verdicts are applied before deduplication so confirmed findings are not shadowed by rejected duplicates. Deduplication key includes subtype and route, and dropped duplicate findings are excluded from `findings_without_verification`.
- **Recursive Stdlib Validator:** Pure Python recursive schema validator for `finding.schema.json` and `route-inventory.schema.json` checking types, required fields, enums, patterns, minItems, maxLength, minimum, items, and `$ref`.
- **Route Inventory Coverage Fix:** Missing/empty route inventory when candidates exist correctly flags missing candidates and exits with code 1; stale outputs (`routes.json`, `findings.json`, `coverage.json`) are cleared on re-run.
- **Resilient Agent Output Handling:** Per-item error capture for malformed documents and items without crashing merge script.
- **Symlink & Path Traversal Guard:** `iter_source_files` and code-behind resolver skip symlinks and paths resolving outside the target repository.

## 0.2.1 — 2026-10-18

Platform release (v0.2.0 / v0.2.1).

- **Pattern & Prompt Hardening (Run 3):** Enhanced `injection-patterns.md` (§1.1
  dynamic `WHERE`/`ORDER BY`/`GROUP BY` clause concatenation and multi-step
  query builders) and `bola-patterns.md` (Pattern P13: indirect reference via
  foreign key / parent object & unscoped bulk listing).
- **Skeptic Verifier Upgrades:** Added explicit allow-list (`switch`/`case`,
  enum mapping) and parent-ownership recognition in `50-finding-verifier.md`.
- **Empirical Benchmark (Evaluation Run 3):** Verified 100% BOLA/IDOR recall
  (25/25), 100% SQL/NoSQL injection recall (34/34), 0 false positives on safe
  code, and 1.000 precision (57/57 active findings).
- **Bilingual & Interactive Reporting:** Added Japanese report template
  (`60-reporter-ja.md`, `report.ja.md` compliant with IPA/NISC terminology) and
  zero-dependency interactive HTML audit dashboard (`report.html`) with inline
  SVG charts and instant English/Japanese toggle.
- **Unified CLI & Zero-Install Distribution:** Packaged into `komainu` CLI
  (`bin/komainu`), all-in-one Docker image, and `komainu-guard` on npmjs.

## 0.1.0 — 2026-10-16

First version.

- Runtime-neutral prompts: orchestrator, stack/auth-model detector, route
  mapper, BOLA auditor, injection auditor, verifier, reporter.
- Knowledge: BOLA and injection pattern catalogues, severity/CWE map, notes
  for PHP, Java, .NET, Classic ASP, Perl CGI, ColdFusion, Node/Python/Ruby.
- Scripts (Python 3.8+, stdlib only): pre-scan, batching, verifier batching,
  merge + validation + coverage check, SARIF 2.1.0 export, report rendering.
- Adapters: Claude Code (skill + subagents), Cursor (rules), generic
  (system prompts + pipeline contract) incl. notes for OpenHands.
- Tests: 10 fixture apps with markers, pre-scan self-test, eval repo builder
  and scorer.
- Prompt fixes from the first end-to-end agent run on the eval repo:
  output-file rule, multi-app auth model, web-root/`app_root`, guard
  `position`, `other_inputs`, needs_review findings, shared build+sink
  findings, dead-code rule, stack → knowledge-file map.
