# Changelog

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
