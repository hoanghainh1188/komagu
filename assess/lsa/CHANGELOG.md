# Changelog

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
