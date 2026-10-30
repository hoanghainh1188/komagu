# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

**Komagu**: Security-first modernization framework for legacy web systems organized by lifecycle:
- [`assess/`](assess/lsa/README.md): Legacy Security Audit Kit (LSA) for BOLA/IDOR and dynamic query injection detection.
- `remediate/`: Drop-in authorization, multi-tenancy, eKYC, and resilience modules (.NET, Go, Spring Boot, Node.js).
- [`operate/`](operate/README.md): DevSecOps CLI (`komagu`), cross-user authorization tester, and SARIF/SBOM integrations.
- [`contracts/`](contracts/README.md): Shared JSON Schemas joining audit findings, route inventories, and verification verdicts.
- `governance/`: Usage policies, human-in-the-loop sign-off procedures, and metric baselines.

## Quick Verification Commands

```bash
# LSA self-tests (~1s, Python stdlib only)
python3 assess/lsa/tests/run_tests.py

# Operate test suite (CLI, cross-user tester, npm package)
python3 -m unittest discover -s operate/tests -p "test_*.py"
npm test

# Remediate modules (run relevant suite when touching language modules)
dotnet test remediate/authz/dotnet/tests/Komagu.Security.Authorization.Tests/Komagu.Security.Authorization.Tests.csproj
(cd remediate/authz/go && go test ./...)
(cd remediate/authz/spring && ./mvnw test)
```

## Workflow & Development Guidelines

- **Issues & Project Board**: Tasks are tracked in `hoanghainh1188/komagu` and Project Board #6. Always work from an issue.
- **Branches**: Create `<issue-number>-<short-kebab-description>` from `main`.
- **Pull Requests**: Open PR targeting `main` with `Closes #N`. Move Project #6 items: *In progress* → *In review* → *Done*.
- **Branch Protection & Merging**: Direct push to `main` is blocked both server-side and locally via `.githooks/pre-push` (`git config core.hooksPath .githooks`). All 6 CI status checks must pass before squash-merging.
- **Runtime & Coding Principles**: Keep LSA prompts runtime-neutral and scripts Python 3.8+ stdlib-only. Keep contracts schema-compliant.
- **Versioning**: LSA version is in `assess/lsa/VERSION`; CLI/npm package version is in `package.json`.
