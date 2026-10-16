# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

**Komainu**: security-first modernization for legacy systems, organised by lifecycle — `assess/` (find problems), `remediate/` (reusable fix modules), `operate/` (keep them fixed), joined by shared formats in `contracts/`. Rationale and the planned folders are in `docs/adr/0001-name-and-repository-structure.md`; create a new top-level area only when its work starts. `docs/` (proposal, Boilerplate 1 plan) is internal and confidential.

The only built component today is **LSA** in `assess/lsa/` (Legacy Security Audit Kit): a runtime-neutral kit of prompts, knowledge files, JSON schemas and Python scripts that lets AI agents audit legacy web codebases for **BOLA/IDOR** and **string-built SQL/HQL/NoSQL queries**. See `AGENTS.md` for the two modes:

- **Running an audit** with this kit: follow `prompts/00-orchestrator.md`; prepend `prompts/_shared-rules.md` to every role prompt; never write into the audited repo (output goes to the OUT folder); run the verifier role in a fresh context.
- **Changing the kit itself**: keep prompts runtime-neutral (no tool-specific wording), keep scripts **Python 3.8+ standard library only**, and run the self-test after every change.

## Commands

Run from `assess/lsa/` (all LSA paths below are relative to it):

```bash
python3 tests/run_tests.py        # full self-test (~1s); add -v for detail
python3 scripts/run_prescan.py TARGET OUT [--config templates/audit-config.json]
python3 scripts/merge_findings.py OUT      # validate + dedupe; exit 1 on coverage gaps
python3 scripts/findings_to_sarif.py OUT
python3 scripts/render_report.py OUT
python3 adapters/build_adapters.py {claude-code|cursor|generic} DEST
```

There is no per-test selector; `run_tests.py` is a single script. Agent-quality evaluation (run after changing a prompt, knowledge file, or model):

```bash
python3 tests/build_eval_repo.py /tmp/lsa-eval     # fixtures with markers stripped + ground-truth.json
python3 scripts/run_prescan.py /tmp/lsa-eval/repo /tmp/lsa-eval/out
# ...run agent phases 2-5...
python3 scripts/merge_findings.py /tmp/lsa-eval/out
python3 tests/score_findings.py /tmp/lsa-eval/ground-truth.json /tmp/lsa-eval/out
```

Results are recorded in `tests/EVAL-RESULTS.md`; `examples/eval-run-1/` is a sample OUT folder.

## Architecture

Pipeline (phases in `prompts/00-orchestrator.md`): deterministic pre-scan → stack/auth-model agent → route-mapper agents per batch → BOLA and injection auditor agents (parallel, per batch) → fresh-context verifier → merge/SARIF/report scripts + reporter agent → human sign-off (`templates/review-log.md`, root `governance/usage-policy.md`).

- **Scripts favour recall; agents provide judgment.** `run_prescan.py` drives `detect_stack.py`, `map_routes.py` (route candidates), `find_injection.py` (dynamic-query lines) and `make_batches.py`. Shared helpers (config loading/deep-merge, file iteration with excludes and encodings, id-name patterns, redaction) live in `scripts/lsa_common.py`. Defaults are overridable via `templates/audit-config.json`.
- **Contracts are the JSON Schemas** in `contracts/schemas/` at the repo root (prompts call them `schemas/...`; `merge_findings.py` falls back to `contracts/schemas` when no local `schemas/` exists, and `build_adapters.py` copies them, plus root `governance/`, into bundles) (stack profile, route inventory, finding, verification). `merge_findings.py` validates against them and checks that every route candidate has a verdict or a rejection reason. Changing a schema usually means updating role prompts, `merge_findings.py`, `findings_to_sarif.py`, `render_report.py`, and `adapters/build_adapters.py` (`ROLES` lists each role's inputs/outputs/knowledge).
- **Prompts ↔ knowledge**: role prompts `prompts/NN-*.md` reference `knowledge/*-patterns.md`, `knowledge/severity-and-cwe.md`, and per-stack notes in `knowledge/stacks/`. Adding a stack typically touches `detect_stack.py`, `map_routes.py`, `find_injection.py`, a new `knowledge/stacks/*.md`, and a new fixture.
- **Adapters** are generated from the neutral sources by `adapters/build_adapters.py`; edit the sources, not generated output.

## Test fixtures and markers

`tests/fixtures/<stack>/` are small vulnerable/safe apps. Expected outcomes are inline comments `LSA-EXPECT:<TAG>` (parsed by `tests/lsa_markers.py`):

- `SQLI` / `NOSQL` — pre-scan must flag; agents must report
- `SAFE-SQL` — pre-scan may flag; agents must judge safe
- `SAFE-SQL-NOFLAG` — parameterized; pre-scan must NOT flag
- `BOLA` — route must be found; agents must report
- `SAFE-BOLA` — ownership bound; agents must not report

`run_tests.py` checks injection recall, NOFLAG precision, route coverage of BOLA markers, and an end-to-end prescan→merge→SARIF→report run. When you change a regex, add/adjust a fixture line with the right marker.

## Working with issues

Tasks are tracked as GitHub issues in `hoanghainh1188/komainu` and on project board #6 (`gh project ... 6 --owner hoanghainh1188`; fields Status, Priority P0–P2, Size).

- Every change starts from an issue; create one first if none exists, with a `Source:` line pointing to the doc section it comes from.
- Branch name: `<issue-number>-<short-kebab-description>` (e.g. `9-d1-authz-library`).
- PR body includes `Closes #N`; move the project item to In progress / In review as work advances.
- Labels: one or more `area:*` (`assess`, `contracts`, `remediate`, `operate`, `delivery`, `governance`, `docs`) matching the folder touched; `decision` for items that need a choice by management or the owner — record the outcome in an ADR under `docs/adr/`.
- Never push to `main` directly. The repo is private on GitHub Free, so `main` has no server-side protection; a versioned pre-push hook blocks it locally (enable per clone: `git config core.hooksPath .githooks`). Merge is squash-only and CI (`.github/workflows/lsa-tests.yml`) must be green before merging.
- Boilerplate 1 work is assigned to milestones M1–M5, which mirror the approval points in `docs/boilerplate-1-delivery-plan.md`.

## Other

- Kit version is in `VERSION`; note changes in `CHANGELOG.md`.
