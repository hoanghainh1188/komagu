#!/usr/bin/env python3
"""Generate runtime-specific files from the neutral LSA kit.

Usage:
  build_adapters.py claude-code DEST   -> DEST/.claude/skills/legacy-security-audit/ + DEST/.claude/agents/lsa-*.md
  build_adapters.py cursor DEST        -> DEST/.lsa-kit/ + DEST/.cursor/rules/lsa-*.mdc
  build_adapters.py generic DEST       -> DEST/system-prompts/*.md + DEST/contract.json (for your own platform / OpenHands / API)

DEST is usually an *audit workspace* (a folder that contains or sits next to the
code under audit), not the customer repository itself.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

KIT = Path(__file__).resolve().parent.parent
REPO = KIT.parent.parent
VERSION = (KIT / "VERSION").read_text().strip()

ROLES = [
    {"id": "stack-detector", "file": "10-stack-detector.md", "phase": 2,
     "description": "LSA phase 2. Confirms the legacy stack and writes auth-model.md (how authentication, role and ownership checks work). Use before any BOLA or injection audit.",
     "inputs": ["stack-profile.json", "routes.candidates.json"], "outputs": ["stack-profile.json", "auth-model.md"],
     "knowledge": ["knowledge/stacks/<stack>.md", "knowledge/bola-patterns.md"]},
    {"id": "route-mapper", "file": "20-route-mapper.md", "phase": 3,
     "description": "LSA phase 3. Builds a complete endpoint inventory for one route batch (methods, paths, id inputs, guards, data operations).",
     "inputs": ["batches/routes-NNN.json", "auth-model.md"], "outputs": ["routes/routes-NNN.json"],
     "knowledge": ["knowledge/stacks/<stack>.md"]},
    {"id": "bola-auditor", "file": "30-bola-auditor.md", "phase": 4,
     "description": "LSA phase 4a. Audits one route batch for BOLA/IDOR: object access by request-controlled id without binding to the current user or tenant.",
     "inputs": ["routes/routes-NNN.json", "auth-model.md"], "outputs": ["findings/bola-routes-NNN.json"],
     "knowledge": ["knowledge/bola-patterns.md", "knowledge/stacks/<stack>.md", "knowledge/severity-and-cwe.md"]},
    {"id": "injection-auditor", "file": "40-injection-auditor.md", "phase": 4,
     "description": "LSA phase 4b. Audits one batch of query-building candidates for SQL/HQL/NoSQL injection.",
     "inputs": ["batches/injection-NNN.json", "auth-model.md", "routes.json"], "outputs": ["findings/inj-NNN.json"],
     "knowledge": ["knowledge/injection-patterns.md", "knowledge/stacks/<stack>.md", "knowledge/severity-and-cwe.md"]},
    {"id": "finding-verifier", "file": "50-finding-verifier.md", "phase": 5,
     "description": "LSA phase 5. Skeptical reviewer that tries to refute up to 10 findings it did not write. Must run in a fresh context.",
     "inputs": ["up to 10 findings", "auth-model.md"], "outputs": ["findings/verified-N.json"],
     "knowledge": ["knowledge/bola-patterns.md", "knowledge/injection-patterns.md", "knowledge/severity-and-cwe.md"]},
    {"id": "reporter", "file": "60-reporter.md", "phase": 6,
     "description": "LSA phase 6. Fills the judgment sections (executive summary, systemic fixes, limitations) of the generated report.md.",
     "inputs": ["report.md", "findings.json", "auth-model.md", "coverage.json"], "outputs": ["report.md"],
     "knowledge": []},
]

# bundle folder -> source folder; schemas and governance are shared at the repository root
COPY_DIRS = {"prompts": KIT / "prompts", "knowledge": KIT / "knowledge", "schemas": REPO / "contracts" / "schemas",
             "scripts": KIT / "scripts", "templates": KIT / "templates", "governance": REPO / "governance"}


def copy_kit(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for d, src in COPY_DIRS.items():
        if (dest / d).exists():
            shutil.rmtree(dest / d)
        shutil.copytree(src, dest / d, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copy2(KIT / "VERSION", dest / "VERSION")


def role_body(role: dict, kit_ref: str) -> str:
    shared = (KIT / "prompts" / "_shared-rules.md").read_text(encoding="utf-8")
    body = (KIT / "prompts" / role["file"]).read_text(encoding="utf-8")
    note = (f"> Kit files (knowledge/, schemas/, templates/) are in `{kit_ref}`. "
            f"Paths like `knowledge/...` in this prompt are relative to that folder.\n\n")
    return note + shared.strip() + "\n\n---\n\n" + body.strip() + "\n"


def build_claude_code(dest: Path) -> None:
    skill = dest / ".claude" / "skills" / "legacy-security-audit"
    copy_kit(skill)
    ref = ".claude/skills/legacy-security-audit"
    orch = (KIT / "prompts" / "00-orchestrator.md").read_text(encoding="utf-8")
    orch = orch.replace("KIT/", ref + "/").replace("`KIT`", f"`{ref}`")
    mapping = "\n".join(f"| `{r['file'][:-3]}` | `lsa-{r['id']}` |" for r in ROLES)
    skill_md = f"""---
name: legacy-security-audit
description: "Read-only AI security audit of legacy web code (PHP, Java/JSP/Struts, ASP.NET WebForms/MVC, Classic ASP, Perl CGI, ColdFusion, old Node/Python/Ruby) for BOLA/IDOR (missing ownership checks) and SQL/NoSQL queries built by string concatenation. Use when asked to audit controllers/routers/endpoints of an old system for IDOR, BOLA, broken object level authorization, missing authorization middleware, or SQL/NoSQL injection."
---

<!-- generated by adapters/build_adapters.py from LSA kit {VERSION}; edit the kit, not this file -->

{orch}

## Claude Code mapping

Run each agent role as the matching subagent (Task/Agent tool). Launch the
phase 4a and 4b subagents in parallel (max `parallel.max_agents`). Give each
subagent its batch file path, OUT path, TARGET path and the auth-model path.

| Role prompt | Subagent |
|---|---|
{mapping}

Scripts: `python3 {ref}/scripts/<script>.py` (Python 3.8+, standard library only).
"""
    (skill / "SKILL.md").write_text(skill_md, encoding="utf-8")
    agents = dest / ".claude" / "agents"
    agents.mkdir(parents=True, exist_ok=True)
    for r in ROLES:
        fm = (f"---\nname: lsa-{r['id']}\ndescription: {json.dumps(r['description'])}\n"
              f"tools: Read, Grep, Glob, Write\n---\n\n"
              f"<!-- generated by adapters/build_adapters.py from LSA kit {VERSION} -->\n\n"
              "Write your output files only into the audit OUT directory given in your task. "
              "Never write into TARGET.\n\n")
        (agents / f"lsa-{r['id']}.md").write_text(fm + role_body(r, ref), encoding="utf-8")
    print(f"Claude Code: skill in {skill}, {len(ROLES)} subagents in {agents}")


def build_cursor(dest: Path) -> None:
    kit_dir = dest / ".lsa-kit"
    copy_kit(kit_dir)
    rules = dest / ".cursor" / "rules"
    rules.mkdir(parents=True, exist_ok=True)
    orch = (KIT / "prompts" / "00-orchestrator.md").read_text(encoding="utf-8").replace("KIT/", ".lsa-kit/").replace("`KIT`", "`.lsa-kit`")
    orch += ("\n\n## Cursor notes\n\nCursor chat runs one agent at a time. Run the phases in order. "
             "For each phase start a **new chat** (fresh context) and mention the role rule, e.g. "
             "`@lsa-bola-auditor audit .lsa-out/batches/routes-001.json`. The verifier must always run in a new chat.\n")
    (rules / "lsa-orchestrator.mdc").write_text(
        "---\ndescription: \"LSA legacy security audit orchestrator (BOLA/IDOR + SQL/NoSQL injection). Use when asked to run the legacy security audit.\"\n"
        "globs:\nalwaysApply: false\n---\n\n" + orch, encoding="utf-8")
    for r in ROLES:
        (rules / f"lsa-{r['id']}.mdc").write_text(
            f"---\ndescription: {json.dumps(r['description'])}\nglobs:\nalwaysApply: false\n---\n\n" + role_body(r, ".lsa-kit"), encoding="utf-8")
    print(f"Cursor: kit in {kit_dir}, {len(ROLES) + 1} rules in {rules}")


def build_generic(dest: Path) -> None:
    sp = dest / "system-prompts"
    sp.mkdir(parents=True, exist_ok=True)
    copy_kit(dest / "kit")
    (sp / "orchestrator.md").write_text((KIT / "prompts" / "00-orchestrator.md").read_text(encoding="utf-8"), encoding="utf-8")
    for r in ROLES:
        (sp / f"{r['id']}.md").write_text(role_body(r, "kit/"), encoding="utf-8")
    contract = {"kit_version": VERSION, "pipeline": [
        {"phase": 1, "type": "script", "run": "python3 kit/scripts/run_prescan.py TARGET OUT [--config CONFIG]"},
        *[{"phase": r["phase"], "type": "agent", "role": r["id"], "system_prompt": f"system-prompts/{r['id']}.md",
           "inputs": r["inputs"], "outputs": r["outputs"], "knowledge": r["knowledge"],
           "tools_needed": ["read_file", "search_code", "list_dir", "write_output_file"],
           "fresh_context": r["id"] == "finding-verifier"} for r in ROLES if r["id"] != "reporter"],
        {"phase": 6, "type": "script", "run": "python3 kit/scripts/merge_findings.py OUT && python3 kit/scripts/findings_to_sarif.py OUT && python3 kit/scripts/render_report.py OUT"},
        {"phase": 6, "type": "agent", "role": "reporter", "system_prompt": "system-prompts/reporter.md",
         "inputs": ROLES[-1]["inputs"], "outputs": ["report.md"], "knowledge": [], "tools_needed": ["read_file", "write_output_file"]},
        {"phase": 7, "type": "human", "role": "security reviewer (not the runner)", "template": "kit/templates/review-log.md"},
    ]}
    (dest / "contract.json").write_text(json.dumps(contract, indent=2), encoding="utf-8")
    print(f"Generic: {len(ROLES) + 1} system prompts in {sp}, pipeline contract in {dest / 'contract.json'}")


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in ("claude-code", "cursor", "generic"):
        print(__doc__)
        return 2
    dest = Path(sys.argv[2]).resolve()
    {"claude-code": build_claude_code, "cursor": build_cursor, "generic": build_generic}[sys.argv[1]](dest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
