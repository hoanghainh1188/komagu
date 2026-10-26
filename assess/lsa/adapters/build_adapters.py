#!/usr/bin/env python3
"""Generate runtime-specific files from the neutral LSA kit.

Usage:
  build_adapters.py claude-code DEST   -> DEST/.claude/skills/legacy-security-audit/ + DEST/.claude/agents/lsa-*.md
  build_adapters.py codex DEST         -> DEST/.agents/skills/legacy-security-audit/ + DEST/.codex/agents/lsa-*.toml + DEST/AGENTS.md block
  build_adapters.py cursor DEST        -> DEST/.lsa-kit/ + DEST/.cursor/rules/lsa-*.mdc
  build_adapters.py generic DEST       -> DEST/system-prompts/*.md + DEST/contract.json + DEST/kit/ (for your own platform / OpenHands / API;
                                        refuses a DEST whose contract.json it did not generate)

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
    print("Next step: In your Claude Code workspace, prompt: 'Run the legacy-security-audit skill. TARGET=src, OUT=lsa-out'")


AGENTS_MD_BEGIN = "<!-- komainu-lsa:begin (generated by adapters/build_adapters.py; edits inside this block are overwritten) -->"
AGENTS_MD_END = "<!-- komainu-lsa:end -->"


def toml_multiline(text: str) -> str:
    """Encode text as a TOML multi-line basic string (stdlib has no TOML writer)."""
    out = []
    for ch in text:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\r":
            out.append("\\r")
        elif ch in "\t\n":
            out.append(ch)
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04X}")
        else:
            out.append(ch)
    # the newline right after the opening quotes is trimmed by TOML parsers
    return '"""\n' + "".join(out) + '"""'


def agents_md_with_block(path: Path, block: str) -> str:
    """Return AGENTS.md text with the LSA section between markers, keeping everything else the user wrote.

    Raises ValueError (before anything is written) if the file is not UTF-8 or its markers are unbalanced.
    """
    current = ""
    if path.exists():
        try:
            with open(path, encoding="utf-8", newline="") as f:
                current = f.read()
        except UnicodeDecodeError as e:
            raise ValueError(f"{path} is not UTF-8 ({e}); convert it, then re-run") from e
    nl = "\r\n" if "\r\n" in current else "\n"
    section = f"{AGENTS_MD_BEGIN}\n{block.strip()}\n{AGENTS_MD_END}\n".replace("\n", nl)
    begins, ends = current.count(AGENTS_MD_BEGIN), current.count(AGENTS_MD_END)
    if begins == 0 and ends == 0:
        return section if not current.strip() else current.rstrip("\r\n") + nl + nl + section
    start, stop = current.find(AGENTS_MD_BEGIN), current.find(AGENTS_MD_END)
    if begins != 1 or ends != 1 or stop < start:
        raise ValueError(f"{path} has unbalanced komainu-lsa markers; remove them by hand, then re-run")
    stop += len(AGENTS_MD_END)
    if current.startswith(nl, stop):
        stop += len(nl)
    return current[:start] + section + current[stop:]


def write_preserving_newlines(path: Path, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


def build_codex(dest: Path) -> None:
    ref = ".agents/skills/legacy-security-audit"
    skill = dest / ref
    agents_md = dest / "AGENTS.md"
    # validate AGENTS.md before writing anything, so a bad file leaves the workspace untouched
    agents_md_text = agents_md_with_block(agents_md, f"""## Legacy security audit (Komainu LSA {VERSION})

When asked to audit legacy code for BOLA/IDOR or SQL/NoSQL injection, use the
`legacy-security-audit` skill (`{ref}/SKILL.md`). Its procedure is binding.

- Never write into TARGET (the code under audit). Write only into the audit OUT folder.
- Run each role as its custom agent in `.codex/agents/` (`lsa-*`), with a fresh context.
- The finding verifier must never review findings from its own context.
- Check the project's `llm_policy` before sending customer code to any model.
""")
    copy_kit(skill)
    orch = (KIT / "prompts" / "00-orchestrator.md").read_text(encoding="utf-8")
    orch = orch.replace("KIT/", ref + "/").replace("`KIT`", f"`{ref}`")
    mapping = "\n".join(f"| `{r['file'][:-3]}` | `lsa-{r['id']}` |" for r in ROLES)
    skill_md = f"""---
name: legacy-security-audit
description: "Read-only AI security audit of legacy web code (PHP, Java/JSP/Struts, ASP.NET WebForms/MVC, Classic ASP, Perl CGI, ColdFusion, old Node/Python/Ruby) for BOLA/IDOR (missing ownership checks) and SQL/NoSQL queries built by string concatenation. Use when asked to audit controllers/routers/endpoints of an old system for IDOR, BOLA, broken object level authorization, missing authorization middleware, or SQL/NoSQL injection. Do not use for writing new features or fixing code."
---

<!-- generated by adapters/build_adapters.py from LSA kit {VERSION}; edit the kit, not this file -->

{orch}

## Codex mapping

Each agent role is a project custom agent in `.codex/agents/`. Spawn the
matching subagent for every role and batch; spawn the phase 4a and 4b
subagents in parallel (max `parallel.max_agents`). Give each subagent its
batch file path, OUT path, TARGET path and the auth-model path.

| Role prompt | Custom agent |
|---|---|
{mapping}

If subagents are not available in this session, run the roles one after
another yourself and run `lsa-finding-verifier` in a new Codex session.

Scripts: `python3 {ref}/scripts/<script>.py` (Python 3.8+, standard library only).
"""
    (skill / "SKILL.md").write_text(skill_md, encoding="utf-8")
    agents = dest / ".codex" / "agents"
    agents.mkdir(parents=True, exist_ok=True)
    for r in ROLES:
        instructions = ("Write your output files only into the audit OUT directory given in your task. "
                        "Never write into TARGET.\n\n" + role_body(r, ref))
        toml = (f"# generated by adapters/build_adapters.py from LSA kit {VERSION}; edit the kit, not this file\n"
                f"name = {json.dumps('lsa-' + r['id'])}\n"
                f"description = {json.dumps(r['description'])}\n"
                f"developer_instructions = {toml_multiline(instructions)}\n")
        (agents / f"lsa-{r['id']}.toml").write_text(toml, encoding="utf-8")
    write_preserving_newlines(agents_md, agents_md_text)
    print(f"Codex: skill in {skill}, {len(ROLES)} custom agents in {agents}, LSA section in {agents_md}")
    print("Next step: Start Codex in the workspace and prompt: 'Run the legacy-security-audit skill. TARGET=src, OUT=lsa-out'")


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
    print("Next step: In Cursor, open a new chat and invoke: '@lsa-orchestrator run security audit on TARGET=src, OUT=lsa-out'")


GENERATOR = "komainu-lsa"


def check_generic_dest(dest: Path) -> None:
    """Refuse a DEST whose contract.json, kit/ or system-prompts/ the generic adapter did not generate.

    Raises ValueError (before anything is written) so a project's own files are never overwritten.
    """
    contract = dest / "contract.json"
    if contract.exists():
        try:
            data = json.loads(contract.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, ValueError):
            data = None
        if not isinstance(data, dict) or data.get("generator") != GENERATOR:
            raise ValueError(f"{contract} was not generated by Komainu LSA (no \"generator\": \"{GENERATOR}\"); "
                             "choose an empty DEST such as ./lsa-bundle, or move that file away")
        return
    for name in ("kit", "system-prompts"):
        if (dest / name).exists():
            raise ValueError(f"{dest / name} exists but {contract} does not, so it was not generated by Komainu LSA; "
                             "choose an empty DEST such as ./lsa-bundle, or move it away")


def build_generic(dest: Path) -> None:
    check_generic_dest(dest)
    sp = dest / "system-prompts"
    sp.mkdir(parents=True, exist_ok=True)
    copy_kit(dest / "kit")
    (sp / "orchestrator.md").write_text((KIT / "prompts" / "00-orchestrator.md").read_text(encoding="utf-8"), encoding="utf-8")
    for r in ROLES:
        (sp / f"{r['id']}.md").write_text(role_body(r, "kit/"), encoding="utf-8")
    contract = {"generator": GENERATOR, "kit_version": VERSION, "pipeline": [
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
    print("Next step: Drive the pipeline contract with your preferred LLM runner (see assess/lsa/adapters/generic/README.md)")


RUNTIMES = {"claude-code": build_claude_code, "codex": build_codex, "cursor": build_cursor, "generic": build_generic}
ALIASES = {"claude": "claude-code", "openhands": "generic"}


def resolve_runtime(name: str) -> str:
    """Map a runtime name or alias to a RUNTIMES key; raise ValueError if unknown."""
    key = ALIASES.get(name.strip().lower(), name.strip().lower())
    if key not in RUNTIMES:
        raise ValueError(f"unknown runtime {name!r}; choose one of: {', '.join(sorted(RUNTIMES))}")
    return key


def build(runtime: str, dest: Path) -> None:
    """Generate the adapter files for runtime into dest."""
    RUNTIMES[resolve_runtime(runtime)](Path(dest).resolve())


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    try:
        build(sys.argv[1], Path(sys.argv[2]))
    except ValueError as e:
        print(f"error: {e}\n{__doc__}")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
