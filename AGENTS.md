# AGENTS.md — Komagu

Repository layout: see `README.md` and `docs/adr/0001-name-and-repository-structure.md`.

If you are an AI agent and a user asks you to audit a legacy codebase for
BOLA/IDOR or for SQL/NoSQL queries built from strings:

1. Read `assess/lsa/prompts/00-orchestrator.md`. It is your procedure.
   `KIT` is `assess/lsa/`; schemas are in `contracts/schemas/`.
2. Before every role, read `assess/lsa/prompts/_shared-rules.md` and the role prompt.
3. Never write into the audited repository. Output goes to the audit OUT folder.
4. If your runtime has sub-agents, run each role as a separate sub-agent with
   a fresh context. If it does not, run the roles one after another and start
   the verifier role in a new conversation.

If you are asked to change the LSA kit (`assess/lsa/`, `contracts/`): keep
prompts runtime-neutral, keep scripts standard-library-only (Python 3.8+), and
run `python3 assess/lsa/tests/run_tests.py` after every change.
