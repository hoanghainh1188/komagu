# AGENTS.md — LSA Legacy Security Audit Kit

If you are an AI agent and a user asks you to audit a legacy codebase for
BOLA/IDOR or for SQL/NoSQL queries built from strings:

1. Read `prompts/00-orchestrator.md`. It is your procedure.
2. Before every role, read `prompts/_shared-rules.md` and the role prompt.
3. Never write into the audited repository. Output goes to the audit OUT folder.
4. If your runtime has sub-agents, run each role as a separate sub-agent with
   a fresh context. If it does not, run the roles one after another and start
   the verifier role in a new conversation.

If you are asked to change this kit itself: keep prompts runtime-neutral,
keep scripts standard-library-only (Python 3.8+), and run
`python3 tests/run_tests.py` after every change.
