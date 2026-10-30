# ADR-0006: Runtime-Neutral Architecture and Bring-Your-Own-LLM (BYO-LLM) Model

Date: 2026-10-24 · Status: accepted · Owner: Harry

## Context

Komagu is designed for enterprise legacy modernization and security audits. Legacy source code often contains proprietary business logic, sensitive customer records, and confidential algorithms subject to non-disclosure agreements (NDAs) and regulatory compliance (e.g. financial institutions, healthcare, government).

A critical architectural question is whether the Komagu core CLI and audit engine should directly embed external LLM SDKs (e.g., `openai`, `anthropic`, `google-generativeai`) and make direct network calls to commercial cloud LLM APIs.

## Decision

Komagu adopts a **Two-Tier Architecture** with a strictly **Runtime-Neutral** and **Bring-Your-Own-LLM (BYO-LLM)** execution model:

### 1. Two-Tier Separation

```text
┌────────────────────────────────────────────────────────┐
│ Tier 1: Deterministic Engine (Offline & Local)          │
│ - CLI (komagu scan, fix, protect, test)               │
│ - Python 3.8+ Standard Library Only (Zero dependencies)│
│ - Fast regex/AST pre-scan, candidate extraction        │
│ - Edge WAF generation, AST query rewriting             │
└──────────────────────────┬─────────────────────────────┘
                           │ Outputs candidate batches
                           ▼
┌────────────────────────────────────────────────────────┐
│ Tier 2: Cognitive AI Multi-Agents (BYO-LLM)            │
│ - Multi-Agent Prompts (00-orchestrator to 60-reporter) │
│ - Pattern Knowledge Base & JSON Schemas                │
│ - Driven by User's AI Runtime (Claude Code, Cursor,    │
│   Antigravity, OpenHands, or Private LLM API)          │
│ - Adversarial Skeptic Verifier for 0 false positives   │
└────────────────────────────────────────────────────────┘
```

### 2. Zero Hardcoded LLM SDK Coupling

- The core audit repository (`assess/lsa/`) must remain **100% standard-library-only** (Python 3.8+).
- No API keys, vendor-specific SDKs, or hardcoded external network endpoints are permitted in the audit scripts.
- Data exchange between Tier 1 and Tier 2 is conducted via formal JSON schemas in `contracts/schemas/`.

### 3. Integration via Standardized Adapters

Instead of locking into one model provider, Komagu provides adapter generators (`assess/lsa/adapters/build_adapters.py`, exposed in the CLI as `komagu init --ai <runtime> [DEST]`):
- **Claude Code**: Produces `.claude/skills/` and `.claude/agents/` subagent files.
- **OpenAI Codex**: Produces a repo-scoped skill in `.agents/skills/`, custom agents in `.codex/agents/*.toml`, and a managed section in `AGENTS.md`.
- **Cursor**: Produces `.cursor/rules/` rule files.
- **Generic LLM Runner / Private Cloud**: Produces system prompt bundles and pipeline contract JSON for private endpoints (e.g., vLLM, Ollama, self-hosted models, or custom API wrappers).

## Consequences

- **Enterprise Data Sovereignty**: Code under audit is never transmitted to third-party AI APIs without explicit user configuration and consent, satisfying [`governance/usage-policy.md`](../../governance/usage-policy.md).
- **Zero Dependency Hell**: Works immediately on legacy environments without conflicting with existing Python package versions.
- **Transparency**: Clear separation between deterministic candidate identification and cognitive semantic reasoning, avoiding user confusion about what is running locally versus with AI.
