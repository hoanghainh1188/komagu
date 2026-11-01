# ADR-0008: Transition from Open Core to 100% Open Source (Apache 2.0)

Date: 2026-11-01 · Status: accepted · Owner: Harry (BOD / Principal Architect) · Supersedes [ADR-0002](0002-ip-position-open-core.md)

## Context

In [ADR-0002](0002-ip-position-open-core.md), Komagu adopted an **Open Core** model where the assessment engine (`assess/lsa/`), contracts (`contracts/`), and governance (`governance/`) were open, while remediation implementations, advanced operate rules, delivery playbooks, and strategic documents remained closed/proprietary.

However, operating in the enterprise AppSec and legacy modernization domain revealed crucial strategic insights:
1. **Security Demands Radical Transparency:** Enterprise security leaders (CISO, CTO, Head of Security) hesitate to integrate proprietary or partially-closed tools into critical software supply chains. An audit and remediation platform must itself be 100% auditable by the community and enterprise security teams ("Who audits the auditor?").
2. **Accelerated Global Adoption & Network Effects:** Restricting remediation adapters (`remediate/`) or operate verification modules behind a commercial boundary created friction for developers. Fully open-sourcing the end-to-end autonomous lifecycle (Assess → Protect → Remediate → Operate) enables frictionless adoption and positions Komagu as the global standard for legacy authorization defense.
3. **Sustainable Commercialization via Services & Cloud:** Industry-leading security platforms (e.g. HashiCorp early days, Trivy/Aqua Security, Coraza, Semgrep OSS) demonstrate that enterprise monetization is superior when built on:
   - **Enterprise Modernization & Advisory Services:** Direct consulting, custom stack migration, and mission-critical modernization delivery.
   - **Enterprise SLA & Support:** Dedicated support, custom rule authoring, and compliance certification guarantees.
   - **Managed Cloud & SIEM Integrations:** Managed control plane, team collaboration dashboard, and enterprise SOC connectors.

## Decision

We officially supersede [ADR-0002](0002-ip-position-open-core.md) and transition Komagu into a **100% Open Source Software (OSS)** platform under the **Apache License 2.0**.

### 1. Unified Repository & Component Licensing

All components across the repository are now open source:

| Lifecycle Component | Scope & Status | Distribution & Licensing |
|---|---|---|
| `assess/` | **Open Source** | Apache 2.0 (LSA kit, 10 legacy stacks pre-scan, Multi-AI Consensus prompts) |
| `contracts/` | **Open Source** | Apache 2.0 (JSON Schemas for finding, route-inventory, stack-profile, verification) |
| `remediate/` | **Open Source** | Apache 2.0 (Authz guards for .NET, Spring, NestJS, FastAPI, Go; safe query shims; eKYC, tenancy RLS, and Coraza WAF configs) |
| `operate/` | **Open Source** | Apache 2.0 (AST code patcher `komagu fix`, cross-user test runner `komagu test`, CycloneDX SBOM, DevSecOps runners) |
| `governance/` | **Open Source** | Apache 2.0 (Two-Person rule, AI code processing ethics, zero-retention guidelines) |
| `examples/` | **Open Source** | Apache 2.0 (Member Portal reference architecture with Alice vs. Bob IDOR demos) |
| `docs/` | **Open Architecture** | Public engineering specifications, ADRs, user guides, and research articles |

### 2. Commercial & Community Strategy

1. **Community-Driven Evolution:** Developers and security researchers worldwide are welcomed to contribute rule definitions, legacy language adapters (e.g. COBOL, Perl, Ruby), and test fixtures via GitHub Pull Requests.
2. **Commercial Offerings:** Enterprise monetization is cleanly decoupled from source code access, shifting entirely to professional engineering delivery, high-assurance SLAs, custom enterprise system integrations, and specialized modernization engagements.
3. **License Standardization:** Standardize on **Apache-2.0** across package manifests, CLI headers, and root repository `LICENSE` to provide explicit patent grants and corporate-friendly adoption terms.

## Consequences

- **Trust & Credibility:** Complete transparency eliminates customer skepticism, proving zero hidden telemetry and enabling independent verification of all security claims.
- **Documentation Updates:** `README.md`, `package.json`, and `docs/README.md` must be updated to reflect the 100% Open Source Apache 2.0 status.
- **Repository Hygiene:** All future contributions follow public open-source contribution guidelines (`CONTRIBUTING.md`), standard code review, and automated CI gating.
