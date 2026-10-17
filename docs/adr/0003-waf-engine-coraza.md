# ADR-0003: WAF Engine for D4 Gateway — Select OWASP Coraza

Date: 2026-10-17 · Status: accepted · Owner: Harry

## Context

Deliverable D4 in the Boilerplate 1 delivery plan (`docs/boilerplate-1-delivery-plan.md`)
specifies edge protection in front of legacy web applications: Kong API Gateway providing
rate limiting and authentication, coupled with a Web Application Firewall (WAF) running
the OWASP Core Rule Set (CRS) to block SQL/NoSQL injection, cross-site scripting (XSS),
and abuse before requests reach legacy backends.

Two candidate WAF engines were evaluated:
1. **ModSecurity (libmodsecurity v3)**: The legacy industry-standard open-source WAF engine,
   written in C++.
2. **OWASP Coraza**: An enterprise-grade, open-source WAF engine written in 100% pure Go,
   developed as an official OWASP flagship project.

Issue #7 required deciding between ModSecurity and Coraza at the design review.

## Decision

We select **OWASP Coraza** as the WAF engine for Boilerplate 1 (D4).

### Rationale

| Evaluation Criteria | ModSecurity v3 | OWASP Coraza | Winning Choice & Rationale |
|---|---|---|---|
| **Memory safety & stability** | Written in C/C++; vulnerable to memory corruption, buffer overflows, and null-pointer dereferences in regex processing. | Written in 100% pure Go; memory-safe by design with built-in runtime bounds checks. | **Coraza** — Edge components must not introduce memory corruption vectors into client environments. |
| **OWASP Core Rule Set (CRS) support** | Native SecLang support, historically the reference engine for CRS v3. | 100% compatibility with OWASP CRS v3 and v4 (passes full CRS regression test suite). | **Tie** — Both run standard OWASP CRS rules cleanly. |
| **Kong / Cloud-native integration** | Requires heavy C++ dynamic library linking or complex Nginx compilation modules. | Supports proxy-wasm (WebAssembly) plugins and lightweight Docker sidecar deployment; native decK integration. | **Coraza** — Significantly simpler deployment via Docker Compose and declarative gateway workflows. |
| **Maintenance & Ecosystem Velocity** | Commercial support from Trustwave ended in 2024; community maintenance has slowed. | Active OWASP flagship project with frequent updates, widespread cloud-native adoption, and growing commercial backing. | **Coraza** — Forward-looking project with long-term active development. |
| **Container & CI Footprint** | Large container image footprint due to C++ build dependencies and glibc linkage. | Small binary size, static compilation, fast startup in CI/local test environments. | **Coraza** — Facilitates rapid automated testing in developer environments. |

## Implementation for D4

1. **Deployment Architecture:** Coraza runs either as a proxy-wasm filter inside Kong or as a lightweight, pre-configured reverse-proxy container sidecar in the D4 Docker Compose stack.
2. **Rule Set Baseline:** Pre-loaded with OWASP Core Rule Set (CRS) v4, configured with paranoid level 1 (default) and tuned rule exclusions for standard REST APIs.
3. **Automated Verification:** The D4 test suite will execute scripted injection payloads (matching LSA fixture vectors) to verify that malicious requests receive HTTP 403 Forbidden before reaching backend services.

## Consequences

- Zero C++ compilation dependencies in CI and Docker builds.
- Modern, memory-safe edge protection ready for production container deployments.
- Standardized declarative configuration alongside Kong decK files.
