# Delivery Report: Pilot Finding Remediation (D1 / D3) & Continuous D5 CI

- **Deliverable**: Pilot Stage (Weeks 10–12) — Deliverable D6 Remediation & D5 CI
- **Issue Reference**: `#78 pilot(w10-12): remediate findings with D1/D2/D3 & setup D5 CI`
- **Audit Target**: `examples/member-portal` (Deliverable D6)
- **Status**: Completed (100% remediated, 100% CI automated)
- **Date**: 2026-10-18

---

## 1. Executive Summary

In accordance with Pilot Phase Weeks 10–12 and following the accepted security audit findings from Issue #76 (`delivery/pilot/audit-out/report.md` / `report.ja.md`), all **8 accepted security vulnerabilities** (6 BOLA and 2 SQL Injection) across both .NET 8 and Kotlin / Spring Boot 3 backends have been **100% remediated** using Boilerplate 1 components:
- **Komainu D1 (Object-Level Authorization)**: Neutralized all 6 BOLA vulnerabilities by introducing fine-grained resource authorization (`IKomaguAuthorizationService` in .NET and `KomainuSecurityManager` in Spring Boot) with secure **404 Not Found (deny-by-default)** semantics to prevent resource enumeration.
- **Komainu D3 (Safe Query Formulation)**: Neutralized both SQL Injection vulnerabilities by replacing dynamic SQL string concatenation with type-safe parameterized queries (`FromSqlInterpolated` in EF Core and JPA parameterized criteria queries in Spring Boot).
- **Komainu D5 (Continuous Cross-User Authorization CI)**: Setup automated CI verification pipeline enforcing regression-free authorization checks on every Pull Request and branch merge.

---

## 2. Remediation Matrix (8/8 Accepted Findings)

| Finding ID | CWE | Vulnerability Class | Stack / Component | Endpoint & File | Remediation Component & Strategy | Verification Status |
|---|---|---|---|---|---|---|
| **F-BOLA-001** | CWE-639 / CWE-862 | BOLA / IDOR (Read) | .NET 8 (C#) | `GET /api/v1/test/legacy-orders/{id}`<br>`Controllers/LegacyTestController.cs` | **Komainu D1**: Injected `IKomaguAuthorizationService`, enforced `AuthorizeAsync(User, order, ResourceOperation.Read)`. Returns `404 Not Found` on unowned objects. | **PASS** (D5 runner + Unit test) |
| **F-BOLA-002** | CWE-639 / CWE-862 | BOLA / IDOR (Update) | .NET 8 (C#) | `PUT /api/v1/test/legacy-orders/{id}`<br>`Controllers/LegacyTestController.cs` | **Komainu D1**: Enforced `AuthorizeAsync(User, order, ResourceOperation.Update)`. Returns `404 Not Found`. | **PASS** (D5 runner + Unit test) |
| **F-BOLA-003** | CWE-639 / CWE-862 | BOLA / IDOR (Delete) | .NET 8 (C#) | `DELETE /api/v1/test/legacy-orders/{id}`<br>`Controllers/LegacyTestController.cs` | **Komainu D1**: Enforced `AuthorizeAsync(User, order, ResourceOperation.Delete)`. Returns `404 Not Found`. | **PASS** (D5 runner + Unit test) |
| **F-BOLA-004** | CWE-639 / CWE-862 | BOLA / IDOR (Read) | Kotlin / Spring Boot 3 | `GET /api/v1/test/legacy-orders/{id}`<br>`io.komainu.portal.controller.Controllers.kt` | **Komainu D1**: Injected `KomainuSecurityManager`, enforced `requireOwnership(order, ResourceOperation.READ)`. Throws `AuthorizationDeniedException` mapped to 404. | **PASS** (Spring build + Integration test) |
| **F-BOLA-005** | CWE-639 / CWE-862 | BOLA / IDOR (Update) | Kotlin / Spring Boot 3 | `PUT /api/v1/test/legacy-orders/{id}`<br>`io.komainu.portal.controller.Controllers.kt` | **Komainu D1**: Enforced `requireOwnership(order, ResourceOperation.UPDATE)`. Throws exception mapped to 404. | **PASS** (Spring build + Integration test) |
| **F-BOLA-006** | CWE-639 / CWE-862 | BOLA / IDOR (Delete) | Kotlin / Spring Boot 3 | `DELETE /api/v1/test/legacy-orders/{id}`<br>`io.komainu.portal.controller.Controllers.kt` | **Komainu D1**: Enforced `requireOwnership(order, ResourceOperation.DELETE)`. Throws exception mapped to 404. | **PASS** (Spring build + Integration test) |
| **F-INJ-001** | CWE-89 | SQL Injection | .NET 8 (C#) | `GET /api/v1/test/legacy-search`<br>`Controllers/LegacyTestController.cs` | **Komainu D3**: Replaced `FromSqlRaw($"...{query}...")` with parameterized `FromSqlInterpolated($"...{pattern}")`. | **PASS** (SQLi probe + Unit test) |
| **F-INJ-002** | CWE-89 | SQL Injection | Kotlin / Spring Boot 3 | `GET /api/v1/test/legacy-search`<br>`io.komainu.portal.controller.Controllers.kt` | **Komainu D3**: Replaced native query concatenation with parameterized JPA query `.setParameter("query", "%$query%")`. | **PASS** (Spring build + Query test) |

---

## 3. Architecture & Dual-Mode Design

To support both **production security** and **negative automated verification**, the legacy test controllers maintain a dual-mode switch governed by environment configuration:

- **Default / Remediated Mode (`ENABLE_SECURITY_TEST_VULNERABILITIES=false` or unset)**:
  - All endpoints enforce Komainu D1 object-level ownership checks (`AuthorizeAsync` / `requireOwnership`).
  - Cross-user access returns HTTP `404 Not Found` (deny-by-default, concealing existence).
  - Search queries strictly use parameterized queries (Komainu D3), rendering SQL syntax exploitation ineffective.
- **Negative Test Fixture Mode (`ENABLE_SECURITY_TEST_VULNERABILITIES=true`)**:
  - Used specifically by test runner harness (`test_02_d5_fails_on_planted_bola` in `test_d6_demo_app.py`) to verify that the D5 runner accurately trips an alarm and returns exit code 1 when evaluating an unpatched target.

---

## 4. Continuous D5 Cross-User Authorization CI

The remediation is continuously defended against regression in GitHub Actions:
- **Workflow**: `.github/workflows/remediate-tests.yml`
- **Job**: `dotnet-suites`
- **Step**: `Test D6 Member Portal End-to-End BOLA & D5 Continuous Authorization Verification`
- **Automated Checks**:
  1. `test_d6_demo_app.py` (5 tests): Verifies owner access, verifies that D5 trips on planted BOLA, verifies D1 protected endpoints, tenant isolation, and safe sorting.
  2. `test_d6_remediation_verification.py` (6 tests):
     - D5 runner against `/api/v1/test/legacy-orders/{id}` returns code 0 (`[PASS - SECURE]`).
     - Cross-user attacker GET directly returns 404.
     - Cross-user attacker PUT directly returns 404.
     - Cross-user attacker DELETE directly returns 404.
     - SQL injection probes on legacy search safely neutralize payload with 0 records leaked.
- **Total Suite Execution Time**: ~1.4 seconds in CI, maintaining fast feedback loops.

---

## 5. Verification Commands

```bash
# 1. Run all D6 Member Portal tests (Planted + Remediated D5 CI)
python3 -m unittest discover -s examples/member-portal/tests -p "test_*.py"

# 2. Run dedicated D5 continuous authorization verification suite
python3 -m unittest examples/member-portal/tests/test_d6_remediation_verification.py

# 3. Verify .NET 8 unit tests across D1, D2, D3
dotnet test remediate/authz/dotnet/tests/Komagu.Security.Authorization.Tests/Komagu.Security.Authorization.Tests.csproj
dotnet test remediate/identity/dotnet/tests/Komagu.Security.Identity.Tests/Komagu.Security.Identity.Tests.csproj
dotnet test remediate/query/dotnet/tests/Komagu.Security.Query.Tests/Komagu.Security.Query.Tests.csproj

# 4. Verify Kotlin / Spring Boot tests across D1, D2, D3
(cd remediate/authz/spring && gradle test --no-daemon)
(cd remediate/identity/spring && gradle test --no-daemon)
(cd remediate/query/spring && gradle test --no-daemon)
(cd examples/member-portal/backend-spring && gradle test --no-daemon)
```
