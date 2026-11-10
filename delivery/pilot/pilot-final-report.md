# Komagu Pilot Final Delivery & ROI Report (Weeks 9–12)
## Komagu パイロット最終成果報告書および費用対効果（ROI）測定レポート

> [!WARNING]
> **Internal fallback run. Not client evidence. Do not quote to clients.**
> This report records an internal fallback run on Komagu's own demo application (Deliverable D6 Member Portal, `examples/member-portal`, 24 endpoints, including deliberately vulnerable test endpoints). No client system or real legacy system was involved. Hours were mostly logged by agents (24.0 of 28.0 hours agent-only, 2.0 by a person, 2.0 joint). Under the [Boilerplate 1 Delivery Plan](../../docs/boilerplate-1-delivery-plan.md), only a pilot on a real system may supply numbers shown to clients, so the results below are internal only.
>
> **社内フォールバック実施の記録であり、顧客実績ではありません。顧客向けに引用しないでください。**
> 本報告書は、Komagu 自身のデモアプリケーション（成果物D6 会員ポータル、`examples/member-portal`、24エンドポイント、意図的に脆弱性を持たせたテスト用エンドポイントを含む）を対象とした社内フォールバック実施の記録です。顧客システムおよび実際のレガシーシステムは対象に含まれていません。工数の大部分はエージェントが記録したものです（全28.0時間のうち、エージェントのみ24.0時間、人2.0時間、共同2.0時間）。[Boilerplate 1 Delivery Plan](../../docs/boilerplate-1-delivery-plan.md) により、顧客に提示できる数値は実システムでのパイロットから得たものに限られるため、以下の結果は社内限りの参考情報です。

- **Project**: Komagu — Automated Legacy Security Audit & Modernization Boilerplate
- **Deliverable Reference**: Pilot Stage (Weeks 9–12) / Issue #79 (`pilot(w12): re-test, measure ROI & prepare Stage 2 Go/No-go review`)
- **Target System**: Deliverable D6 — Member Portal (`examples/member-portal`)
- **System Sizing**: 24 endpoints (12 .NET 8 ASP.NET Core, 12 Kotlin Spring Boot 3, PostgreSQL / SQLite)
- **Reporting Date**: 2026-10-19
- **Project Lead & Principal Architect**: Harry Nguyen
- **Status**: **INTERNAL FALLBACK RUN: internal criteria met on the demo app; internal Stage 2 recommendation only; not client evidence**

---

## 1. Executive Summary / エグゼクティブサマリー

### English
The Pilot phase (Weeks 9–12) of Project Komagu was executed on Deliverable D6 (Member Portal) as an internal fallback to exercise the platform's workflow, security controls, and effort tracking on Komagu's own demo application. It does not establish real-world feasibility. The internal targets from [ADR-0005](../../docs/adr/0005-effort-baseline-and-roi-measurement.md) were met on the demo app; the real-system pilot required by the [Boilerplate 1 Delivery Plan](../../docs/boilerplate-1-delivery-plan.md) remains open:
- **100% of Security Findings Remediated**: All 8 accepted vulnerabilities (6 BOLA / IDOR and 2 SQL Injection) were eliminated using Boilerplate 1 components (**Komagu D1 Authz** and **Komagu D3 Safe Query**).
- **Edge Layer Defense (D4)**: Kong Gateway and Coraza WAF (OWASP CRS v4) were deployed in DB-less declarative mode, demonstrating real-time blocking of SQLi, XSS, and Path Traversal with HTTP 403, and automated rate-limiting protection with HTTP 429.
- **Continuous Cross-User CI (D5)**: An automated D5 regression test harness was integrated into GitHub Actions, enforcing deny-by-default (HTTP 404) cross-user authorization checks on every Pull Request.
- **Internal Effort Result (not client evidence)**: Logged effort across the run, mostly by agents, was **3.5 Person-Days (28.0 hours)**. That is an internal **81.1% reduction** against the modeled Tier 2 baseline (18.5 person-days) and **86.1% reduction** against an IPA-derived estimate (25.2 person-days), above the internal $\ge 50\%$ threshold.
- **Stage 2 Recommendation**: **Internal GO only**, not client-validated, for continuing engineering on Stage 2 modernization boilerplates (BP2 Zero-Privilege DB, BP3 Multi-Tenancy, BP4 Audit Trail, BP5 DevSecOps CI/CD).

### 日本語 (Japanese)
Komagu プロジェクトのパイロット運用（第9週〜第12週）は、成果物D6「会員ポータル（Member Portal）」を対象とした社内フォールバックとして実施され、プラットフォームのワークフロー、セキュリティ対策、および工数記録をデモアプリケーション上で試行しました。実環境での実現可能性を実証するものではありません。[ADR-0005](../../docs/adr/0005-effort-baseline-and-roi-measurement.md) の社内目標はデモアプリケーション上で達成しましたが、配備計画が求める実システムでのパイロットは未実施です。
- **検出された脆弱性の100%解消**: 検出・承認された全8件の脆弱性（BOLA/IDOR 6件、SQLインジェクション 2件）を、ボイラープレート1のコンポーネント（**Komagu D1 認可** および **Komagu D3 安全クエリ**）により完全改修（100%解消）。
- **エッジ防御（D4）の展開**: Kong GatewayとCoraza WAF（OWASP CRS v4）をDBレス・宣言的設定で配置し、SQLi/XSS/パストラバーサルをHTTP 403で即時遮断、DoS対策レート制限（HTTP 429）を実証。
- **継続的クロスユーザー認可CI（D5）**: GitHub Actionsにおいて、認可不備を即時検知するD5自動テストスイートを確立し、リグレッション防止体制を配備。
- **社内工数結果（顧客実績ではありません）**: 本実施で記録された工数（大部分はエージェントによる記録）は **3.5人日（28.0時間）** です。モデルに基づくスクラッチ改修基準（18.5人日）に対して社内結果で **81.1%の削減**、IPA（情報処理推進機構）の指標から算出した推定値（25.2人日）に対して **86.1%の削減** であり、社内判定ライン $\ge 50\%$ を上回りました。
- **Stage 2 判定**: **社内推奨のGOのみ**（顧客による検証なし）。次期ボイラープレート（BP2 ゼロ特権DB、BP3 マルチテナント、BP4 監査証跡、BP5 DevSecOps CI/CD）の開発継続を社内で推奨。

---

## 2. Pilot Scope & Architecture

- **Audit Target System**: Deliverable D6 (`examples/member-portal`)
- **Technology Stack**:
  - Backend 1: C# / ASP.NET Core (.NET 8), Entity Framework Core
  - Backend 2: Kotlin / Spring Boot 3, Spring Data JPA / Hibernate
  - Databases: PostgreSQL / SQLite
  - Edge Gateway: Kong Gateway 3.6 (DB-less) + Coraza WAF (OWASP CRS v4)
  - CI/CD: GitHub Actions (Matrix test across .NET 8, Java 17, Python 3.8/3.11)
- **Total API Endpoints Audited**: 24 endpoints
  - Orders Service (Read, Update, Delete, Search)
  - Profile & Persona Management
  - Health & Metadata

```
+----------------------------------------------------------------------------------------------------+
|                                    PILOT INTEGRATION ARCHITECTURE                                  |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|    [External Client / Attacker]                                                                    |
|                 │                                                                                  |
|                 ▼                                                                                  |
|    [D4 Edge Protection] ── Kong Gateway 3.6 + Coraza WAF (OWASP CRS v4)                            |
|                 │       • Drops SQLi / XSS / Traversal -> HTTP 403                                 |
|                 │       • Enforces Per-IP Rate Limiting -> HTTP 429                                |
|                 ▼                                                                                  |
|    [Upstream Application Services]                                                                 |
|         ├── .NET 8 Backend (ASP.NET Core)                                                          |
|         │     • D1: IKomaguAuthorizationService (Deny-by-default -> HTTP 404)                     |
|         │     • D3: EF Core FromSqlInterpolated Parameterization                                   |
|         │                                                                                          |
|         └── Kotlin Spring Boot 3 Backend                                                           |
|               • D1: KomaguSecurityManager (Resource ownership check -> HTTP 404)                   |
|               • D3: JPA Parameterized Criteria Queries                                             |
|                                                                                                    |
|    [Continuous CI Verification]                                                                    |
|         • D5 Cross-User Automated CI Runner (Schemathesis & Python test runner)                    |
+----------------------------------------------------------------------------------------------------+
```

---

## 3. Security Findings & Remediation Matrix

All 8 vulnerabilities accepted during the Phase 5–6 audit sign-off ([Issue #76](https://github.com/hoanghainh1188/komagu/issues/76)) were completely neutralized:

| Finding ID | CWE | Vulnerability Class | Stack / Component | Endpoint | Remediation Component | Verification Result |
|---|---|---|---|---|---|---|
| **F-BOLA-001** | CWE-639 | BOLA / IDOR (Read) | .NET 8 | `GET /api/v1/test/legacy-orders/{id}` | **D1**: `AuthorizeAsync(User, order, Read)` | **REMEDIATED (404)** |
| **F-BOLA-002** | CWE-639 | BOLA / IDOR (Update) | .NET 8 | `PUT /api/v1/test/legacy-orders/{id}` | **D1**: `AuthorizeAsync(User, order, Update)` | **REMEDIATED (404)** |
| **F-BOLA-003** | CWE-639 | BOLA / IDOR (Delete) | .NET 8 | `DELETE /api/v1/test/legacy-orders/{id}` | **D1**: `AuthorizeAsync(User, order, Delete)` | **REMEDIATED (404)** |
| **F-BOLA-004** | CWE-639 | BOLA / IDOR (Read) | Spring Boot 3 | `GET /api/v1/test/legacy-orders/{id}` | **D1**: `requireOwnership(order, READ)` | **REMEDIATED (404)** |
| **F-BOLA-005** | CWE-639 | BOLA / IDOR (Update) | Spring Boot 3 | `PUT /api/v1/test/legacy-orders/{id}` | **D1**: `requireOwnership(order, UPDATE)` | **REMEDIATED (404)** |
| **F-BOLA-006** | CWE-639 | BOLA / IDOR (Delete) | Spring Boot 3 | `DELETE /api/v1/test/legacy-orders/{id}` | **D1**: `requireOwnership(order, DELETE)` | **REMEDIATED (404)** |
| **F-INJ-001** | CWE-89 | SQL Injection | .NET 8 | `GET /api/v1/test/legacy-search` | **D3**: EF Core `FromSqlInterpolated` | **REMEDIATED (Safe)** |
| **F-INJ-002** | CWE-89 | SQL Injection | Spring Boot 3 | `GET /api/v1/test/legacy-search` | **D3**: JPA `.setParameter("query", ...)` | **REMEDIATED (Safe)** |

**Remaining Accepted Findings: 0 / 8 (100% Fix Rate).**

---

## 4. Empirical Verification & Re-Scan Results

Re-scan tests executed across all audit, remediation, and edge components yielded 100% passing results:

1. **Member Portal Remediation & D5 CI (`test_d6_remediation_verification.py` & `test_d6_demo_app.py`)**:
   - Total Tests: 11
   - Passed: 11/11 (0 failures, 0 errors, 1.4s duration)
   - Cross-user attacker read/update/delete blocked with HTTP 404.
   - D5 cross-user test runner exit code: `0` (`[PASS - SECURE]`).
2. **Edge Protection Suite (`verify_pilot_edge.py`)**:
   - Total Tests: 6
   - Passed: 6/6 (SQLi dropped 403, XSS dropped 403, Traversal dropped 403, Rate limit triggered 429).
3. **LSA Pipeline Re-Test (`assess/lsa/tests/run_tests.py`)**:
   - 10 legacy stacks verified: ALL PASSED.
4. **Unit Test Suites (.NET & Spring)**:
   - .NET 8 (D1, D2, D3): 35/35 PASSED.
   - Kotlin / Spring Boot 3 (D1, D2, D3, D6): ALL PASSED.

---

## 5. Effort & ROI Measurement (ADR-0005 Compliance, Internal Only)

> [!WARNING]
> **Internal result only. Do not quote these figures to clients.**
> Every effort and cost figure in this section comes from the internal fallback run on Komagu's own demo application (D6), not from a client or real legacy system. Hours were mostly logged by agents (24.0 of 28.0 hours agent-only), and all entries are dated 2026-10-18 to 2026-10-19 although the stage labels span Weeks 9–12. Limits of the comparison:
> - The 18.5 person-day baseline is a modeled planning hypothesis (ADR-0005 §2), and it includes 3.0 person-days of D2 OIDC work that the timesheet does not record.
> - The 25.2 person-day figure applies the ADR-0005 §1 formula, defined for 30–150 endpoints, to 24 endpoints. `pilot-config.json` records 22.0 person-days for this baseline.
> - The JPY figures are arithmetic on these baselines, not realized savings.
>
> **社内限りの結果です。本節の数値を顧客向けに引用しないでください。**
> 本節の工数および費用の数値はすべて、Komagu 自身のデモアプリケーション（D6）を対象とした社内フォールバック実施によるものであり、顧客システムや実際のレガシーシステムの結果ではありません。工数の大部分はエージェントが記録したものです（全28.0時間のうち、エージェントのみ24.0時間）。また、工程ラベルは第9週〜第12週にわたりますが、記録日はすべて2026-10-18〜2026-10-19です。比較の制約は次のとおりです。
> - 18.5人日の基準値はモデルに基づく計画上の仮説（ADR-0005 §2）であり、タイムシートに記録のないD2 OIDC作業3.0人日を含みます。
> - 25.2人日は、30〜150エンドポイントを対象とするADR-0005 §1の計算式を24エンドポイントに適用した値です。`pilot-config.json` にはこの基準値として22.0人日が記録されています。
> - 円建ての金額はこれらの基準値に基づく計算結果であり、実現した削減額ではありません。

### A. Actual Time Invested (Timesheet Breakdown)
Extracted directly from [`delivery/pilot/timesheet-pilot.csv`](timesheet-pilot.csv):

| Stage / Phase | Tag | Description | Hours Spent | Person-Days (8h/day) |
|---|---|---|:---:|:---:|
| **Week 9: Prep** | `[PILOT-LSA]` | Pilot configuration & environment setup | 2.0 | 0.250 |
| **Week 9: Phase 1-2** | `[PILOT-LSA]` | Pre-scan, AST route mapping, stack detection | 3.0 | 0.375 |
| **Week 10: Phase 3-4** | `[PILOT-LSA]` | Route mapping, BOLA audit, SQLi audit | 6.0 | 0.750 |
| **Week 10: Phase 5** | `[PILOT-LSA]` | Skeptic verification (0 false positives) | 3.0 | 0.375 |
| **Week 10: Phase 6** | `[PILOT-LSA]` | Bilingual reporting & Person B sign-off | 2.0 | 0.250 |
| **Week 10: D4 Deploy** | `[PILOT-GATEWAY]` | Kong Gateway + Coraza WAF deployment | 4.0 | 0.500 |
| **Week 10–12: Fix** | `[PILOT-REMEDIATE]`| Remediate 8 findings (D1/D3) & D5 CI setup | 6.0 | 0.750 |
| **Week 12: Re-Test** | `[PILOT-TEST-CI]` | Verification re-scan, ROI & final report | 2.0 | 0.250 |
| **TOTAL** | — | **Entire Pilot Engagement (Weeks 9–12)** | **28.0 h** | **3.500 PD** |

---

### B. ROI & Effort Reduction Rate Calculations

#### 1. Comparison Against Tier 2 Reference Baseline (Scratch Implementation on D6)
Per ADR-0005 §2, manual scratch implementation of the identical security baseline for 24 endpoints is modeled at **18.5 Person-Days**:

$$\text{Effort Reduction Rate (Tier 2)} = \frac{18.5 - 3.5}{18.5} \times 100\% = \mathbf{81.08\% \approx 81.1\%}$$

$$\text{Person-Days Saved} = 18.5 - 3.5 = \mathbf{15.0\text{ Person-Days}}$$

#### 2. Comparison Against Tier 1 Industry Benchmark (IPA Japan Software Metrics)
Applying the ADR-0005 §1 formula, derived from Information-technology Promotion Agency (IPA) Japan metrics, to 24 endpoints (below its 30–150 endpoint range) gives **25.2 Person-Days**:

$$\text{Effort Reduction Rate (Tier 1 IPA)} = \frac{25.2 - 3.5}{25.2} \times 100\% = \mathbf{86.11\% \approx 86.1\%}$$

$$\text{Person-Days Saved vs. IPA} = 25.2 - 3.5 = \mathbf{21.7\text{ Person-Days}}$$

#### 3. Illustrative Cost Arithmetic (Internal Only, Not Realized Savings)
Applying the blended standard market rate of **80,000 JPY / Person-Day** (~1,000,000 JPY / Person-Month) for Senior Software / Security Engineers:

$$\text{Cost Savings (vs. Scratch Baseline)} = 15.0\text{ PD} \times 80,000\text{ JPY} = \mathbf{1,200,000\text{ JPY}}$$

$$\text{Cost Savings (vs. IPA Standard)} = 21.7\text{ PD} \times 80,000\text{ JPY} = \mathbf{1,736,000\text{ JPY}}$$

---

### C. Internal Evaluation on the Demo App (Not Client Validation)

| Acceptance Metric | Requirement Threshold | Actual Measured Result | Assessment |
|---|:---:|:---:|:---:|
| **Finding Fix Rate** | 100% of accepted findings | 8/8 (100%) | **PASS** |
| **Remaining Critical/High Vulns** | 0 | 0 | **PASS** |
| **Effort Reduction Rate** | $\ge 50\%$ | **81.1%** (vs Tier 2) / **86.1%** (vs IPA), internal | **PASS (internal only)** |
| **CI Automation** | Automated cross-user checks | GitHub Actions D5 pipeline active | **PASS** |
| **Client Reference Status** | Verified repeatable methodology | Internal demo-app run only; no client reference | **NOT MET** |

---

## 6. Internal Engineering Artifacts (Not a Client Reference)

The fallback run on Deliverable D6 produced the internal engineering artifacts below. They are not a client reference or 導入実績 (customer track record) and must not be presented as one in presales or board material:
1. **Reproducible Demo-App Evidence**:
   - Complete audit trail (`delivery/pilot/audit-out/`) with AST mappings and verification logs.
   - Verifiable test suites that prove both failure on unpatched endpoints and pass on remediated ones.
2. **WAF & Gateway Configuration**:
   - Kong `deck.yaml` and Coraza CRS configurations exercised against the demo app.
3. **Remediation Libraries**:
   - .NET NuGet (`Komagu.Security.Authorization`, `Komagu.Security.Query`) and Spring Boot starter (`komagu-security-spring`), exercised on the demo app. This run does not establish production readiness on a real legacy system.

---

## 7. Board of Directors (BOD) Stage 2 Go/No-go Recommendation

### Internal Recommendation: **GO (社内推奨のみ)**

Based on internal criteria met on the demo app only, the engineering team's internal view is to continue **Stage 2 Modernization Expansion** engineering. This is not a client-validated result, and the real-system pilot criteria in the Delivery Plan remain open:
- **Issue #80**: `feat(boilerplate-5): DevSecOps CI/CD Hardening Boilerplate`
- **Issue #81**: `feat(boilerplate-2): Zero-Privilege Secretless Database Access Boilerplate`
- **Issue #82**: `feat(boilerplate-3): Multi-Tenancy Hardening Boilerplate`
- **Issue #83**: `feat(boilerplate-4): Tenant Isolation & Audit Trail Boilerplate`
- **Issue #84**: `feat(remediate): expand D1/D2/D3 to Go, Python, and Node.js`

---

*Report prepared and submitted by:*  
**Harry Nguyen** (Principal Architect / BOD / BrSE) & **Antigravity AI Agent**  
*Project Komagu Core Engineering Team*
