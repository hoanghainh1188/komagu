# Auth Model — member-portal

## 0. Sub-applications

| folder | stack ids | web root |
|---|---|---|
| backend-dotnet | dotnet-webapi | /api/v1 |
| backend-spring | java-spring-mvc | /api/v1 |

## 1. Stacks and data access layers

### backend-dotnet
- Stack: ASP.NET Core 8.0 Web API (`net8.0`, C#) in `backend-dotnet/MemberPortal.Backend.csproj:4`.
- Data Access: Entity Framework Core 8.0 (`Microsoft.EntityFrameworkCore.Sqlite:11`) via `PortalDbContext` in `backend-dotnet/Data/PortalDbContext.cs:6-28`.
- Direct Query Sink: Raw SQL string interpolation via `_dbContext.Orders.FromSqlRaw(rawSql)` in `backend-dotnet/Controllers/LegacyTestController.cs:99`.
- Scoped Query Helper: `.WithUserScope<T, string>(userId, tenantId)` query filter extension in `backend-dotnet/Controllers/OrdersController.cs:35` and `backend-dotnet/Controllers/DocumentsController.cs:30`.

### backend-spring
- Stack: Spring Boot 3.3.4 (Kotlin 2.0.21, Java 17) in `backend-spring/build.gradle.kts:2-5,18`.
- Data Access: Spring Data JPA / Hibernate (`spring-boot-starter-data-jpa:26`) with in-memory H2 database (`application.properties:5-10`).
- Repositories: `OrderRepository` and `DocumentRepository` in `backend-spring/src/main/kotlin/io/komainu/portal/repository/Repositories.kt:10-19`.
- Direct Query Sink: Native SQL string concatenation via `entityManager.createNativeQuery(sql, ...)` in `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:227`.

## 2. Authentication (who is the user)

### backend-dotnet
- Mechanism: Mock Bearer Token authentication via custom handler `DemoAuthenticationHandler` in `backend-dotnet/Program.cs:60-123`. Simulates OIDC claims: `token-user-a` -> `sub: user-a`, `tenant_id: tenant-alpha` (`Program.cs:85-92`); `token-user-b` -> `sub: user-b`, `tenant_id: tenant-alpha` (`Program.cs:93-100`); `token-user-c` -> `sub: user-c`, `tenant_id: tenant-beta` (`Program.cs:101-108`).
- Enforced by (global / per-page / per-controller): Global middleware `app.UseAuthentication()` in `backend-dotnet/Program.cs:50`. However, no global or controller-level `[Authorize]` attribute is declared; unauthenticated requests fall back to `AuthenticateResult.NoResult()` (`Program.cs:75`), proceeding with anonymous identity.
- Current-user accessor(s):
  - `_authzService.GetCurrentUserId(User)` in `backend-dotnet/Controllers/OrdersController.cs:31,81` and `backend-dotnet/Controllers/DocumentsController.cs:26`.
  - `_authzService.GetCurrentTenantId(User)` in `backend-dotnet/Controllers/OrdersController.cs:32,82` and `backend-dotnet/Controllers/DocumentsController.cs:27`.

### backend-spring
- Mechanism: `DemoTokenFilter` (`OncePerRequestFilter`) parsing `Authorization: Bearer <token>` into Spring `UsernamePasswordAuthenticationToken` containing `Jwt` with `sub` and `tenant_id` claims in `backend-spring/src/main/kotlin/io/komainu/portal/Application.kt:134-170`.
- Enforced by (global / per-page / per-controller): Global security filter chain in `backend-spring/src/main/kotlin/io/komainu/portal/Application.kt:123-132`. Explicitly configured with `authorizeHttpRequests { it.anyRequest().permitAll() }` (`Application.kt:127`); authentication is optional at transport level.
- Current-user accessor(s):
  - `securityManager.getCurrentUserId()` in `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:76,104,151`.
  - `securityManager.getCurrentTenantId()` in `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:77,105,152`.

## 3. Authorization (what may the user access)

### backend-dotnet
- Role / function-level checks: None. Role claim `member` is populated (`backend-dotnet/Program.cs:91,99,107,114`), but neither `[Authorize(Roles = "...")]` nor role evaluations exist.
- Object-level (ownership / tenant) checks:
  - Single object load/mutate: `await _authzService.AuthorizeAsync(User, resource, ResourceOperation)` in `backend-dotnet/Controllers/OrdersController.cs:68` (Read), `backend-dotnet/Controllers/OrdersController.cs:109` (Update), `backend-dotnet/Controllers/OrdersController.cs:131` (Delete), and `backend-dotnet/Controllers/DocumentsController.cs:46` (Read). On failure, returns `NotFound()` (HTTP 404) in `OrdersController.cs:72,112,134` and `DocumentsController.cs:49`.
  - Collections: `.WithUserScope<T, string>(userId, tenantId)` applies SQL WHERE filter on `OwnerUserId == userId && TenantId == tenantId` in `backend-dotnet/Controllers/OrdersController.cs:35` and `backend-dotnet/Controllers/DocumentsController.cs:30`.
- Helpers that are SAFE to treat as an ownership check:
  - `_authzService.AuthorizeAsync(User, resource, operation)` in `backend-dotnet/Controllers/OrdersController.cs:68,109,131` and `backend-dotnet/Controllers/DocumentsController.cs:46`: Enforces object ownership and tenant match; non-match halts request with HTTP 404.
  - `.WithUserScope<T, string>(userId, tenantId)` in `backend-dotnet/Controllers/OrdersController.cs:35` and `backend-dotnet/Controllers/DocumentsController.cs:30`: Guarantees query-level isolation by owner and tenant.
- Helpers that LOOK like checks but are NOT (e.g. only check login):
  - Feature toggle check `if (!_vulnerabilitiesEnabled)` in `backend-dotnet/Controllers/LegacyTestController.cs:30,49,71,92`: Only checks environment flag `ENABLE_SECURITY_TEST_VULNERABILITIES`, not caller authorization or ownership.
  - `SortAllowList.ValidateColumnName(sort)` in `backend-dotnet/Controllers/OrdersController.cs:39`: Whitelists SQL order-by column identifiers; does not check object ownership.

### backend-spring
- Role / function-level checks: None. Authority `ROLE_USER` is assigned in `backend-spring/src/main/kotlin/io/komainu/portal/Application.kt:164` but never asserted.
- Object-level (ownership / tenant) checks:
  - Single object load/mutate: `securityManager.requireOwnership(resource, ResourceOperation)` in `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:98` (Read), `Controllers.kt:125` (Update), `Controllers.kt:136` (Delete), and `Controllers.kt:159` (Read). Throws `ResourceNotFoundException`, converted to HTTP 404 by `GlobalSecurityExceptionHandler` in `Application.kt:112-117`.
  - Collections: `orderRepository.findByTenantIdAndOwnerUserId(tenantId, userId)` in `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:79` and `documentRepository.findByTenantIdAndOwnerUserId(tenantId, userId)` in `Controllers.kt:153`.
- Helpers that are SAFE to treat as an ownership check:
  - `securityManager.requireOwnership(...)` in `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:98,125,136,159`: Enforces owner and tenant identity match; aborts request with HTTP 404 on violation.
  - `findByTenantIdAndOwnerUserId(tenantId, userId)` in `backend-spring/src/main/kotlin/io/komainu/portal/repository/Repositories.kt:11,17`: Restricts result sets to authenticated tenant and user.
  - `findByIdAndTenantIdAndOwnerUserId(id, tenantId, ownerUserId)` in `backend-spring/src/main/kotlin/io/komainu/portal/repository/Repositories.kt:12,18`: Scoped entity lookup.
- Helpers that LOOK like checks but are NOT (e.g. only check login):
  - Feature toggle check `if (!vulnerabilitiesEnabled)` in `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:174,190,207,221`: Verifies configuration property `enable.security.test.vulnerabilities` only, no authorization.
  - `sortAllowList.validateColumnName(sort)` in `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:82`: Column name validator against SQLi, not an ownership check.
  - `orderRepository.findById(id)` / `documentRepository.findById(id)` in `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:96,124,135,158,179,195,212`: Unfiltered primary key lookup.

## 4. Tenant / ownership data model

### backend-dotnet
- Owner columns seen: `TenantId` (`string`), `OwnerUserId` (`string`) on `Order` and `Document` entities in `backend-dotnet/Models/Entities.cs:12-13,26-27`. Both models implement `IOwnedResource<string>` (`Entities.cs:9,23`).
- Storage tables: `Orders` and `Documents` in `backend-dotnet/Data/PortalDbContext.cs:12-13`.

### backend-spring
- Owner columns seen: `tenantId` (`String` / column `tenant_id`), `ownerUserId` (`String` / column `owner_user_id`) on `OrderEntity` and `DocumentEntity` in `backend-spring/src/main/kotlin/io/komainu/portal/model/Entities.kt:16-17,29-30`. Both models implement `OwnedResource<String>` (`Entities.kt:22,35`).
- Storage tables: `portal_orders` and `portal_documents` in `backend-spring/src/main/kotlin/io/komainu/portal/model/Entities.kt:12,25`.

## 5. Exclusions and bypass paths

### backend-dotnet
- Public persona catalog: `GET /api/v1/auth/personas` in `backend-dotnet/Controllers/AuthController.cs:38-42` allows unauthenticated access to user tokens and credentials.
- Unprotected legacy test routes (when `ENABLE_SECURITY_TEST_VULNERABILITIES=true`):
  - `GET /api/v1/test/legacy-orders/{id}` in `backend-dotnet/Controllers/LegacyTestController.cs:27-44` — BOLA (retrieves order by ID without owner or tenant check).
  - `PUT /api/v1/test/legacy-orders/{id}` in `backend-dotnet/Controllers/LegacyTestController.cs:46-66` — BOLA (modifies order by ID without owner or tenant check).
  - `DELETE /api/v1/test/legacy-orders/{id}` in `backend-dotnet/Controllers/LegacyTestController.cs:68-87` — BOLA (deletes order by ID without owner or tenant check).
  - `GET /api/v1/test/legacy-search` in `backend-dotnet/Controllers/LegacyTestController.cs:89-101` — SQL Injection via unparameterized query interpolation across all orders.

### backend-spring
- Transport-level bypass: `authorizeHttpRequests { it.anyRequest().permitAll() }` in `backend-spring/src/main/kotlin/io/komainu/portal/Application.kt:127`. No global security barrier prevents direct access to endpoints.
- Public persona catalog: `GET /api/v1/auth/personas` in `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:59-60` is unauthenticated.
- Unprotected legacy test routes (when `enable.security.test.vulnerabilities=true`):
  - `GET /api/v1/test/legacy-orders/{id}` in `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:172-183` — BOLA (retrieves order by ID without owner or tenant check).
  - `PUT /api/v1/test/legacy-orders/{id}` in `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:185-203` — BOLA (modifies order by ID without owner or tenant check).
  - `DELETE /api/v1/test/legacy-orders/{id}` in `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:205-217` — BOLA (deletes order by ID without owner or tenant check).
  - `GET /api/v1/test/legacy-search` in `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:219-230` — SQL Injection via string interpolation in native query across all orders.

## 6. Unknowns (checks that may live outside the code)

- Edge Gateway & WAF: Architecture documentation specifies Kong Gateway 3.6+ and OWASP Coraza WAF (`README.md:16-19,31-33`) at the perimeter. WAF rules and gateway token validations are external to this repository.
- Centralized Identity Provider: Keycloak OIDC is specified for production authentication (`README.md:28,135-139`). Backends currently employ mock token handlers (`DemoAuthenticationHandler:60`, `DemoTokenFilter:134`) without cryptographic token validation.
- Production Database Security: `docker-compose.yml:4-20` deploys PostgreSQL, while default local runs use SQLite and H2. Any potential PostgreSQL Row-Level Security (RLS) policies or triggers are outside application code.

## 7. Notes for auditors

- Twin Implementation: Repository contains two independent backends (`backend-dotnet` and `backend-spring`) implementing the exact same API contract. Findings should be mapped to the respective sub-application codebase.
- Invariant HTTP 404 on BOLA Rejection: Remediated endpoints (`/api/v1/orders/*`, `/api/v1/documents/*`) consistently return HTTP 404 (Not Found) rather than HTTP 403 (Forbidden) on authorization failures to eliminate oracle probing and ID enumeration.
- Planted Test Endpoints: Endpoints under `/api/v1/test/*` are intentional test fixtures designed for D5 CI verification. They deliberately omit ownership verification and safe query parameterization, and must be reported as high/critical findings.
- Allow-list Sorting: Production endpoints use `SafeSortAllowList` to safely map user sort inputs, mitigating SQL injection on dynamic ordering.
