# Security Audit Report — Komainu Pilot (D6 Member Portal)

> **Classification: CONFIDENTIAL.** AI-assisted static review. All findings require human review (record decisions in `review-log.md`, created from `templates/review-log.md`) before they are shared outside the team.

| Item | Value |
|---|---|
| Date | 2026-10-18 |
| Kit version | 0.2.1 |
| Scope | BOLA/IDOR; SQL/HQL/NoSQL queries built from input |
| Stacks | dotnet-webapi, java-spring-mvc |
| Endpoints inventoried | 24 (candidates: 24) |
| Endpoints audited for BOLA | 16 |
| Injection candidates reviewed | 2 |

## 1. Executive summary

- **Overall risk level is Critical.** The assessment identified 8 confirmed vulnerabilities (6 Critical, 2 High) across the legacy test endpoints in both .NET 8 Web API (`LegacyTestController.cs`) and Kotlin Spring Boot 3 (`Controllers.kt`).
- **Critical SQL Injection (`INJ-I-0001-1`, `INJ-I-0002-1`).** `GET /api/v1/test/legacy-search` interpolates unvalidated user search queries directly into raw SQL statements (`FromSqlRaw` in EF Core and `createNativeQuery` in Spring JPA/Hibernate), allowing complete database compromise and arbitrary data extraction.
- **Critical Cross-Tenant Modification & Deletion (`BOLA-R-0005-1`, `BOLA-R-0006-1`, `BOLA-R-0022-1`, `BOLA-R-0023-1`).** `PUT` and `DELETE /api/v1/test/legacy-orders/{id}` allow any unauthenticated or unauthorized caller to mutate or delete orders belonging to any customer without ownership verification.
- **High-Severity Cross-Tenant Order Exposure (`BOLA-R-0004-1`, `BOLA-R-0021-1`).** `GET /api/v1/test/legacy-orders/{id}` allows unauthenticated callers to read full customer order records simply by guessing or iterating order IDs.
- **Production Endpoints Verified Safe.** All core production endpoints (`/api/v1/orders/*`, `/api/v1/documents/*`) enforce robust object-level authorization via Komainu D1 patterns (`_authzService.AuthorizeAsync` in .NET and `securityManager.requireOwnership` in Spring Boot).
- **Systemic Root Cause — Test Controllers Left Exposed Without Security Controls.** Legacy test controllers were exposed in the application routing without authentication guards, tenant scoping, or parameter binding, creating severe attack vectors alongside secure production routes.

## 2. Findings overview

| Severity | critical | high | medium | low | info |
|---|---|---|---|---|---|
| Count | 6 | 2 | 0 | 0 | 0 |

| Category | Count |
|---|---|
| bola | 6 |
| sql_injection | 2 |
| nosql_injection | 0 |

Status: unverified=0, confirmed=8, likely=0, rejected=0, needs_review=0

## 3. Findings

| ID | Sev | Conf | Status | Category | Endpoint | Location | Title |
|---|---|---|---|---|---|---|---|
| BOLA-R-0005-1 | critical | high | confirmed | bola | PUT /api/v1/test/legacy-orders/{id} | `backend-dotnet/Controllers/LegacyTestController.cs:47` | Unauthenticated cross-tenant order modification via legacy test endpoint |
| BOLA-R-0006-1 | critical | high | confirmed | bola | DELETE /api/v1/test/legacy-orders/{id} | `backend-dotnet/Controllers/LegacyTestController.cs:69` | Unauthenticated cross-tenant order deletion via legacy test endpoint |
| BOLA-R-0022-1 | critical | high | confirmed | bola | PUT /api/v1/test/legacy-orders/{id} | `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:185` | Unauthenticated cross-tenant order modification via Spring legacy test endpoint |
| BOLA-R-0023-1 | critical | high | confirmed | bola | DELETE /api/v1/test/legacy-orders/{id} | `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:205` | Unauthenticated cross-tenant order deletion via Spring legacy test endpoint |
| INJ-I-0001-1 | critical | high | confirmed | sql_injection | GET /api/v1/test/legacy-search | `backend-dotnet/Controllers/LegacyTestController.cs:98` | Raw SQL query uses string interpolation with unvalidated search query parameter |
| INJ-I-0002-1 | critical | high | confirmed | sql_injection | GET /api/v1/test/legacy-search | `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:226` | Native SQL query interpolates unvalidated search query parameter |
| BOLA-R-0004-1 | high | high | confirmed | bola | GET /api/v1/test/legacy-orders/{id} | `backend-dotnet/Controllers/LegacyTestController.cs:28` | Unauthenticated cross-tenant order retrieval via legacy test endpoint |
| BOLA-R-0021-1 | high | high | confirmed | bola | GET /api/v1/test/legacy-orders/{id} | `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:172` | Unauthenticated cross-tenant order retrieval via Spring legacy test endpoint |

### BOLA-R-0005-1 — Unauthenticated cross-tenant order modification via legacy test endpoint

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023  
- **Endpoint:** PUT /api/v1/test/legacy-orders/{id}  
- **Location:** `backend-dotnet/Controllers/LegacyTestController.cs:47`

**Scenario.** An attacker sends PUT /api/v1/test/legacy-orders/{id} with another user's order ID and payload to mutate order description and status without authentication.

**Impact.** Unauthorized modification of customer orders across tenant boundaries, compromising data integrity.

**Evidence.**

- `backend-dotnet/Controllers/LegacyTestController.cs:47` — Target order ID and update payload received from untrusted request body and route parameter  
  `public async Task<ActionResult<Order>> UpdateLegacyOrder(string id, [FromBody] UpdateOrderRequest request)`
- `backend-dotnet/Controllers/LegacyTestController.cs:55` — Loads order by primary key without verifying caller identity or tenant  
  `var order = await _dbContext.Orders.FirstOrDefaultAsync(o => o.Id == id);`
- `backend-dotnet/Controllers/LegacyTestController.cs:63` — Persists status and description changes without checking caller authorization  
  `await _dbContext.SaveChangesAsync();`

**Data flow.** id path parameter and UpdateOrderRequest body (LegacyTestController.cs:47) → FirstOrDefaultAsync(o => o.Id == id) (LegacyTestController.cs:55) → SaveChangesAsync() (LegacyTestController.cs:63)

**Recommendation.** Verify caller identity and object ownership using _authzService.AuthorizeAsync with ResourceOperation.Update, returning 404 on authorization failure.

```
var auth = await _authzService.AuthorizeAsync(User, order, ResourceOperation.Update);
if (!auth.Succeeded) return NotFound();
```

*Verifier:* confirmed — checked: LegacyTestController.UpdateLegacyOrder, PortalDbContext query filters, Program.cs authentication/authorization middleware, post-load ownership comparison. Verified. Endpoint allows unauthenticated cross-tenant modification of order description and status without ownership or tenant verification.

### BOLA-R-0006-1 — Unauthenticated cross-tenant order deletion via legacy test endpoint

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023  
- **Endpoint:** DELETE /api/v1/test/legacy-orders/{id}  
- **Location:** `backend-dotnet/Controllers/LegacyTestController.cs:69`

**Scenario.** An attacker sends DELETE /api/v1/test/legacy-orders/{id} with any order ID to delete that order across tenants without authentication.

**Impact.** Permanent deletion of order records belonging to any user or tenant, causing severe data loss.

**Evidence.**

- `backend-dotnet/Controllers/LegacyTestController.cs:69` — Target order ID received from client via URL route parameter without validation  
  `public async Task<IActionResult> DeleteLegacyOrder(string id)`
- `backend-dotnet/Controllers/LegacyTestController.cs:77` — Retrieves order to delete by ID alone with no ownership validation  
  `var order = await _dbContext.Orders.FirstOrDefaultAsync(o => o.Id == id);`
- `backend-dotnet/Controllers/LegacyTestController.cs:83` — Removes the order from database without verifying caller ownership  
  `_dbContext.Orders.Remove(order);`

**Data flow.** id path parameter (LegacyTestController.cs:69) → FirstOrDefaultAsync(o => o.Id == id) (LegacyTestController.cs:77) → Orders.Remove(order) (LegacyTestController.cs:83)

**Recommendation.** Require caller authentication and object-level deletion authorization using _authzService.AuthorizeAsync with ResourceOperation.Delete.

```
var auth = await _authzService.AuthorizeAsync(User, order, ResourceOperation.Delete);
if (!auth.Succeeded) return NotFound();
_dbContext.Orders.Remove(order);
```

*Verifier:* confirmed — checked: LegacyTestController.DeleteLegacyOrder, PortalDbContext query filters, Program.cs authentication/authorization middleware, post-load ownership comparison. Verified. Endpoint permits unauthenticated cross-tenant order deletion by ID alone with no authorization checks.

### BOLA-R-0022-1 — Unauthenticated cross-tenant order modification via Spring legacy test endpoint

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023  
- **Endpoint:** PUT /api/v1/test/legacy-orders/{id}  
- **Location:** `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:185`

**Scenario.** An attacker sends PUT /api/v1/test/legacy-orders/{id} with modified fields to alter any user's order in any tenant.

**Impact.** Unauthorized tampering and alteration of order status and descriptions across tenant boundaries.

**Evidence.**

- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:185` — Target order ID and updated fields received from untrusted request without validation  
  `fun updateLegacyOrder(@PathVariable id: String, @RequestBody request: UpdateOrderRequest): ResponseEntity<Any>`
- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:195` — Fetches order to mutate by ID alone without verifying ownership or tenant  
  `val order = orderRepository.findById(id).orElse(null)`
- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:200` — Saves modified order entity directly without ownership check  
  `val updated = orderRepository.save(order)`

**Data flow.** id path variable and UpdateOrderRequest body (Controllers.kt:185) → orderRepository.findById(id) (Controllers.kt:195) → orderRepository.save(order) (Controllers.kt:200)

**Recommendation.** Enforce ownership check via securityManager.requireOwnership(order, ResourceOperation.UPDATE) prior to mutating and saving the entity.

```
val order = orderRepository.findById(id).orElse(null)
securityManager.requireOwnership(order, ResourceOperation.UPDATE)
request.description?.let { order!!.description = it }
...
```

*Verifier:* confirmed — checked: LegacyTestController.updateLegacyOrder, OrderRepository.findById, Entities.kt Hibernate mappings, WebSecurityConfig filterChain permitAll. Verified. Endpoint allows unauthenticated caller to modify order description and status across tenant boundaries without ownership checks.

### BOLA-R-0023-1 — Unauthenticated cross-tenant order deletion via Spring legacy test endpoint

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023  
- **Endpoint:** DELETE /api/v1/test/legacy-orders/{id}  
- **Location:** `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:205`

**Scenario.** An attacker sends DELETE /api/v1/test/legacy-orders/{id} with any order id and permanently deletes the record without authorization.

**Impact.** Unauthorized deletion of orders across tenants, resulting in permanent data loss.

**Evidence.**

- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:205` — Target order ID received from client via path variable without validation  
  `fun deleteLegacyOrder(@PathVariable id: String): ResponseEntity<Any>`
- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:212` — Fetches order to delete without tenant or owner verification  
  `val order = orderRepository.findById(id).orElse(null)`
- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:215` — Deletes order row from database without verifying caller authorization or ownership  
  `orderRepository.delete(order)`

**Data flow.** id path variable (Controllers.kt:205) → orderRepository.findById(id) (Controllers.kt:212) → orderRepository.delete(order) (Controllers.kt:215)

**Recommendation.** Verify caller ownership via securityManager.requireOwnership(order, ResourceOperation.DELETE) before executing deletion.

```
val order = orderRepository.findById(id).orElse(null)
securityManager.requireOwnership(order, ResourceOperation.DELETE)
orderRepository.delete(order!!)
return ResponseEntity.noContent().build()
```

*Verifier:* confirmed — checked: LegacyTestController.deleteLegacyOrder, OrderRepository.findById, Entities.kt Hibernate mappings, WebSecurityConfig filterChain permitAll. Verified. Endpoint allows unauthenticated deletion of orders across tenants by primary key alone with no ownership verification.

### INJ-I-0001-1 — Raw SQL query uses string interpolation with unvalidated search query parameter

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_interpolation) — CWE-89 A03:2021  
- **Endpoint:** GET /api/v1/test/legacy-search  
- **Location:** `backend-dotnet/Controllers/LegacyTestController.cs:98`

**Scenario.** An unauthenticated caller provides a crafted query parameter to escape the LIKE string literal and inject arbitrary SQL clauses or statements.

**Impact.** Arbitrary SQL execution against the underlying database, allowing an attacker to read, modify, or delete orders across all tenants.

**Evidence.**

- `backend-dotnet/Controllers/LegacyTestController.cs:90` — source: unvalidated query parameter  
  `public async Task<ActionResult<List<Order>>> SearchLegacy([FromQuery] string query)`
- `backend-dotnet/Controllers/LegacyTestController.cs:98` — string interpolation directly constructs SQL statement  
  `var rawSql = $"SELECT * FROM Orders WHERE Description LIKE '%{query}%'";`
- `backend-dotnet/Controllers/LegacyTestController.cs:99` — sink: raw SQL execution without parameter binding  
  `var results = await _dbContext.Orders.FromSqlRaw(rawSql).ToListAsync();`

**Data flow.** [FromQuery] string query (backend-dotnet/Controllers/LegacyTestController.cs:90) → rawSql (backend-dotnet/Controllers/LegacyTestController.cs:98) → _dbContext.Orders.FromSqlRaw(rawSql) (backend-dotnet/Controllers/LegacyTestController.cs:99)

**Recommendation.** Use parameterized queries with FromSqlInterpolated or bind parameters through FormattableString rather than passing interpolated strings to FromSqlRaw.

```
var results = await _dbContext.Orders.FromSqlInterpolated($"SELECT * FROM Orders WHERE Description LIKE {'%' + query + '%'}").ToListAsync();
```

*Verifier:* confirmed — checked: LegacyTestController.SearchLegacy, FromSqlRaw parameter binding, query parameter sanitization/validation, Program.cs pipeline. Verified. Unvalidated query parameter is interpolated directly into raw SQL string executed via FromSqlRaw without parameter binding, reachable without authentication.

### INJ-I-0002-1 — Native SQL query interpolates unvalidated search query parameter

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_interpolation) — CWE-89 A03:2021  
- **Endpoint:** GET /api/v1/test/legacy-search  
- **Location:** `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:226`

**Scenario.** An unauthenticated caller provides a crafted query parameter containing SQL syntax to break out of the LIKE pattern and manipulate the query structure.

**Impact.** Arbitrary SQL execution in the database, allowing an attacker to read or manipulate records across all tenants.

**Evidence.**

- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:220` — source: unvalidated request parameter  
  `fun searchLegacy(@RequestParam query: String): ResponseEntity<Any>`
- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:226` — string template interpolation directly into SQL string  
  `val sql = "SELECT * FROM portal_orders WHERE description LIKE '%$query%'"`
- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:227` — sink: native query execution without parameter binding  
  `val queryResult = entityManager.createNativeQuery(sql, OrderEntity::class.java).resultList`

**Data flow.** @RequestParam query (backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:220) → sql (backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:226) → entityManager.createNativeQuery(sql, ...) (backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:227)

**Recommendation.** Use parameterized queries with named or positional parameters via Query.setParameter instead of string interpolation.

```
val queryResult = entityManager.createNativeQuery("SELECT * FROM portal_orders WHERE description LIKE :query", OrderEntity::class.java).setParameter("query", "%$query%").resultList
```

*Verifier:* confirmed — checked: LegacyTestController.searchLegacy, entityManager.createNativeQuery parameter binding, query parameter validation, WebSecurityConfig filterChain permitAll. Verified. User-supplied query parameter is interpolated directly into a native SQL query executed via entityManager.createNativeQuery without parameterization or authentication.

### BOLA-R-0004-1 — Unauthenticated cross-tenant order retrieval via legacy test endpoint

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023  
- **Endpoint:** GET /api/v1/test/legacy-orders/{id}  
- **Location:** `backend-dotnet/Controllers/LegacyTestController.cs:28`

**Scenario.** An unauthenticated user sends GET /api/v1/test/legacy-orders/{id} with any order ID and receives the complete order entity belonging to another user or tenant.

**Impact.** Cross-tenant data exposure disclosing customer orders, total amount, order description, and owner identity without authentication.

**Evidence.**

- `backend-dotnet/Controllers/LegacyTestController.cs:28` — Order identifier supplied directly from URL route path without validation  
  `public async Task<ActionResult<Order>> GetLegacyOrder(string id)`
- `backend-dotnet/Controllers/LegacyTestController.cs:36` — Direct query on Orders table by id alone without tenant or user ownership constraint  
  `var order = await _dbContext.Orders.FirstOrDefaultAsync(o => o.Id == id);`
- `backend-dotnet/Controllers/LegacyTestController.cs:43` — Returns full order record without post-load owner verification or caller authorization  
  `return Ok(order);`

**Data flow.** id path parameter (LegacyTestController.cs:28) → FirstOrDefaultAsync(o => o.Id == id) (LegacyTestController.cs:36) → Ok(order) (LegacyTestController.cs:43)

**Recommendation.** Enforce authentication and verify caller ownership and tenant scope using _authzService.AuthorizeAsync before returning order data.

```
var order = await _dbContext.Orders.FirstOrDefaultAsync(o => o.Id == id);
if (order == null) return NotFound();
var auth = await _authzService.AuthorizeAsync(User, order, ResourceOperation.Read);
if (!auth.Succeeded) return NotFound();
```

*Verifier:* confirmed — checked: LegacyTestController.GetLegacyOrder, PortalDbContext query filters, Program.cs authentication/authorization middleware, post-load ownership comparison. Verified. Endpoint retrieves and returns full order entity by ID without tenant or user ownership checks, and requires no authentication.

### BOLA-R-0021-1 — Unauthenticated cross-tenant order retrieval via Spring legacy test endpoint

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023  
- **Endpoint:** GET /api/v1/test/legacy-orders/{id}  
- **Location:** `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:172`

**Scenario.** An attacker sends GET /api/v1/test/legacy-orders/{id} and retrieves any order in the system across all tenants without authentication.

**Impact.** Confidentiality breach exposing customer order records, tenant IDs, and user IDs across tenant boundaries.

**Evidence.**

- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:172` — Target order ID taken directly from request path variable without validation  
  `fun getLegacyOrder(@PathVariable id: String): ResponseEntity<Any>`
- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:179` — Queries database by primary key alone using Spring Data repository without tenant or owner scoping  
  `val order = orderRepository.findById(id).orElse(null)`
- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:182` — Returns the fetched order entity without post-load ownership comparison  
  `return ResponseEntity.ok(order)`

**Data flow.** id path variable (Controllers.kt:172) → orderRepository.findById(id) (Controllers.kt:179) → ResponseEntity.ok(order) (Controllers.kt:182)

**Recommendation.** Enforce ownership verification via securityManager.requireOwnership(order, ResourceOperation.READ) before returning the order entity.

```
val order = orderRepository.findById(id).orElse(null)
securityManager.requireOwnership(order, ResourceOperation.READ)
return ResponseEntity.ok(order!!)
```

*Verifier:* confirmed — checked: LegacyTestController.getLegacyOrder, OrderRepository.findById, Entities.kt Hibernate mappings, WebSecurityConfig filterChain permitAll. Verified. Endpoint retrieves and returns full order entity by primary key alone without tenant or user ownership checks, reachable without authentication.

## 4. Systemic fixes

1. **Decommission or strictly restrict test controllers in non-development environments.** Remove `LegacyTestController` from production deployments or guard routes under environment-specific flags (`[Authorize(Roles = "TestAdmin")]` or `#if DEBUG` in .NET, `@Profile("test")` in Spring Boot).
   - **Effort:** S (≤ 1 day)
   - **Closes:** All 8 findings (`BOLA-R-0004-1`, `BOLA-R-0005-1`, `BOLA-R-0006-1`, `BOLA-R-0021-1`, `BOLA-R-0022-1`, `BOLA-R-0023-1`, `INJ-I-0001-1`, `INJ-I-0002-1`).
2. **Standardize all data operations on Komainu D1 authorization helpers.** Require all controllers to invoke `_authzService.AuthorizeAsync(User, resource, operation)` in .NET and `securityManager.requireOwnership(resource, operation)` in Spring Boot before exposing, modifying, or deleting entities.
   - **Effort:** S (≤ 1 day)
   - **Closes:** `BOLA-R-0004-1`, `BOLA-R-0005-1`, `BOLA-R-0006-1`, `BOLA-R-0021-1`, `BOLA-R-0022-1`, `BOLA-R-0023-1`.
3. **Enforce parameterized SQL and eliminate raw string interpolation.** Replace `FromSqlRaw` string interpolation in EF Core with parameterized `FromSqlInterpolated` or LINQ queries, and use JPA parameterized queries (`setParameter`) instead of string interpolation in `createNativeQuery`.
   - **Effort:** S (≤ 1 day)
   - **Closes:** `INJ-I-0001-1`, `INJ-I-0002-1`.

## 5. Coverage and limitations

- missing from inventory: 0
- bola routes without verdict: 0
- injection candidates without verdict: 0
- findings without verification: 0

- **Audit Scope:** The assessment focused strictly on BOLA/IDOR (missing ownership checks) and SQL/HQL/NoSQL query construction from untrusted input across 24 inventoried endpoints.
- **Out of Scope:** Stored procedures, authentication token issuance/signing vulnerabilities, CSRF, SSRF, XSS, and rate limiting were not analyzed.
- **AI-Assisted Assessment Notice:** All findings were detected and validated using AI agents with an independent skeptic verifier. Human review and sign-off recorded in `review-log.md` is mandatory prior to external distribution.
- **Out-of-scope notes:** None logged by auditors or verifiers during this evaluation.

## Appendix A — Findings rejected by the verifier

None.

## Appendix B — Method

1. Deterministic pre-scan (stack detection, endpoint candidates, query-building candidates).
2. AI agents: auth-model extraction, route inventory, BOLA audit, injection audit.
3. Independent AI verifier tries to refute each finding.
4. Human review and sign-off (`review-log.md`).

This is not a penetration test. Absence of findings does not prove absence of vulnerabilities.
