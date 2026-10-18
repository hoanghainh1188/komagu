# セキュリティ監査報告書 — Komainu Pilot (D6 Member Portal)

> **機密区分: 社外秘 (CONFIDENTIAL)** 本報告書はAI支援による静的コードレビュー結果です。外部共有前に必ず人間のレビュー担当者による確認・承認が必要です（判定結果は `review-log.md` に記録）。

| 項目 | 値 |
|---|---|
| 診断実施日 | 2026-10-18 |
| 監査キットバージョン | 0.2.1 |
| 監査対象スコープ | BOLA/IDOR（オブジェクトレベルの認可不備）および外部入力によるSQL/HQL/NoSQLクエリ構築 |
| 検出技術スタック | dotnet-webapi, java-spring-mvc |
| インベントリ登録エンドポイント数 | 24 (候補数: 24) |
| BOLA監査対象エンドポイント数 | 16 |
| レビュー対象インジェクション候補数 | 2 |

## 1. エグゼクティブサマリー

- **全体のリスクレベルは「緊急（Critical）」です。** .NET 8 Web API (`LegacyTestController.cs`) および Kotlin Spring Boot 3 (`Controllers.kt`) のレガシー検証用エンドポイントにおいて、計8件（Critical: 6件、High: 2件）の確定脆弱性が検出されました。
- **深刻なSQLインジェクション脆弱性 (`INJ-I-0001-1`, `INJ-I-0002-1`):** `GET /api/v1/test/legacy-search` において、入力値の検証やパラメータバインドを行わずに生SQL文字列に直接展開（EF Core `FromSqlRaw` および Spring JPA `createNativeQuery`）しており、データベース全体の奪取や任意のデータ改ざんが可能です。
- **深刻なマルチテナント境界越えの注文データ改ざん・削除 (`BOLA-R-0005-1`, `BOLA-R-0006-1`, `BOLA-R-0022-1`, `BOLA-R-0023-1`):** `PUT` および `DELETE /api/v1/test/legacy-orders/{id}` では所有権チェックが存在せず、未認証・別テナントの攻撃者が他顧客の注文のステータス変更や任意削除を実行可能です。
- **高重大度の顧客注文情報漏洩 (`BOLA-R-0004-1`, `BOLA-R-0021-1`):** `GET /api/v1/test/legacy-orders/{id}` により、注文IDを指定するだけで未認証の第三者が他顧客の注文詳細を閲覧可能です。
- **本番系エンドポイントの堅牢性の確認:** コア本番系エンドポイント（`/api/v1/orders/*`, `/api/v1/documents/*`）は、Komainu D1アーキテクチャ（.NET: `_authzService.AuthorizeAsync`、Spring: `securityManager.requireOwnership`）により厳格に保護されており、脆弱性は認められませんでした。
- **根本原因 — テスト用コントローラの無防備な公開:** 本番認可制御の対象外としてレガシー検証用コントローラが認証不要（`permitAll()` / `AllowAnonymous`）かつパラメータ非バインドの状態でルーティングに残存していたことが脆弱性の根本原因です。

## 2. 検出事項の概要

| 重要度 | 緊急 (Critical) | 高 (High) | 中 (Medium) | 低 (Low) | 情報 (Info) |
|---|---|---|---|---|---|
| 件数 | 6 | 2 | 0 | 0 | 0 |

| 脆弱性分類 | 件数 |
|---|---|
| オブジェクトレベルの認可不備 (BOLA/IDOR) | 6 |
| SQLインジェクション (SQLi) | 2 |
| NoSQLインジェクション (NoSQLi) | 0 |

ステータス内訳: 未検証 (Unverified)=0, 確認済 (Confirmed)=8, likely=0, 棄却 (Rejected)=0, 要確認 (Needs Review)=0

## 3. 検出事項の詳細

| ID | 重要度 | 確信度 | ステータス | 脆弱性分類 | 対象エンドポイント | 該当箇所 | タイトル |
|---|---|---|---|---|---|---|---|
| BOLA-R-0005-1 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | PUT /api/v1/test/legacy-orders/{id} | `backend-dotnet/Controllers/LegacyTestController.cs:47` | Unauthenticated cross-tenant order modification via legacy test endpoint |
| BOLA-R-0006-1 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | DELETE /api/v1/test/legacy-orders/{id} | `backend-dotnet/Controllers/LegacyTestController.cs:69` | Unauthenticated cross-tenant order deletion via legacy test endpoint |
| BOLA-R-0022-1 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | PUT /api/v1/test/legacy-orders/{id} | `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:185` | Unauthenticated cross-tenant order modification via Spring legacy test endpoint |
| BOLA-R-0023-1 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | DELETE /api/v1/test/legacy-orders/{id} | `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:205` | Unauthenticated cross-tenant order deletion via Spring legacy test endpoint |
| INJ-I-0001-1 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) | GET /api/v1/test/legacy-search | `backend-dotnet/Controllers/LegacyTestController.cs:98` | Raw SQL query uses string interpolation with unvalidated search query parameter |
| INJ-I-0002-1 | 緊急 (Critical) | 高 (High) | 確認済 (Confirmed) | SQLインジェクション (SQLi) | GET /api/v1/test/legacy-search | `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:226` | Native SQL query interpolates unvalidated search query parameter |
| BOLA-R-0004-1 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /api/v1/test/legacy-orders/{id} | `backend-dotnet/Controllers/LegacyTestController.cs:28` | Unauthenticated cross-tenant order retrieval via legacy test endpoint |
| BOLA-R-0021-1 | 高 (High) | 高 (High) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /api/v1/test/legacy-orders/{id} | `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:172` | Unauthenticated cross-tenant order retrieval via Spring legacy test endpoint |

### BOLA-R-0005-1 — Unauthenticated cross-tenant order modification via legacy test endpoint

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023  
- **対象エンドポイント:** PUT /api/v1/test/legacy-orders/{id}  
- **該当箇所:** `backend-dotnet/Controllers/LegacyTestController.cs:47`

**攻撃シナリオ:** An attacker sends PUT /api/v1/test/legacy-orders/{id} with another user's order ID and payload to mutate order description and status without authentication.

**影響度 (Impact):** Unauthorized modification of customer orders across tenant boundaries, compromising data integrity.

**脆弱性の根拠コード (Evidence):**

- `backend-dotnet/Controllers/LegacyTestController.cs:47` — Target order ID and update payload received from untrusted request body and route parameter  
  `public async Task<ActionResult<Order>> UpdateLegacyOrder(string id, [FromBody] UpdateOrderRequest request)`
- `backend-dotnet/Controllers/LegacyTestController.cs:55` — Loads order by primary key without verifying caller identity or tenant  
  `var order = await _dbContext.Orders.FirstOrDefaultAsync(o => o.Id == id);`
- `backend-dotnet/Controllers/LegacyTestController.cs:63` — Persists status and description changes without checking caller authorization  
  `await _dbContext.SaveChangesAsync();`

**データフロー:** id path parameter and UpdateOrderRequest body (LegacyTestController.cs:47) → FirstOrDefaultAsync(o => o.Id == id) (LegacyTestController.cs:55) → SaveChangesAsync() (LegacyTestController.cs:63)

**推奨対策 (Recommendation):** Verify caller identity and object ownership using _authzService.AuthorizeAsync with ResourceOperation.Update, returning 404 on authorization failure.

```
var auth = await _authzService.AuthorizeAsync(User, order, ResourceOperation.Update);
if (!auth.Succeeded) return NotFound();
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: LegacyTestController.UpdateLegacyOrder, PortalDbContext query filters, Program.cs authentication/authorization middleware, post-load ownership comparison. Verified. Endpoint allows unauthenticated cross-tenant modification of order description and status without ownership or tenant verification.

### BOLA-R-0006-1 — Unauthenticated cross-tenant order deletion via legacy test endpoint

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023  
- **対象エンドポイント:** DELETE /api/v1/test/legacy-orders/{id}  
- **該当箇所:** `backend-dotnet/Controllers/LegacyTestController.cs:69`

**攻撃シナリオ:** An attacker sends DELETE /api/v1/test/legacy-orders/{id} with any order ID to delete that order across tenants without authentication.

**影響度 (Impact):** Permanent deletion of order records belonging to any user or tenant, causing severe data loss.

**脆弱性の根拠コード (Evidence):**

- `backend-dotnet/Controllers/LegacyTestController.cs:69` — Target order ID received from client via URL route parameter without validation  
  `public async Task<IActionResult> DeleteLegacyOrder(string id)`
- `backend-dotnet/Controllers/LegacyTestController.cs:77` — Retrieves order to delete by ID alone with no ownership validation  
  `var order = await _dbContext.Orders.FirstOrDefaultAsync(o => o.Id == id);`
- `backend-dotnet/Controllers/LegacyTestController.cs:83` — Removes the order from database without verifying caller ownership  
  `_dbContext.Orders.Remove(order);`

**データフロー:** id path parameter (LegacyTestController.cs:69) → FirstOrDefaultAsync(o => o.Id == id) (LegacyTestController.cs:77) → Orders.Remove(order) (LegacyTestController.cs:83)

**推奨対策 (Recommendation):** Require caller authentication and object-level deletion authorization using _authzService.AuthorizeAsync with ResourceOperation.Delete.

```
var auth = await _authzService.AuthorizeAsync(User, order, ResourceOperation.Delete);
if (!auth.Succeeded) return NotFound();
_dbContext.Orders.Remove(order);
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: LegacyTestController.DeleteLegacyOrder, PortalDbContext query filters, Program.cs authentication/authorization middleware, post-load ownership comparison. Verified. Endpoint permits unauthenticated cross-tenant order deletion by ID alone with no authorization checks.

### BOLA-R-0022-1 — Unauthenticated cross-tenant order modification via Spring legacy test endpoint

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023  
- **対象エンドポイント:** PUT /api/v1/test/legacy-orders/{id}  
- **該当箇所:** `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:185`

**攻撃シナリオ:** An attacker sends PUT /api/v1/test/legacy-orders/{id} with modified fields to alter any user's order in any tenant.

**影響度 (Impact):** Unauthorized tampering and alteration of order status and descriptions across tenant boundaries.

**脆弱性の根拠コード (Evidence):**

- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:185` — Target order ID and updated fields received from untrusted request without validation  
  `fun updateLegacyOrder(@PathVariable id: String, @RequestBody request: UpdateOrderRequest): ResponseEntity<Any>`
- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:195` — Fetches order to mutate by ID alone without verifying ownership or tenant  
  `val order = orderRepository.findById(id).orElse(null)`
- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:200` — Saves modified order entity directly without ownership check  
  `val updated = orderRepository.save(order)`

**データフロー:** id path variable and UpdateOrderRequest body (Controllers.kt:185) → orderRepository.findById(id) (Controllers.kt:195) → orderRepository.save(order) (Controllers.kt:200)

**推奨対策 (Recommendation):** Enforce ownership check via securityManager.requireOwnership(order, ResourceOperation.UPDATE) prior to mutating and saving the entity.

```
val order = orderRepository.findById(id).orElse(null)
securityManager.requireOwnership(order, ResourceOperation.UPDATE)
request.description?.let { order!!.description = it }
...
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: LegacyTestController.updateLegacyOrder, OrderRepository.findById, Entities.kt Hibernate mappings, WebSecurityConfig filterChain permitAll. Verified. Endpoint allows unauthenticated caller to modify order description and status across tenant boundaries without ownership checks.

### BOLA-R-0023-1 — Unauthenticated cross-tenant order deletion via Spring legacy test endpoint

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023  
- **対象エンドポイント:** DELETE /api/v1/test/legacy-orders/{id}  
- **該当箇所:** `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:205`

**攻撃シナリオ:** An attacker sends DELETE /api/v1/test/legacy-orders/{id} with any order id and permanently deletes the record without authorization.

**影響度 (Impact):** Unauthorized deletion of orders across tenants, resulting in permanent data loss.

**脆弱性の根拠コード (Evidence):**

- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:205` — Target order ID received from client via path variable without validation  
  `fun deleteLegacyOrder(@PathVariable id: String): ResponseEntity<Any>`
- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:212` — Fetches order to delete without tenant or owner verification  
  `val order = orderRepository.findById(id).orElse(null)`
- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:215` — Deletes order row from database without verifying caller authorization or ownership  
  `orderRepository.delete(order)`

**データフロー:** id path variable (Controllers.kt:205) → orderRepository.findById(id) (Controllers.kt:212) → orderRepository.delete(order) (Controllers.kt:215)

**推奨対策 (Recommendation):** Verify caller ownership via securityManager.requireOwnership(order, ResourceOperation.DELETE) before executing deletion.

```
val order = orderRepository.findById(id).orElse(null)
securityManager.requireOwnership(order, ResourceOperation.DELETE)
orderRepository.delete(order!!)
return ResponseEntity.noContent().build()
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: LegacyTestController.deleteLegacyOrder, OrderRepository.findById, Entities.kt Hibernate mappings, WebSecurityConfig filterChain permitAll. Verified. Endpoint allows unauthenticated deletion of orders across tenants by primary key alone with no ownership verification.

### INJ-I-0001-1 — Raw SQL query uses string interpolation with unvalidated search query parameter

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_interpolation) — CWE-89 A03:2021  
- **対象エンドポイント:** GET /api/v1/test/legacy-search  
- **該当箇所:** `backend-dotnet/Controllers/LegacyTestController.cs:98`

**攻撃シナリオ:** An unauthenticated caller provides a crafted query parameter to escape the LIKE string literal and inject arbitrary SQL clauses or statements.

**影響度 (Impact):** Arbitrary SQL execution against the underlying database, allowing an attacker to read, modify, or delete orders across all tenants.

**脆弱性の根拠コード (Evidence):**

- `backend-dotnet/Controllers/LegacyTestController.cs:90` — source: unvalidated query parameter  
  `public async Task<ActionResult<List<Order>>> SearchLegacy([FromQuery] string query)`
- `backend-dotnet/Controllers/LegacyTestController.cs:98` — string interpolation directly constructs SQL statement  
  `var rawSql = $"SELECT * FROM Orders WHERE Description LIKE '%{query}%'";`
- `backend-dotnet/Controllers/LegacyTestController.cs:99` — sink: raw SQL execution without parameter binding  
  `var results = await _dbContext.Orders.FromSqlRaw(rawSql).ToListAsync();`

**データフロー:** [FromQuery] string query (backend-dotnet/Controllers/LegacyTestController.cs:90) → rawSql (backend-dotnet/Controllers/LegacyTestController.cs:98) → _dbContext.Orders.FromSqlRaw(rawSql) (backend-dotnet/Controllers/LegacyTestController.cs:99)

**推奨対策 (Recommendation):** Use parameterized queries with FromSqlInterpolated or bind parameters through FormattableString rather than passing interpolated strings to FromSqlRaw.

```
var results = await _dbContext.Orders.FromSqlInterpolated($"SELECT * FROM Orders WHERE Description LIKE {'%' + query + '%'}").ToListAsync();
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: LegacyTestController.SearchLegacy, FromSqlRaw parameter binding, query parameter sanitization/validation, Program.cs pipeline. Verified. Unvalidated query parameter is interpolated directly into raw SQL string executed via FromSqlRaw without parameter binding, reachable without authentication.

### INJ-I-0002-1 — Native SQL query interpolates unvalidated search query parameter

- **重要度 / 確信度:** 緊急 (Critical) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_interpolation) — CWE-89 A03:2021  
- **対象エンドポイント:** GET /api/v1/test/legacy-search  
- **該当箇所:** `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:226`

**攻撃シナリオ:** An unauthenticated caller provides a crafted query parameter containing SQL syntax to break out of the LIKE pattern and manipulate the query structure.

**影響度 (Impact):** Arbitrary SQL execution in the database, allowing an attacker to read or manipulate records across all tenants.

**脆弱性の根拠コード (Evidence):**

- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:220` — source: unvalidated request parameter  
  `fun searchLegacy(@RequestParam query: String): ResponseEntity<Any>`
- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:226` — string template interpolation directly into SQL string  
  `val sql = "SELECT * FROM portal_orders WHERE description LIKE '%$query%'"`
- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:227` — sink: native query execution without parameter binding  
  `val queryResult = entityManager.createNativeQuery(sql, OrderEntity::class.java).resultList`

**データフロー:** @RequestParam query (backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:220) → sql (backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:226) → entityManager.createNativeQuery(sql, ...) (backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:227)

**推奨対策 (Recommendation):** Use parameterized queries with named or positional parameters via Query.setParameter instead of string interpolation.

```
val queryResult = entityManager.createNativeQuery("SELECT * FROM portal_orders WHERE description LIKE :query", OrderEntity::class.java).setParameter("query", "%$query%").resultList
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: LegacyTestController.searchLegacy, entityManager.createNativeQuery parameter binding, query parameter validation, WebSecurityConfig filterChain permitAll. Verified. User-supplied query parameter is interpolated directly into a native SQL query executed via entityManager.createNativeQuery without parameterization or authentication.

### BOLA-R-0004-1 — Unauthenticated cross-tenant order retrieval via legacy test endpoint

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023  
- **対象エンドポイント:** GET /api/v1/test/legacy-orders/{id}  
- **該当箇所:** `backend-dotnet/Controllers/LegacyTestController.cs:28`

**攻撃シナリオ:** An unauthenticated user sends GET /api/v1/test/legacy-orders/{id} with any order ID and receives the complete order entity belonging to another user or tenant.

**影響度 (Impact):** Cross-tenant data exposure disclosing customer orders, total amount, order description, and owner identity without authentication.

**脆弱性の根拠コード (Evidence):**

- `backend-dotnet/Controllers/LegacyTestController.cs:28` — Order identifier supplied directly from URL route path without validation  
  `public async Task<ActionResult<Order>> GetLegacyOrder(string id)`
- `backend-dotnet/Controllers/LegacyTestController.cs:36` — Direct query on Orders table by id alone without tenant or user ownership constraint  
  `var order = await _dbContext.Orders.FirstOrDefaultAsync(o => o.Id == id);`
- `backend-dotnet/Controllers/LegacyTestController.cs:43` — Returns full order record without post-load owner verification or caller authorization  
  `return Ok(order);`

**データフロー:** id path parameter (LegacyTestController.cs:28) → FirstOrDefaultAsync(o => o.Id == id) (LegacyTestController.cs:36) → Ok(order) (LegacyTestController.cs:43)

**推奨対策 (Recommendation):** Enforce authentication and verify caller ownership and tenant scope using _authzService.AuthorizeAsync before returning order data.

```
var order = await _dbContext.Orders.FirstOrDefaultAsync(o => o.Id == id);
if (order == null) return NotFound();
var auth = await _authzService.AuthorizeAsync(User, order, ResourceOperation.Read);
if (!auth.Succeeded) return NotFound();
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: LegacyTestController.GetLegacyOrder, PortalDbContext query filters, Program.cs authentication/authorization middleware, post-load ownership comparison. Verified. Endpoint retrieves and returns full order entity by ID without tenant or user ownership checks, and requires no authentication.

### BOLA-R-0021-1 — Unauthenticated cross-tenant order retrieval via Spring legacy test endpoint

- **重要度 / 確信度:** 高 (High) / 高 (High)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023  
- **対象エンドポイント:** GET /api/v1/test/legacy-orders/{id}  
- **該当箇所:** `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:172`

**攻撃シナリオ:** An attacker sends GET /api/v1/test/legacy-orders/{id} and retrieves any order in the system across all tenants without authentication.

**影響度 (Impact):** Confidentiality breach exposing customer order records, tenant IDs, and user IDs across tenant boundaries.

**脆弱性の根拠コード (Evidence):**

- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:172` — Target order ID taken directly from request path variable without validation  
  `fun getLegacyOrder(@PathVariable id: String): ResponseEntity<Any>`
- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:179` — Queries database by primary key alone using Spring Data repository without tenant or owner scoping  
  `val order = orderRepository.findById(id).orElse(null)`
- `backend-spring/src/main/kotlin/io/komainu/portal/controller/Controllers.kt:182` — Returns the fetched order entity without post-load ownership comparison  
  `return ResponseEntity.ok(order)`

**データフロー:** id path variable (Controllers.kt:172) → orderRepository.findById(id) (Controllers.kt:179) → ResponseEntity.ok(order) (Controllers.kt:182)

**推奨対策 (Recommendation):** Enforce ownership verification via securityManager.requireOwnership(order, ResourceOperation.READ) before returning the order entity.

```
val order = orderRepository.findById(id).orElse(null)
securityManager.requireOwnership(order, ResourceOperation.READ)
return ResponseEntity.ok(order!!)
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: LegacyTestController.getLegacyOrder, OrderRepository.findById, Entities.kt Hibernate mappings, WebSecurityConfig filterChain permitAll. Verified. Endpoint retrieves and returns full order entity by primary key alone without tenant or user ownership checks, reachable without authentication.

## 4. 根本的恒久対策

1. **非本番・テスト用コントローラの完全無効化・分離:** `LegacyTestController` を本番環境から完全に除外、あるいは環境依存フラグ（.NET: `[Authorize(Roles = "TestAdmin")]` または `#if DEBUG`、Spring: `@Profile("test")`）によりアクセスを遮断します。
   - **改修規模:** S（1日以内）
   - **解消対象:** 全8件（`BOLA-R-0004-1`, `BOLA-R-0005-1`, `BOLA-R-0006-1`, `BOLA-R-0021-1`, `BOLA-R-0022-1`, `BOLA-R-0023-1`, `INJ-I-0001-1`, `INJ-I-0002-1`）
2. **Komainu D1共通認可パターンの全データ操作への徹底適用:** すべてのコントローラにおいて、エンティティの取得・更新・削除前に .NET では `_authzService.AuthorizeAsync`、Spring Boot では `securityManager.requireOwnership` を呼び出すことをアーキテクチャ標準として義務付けます。
   - **改修規模:** S（1日以内）
   - **解消対象:** `BOLA-R-0004-1`, `BOLA-R-0005-1`, `BOLA-R-0006-1`, `BOLA-R-0021-1`, `BOLA-R-0022-1`, `BOLA-R-0023-1`
3. **パラメータバインドSQLの徹底と文字列補間の禁止:** EF Core の `FromSqlRaw` による文字列補間を廃止し `FromSqlInterpolated` または LINQ を採用、また Spring JPA においては `createNativeQuery` でのパラメータバインド（`setParameter`）を徹底します。
   - **改修規模:** S（1日以内）
   - **解消対象:** `INJ-I-0001-1`, `INJ-I-0002-1`

## 5. 調査範囲と制約事項

- missing from inventory: 0
- bola routes without verdict: 0
- injection candidates without verdict: 0
- findings without verification: 0

- **監査スコープ:** インベントリ化された全24エンドポイントにおけるオブジェクトレベル認可不備（BOLA/IDOR）および外部入力に基づくSQL/HQL/NoSQLクエリ生成に特化して実施しました。
- **対象外事項:** ストアドプロシージャの内部ロジック、JWTトークン署名・失効の堅牢性、CSRF、SSRF、XSS、レートリミット等の評価は本監査スコープに含まれません。
- **AI支援監査に関する留意事項:** 本報告書はAIエージェントおよび懐疑的検証エージェントにより生成・検証されたものです。組織外への共有前に `review-log.md` における人間のレビュー担当者（Person B）による最終承認が必須となります。
- **スコープ外メモ:** 監査エージェントおよび検証エージェントから記録されたスコープ外メモはありません。

## 付録A — 検証により棄却された検出事項

なし。

## 付録B — 監査手法とプロセス

1. **決定論的静的事前スキャン**: 技術スタック判定、エンドポイント候補抽出、クエリ生成箇所抽出。
2. **独立したAI監査エージェント群**: 認可モデル抽出、エンドポイント詳細精査、BOLA監査、インジェクション監査。
3. **懐疑的AI検証エージェント（Skeptic）**: 検出事項に対する反論テストを実施し、既存の防御制御による誤検知を排除。
4. **人間のエンジニアによる最終確認と承認**: `review-log.md` による判定記録とサインオフ。

**免責事項:** 本監査は侵入テスト（ペネトレーションテスト）ではありません。脆弱性が検出されなかったことは、脆弱性の非存在を証明するものではありません。
