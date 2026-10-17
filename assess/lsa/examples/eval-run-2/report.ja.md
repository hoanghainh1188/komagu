# セキュリティ監査報告書 — LSA Multi-Stack Evaluation Run 2

> **機密区分: 社外秘 (CONFIDENTIAL)** 本報告書はAI支援による静的コードレビュー結果です。外部共有前に必ず人間のレビュー担当者による確認・承認が必要です（判定結果は `review-log.md` に記録）。

| 項目 | 値 |
|---|---|
| 診断実施日 | 2026-10-17 |
| 監査キットバージョン | 0.1.0 |
| 監査対象スコープ | BOLA/IDOR（オブジェクトレベルの認可不備）および外部入力によるSQL/HQL/NoSQLクエリ構築 |
| 検出技術スタック | php, php-codeigniter, java-servlet, java-jsp, java-struts1, java-spring-mvc, java-mybatis, java-hibernate, dotnet-webforms, dotnet-handlers, dotnet-mvc, classic-asp, perl-cgi, coldfusion, node-express, python-flask |
| インベントリ登録エンドポイント数 | 36 (候補数: 36) |
| BOLA監査対象エンドポイント数 | 34 |
| レビュー対象インジェクション候補数 | 38 |

## 1. エグゼクティブサマリー

<!-- LLM: reporter agent writes max 8 bullets here (日本語で記載: 全体のリスクレベル、事業影響の大きい上位3件の検出事項、根本原因) -->

## 2. 検出事項の概要

| 重要度 | 緊急 (Critical) | 高 (High) | 中 (Medium) | 低 (Low) | 情報 (Info) |
|---|---|---|---|---|---|
| 件数 | 13 | 30 | 10 | 4 | 0 |

| 脆弱性分類 | 件数 |
|---|---|
| オブジェクトレベルの認可不備 (BOLA/IDOR) | 28 |
| SQLインジェクション (SQLi) | 25 |
| NoSQLインジェクション (NoSQLi) | 4 |

ステータス内訳: 未検証 (Unverified)=0, 確認済 (Confirmed)=34, likely=23, 棄却 (Rejected)=2, needs_review=0

## 3. 検出事項の詳細

| ID | 重要度 | 確信度 | ステータス | 脆弱性分類 | 対象エンドポイント | 該当箇所 | タイトル |
|---|---|---|---|---|---|---|---|
| BOLA-R-0002-1 | 緊急 (Critical) | high | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /shop/member.asp?mode=delete | `classic-asp/shop/member.asp:9` | Any logged-in user can delete any member via GET member_id |
| BOLA-R-0004-1 | 緊急 (Critical) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /app/OrderService.cfc?method=getOrder | `coldfusion/app/OrderService.cfc:2` | Remote CFC getOrder returns any order to anonymous callers |
| BOLA-R-0009-1 | 緊急 (Critical) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /Handlers/GetFile.ashx | `dotnet-legacy/Web/Handlers/GetFile.ashx:6` | Anonymous file download by file_id in GetFile.ashx (Handlers folder allows all users) |
| BOLA-R-0012-1 | 緊急 (Critical) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /user/edit.do | `java-legacy/src/com/acme/struts/EditUserAction.java:10` | Any user's email can be changed via user_id request parameter |
| BOLA-R-0024-1 | 緊急 (Critical) | high | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /perl-cgi/cgi-bin/order.cgi | `perl-cgi/cgi-bin/order.cgi:8` | Any client can delete any cart by cart id (no login, no owner filter) |
| BOLA-R-0029-1 | 緊急 (Critical) | high | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /php-plain/admin.php?action=delete | `php-plain/admin.php:10` | Any logged-in user can delete any user via admin.php?action=delete |
| INJ-I-0006-1 | 緊急 (Critical) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | ANY /coldfusion/app/OrderService.cfc?method=getOrder | `coldfusion/app/OrderService.cfc:2` | Remote CFC getOrder puts orderId into cfquery without cfqueryparam |
| INJ-I-0014-1 | 緊急 (Critical) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | GET /java-legacy/WebContent/order/detail.jsp | `java-legacy/WebContent/order/detail.jsp:3` | detail.jsp executes Statement query with concatenated order_no |
| INJ-I-0018-1 | 緊急 (Critical) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | GET /order/view | `java-legacy/src/com/acme/web/OrderServlet.java:11` | Unauthenticated order servlet concatenates orderId into JDBC Statement |
| INJ-I-0021-1 | 緊急 (Critical) | 中 (Medium) | 確認済 (Confirmed) | SQLインジェクション (SQLi) | GET /stats | `node-express/routes/orders.js:28` | /stats interpolates req.query.shop into SQL without login |
| INJ-I-0022-1 | 緊急 (Critical) | 中 (Medium) | likely | NoSQLインジェクション (NoSQLi) | POST /login | `node-express/routes/orders.js:20` | POST /login passes req.body directly as Mongo filter |
| INJ-I-0024-1 | 緊急 (Critical) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | GET /perl-cgi/cgi-bin/order.cgi | `perl-cgi/cgi-bin/order.cgi:11` | order.cgi interpolates id param into prepared SQL with no binds |
| INJ-I-0025-1 | 緊急 (Critical) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | POST /perl-cgi/cgi-bin/order.cgi | `perl-cgi/cgi-bin/order.cgi:19` | order.cgi DELETE concatenates cart param |
| BOLA-R-0001-1 | 高 (High) | high | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /shop/member.asp?mode=edit | `classic-asp/shop/member.asp:4` | Any logged-in user can rename any member via form member_id |
| BOLA-R-0003-1 | 高 (High) | high | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /shop/order.asp | `classic-asp/shop/order.asp:5` | Order address readable by any logged-in user via id |
| BOLA-R-0005-1 | 高 (High) | high | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /app/order.cfm | `coldfusion/app/order.cfm:2` | order.cfm renders unscoped qOrder instead of owner-bound qMine |
| BOLA-R-0006-1 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /Invoice/Details/{id} | `dotnet-legacy/Web/Controllers/InvoiceController.cs:11` | Invoice details readable by any logged-in user via id |
| BOLA-R-0008-1 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /Invoice/Search | `dotnet-legacy/Web/Controllers/InvoiceController.cs:25` | Invoice search returns any customer's invoices to any logged-in user |
| BOLA-R-0014-1 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /invoices/{id} | `java-legacy/src/com/acme/web/InvoiceController.java:15` | Invoice readable by id via Spring show() with no owner or login check visible |
| BOLA-R-0016-1 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /invoices/search | `java-legacy/src/com/acme/web/InvoiceController.java:27` | Invoice search by customer returns any customer's invoices |
| BOLA-R-0018-1 | 高 (High) | 中 (Medium) | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /orders/:id | `node-express/routes/orders.js:8` | Any logged-in user can read any order via /orders/:id (findById) |
| BOLA-R-0025-1 | 高 (High) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /invoice/view/{id} | `php-codeigniter/application/controllers/Invoice.php:9` | Invoice readable by id with no owner filter (Invoice::view) |
| BOLA-R-0031-1 | 高 (High) | high | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /php-plain/order_detail.php | `php-plain/order_detail.php:5` | Order detail (address) readable for any order id by any logged-in user |
| BOLA-R-0034-1 | 高 (High) | high | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /orders/<int:order_id> | `python-flask/app.py:8` | Any logged-in user can read any order via /orders/<order_id> |
| INJ-I-0002-1 | 高 (High) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | POST /classic-asp/shop/member.asp?mode=edit | `classic-asp/shop/member.asp:6` | Member UPDATE concatenates unquoted member_id from POST |
| INJ-I-0003-1 | 高 (High) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | GET /classic-asp/shop/member.asp?mode=delete | `classic-asp/shop/member.asp:10` | Member DELETE concatenates unquoted member_id from query string |
| INJ-I-0004-1 | 高 (High) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | GET /classic-asp/shop/order.asp | `classic-asp/shop/order.asp:5` | Order SELECT concatenates unvalidated id from Request() |
| INJ-I-0007-1 | 高 (High) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | GET /coldfusion/app/order.cfm | `coldfusion/app/order.cfm:2` | order.cfm qOrder puts url.id into cfquery without cfqueryparam |
| INJ-I-0008-1 | 高 (High) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | POST /Invoice/Search | `dotnet-legacy/Web/Controllers/InvoiceController.cs:26` | Invoice search concatenates customer into EF SqlQuery |
| INJ-I-0009-1 | 高 (High) | 中 (Medium) | likely | SQLインジェクション (SQLi) | POST /dotnet-legacy/Web/Orders/EditOrder.aspx | `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7` | EditOrder UPDATE concatenates txtNote.Text and hidden field hfOrderId |
| INJ-I-0011-1 | 高 (High) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | GET /dotnet-legacy/Web/Orders/OrderDetail.aspx | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10` | OrderDetail executes SELECT concatenated with query-string id |
| INJ-I-0016-1 | 高 (High) | 中 (Medium) | likely | SQLインジェクション (SQLi) | POST /user/edit.do | `java-legacy/src/com/acme/struts/EditUserAction.java:10` | EditUserAction prepareStatement built by concatenating email and user_id |
| INJ-I-0017-1 | 高 (High) | 中 (Medium) | likely | SQLインジェクション (SQLi) | GET /invoices/search | `java-legacy/src/com/acme/web/InvoiceController.java:27` | Invoice search builds HQL by concatenating customer parameter |
| INJ-I-0020-1 | 高 (High) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | GET /reports | `node-express/routes/orders.js:16` | /reports concatenates req.query.month into SQL |
| INJ-I-0023-1 | 高 (High) | high | 確認済 (Confirmed) | NoSQLインジェクション (NoSQLi) | GET /search | `node-express/routes/orders.js:24` | /search builds Mongo $where JavaScript from req.query.n |
| INJ-I-0026-1 | 高 (High) | 中 (Medium) | likely | SQLインジェクション (SQLi) | ANY /invoice/view/{id} | `php-codeigniter/application/controllers/Invoice.php:9` | CodeIgniter invoice view interpolates URI segment into db->query |
| INJ-I-0028-1 | 高 (High) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | POST /php-plain/admin.php?action=delete | `php-plain/admin.php:11` | admin.php delete interpolates POST id into mysql_query |
| INJ-I-0030-1 | 高 (High) | 低 (Low) | likely | NoSQLインジェクション (NoSQLi) | GET /php-plain/mongo_find.php | `php-plain/mongo_find.php:6` | mongo_find.php builds $where JavaScript from GET n |
| INJ-I-0031-1 | 高 (High) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | GET /php-plain/order_detail.php | `php-plain/order_detail.php:5` | Order detail query concatenates unquoted GET id |
| INJ-I-0032-1 | 高 (High) | 低 (Low) | likely | SQLインジェクション (SQLi) | GET /php-plain/search.php | `php-plain/search.php:5` | Product search LIKE clause relies on addslashes only |
| INJ-I-0033-1 | 高 (High) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | GET /php-plain/search.php | `php-plain/search.php:6` | ORDER BY clause taken directly from GET sort |
| INJ-I-0034-1 | 高 (High) | 中 (Medium) | 確認済 (Confirmed) | SQLインジェクション (SQLi) | GET /php-plain/search.php | `php-plain/search.php:12` | Category filter interpolates $_GET['cat'] in heredoc SQL |
| INJ-I-0036-1 | 高 (High) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | GET\|POST /search | `python-flask/app.py:27` | Flask search builds LIKE query with f-string |
| BOLA-R-0010-1 | 中 (Medium) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /Orders/EditOrder.aspx | `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:6` | Order note writable on any order via client-controlled hidden field |
| BOLA-R-0013-1 | 中 (Medium) | high | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /order/detail.jsp | `java-legacy/WebContent/order/detail.jsp:3` | Unfiltered JSP loads any order by order_no without login |
| BOLA-R-0017-1 | 中 (Medium) | high | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /order/view | `java-legacy/src/com/acme/web/OrderServlet.java:8` | Order row loaded by request orderId on unauthenticated servlet, no owner filter |
| BOLA-R-0020-1 | 中 (Medium) | 低 (Low) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /reports | `node-express/routes/orders.js:16` | Reports selected by month with no owner/tenant filter; per-user scope unknown |
| BOLA-R-0022-1 | 中 (Medium) | 低 (Low) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /search | `node-express/routes/orders.js:24` | Item search returns all matching items with no owner filter; ownership of items unknown |
| BOLA-R-0023-1 | 中 (Medium) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /stats | `node-express/routes/orders.js:28` | Unauthenticated per-shop order count via request-controlled shop id |
| BOLA-R-0027-1 | 中 (Medium) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /invoice/update | `php-codeigniter/application/controllers/Invoice.php:20` | Invoice note writable for any invoice id from POST (Invoice::update) |
| INJ-I-0015-1 | 中 (Medium) | 低 (Low) | likely | SQLインジェクション (SQLi) |   | `java-legacy/src/com/acme/mapper/OrderMapper.xml:7` | MyBatis list query uses ${orderBy} (caller not in repo) |
| INJ-I-0029-1 | 中 (Medium) | high | 確認済 (Confirmed) | NoSQLインジェクション (NoSQLi) | GET /php-plain/mongo_find.php | `php-plain/mongo_find.php:5` | mongo_find.php uses GET login/pass directly in Mongo filter |
| INJ-I-0037-1 | 中 (Medium) | 低 (Low) | likely | SQLインジェクション (SQLi) |   | `sql-procs/sp_search_orders.sql:5` | sp_search_orders builds and EXECs dynamic SQL from @Customer and @Sort |
| BOLA-R-0011-1 | 低 (Low) | high | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | ANY /Orders/OrderDetail.aspx | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10` | Order detail loaded by query id without owner filter (owner-bound command never executed) |
| BOLA-R-0024-2 | 低 (Low) | high | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /perl-cgi/cgi-bin/order.cgi | `perl-cgi/cgi-bin/order.cgi:11` | Order loaded by request id without owner filter (line 13) on unauthenticated CGI |
| BOLA-R-0028-1 | 低 (Low) | high | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /php-plain/admin.php?action=view | `php-plain/admin.php:5` | Any logged-in user can load any user record via admin.php?action=view&uid= |
| BOLA-R-0030-1 | 低 (Low) | 中 (Medium) | likely | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /mongo_find.php | `php-plain/mongo_find.php:5` | mongo_find.php queries any member record by request-supplied login/name, not bound to session user |

### BOLA-R-0002-1 — Any logged-in user can delete any member via GET member_id

- **重要度 / 確信度:** 緊急 (Critical) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (id_from_request_used_as_identity) — CWE-639, CWE-566 API1:2023  
- **対象エンドポイント:** ANY /shop/member.asp?mode=delete  
- **該当箇所:** `classic-asp/shop/member.asp:9`

**攻撃シナリオ:** User A sends GET /shop/member.asp?mode=delete&member_id=<member id of user B>; B's member record is deleted.

**影響度 (Impact):** Delete any member account (data loss, denial of service for other users).

**脆弱性の根拠コード (Evidence):**

- `classic-asp/shop/inc/auth.asp:2` — Login check only  
  `If Session("UserID") = "" Then Response.Redirect "/login.asp"`
- `classic-asp/shop/member.asp:10` — DELETE by query-string id; no owner/role binding  
  `conn.Execute "DELETE FROM members WHERE member_id = " & Request.QueryString("member_id")`

**データフロー:** Request.QueryString("member_id") (member.asp:10) → DELETE FROM members WHERE member_id = <value> (member.asp:10)

**推奨対策 (Recommendation):** Restrict deletion to the session member (or an enforced admin role); bind member_id to Session("UserID"); require POST.

```
"DELETE FROM members WHERE member_id = " & CLng(Session("UserID"))
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: evidence lines member.asp:9-10 and inc/auth.asp:2 re-read (match), inc/conn.asp, global.asa / web.config / .htaccess for classic-asp (none in repo), role check before delete (none). DELETE by query-string member_id after login-only include. Deleting other users' objects is critical per bola-patterns §6. Reachable via GET.

### BOLA-R-0004-1 — Remote CFC getOrder returns any order to anonymous callers

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (no_authentication) — CWE-306, CWE-639 API1:2023, API2:2023  
- **対象エンドポイント:** ANY /app/OrderService.cfc?method=getOrder  
- **該当箇所:** `coldfusion/app/OrderService.cfc:2`

**攻撃シナリオ:** Anonymous attacker sends GET /app/OrderService.cfc?method=getOrder&orderId=<any id> and receives the full order.

**影響度 (Impact):** Unauthenticated read of all orders (personal and order data); trivially enumerable.

**脆弱性の根拠コード (Evidence):**

- `coldfusion/app/OrderService.cfc:2` — Remotely callable over URL/form; no login check in the component  
  `<cffunction name="getOrder" access="remote" returnformat="json">`
- `coldfusion/app/OrderService.cfc:5` — Lookup by caller-supplied id only; no owner filter  
  `SELECT * FROM orders WHERE id = #arguments.orderId#`
- `coldfusion/app/OrderService.cfc:7` — Full order row(s) returned as JSON  
  `<cfreturn q>`
- `coldfusion/app/OrderService.cfc:1` — No Application.cfc/.cfm in repo; server-level restriction unknown (reason for medium confidence)  
  `<cfcomponent>`

**データフロー:** arguments.orderId (OrderService.cfc:3) → SELECT * FROM orders WHERE id = ... (OrderService.cfc:5) → cfreturn q as JSON (OrderService.cfc:7)

**推奨対策 (Recommendation):** Change access to public/private, or check session.userID and bind user_id = <cfqueryparam value="#session.userID#"> in the query.

```
WHERE id = <cfqueryparam value="#arguments.orderId#" cfsqltype="cf_sql_integer"> AND user_id = <cfqueryparam value="#session.userID#" cfsqltype="cf_sql_integer">
```

*検証結果 (Verifier):* likely — 確認対象: OrderService.cfc:1-12 re-read (match), searched whole repo for Application.cfc/.cfm (none; would hold onCFCRequest/onRequestStart guard), roles= attribute on cffunction (absent), owner filter or post-query check before cfreturn (none), auth-model §5/§6 (remote CFC unauthenticated; CF Admin restrictions unknown). Every in-repo path is unguarded: access="remote", no roles, no session check, id-only lookup, full row returned. Kept critical (personal data read, +1 for no auth). 'likely' only because an Application.cfc or server/CF Admin restriction outside the repo cannot be ruled out.

### BOLA-R-0009-1 — Anonymous file download by file_id in GetFile.ashx (Handlers folder allows all users)

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (no_authentication) — CWE-306, CWE-639 API1:2023, API2:2023  
- **対象エンドポイント:** ANY /Handlers/GetFile.ashx  
- **該当箇所:** `dotnet-legacy/Web/Handlers/GetFile.ashx:6`

**攻撃シナリオ:** An unauthenticated client sends GET /Handlers/GetFile.ashx?file_id=<any file id> and receives the stored document.

**影響度 (Impact):** Anyone on the network can download any user's stored documents if DocStore.PathFor resolves the ID without an access check.

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Web.config:7` — Overrides global <deny users="?"/> (Web.config:5); handler is reachable anonymously  
  `<location path="Handlers">
  <system.web><authorization><allow users="*" /></authorization></system.web>`
- `dotnet-legacy/Web/Handlers/GetFile.ashx:8` — Object ID from query string  
  `string fileId = context.Request.QueryString["file_id"];`
- `dotnet-legacy/Web/Handlers/GetFile.ashx:9` — Only the request ID is passed; no user identity passed to the helper. Helper source not in repo  
  `string path = DocStore.PathFor(fileId);`
- `dotnet-legacy/Web/Handlers/GetFile.ashx:10` — File streamed with no authn check, no owner check, no stop path in the handler  
  `context.Response.TransmitFile(path);`

**データフロー:** query file_id (GetFile.ashx:8) → DocStore.PathFor(fileId) -> path (GetFile.ashx:9, helper not visible) → Response.TransmitFile(path) (GetFile.ashx:10)

**推奨対策 (Recommendation):** Remove the <location path="Handlers"> allow-all rule (or scope it to truly public handlers), require an authenticated user in ProcessRequest, and look up the file by id AND owner = Session/User identity, returning 404 on mismatch. Confirm what DocStore.PathFor does.

```
if (!context.User.Identity.IsAuthenticated) { context.Response.StatusCode = 401; return; }
string path = DocStore.PathForOwner(fileId, CurrentUserId());
if (path == null) { context.Response.StatusCode = 404; return; }
```

*検証結果 (Verifier):* likely — 確認対象: Web.config:5 global deny ?, Web.config:7-9 <location path="Handlers"> allow * (overrides deny; path matches Web/Handlers), GetFile.ashx:6-11 (no IsAuthenticated, no owner check, no stop), repo search for DocStore (not in repo), Global.asax / IIS config (absent). Anonymous reach is confirmed from Web.config. Only DocStore.PathFor (not in repo) could enforce anything; it receives only fileId, and the caller is anonymous, so an ownership check there is implausible but not provable. Out of scope: file_id flows into a file path -> possible path traversal depending on DocStore.

### BOLA-R-0012-1 — Any user's email can be changed via user_id request parameter

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (id_from_request_used_as_identity) — CWE-639, CWE-566 API1:2023  
- **対象エンドポイント:** ANY /user/edit.do  
- **該当箇所:** `java-legacy/src/com/acme/struts/EditUserAction.java:10`

**攻撃シナリオ:** User A sends POST /user/edit.do with user_id=<id of user B>&email=<A's address>; B's email changes, enabling password-reset takeover.

**影響度 (Impact):** Change any user's email (account takeover path).

**脆弱性の根拠コード (Evidence):**

- `java-legacy/WebContent/WEB-INF/struts-config.xml:4` — Struts action mapping  
  `<action path="/user/edit" type="com.acme.struts.EditUserAction" name="userForm" scope="request"/>`
- `java-legacy/src/com/acme/struts/EditUserAction.java:10` — Target user identity taken from request; no session lookup  
  `String userId = request.getParameter("user_id");`
- `java-legacy/src/com/acme/struts/EditUserAction.java:13` — UPDATE by request id, no ownership/role check  
  `prepareStatement("UPDATE users SET email = '" + email + "' WHERE id = " + userId)`
- `java-legacy/WebContent/WEB-INF/web.xml:9` — LoginFilter source missing (assumed login only); no ActionServlet mapping, so reachability assumed  
  `<url-pattern>*.do</url-pattern>`

**データフロー:** request.getParameter("user_id") (EditUserAction.java:10) → UPDATE users ... WHERE id = <user_id> (EditUserAction.java:13) → executeUpdate (EditUserAction.java:14)

**推奨対策 (Recommendation):** Take the user id from session.getAttribute("loginUser"); ignore user_id from the request; use bound parameters.

```
ps = conn.prepareStatement("UPDATE users SET email = ? WHERE id = ?"); ps.setString(1, email); ps.setLong(2, loginUser.getId());
```

*検証結果 (Verifier):* likely — 確認対象: EditUserAction.execute full method (:8-16), struts-config.xml action mapping (:4; no form-beans section, no roles attribute), web.xml for ActionServlet mapping (absent) and LoginFilter (*.do, source missing), session use in action (none). Target user taken from request user_id (:10), UPDATE email by that id (:13-14), no session or role check in visible code. Writing another user's email = critical. Not confirmed only because ActionServlet is not mapped in web.xml and userForm/LoginFilter sources are missing, so reachability and any ActionForm validate() are unproven.

### BOLA-R-0024-1 — Any client can delete any cart by cart id (no login, no owner filter)

- **重要度 / 確信度:** 緊急 (Critical) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (no_authentication) — CWE-306, CWE-639 API1:2023, API2:2023  
- **対象エンドポイント:** GET /perl-cgi/cgi-bin/order.cgi  
- **該当箇所:** `perl-cgi/cgi-bin/order.cgi:8`

**攻撃シナリオ:** Anonymous client sends GET /cgi-bin/order.cgi?cart=<victim cart id> (or POST body) and the victim's cart is deleted.

**影響度 (Impact):** Delete other users' carts without authentication (integrity / availability). SQL injection on the same line is for the injection auditor.

**脆弱性の根拠コード (Evidence):**

- `perl-cgi/cgi-bin/order.cgi:8` — load() returns an empty session when none exists; not a login check (auth-model §2)  
  `my $session = CGI::Session->load() or die;`
- `perl-cgi/cgi-bin/order.cgi:9` — uid read but never tested  
  `my $uid = $session->param('user_id');`
- `perl-cgi/cgi-bin/order.cgi:19` — Delete by request cart id only; no user_id binding; runs on every request  
  `$dbh->do("DELETE FROM carts WHERE cart_id = " . $q->param('cart'));`

**推奨対策 (Recommendation):** Stop when $uid is undefined (print 401/redirect and exit), and delete with a bound owner filter.

```
die unless defined $uid; $dbh->do('DELETE FROM carts WHERE cart_id = ? AND user_id = ?', undef, scalar $q->param('cart'), $uid);
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: order.cgi:8 CGI::Session->load() or die (dies only on load failure, not on missing login), order.cgi:9 $uid never tested, order.cgi:10 DBI->connect without RaiseError, so failing statements at :13-17 do not stop execution, order.cgi:19 DELETE by request cart only, unconditional, web server auth (.htaccess) absent from repo. Delete of other users' objects is critical even for logged-in users, so severity holds regardless of web-server auth. Minor: endpoint.path '/perl-cgi/cgi-bin/order.cgi' and attack_scenario '/cgi-bin/order.cgi' disagree; URL mapping unknown.

### BOLA-R-0029-1 — Any logged-in user can delete any user via admin.php?action=delete

- **重要度 / 確信度:** 緊急 (Critical) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **対象エンドポイント:** POST /php-plain/admin.php?action=delete  
- **該当箇所:** `php-plain/admin.php:10`

**攻撃シナリオ:** Ordinary user POSTs id=<any user id> to /admin.php?action=delete and that account is deleted.

**影響度 (Impact):** Delete arbitrary user accounts. SQL injection on the same line is for the injection auditor.

**脆弱性の根拠コード (Evidence):**

- `php-plain/inc/auth.php:4` — Login check only; no role check  
  `if (empty($_SESSION['user_id'])) {`
- `php-plain/admin.php:11` — Target id from POST body  
  `$id = $_POST['id'];`
- `php-plain/admin.php:12` — Deletes any user row; no admin role, no owner/self binding  
  `mysql_query("DELETE FROM users WHERE id = $id");`

**推奨対策 (Recommendation):** Enforce an admin role check from the session and exit on failure; use a bound, int-cast id.

```
if (empty($_SESSION['is_admin'])) { http_response_code(403); exit; } $st = $pdo->prepare('DELETE FROM users WHERE id = ?'); $st->execute(array((int)$_POST['id']));
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: php-plain/inc/auth.php:1-7 login only, exit on fail, no role check, php-plain/inc/db.php:1-4 connection only, no auth, admin.php:1-14 no role/self check before DELETE, auth-model §3: no role checks anywhere, no .htaccess / auto_prepend in repo. Any logged-in user can delete any user row. Subtype is better classed missing_role_check (CWE-285, API5:2023) than missing_ownership_check. Deleting other users' objects -> critical. Web-server auth on admin.php is not in repo and would be the only possible compensating control.

### INJ-I-0006-1 — Remote CFC getOrder puts orderId into cfquery without cfqueryparam

- **重要度 / 確信度:** 緊急 (Critical) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (template_placeholder) — CWE-89 A03:2021  
- **対象エンドポイント:** ANY /coldfusion/app/OrderService.cfc?method=getOrder  
- **該当箇所:** `coldfusion/app/OrderService.cfc:2`

**攻撃シナリオ:** An anonymous caller passes a crafted orderId that changes the WHERE clause or appends a UNION.

**影響度 (Impact):** Unauthenticated read of any data the 'shop' datasource can access.

**脆弱性の根拠コード (Evidence):**

- `coldfusion/app/OrderService.cfc:2` — remotely callable, no login check (auth-model §2/§5)  
  `<cffunction name="getOrder" access="remote" returnformat="json">`
- `coldfusion/app/OrderService.cfc:3` — type string: no numeric validation  
  `<cfargument name="orderId" type="string" required="true">`
- `coldfusion/app/OrderService.cfc:5` — unquoted numeric context; CF quote-escaping does not help  
  `SELECT * FROM orders WHERE id = #arguments.orderId#`

**データフロー:** URL/form arg orderId (OrderService.cfc:3) → #arguments.orderId# (OrderService.cfc:5) → cfquery (OrderService.cfc:4)

**推奨対策 (Recommendation):** Use cfqueryparam with cf_sql_integer and declare the argument type numeric; add an auth check.

```
<cfqueryparam value="#arguments.orderId#" cfsqltype="cf_sql_integer">
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: OrderService.cfc:2-6 re-read (match), cfargument type="string" (no numeric validation), cfqueryparam (absent), CF quote auto-escape: does not apply in unquoted numeric context (knowledge/stacks/coldfusion.md), Application.cfc anywhere in repo (none). Source->sink traced fully. Critical as remotely callable without login. If an out-of-repo Application.cfc enforced login, severity would drop to high; the injection itself remains.

### INJ-I-0014-1 — detail.jsp executes Statement query with concatenated order_no

- **重要度 / 確信度:** 緊急 (Critical) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89 A03:2021  
- **対象エンドポイント:** GET /java-legacy/WebContent/order/detail.jsp  
- **該当箇所:** `java-legacy/WebContent/order/detail.jsp:3`

**攻撃シナリオ:** An anonymous user closes the quote in 'no' and appends SQL; LoginFilter covers only *.do (web.xml:15).

**影響度 (Impact):** Unauthenticated read of any data the shared connection can access.

**脆弱性の根拠コード (Evidence):**

- `java-legacy/WebContent/order/detail.jsp:3` — source: request parameter  
  `String no = request.getParameter("no");`
- `java-legacy/WebContent/order/detail.jsp:5` — concatenated in quotes, no escaping; Statement sink  
  `ResultSet rs = c.createStatement().executeQuery("SELECT * FROM orders WHERE order_no = '" + no + "'");`

**データフロー:** request.getParameter("no") (detail.jsp:3) → no → Statement.executeQuery (detail.jsp:5)

**推奨対策 (Recommendation):** Use PreparedStatement with a bound parameter; move DB access out of the JSP.

```
PreparedStatement ps = c.prepareStatement("SELECT * FROM orders WHERE order_no = ?"); ps.setString(1, no);
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: detail.jsp:3-5 (no escaping, Statement.executeQuery), web.xml:3-10 LoginFilter mapped to *.do only (JSP not covered), web.xml security-constraint (none), auth-model §5 java-legacy exclusions. Unauthenticated, tainted, no sanitizer -> critical. Out of scope: ${param.no} reflected at detail.jsp:7 (XSS).

### INJ-I-0018-1 — Unauthenticated order servlet concatenates orderId into JDBC Statement

- **重要度 / 確信度:** 緊急 (Critical) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89 A03:2021  
- **対象エンドポイント:** GET /order/view  
- **該当箇所:** `java-legacy/src/com/acme/web/OrderServlet.java:11`

**攻撃シナリオ:** An anonymous user closes the quote in orderId and appends SQL that changes the query.

**影響度 (Impact):** Unauthenticated read (and possibly modification, driver-dependent) of any data the DB user can access.

**脆弱性の根拠コード (Evidence):**

- `java-legacy/WebContent/WEB-INF/web.xml:9` — LoginFilter covers *.do only; /order/view (web.xml:17) is not filtered  
  `<url-pattern>*.do</url-pattern>`
- `java-legacy/src/com/acme/web/OrderServlet.java:10` — read but never checked  
  `Object loginUser = session.getAttribute("loginUser");`
- `java-legacy/src/com/acme/web/OrderServlet.java:11` — source: request parameter  
  `String id = request.getParameter("orderId");`
- `java-legacy/src/com/acme/web/OrderServlet.java:15` — concatenated into Statement.executeQuery, sink  
  `ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE id = '" + id + "'");`

**データフロー:** request.getParameter("orderId") (OrderServlet.java:11) → id → Statement.executeQuery (OrderServlet.java:15)

**推奨対策 (Recommendation):** Use PreparedStatement with setString/setLong (as already done on line 18-19), and add the servlet path to the login filter.

```
PreparedStatement ps = conn.prepareStatement("SELECT * FROM orders WHERE id = ?"); ps.setString(1, id);
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: web.xml servlet-mapping /order/view (:15-18) and filter-mapping *.do (:9), OrderServlet.doGet full method (:8-23), loginUser use (read at :10, never tested), sink Statement.executeQuery (:15) and any cast/validation of id (none). Unauthenticated, tainted orderId concatenated into an executed Statement query. Critical per injection guide. Line 16-17 StringBuilder is never executed (not part of this finding); line 18-19 is bound.

### INJ-I-0021-1 — /stats interpolates req.query.shop into SQL without login

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_interpolation) — CWE-89 A03:2021  
- **対象エンドポイント:** GET /stats  
- **該当箇所:** `node-express/routes/orders.js:28`

**攻撃シナリオ:** An anonymous user sends a crafted shop value that adds a UNION or boolean condition to read other data.

**影響度 (Impact):** Unauthenticated read of any data the DB user can access.

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/orders.js:28` — no ensureLoggedIn  
  `router.get('/stats', function (req, res) {`
- `node-express/routes/orders.js:29` — template literal, numeric context  
  `db.query('SELECT COUNT(*) AS n FROM orders WHERE shop_id = ${req.query.shop}', ...`

**データフロー:** req.query.shop (orders.js:29) → db.query (orders.js:29)

**推奨対策 (Recommendation):** Use a placeholder and parse the value as integer.

```
db.query('SELECT COUNT(*) AS n FROM orders WHERE shop_id = ?', [parseInt(req.query.shop, 10)], cb)
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: orders.js:28-30 route has no ensureLoggedIn, whole file for parseInt/cast of req.query.shop (none), app entry for global app.use auth (absent, auth-model §6). Template literal interpolates req.query.shop unquoted into db.query; no cast or binding on any visible path. Injection itself is fully traced. Confidence medium only because a global auth middleware outside repo could lower severity to high.

### INJ-I-0022-1 — POST /login passes req.body directly as Mongo filter

- **重要度 / 確信度:** 緊急 (Critical) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** NoSQLインジェクション (NoSQLi) (operator_injection) — CWE-943 A03:2021  
- **対象エンドポイント:** POST /login  
- **該当箇所:** `node-express/routes/orders.js:20`

**攻撃シナリオ:** An anonymous user sends operator objects (e.g. not-equal) for the password field so the login check returns true.

**影響度 (Impact):** Authentication bypass and user enumeration; arbitrary filter keys on the users collection.

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/orders.js:20` — no auth by design  
  `router.post('/login', function (req, res) {`
- `node-express/routes/orders.js:21` — whole request body is the filter  
  `db.collection('users').findOne(req.body, function (e, u) { res.json(!!u); });`

**データフロー:** req.body (orders.js:21) → collection('users').findOne (orders.js:21)

**推奨対策 (Recommendation):** Build the filter from typed string fields and compare a password hash in code.

```
const u = String(req.body.user), p = String(req.body.pass); db.collection('users').findOne({ user: u }, (e, doc) => res.json(!!doc && bcrypt.compareSync(p, doc.hash)));
```

*検証結果 (Verifier):* likely — 確認対象: orders.js:20-22 route has no ensureLoggedIn, whole file for any sanitizer or type cast of req.body, app entry / body-parser config (absent from repo, auth-model §6), ../db module (absent). Evidence matches. req.body is passed as the whole filter. Operator injection needs a body parser that yields objects (express.json or urlencoded extended:true); app entry not in repo, so kept medium. Even with plain strings, arbitrary filter keys allow user enumeration. Critical: unauthenticated by design.

### INJ-I-0024-1 — order.cgi interpolates id param into prepared SQL with no binds

- **重要度 / 確信度:** 緊急 (Critical) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_interpolation) — CWE-89 A03:2021  
- **対象エンドポイント:** GET /perl-cgi/cgi-bin/order.cgi  
- **該当箇所:** `perl-cgi/cgi-bin/order.cgi:11`

**攻撃シナリオ:** An anonymous user sends a crafted id that rewrites the WHERE clause or adds a UNION.

**影響度 (Impact):** Unauthenticated read of the shop DB.

**脆弱性の根拠コード (Evidence):**

- `perl-cgi/cgi-bin/order.cgi:8` — not a login check (auth-model §2)  
  `my $session = CGI::Session->load() or die;`
- `perl-cgi/cgi-bin/order.cgi:11` — source  
  `my $id = $q->param('id');`
- `perl-cgi/cgi-bin/order.cgi:13` — interpolated, numeric context  
  `my $sth = $dbh->prepare("SELECT * FROM orders WHERE id = $id");`
- `perl-cgi/cgi-bin/order.cgi:14` — executed with no binds  
  `$sth->execute();`

**データフロー:** $q->param('id') (order.cgi:11) → $id → $dbh->prepare (order.cgi:13) → execute (order.cgi:14)

**推奨対策 (Recommendation):** Use the bound form already on line 16-17.

```
my $sth = $dbh->prepare('SELECT * FROM orders WHERE id = ?'); $sth->execute($id);
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: order.cgi:11 $id from $q->param, no validation, order.cgi:13-14 interpolated prepare, execute with no binds, order.cgi:8-9 no effective login stop, order.cgi:16-17 bound variant for contrast. Fully traced. Note: order.cgi:19 also concatenates $q->param('cart') into a DELETE (separate SQLi, more severe as a write); not in this batch as an INJ finding - check it exists elsewhere.

### INJ-I-0025-1 — order.cgi DELETE concatenates cart param

- **重要度 / 確信度:** 緊急 (Critical) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89 A03:2021  
- **対象エンドポイント:** POST /perl-cgi/cgi-bin/order.cgi  
- **該当箇所:** `perl-cgi/cgi-bin/order.cgi:19`

**攻撃シナリオ:** An anonymous user widens the DELETE condition to remove every cart.

**影響度 (Impact):** Unauthenticated mass deletion of carts; possible further SQL.

**脆弱性の根拠コード (Evidence):**

- `perl-cgi/cgi-bin/order.cgi:19` — request param concatenated, numeric context, do() sink  
  `$dbh->do("DELETE FROM carts WHERE cart_id = " . $q->param('cart'));`

**データフロー:** $q->param('cart') (order.cgi:19) → $dbh->do (order.cgi:19)

**推奨対策 (Recommendation):** Bind the value.

```
$dbh->do('DELETE FROM carts WHERE cart_id = ?', undef, scalar $q->param('cart'));
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: perl-cgi/cgi-bin/order.cgi:1-20 (whole file), order.cgi:8-9 CGI::Session->load() / $uid never tested (auth-model §2), no cast, regex or quote() on param('cart') before :19, no .htaccess / Apache auth config in repo (auth-model §6), only file in perl-cgi/. Evidence matches. param('cart') concatenated unquoted into $dbh->do at :19; no sanitizer on any path. Critical relies on the endpoint being unauthenticated: load() does not reject missing sessions (library behavior, per auth-model) and Apache-level auth is not in repo. The DELETE also has no owner filter (cart BOLA, not raised in this batch). Line 13 has the same unbound pattern for 'id'.

### BOLA-R-0001-1 — Any logged-in user can rename any member via form member_id

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (id_from_request_used_as_identity) — CWE-639, CWE-566 API1:2023  
- **対象エンドポイント:** ANY /shop/member.asp?mode=edit  
- **該当箇所:** `classic-asp/shop/member.asp:4`

**攻撃シナリオ:** User A posts mode=edit&name=x&member_id=<member id of user B> to /shop/member.asp; B's name is overwritten.

**影響度 (Impact):** Modify other members' profile data (name).

**脆弱性の根拠コード (Evidence):**

- `classic-asp/shop/inc/auth.asp:2` — Login check only; no object scope  
  `If Session("UserID") = "" Then Response.Redirect "/login.asp"`
- `classic-asp/shop/member.asp:7` — Target member chosen by request field; Session("UserID") never used  
  `sql = sql & " WHERE member_id = " & Request.Form("member_id")`
- `classic-asp/shop/member.asp:8` — UPDATE runs with no owner binding and no later check  
  `conn.Execute sql`

**データフロー:** Request.Form("member_id") (member.asp:7) → UPDATE members ... WHERE member_id = <value> (member.asp:7) → conn.Execute (member.asp:8)

**推奨対策 (Recommendation):** Do not take the member id from the request; use Session("UserID"), or add AND member_id = CLng(Session("UserID")) and use a parameterized ADO Command.

```
" WHERE member_id = " & CLng(Session("UserID"))
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: evidence lines member.asp:4-8 and inc/auth.asp:2 re-read (match), inc/conn.asp:1-3 (connection only, no filter), searched repo for global.asa / web.config / .htaccess covering classic-asp (none), code after conn.Execute (none; no owner comparison), role checks (auth-model §3: none). member_id taken from Request.Form; Session("UserID") never used in member.asp. Severity lowered critical->high: only `name` is written, which bola-patterns §6 rates as 'other non-sensitive field' (high). The SQLi on the same line (INJ-I-0002-1) can widen impact but is rated separately.

### BOLA-R-0003-1 — Order address readable by any logged-in user via id

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **対象エンドポイント:** ANY /shop/order.asp  
- **該当箇所:** `classic-asp/shop/order.asp:5`

**攻撃シナリオ:** User A sends GET /shop/order.asp?id=<order id of user B> and receives B's delivery address.

**影響度 (Impact):** Read other customers' order addresses (personal data).

**脆弱性の根拠コード (Evidence):**

- `classic-asp/shop/order.asp:5` — ID from QueryString/Form/Cookie  
  `id = Request("id")`
- `classic-asp/shop/order.asp:6` — No user_id filter (contrast line 12 which binds Session("UserID"))  
  `Set rs = conn.Execute("SELECT * FROM orders WHERE id = " & id)`
- `classic-asp/shop/order.asp:7` — Address of the loaded order is returned to the caller  
  `Response.Write Server.HTMLEncode(rs("address"))`

**データフロー:** Request("id") (order.asp:5) → SELECT * FROM orders WHERE id = <id> (order.asp:6) → rs("address") written to response (order.asp:7)

**推奨対策 (Recommendation):** Use the same pattern as line 12: CLng the id and add AND user_id = CLng(Session("UserID")); return 404 if no row.

```
"SELECT * FROM orders WHERE id = " & CLng(id) & " AND user_id = " & CLng(Session("UserID"))
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: order.asp:5-7 re-read (match), order.asp:10-12 safe variant uses a different variable (sid) and result rs2; does not guard line 6-7, post-query owner comparison before Response.Write (none), inc/auth.asp, inc/conn.asp, global.asa/IIS config (not in repo). Address (personal data) of any order returned to any logged-in user. High per bola-patterns §6.

### BOLA-R-0005-1 — order.cfm renders unscoped qOrder instead of owner-bound qMine

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **対象エンドポイント:** ANY /app/order.cfm  
- **該当箇所:** `coldfusion/app/order.cfm:2`

**攻撃シナリオ:** User A sends GET /app/order.cfm?id=<order id of user B> and sees B's address.

**影響度 (Impact):** Read other customers' order addresses.

**脆弱性の根拠コード (Evidence):**

- `coldfusion/app/order.cfm:1` — Login check only  
  `<cfif NOT structKeyExists(session, "userID")><cflocation url="/login.cfm"></cfif>`
- `coldfusion/app/order.cfm:3` — qOrder: id only, no owner filter  
  `SELECT * FROM orders WHERE id = #url.id#`
- `coldfusion/app/order.cfm:8` — Owner binding exists only in qMine, whose result is never used  
  `AND user_id = <cfqueryparam value="#session.userID#" cfsqltype="cf_sql_integer">`
- `coldfusion/app/order.cfm:10` — Output comes from the unscoped query  
  `<cfoutput>#qOrder.address#</cfoutput>`

**データフロー:** url.id (order.cfm:3) → qOrder (order.cfm:2-4) → qOrder.address output (order.cfm:10)

**推奨対策 (Recommendation):** Remove qOrder and render qMine; stop with 404 when qMine.recordCount is 0.

```
<cfif qMine.recordCount EQ 0><cfheader statuscode="404"><cfabort></cfif><cfoutput>#qMine.address#</cfoutput>
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: order.cfm:1-10 re-read (match), qMine (lines 5-9) is executed but never read; output at :10 uses qOrder, no recordCount check / cfabort on qMine, Application.cfc/.cfm (none in repo). Owner-bound query exists but its result is ignored; the unscoped qOrder.address is rendered. High (personal data).

### BOLA-R-0006-1 — Invoice details readable by any logged-in user via id

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **対象エンドポイント:** ANY /Invoice/Details/{id}  
- **該当箇所:** `dotnet-legacy/Web/Controllers/InvoiceController.cs:11`

**攻撃シナリオ:** User A requests GET /Invoice/Details/<invoice id of user B> and sees B's invoice.

**影響度 (Impact):** Read other customers' invoices (financial data).

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Controllers/InvoiceController.cs:6` — Login only, no Roles/Policy  
  `[Authorize]`
- `dotnet-legacy/Web/Controllers/InvoiceController.cs:13` — Load by primary key only; no owner comparison before View(inv) (contrast Mine, line 20)  
  `var inv = db.Invoices.Find(id);`
- `dotnet-legacy/Web/Controllers/InvoiceController.cs:9` — ShopDb source not in repo (auth-model Unknowns); a global filter is unlikely for Find but not provable  
  `private ShopDb db = new ShopDb();`

**データフロー:** int id (route/query/form) (InvoiceController.cs:11) → db.Invoices.Find(id) (InvoiceController.cs:13) → View(inv) (InvoiceController.cs:14)

**推奨対策 (Recommendation):** Filter by owner as in Mine: FirstOrDefault(i => i.Id == id && i.UserId == CurrentUserId()) and return HttpNotFound() when null.

```
var inv = db.Invoices.FirstOrDefault(i => i.Id == id && i.UserId == uid); if (inv == null) return HttpNotFound();
```

*検証結果 (Verifier):* likely — 確認対象: InvoiceController.cs:6-15 (class [Authorize] has no Roles/Policy), Web.config:3-9 (login only, no role/location rule for Invoice), search for ShopDb / Global.asax / filters in repo (none present), post-query comparison before View(inv) at :14 (none). Evidence matches. Find(id) by PK, no owner comparison; contrast Mine :20-21. Only ShopDb (not in repo) or the Details view could add a check; EF6 (System.Web.Mvc) has no built-in global query filter, so a hidden control is unlikely but not provable.

### BOLA-R-0008-1 — Invoice search returns any customer's invoices to any logged-in user

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **対象エンドポイント:** POST /Invoice/Search  
- **該当箇所:** `dotnet-legacy/Web/Controllers/InvoiceController.cs:25`

**攻撃シナリオ:** User A posts customer=<name of customer B> to /Invoice/Search and receives B's invoice list.

**影響度 (Impact):** Read other customers' invoices (financial data) in bulk.

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Controllers/InvoiceController.cs:6` — Login only, no Roles/Policy  
  `[Authorize]`
- `dotnet-legacy/Web/Controllers/InvoiceController.cs:28` — Selector from request; no UserId filter  
  `SqlQuery<Invoice>("SELECT * FROM Invoices WHERE Customer = '" + customer + "'")`
- `dotnet-legacy/Web/Controllers/InvoiceController.cs:26` — No role check; business intent (staff search vs customer self-search) unknown, hence medium confidence  
  `public ActionResult Search(string customer)`

**データフロー:** string customer (form/query) (InvoiceController.cs:26) → raw SQL by Customer (InvoiceController.cs:28) → View(list) (InvoiceController.cs:29)

**推奨対策 (Recommendation):** Add AND UserId = @uid bound to the current user (or require an enforced staff role); use SqlQuery with parameters.

```
db.Database.SqlQuery<Invoice>("SELECT * FROM Invoices WHERE Customer = @p0 AND UserId = @p1", customer, uid)
```

*検証結果 (Verifier):* likely — 確認対象: InvoiceController.cs:6,25-30, Web.config:3-9, auth-model §3 (no role checks anywhere), post-query filtering before View(list) (none). Any logged-in user lists invoices of any Customer value; no UserId filter and no staff role. Business intent (staff search vs self-search) is not visible, so likely rather than confirmed. Same sink as INJ-I-0008-1.

### BOLA-R-0014-1 — Invoice readable by id via Spring show() with no owner or login check visible

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **対象エンドポイント:** GET /invoices/{id}  
- **該当箇所:** `java-legacy/src/com/acme/web/InvoiceController.java:15`

**攻撃シナリオ:** User A requests GET /invoices/<invoice id of user B> and sees B's invoice.

**影響度 (Impact):** Read other customers' invoices (financial data); possibly unauthenticated (no Spring Security / filter coverage visible).

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/web/InvoiceController.java:16` — ID from path  
  `public String show(@PathVariable("id") Long id, Model model) {`
- `java-legacy/src/com/acme/web/InvoiceController.java:17` — DAO lookup by id only (contrast findByIdAndOwner at line 23); InvoiceDao source not in repo  
  `model.addAttribute("invoice", invoiceDao.findById(id));`

**データフロー:** @PathVariable id (InvoiceController.java:16) → invoiceDao.findById(id) (InvoiceController.java:17) → view invoice/show (InvoiceController.java:18)

**推奨対策 (Recommendation):** Use invoiceDao.findByIdAndOwner(id, principal.getName()) and return 404 on null; add authentication for /invoices/*.

```
Invoice inv = invoiceDao.findByIdAndOwner(id, principal.getName()); if (inv == null) throw new ResourceNotFoundException();
```

*検証結果 (Verifier):* likely — 確認対象: InvoiceController.show (:15-19; no Principal, no post-query check), contrast with mine() owner-bound call (:23), repo-wide grep for InvoiceDao source (absent), Spring Security / interceptor config (none in repo), class-level annotations (:8-9 only @Controller/@RequestMapping). findById(id) receives no user context, so an owner filter inside the DAO is improbable but unverifiable. Spring wiring: InvoiceController fields invoiceDao/session (InvoiceController.java:12-13) have no @Autowired/setters and no DispatcherServlet or Spring config is in repo; wiring and reachability assumed outside visible code. Severity high (financial data); would be critical if /invoices/* is unauthenticated.

### BOLA-R-0016-1 — Invoice search by customer returns any customer's invoices

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **対象エンドポイント:** GET /invoices/search  
- **該当箇所:** `java-legacy/src/com/acme/web/InvoiceController.java:27`

**攻撃シナリオ:** User A sends GET /invoices/search?customer=<customer B> and receives B's invoices.

**影響度 (Impact):** Bulk read of other customers' invoices; possibly unauthenticated (no auth coverage visible for /invoices/*).

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/web/InvoiceController.java:28` — Selector from query string; no Principal used  
  `public String search(@RequestParam("customer") String customer, Model model) {`
- `java-legacy/src/com/acme/web/InvoiceController.java:29` — HQL filters by customer only; no owner binding  
  `session.createQuery("from Invoice i where i.customer = '" + customer + "'").list()`

**データフロー:** @RequestParam customer (InvoiceController.java:28) → HQL from Invoice where customer = ... (InvoiceController.java:29) → view invoice/list (InvoiceController.java:30)

**推奨対策 (Recommendation):** Bind the owner from Principal in the HQL (and i.owner = :owner) with named parameters, or restrict to an enforced staff role.

```
session.createQuery("from Invoice i where i.customer = :c and i.owner = :o").setParameter("c", customer).setParameter("o", principal.getName())
```

*検証結果 (Verifier):* likely — 確認対象: InvoiceController.search (:27-31; no Principal, no owner predicate), HQL text at :29 (filters i.customer only), Spring Security / role config (none in repo), post-query filtering before view (none). Customer selector from query string returns that customer's invoices with no owner/role binding. Bulk financial read = high. Spring wiring: InvoiceController fields invoiceDao/session (InvoiceController.java:12-13) have no @Autowired/setters and no DispatcherServlet or Spring config is in repo; wiring and reachability assumed outside visible code.

### BOLA-R-0018-1 — Any logged-in user can read any order via /orders/:id (findById)

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **対象エンドポイント:** GET /orders/:id  
- **該当箇所:** `node-express/routes/orders.js:8`

**攻撃シナリオ:** User A sends GET /orders/<order id of user B> and receives B's order as JSON.

**影響度 (Impact):** Read other customers' full order documents.

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/orders.js:6` — Login check only  
  `function ensureLoggedIn(req, res, next) { if (!req.user) return res.redirect('/login'); next(); }`
- `node-express/routes/orders.js:9` — Loads by path id only and returns the full document; no owner comparison  
  `Order.findById(req.params.id, function (err, order) { res.json(order); });`

**推奨対策 (Recommendation):** Use the scoped lookup already used in /orders/:id/mine: findOne({_id: req.params.id, owner: req.user._id}); return 404 when null.

```
Order.findOne({ _id: req.params.id, owner: req.user._id }, ...)
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: orders.js:6 ensureLoggedIn (login only), orders.js:9 findById by path id, response returned without owner comparison, orders.js:12-14 scoped sibling route for contrast, ../models/order (absent; could hold a scoping plugin, auth-model §6). No owner check in the handler or after the query. The safe sibling /orders/:id/mine shows ownership is expected. Confidence medium per auth-model §7 because the Order model source is missing.

### BOLA-R-0025-1 — Invoice readable by id with no owner filter (Invoice::view)

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **対象エンドポイント:** GET /invoice/view/{id}  
- **該当箇所:** `php-codeigniter/application/controllers/Invoice.php:9`

**攻撃シナリオ:** User A requests /invoice/view/<invoice id of user B> and sees B's invoice.

**影響度 (Impact):** Read other customers' invoices (financial data). MY_Controller (:2, source not in repo) may add a login check; an object-level check there is unlikely but unverified.

**脆弱性の根拠コード (Evidence):**

- `php-codeigniter/application/controllers/Invoice.php:9` — ID from URI segment  
  `public function view($id) {`
- `php-codeigniter/application/controllers/Invoice.php:10` — No user_id filter (compare mine() at :16)  
  `$q = $this->db->query("SELECT * FROM invoices WHERE id = $id");`
- `php-codeigniter/application/controllers/Invoice.php:11` — Row rendered without owner comparison  
  `$this->load->view('invoice', array('inv' => $q->row()));`

**推奨対策 (Recommendation):** Use the mine() pattern: get_where('invoices', ['id' => $id, 'user_id' => $this->session->userdata('user_id')]); show_404() when no row.

```
$q = $this->db->get_where('invoices', array('id' => $id, 'user_id' => $this->session->userdata('user_id')));
```

*検証結果 (Verifier):* likely — 確認対象: Invoice.php:9-12 view(): query by id only, row passed to view, Invoice.php:2-7 constructor; MY_Controller source not in repo, Invoice.php:14-18 mine() shows owner-bound pattern exists but view() does not use it, config/routes.php and hooks.php absent (auth-model §6), no post-query owner comparison before load->view. Code says what the finding claims. Only place a control could hide is MY_Controller / hooks (not in repo); an object-level check there is unlikely but cannot be excluded. Invoices are financial data -> high.

### BOLA-R-0031-1 — Order detail (address) readable for any order id by any logged-in user

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **対象エンドポイント:** GET /php-plain/order_detail.php  
- **該当箇所:** `php-plain/order_detail.php:5`

**攻撃シナリオ:** User A requests /order_detail.php?id=<order id of user B> and sees B's delivery address.

**影響度 (Impact):** Read other customers' personal data (address).

**脆弱性の根拠コード (Evidence):**

- `php-plain/order_detail.php:5` — ID from query string  
  `$id = $_GET['id'];`
- `php-plain/order_detail.php:6` — No user_id filter  
  `$res = mysql_query("SELECT * FROM orders WHERE id = " . $id);`
- `php-plain/order_detail.php:8` — Other user's address printed; no comparison with $_SESSION['user_id']  
  `echo htmlspecialchars($order['address']);`

**推奨対策 (Recommendation):** Use the order_detail_safe.php pattern: PDO with WHERE id = ? AND user_id = ? bound to $_SESSION['user_id'].

```
$st = $pdo->prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?'); $st->execute(array($_GET['id'], $_SESSION['user_id']));
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: php-plain/order_detail.php:1-8 (whole file), php-plain/inc/auth.php:2-7 (login only), php-plain/inc/db.php:1-4 (no query wrapper), post-query owner comparison (none before echo at :8), auth-model §3/§5: no global prepend or role layer. Lookup by request id only; address of any order echoed. Contrast order_detail_safe.php binds user_id. Personal data read -> high.

### BOLA-R-0034-1 — Any logged-in user can read any order via /orders/<order_id>

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **対象エンドポイント:** GET /orders/<int:order_id>  
- **該当箇所:** `python-flask/app.py:8`

**攻撃シナリオ:** User A, logged in, sends GET /orders/<order id of user B> and receives B's full order row as JSON. IDs are sequential integers, so enumeration is trivial.

**影響度 (Impact):** Read other customers' orders (all columns of orders table; likely personal and financial data).

**脆弱性の根拠コード (Evidence):**

- `python-flask/app.py:8` — Object ID taken from the URL path (attacker-controlled)  
  `@app.route('/orders/<int:order_id>')`
- `python-flask/app.py:9` — Login check only (Flask-Login); not an ownership check  
  `@login_required`
- `python-flask/app.py:12` — Lookup by id only; no user_id filter, unlike the safe variant at line 20  
  `cur.execute("SELECT * FROM orders WHERE id = %s" % order_id)`
- `python-flask/app.py:13` — Row returned to caller with no post-load owner comparison  
  `return jsonify(cur.fetchone())`

**データフロー:** path order_id (app.py:8) → % formatted into SELECT ... WHERE id (app.py:12) → full row returned as JSON (app.py:13)

**推奨対策 (Recommendation):** Bind the order to the current principal in the query (as my_order does at app.py:20), or load and compare owner and return 404 on mismatch. Also switch to parameter binding.

```
cur.execute("SELECT * FROM orders WHERE id = %s AND user_id = %s", (order_id, current_user.id))
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: python-flask/app.py:8-13, python-flask/app.py:9 @login_required (login only), python-flask/app.py:16-21 safe variant for contrast, post-query owner comparison (none; row returned directly), auth-model §6: db module and user_loader absent (irrelevant to the missing filter). Lookup by path id only, full row returned as JSON. The <int:> converter prevents SQLi at :12 but not BOLA.

### INJ-I-0002-1 — Member UPDATE concatenates unquoted member_id from POST

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89 A03:2021  
- **対象エンドポイント:** POST /classic-asp/shop/member.asp?mode=edit  
- **該当箇所:** `classic-asp/shop/member.asp:6`

**攻撃シナリオ:** A crafted member_id changes the WHERE clause so the UPDATE hits other or all rows, or appends extra SQL.

**影響度 (Impact):** Modify any members row; read/modify other tables the DB user can access.

**脆弱性の根拠コード (Evidence):**

- `classic-asp/shop/member.asp:7` — source: form field, numeric context, no cast  
  `sql = sql & " WHERE member_id = " & Request.Form("member_id")`
- `classic-asp/shop/member.asp:6` — name part is escaped in quoted context (enough for that part only)  
  `sql = "UPDATE members SET name = '" & Replace(Request.Form("name"), "'", "''") & "'"`
- `classic-asp/shop/member.asp:8` — sink, no parameters  
  `conn.Execute sql`

**データフロー:** Request.Form("member_id") (member.asp:7) → sql (member.asp:7) → conn.Execute (member.asp:8)

**推奨対策 (Recommendation):** Use ADODB.Command with ? parameters, or CLng() the id after IsNumeric with failure stopping the page.

```
cmd.CommandText = "UPDATE members SET name = ? WHERE member_id = ?" : cmd.Parameters.Append cmd.CreateParameter("n",202,1,100,name) ...
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: member.asp:6-8 re-read (match), casts/IsNumeric/CLng on member_id (none), inc/conn.asp: plain ADODB.Connection, no Command/parameters, DB account privileges (conn string from Application("ConnStr"), not visible; so no raise to critical). Unquoted numeric context; Replace("'","''") applies only to `name`. Login required -> high per injection-patterns §5.

### INJ-I-0003-1 — Member DELETE concatenates unquoted member_id from query string

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89 A03:2021  
- **対象エンドポイント:** GET /classic-asp/shop/member.asp?mode=delete  
- **該当箇所:** `classic-asp/shop/member.asp:10`

**攻撃シナリオ:** A crafted member_id widens the DELETE condition so many or all member rows are removed.

**影響度 (Impact):** Mass deletion of members; possible further SQL on the same connection.

**脆弱性の根拠コード (Evidence):**

- `classic-asp/shop/member.asp:10` — source query string concatenated into sink, numeric context  
  `conn.Execute "DELETE FROM members WHERE member_id = " & Request.QueryString("member_id")`

**データフロー:** Request.QueryString("member_id") (member.asp:10) → conn.Execute (member.asp:10)

**推奨対策 (Recommendation):** Bind member_id via ADODB.Command parameter or CLng() after IsNumeric check.

```
conn.Execute "DELETE FROM members WHERE member_id = " & CLng(id)  ' only after IsNumeric(id) else stop
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: member.asp:10 re-read (match), casts/validation on QueryString("member_id") (none), inc/conn.asp (no parameter binding), auth include member.asp:1 -> login required. QueryString concatenated directly into DELETE. High (authenticated).

### INJ-I-0004-1 — Order SELECT concatenates unvalidated id from Request()

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89 A03:2021  
- **対象エンドポイント:** GET /classic-asp/shop/order.asp  
- **該当箇所:** `classic-asp/shop/order.asp:5`

**攻撃シナリオ:** A crafted id adds conditions or UNION parts to read data beyond the requested order.

**影響度 (Impact):** Read any table the DB user can access.

**脆弱性の根拠コード (Evidence):**

- `classic-asp/shop/order.asp:5` — source: query/form/cookie collection  
  `id = Request("id")`
- `classic-asp/shop/order.asp:6` — concatenated in numeric context, sink  
  `Set rs = conn.Execute("SELECT * FROM orders WHERE id = " & id)`

**データフロー:** Request("id") (order.asp:5) → id → conn.Execute (order.asp:6)

**推奨対策 (Recommendation):** Use the pattern already on line 10-12 (IsNumeric + CLng) or ADODB.Command parameters.

```
If Not IsNumeric(Request("id")) Then Response.End
Set rs = conn.Execute("SELECT * FROM orders WHERE id = " & CLng(Request("id")))
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: order.asp:4-6 re-read (match), `Dim id` is untyped Variant; no IsNumeric/CLng on id (only on sid at :10-11), inc/conn.asp (no parameters). Request("id") also reads Form and Cookies. Authenticated -> high.

### INJ-I-0007-1 — order.cfm qOrder puts url.id into cfquery without cfqueryparam

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (template_placeholder) — CWE-89 A03:2021  
- **対象エンドポイント:** GET /coldfusion/app/order.cfm  
- **該当箇所:** `coldfusion/app/order.cfm:2`

**攻撃シナリオ:** A logged-in user sends a crafted id that changes the query and leaks other rows via qOrder.address output.

**影響度 (Impact):** Read any data the 'shop' datasource can access.

**脆弱性の根拠コード (Evidence):**

- `coldfusion/app/order.cfm:1` — login required only  
  `<cfif NOT structKeyExists(session, "userID")><cflocation url="/login.cfm"></cfif>`
- `coldfusion/app/order.cfm:3` — url.id in numeric context, no cfqueryparam  
  `SELECT * FROM orders WHERE id = #url.id#`

**データフロー:** url.id (order.cfm:3) → cfquery qOrder (order.cfm:2)

**推奨対策 (Recommendation):** Remove qOrder and use the parameterized qMine query (order.cfm:5-9).

```
<cfqueryparam value="#url.id#" cfsqltype="cf_sql_integer">
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: order.cfm:1-4 re-read (match), validation of url.id before qOrder (none; isNumeric/cfparam type absent), qMine cf_sql_integer at :7 runs AFTER qOrder, so it cannot block the injected query, Application.cfc (none in repo). url.id in unquoted numeric context. Login required -> high.

### INJ-I-0008-1 — Invoice search concatenates customer into EF SqlQuery

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89 A03:2021  
- **対象エンドポイント:** POST /Invoice/Search  
- **該当箇所:** `dotnet-legacy/Web/Controllers/InvoiceController.cs:26`

**攻撃シナリオ:** A logged-in user closes the quote in customer and appends SQL; SQL Server allows stacked statements.

**影響度 (Impact):** Read invoices of all customers and other tables; possibly modify data (stacked queries).

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Controllers/InvoiceController.cs:6` — login-only gate, no Roles  
  `[Authorize]`
- `dotnet-legacy/Web/Controllers/InvoiceController.cs:26` — source: model-bound POST/query value  
  `public ActionResult Search(string customer)`
- `dotnet-legacy/Web/Controllers/InvoiceController.cs:28` — concatenated into raw EF SQL, sink  
  `db.Database.SqlQuery<Invoice>("SELECT * FROM Invoices WHERE Customer = '" + customer + "'")`

**データフロー:** customer action parameter (InvoiceController.cs:26) → string concat (InvoiceController.cs:28) → Database.SqlQuery (InvoiceController.cs:28)

**推奨対策 (Recommendation):** Use SqlQuery with a SqlParameter, or LINQ (db.Invoices.Where(i => i.Customer == customer)).

```
db.Database.SqlQuery<Invoice>("SELECT * FROM Invoices WHERE Customer = @c", new SqlParameter("@c", customer))
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: InvoiceController.cs:26-28 (string param, no cast/allow-list), Database.SqlQuery called with no parameters argument, reachability: [Authorize] :6 + Web.config:5 (login required), DB account privilege (not shown in repo). Quoted string concatenation into raw EF SQL, executed via ToList(). Login required -> high; no evidence of sa/admin DB account.

### INJ-I-0009-1 — EditOrder UPDATE concatenates txtNote.Text and hidden field hfOrderId

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89 A03:2021  
- **対象エンドポイント:** POST /dotnet-legacy/Web/Orders/EditOrder.aspx  
- **該当箇所:** `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7`

**攻撃シナリオ:** A logged-in user puts a quote in the note or edits the hidden OrderId to rewrite the UPDATE (all rows or extra statements).

**影響度 (Impact):** Modify any Orders rows; SQL Server allows stacked statements, so further writes are possible.

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7` — TextBox value, quoted, not escaped (I-0009)  
  `Dim sql As String = "UPDATE Orders SET Note = '" & txtNote.Text & "'"`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8` — hidden field, client-controlled, numeric context (I-0010)  
  `sql &= " WHERE OrderId = " & hfOrderId.Value`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:10` — command built from string  
  `Dim cmd As New SqlCommand(sql, conn)`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:12` — sink, no parameters  
  `cmd.ExecuteNonQuery()`

**データフロー:** txtNote.Text / hfOrderId.Value (EditOrder.aspx.vb:7-8) → sql → SqlCommand (EditOrder.aspx.vb:10) → ExecuteNonQuery (EditOrder.aspx.vb:12)

**推奨対策 (Recommendation):** Use SqlCommand parameters for both values.

```
cmd = New SqlCommand("UPDATE Orders SET Note = @n WHERE OrderId = @id", conn): cmd.Parameters.AddWithValue("@n", txtNote.Text): cmd.Parameters.AddWithValue("@id", CInt(hfOrderId.Value))
```

*検証結果 (Verifier):* likely — 確認対象: EditOrder.aspx.vb:6-13 (no escaping, no CInt, no parameters), EditOrder.aspx:1-2 (controls declared), Web.config:5 login required for /Orders, BasePage (not in repo). Taint and sink are correct. Reachability gap: handler is wired via 'Handles btnSave.Click' but EditOrder.aspx:2 declares no btnSave control and no designer file exists, so the visible code would not compile/fire as-is; markup may be truncated. Also Inherits="Web.Orders.EditOrder" vs class EditOrder without namespace. Keep high severity; confidence lowered.

### INJ-I-0011-1 — OrderDetail executes SELECT concatenated with query-string id

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89 A03:2021  
- **対象エンドポイント:** GET /dotnet-legacy/Web/Orders/OrderDetail.aspx  
- **該当箇所:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10`

**攻撃シナリオ:** A logged-in user sends a crafted id that appends conditions, UNION or stacked statements.

**影響度 (Impact):** Read/modify any data the connection's DB login can access.

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10` — source: query string  
  `string id = Request.QueryString["id"];`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13` — concatenated, numeric context  
  `var cmd = new SqlCommand("SELECT * FROM Orders WHERE OrderId = " + id, conn);`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:15` — sink executed  
  `var r = cmd.ExecuteReader();`

**データフロー:** Request.QueryString["id"] (OrderDetail.aspx.cs:10) → id → SqlCommand (OrderDetail.aspx.cs:13) → ExecuteReader (OrderDetail.aspx.cs:15)

**推奨対策 (Recommendation):** Execute the parameterized 'safe' command from line 16-18 instead of line 13.

```
var cmd = new SqlCommand("SELECT * FROM Orders WHERE OrderId = @id AND UserId = @uid", conn); cmd.Parameters.AddWithValue("@id", int.Parse(id));
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: OrderDetail.aspx.cs:10-15 (string id, no int.Parse/cast before :13), ExecuteReader :15 executes the tainted command, reachability: Web.config:5 deny ? applies to /Orders; not under Handlers exclusion, BasePage (not in repo; at most login). Numeric-context concatenation executed. Unused result does not reduce injection impact (SqlClient allows batched statements / blind techniques). Login required -> high.

### INJ-I-0016-1 — EditUserAction prepareStatement built by concatenating email and user_id

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89 A03:2021  
- **対象エンドポイント:** POST /user/edit.do  
- **該当箇所:** `java-legacy/src/com/acme/struts/EditUserAction.java:10`

**攻撃シナリオ:** A logged-in user crafts email or user_id to rewrite the UPDATE, e.g. changing every user's email.

**影響度 (Impact):** Modify any users rows (account takeover via email change); read data via error/boolean techniques.

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/struts/EditUserAction.java:10` — source  
  `String userId = request.getParameter("user_id");`
- `java-legacy/src/com/acme/struts/EditUserAction.java:11` — source  
  `String email = request.getParameter("email");`
- `java-legacy/src/com/acme/struts/EditUserAction.java:13` — prepared but concatenated; no placeholders  
  `PreparedStatement ps = conn.prepareStatement("UPDATE users SET email = '" + email + "' WHERE id = " + userId);`
- `java-legacy/src/com/acme/struts/EditUserAction.java:14` — sink  
  `ps.executeUpdate();`

**データフロー:** request params user_id/email (EditUserAction.java:10-11) → SQL string (EditUserAction.java:13) → executeUpdate (EditUserAction.java:14)

**推奨対策 (Recommendation):** Use ? placeholders and setString/setLong.

```
PreparedStatement ps = conn.prepareStatement("UPDATE users SET email = ? WHERE id = ?"); ps.setString(1, email); ps.setLong(2, Long.parseLong(userId));
```

*検証結果 (Verifier):* likely — 確認対象: EditUserAction.java:10-14 (email quoted-concat, userId unquoted-concat, no setX calls), casts/validation between source and sink (none), struts-config.xml userForm (form-bean undefined, validate() unknown), web.xml ActionServlet mapping (absent). prepareStatement with concatenated values and no placeholders is not parameterized; both params tainted. High = after login (LoginFilter on *.do). Likely, not confirmed: reachability (no ActionServlet mapping) and ActionForm validation are not visible.

### INJ-I-0017-1 — Invoice search builds HQL by concatenating customer parameter

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-564, CWE-89 A03:2021  
- **対象エンドポイント:** GET /invoices/search  
- **該当箇所:** `java-legacy/src/com/acme/web/InvoiceController.java:27`

**攻撃シナリオ:** A crafted customer value closes the quote and adds 'or 1=1'-style HQL conditions to list all invoices.

**影響度 (Impact):** Read every Invoice entity; HQL injection can sometimes reach native SQL functions.

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/web/InvoiceController.java:28` — source: request parameter  
  `public String search(@RequestParam("customer") String customer, Model model) {`
- `java-legacy/src/com/acme/web/InvoiceController.java:29` — concatenated HQL, Hibernate sink  
  `session.createQuery("from Invoice i where i.customer = '" + customer + "'").list()`

**データフロー:** @RequestParam customer (InvoiceController.java:28) → HQL string (InvoiceController.java:29) → Session.createQuery().list() (InvoiceController.java:29)

**推奨対策 (Recommendation):** Use a named HQL parameter.

```
session.createQuery("from Invoice i where i.customer = :c").setParameter("c", customer).list()
```

*検証結果 (Verifier):* likely — 確認対象: InvoiceController.java:28-29 (String param concatenated in quotes into createQuery), setParameter / validation (none), Spring auth coverage for /invoices/* (unknown). HQL injection evidence correct; String type gives no protection. Spring wiring: InvoiceController fields invoiceDao/session (InvoiceController.java:12-13) have no @Autowired/setters and no DispatcherServlet or Spring config is in repo; wiring and reachability assumed outside visible code. Rated high (assumed login); critical if unauthenticated.

### INJ-I-0020-1 — /reports concatenates req.query.month into SQL

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89 A03:2021  
- **対象エンドポイント:** GET /reports  
- **該当箇所:** `node-express/routes/orders.js:16`

**攻撃シナリオ:** A logged-in user closes the quote in month and appends SQL (UNION) to read other tables.

**影響度 (Impact):** Read any data the DB user can access.

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/orders.js:16` — login only  
  `router.get('/reports', ensureLoggedIn, function (req, res) {`
- `node-express/routes/orders.js:17` — concatenated, quoted, no escaping; db.query sink  
  `db.query("SELECT * FROM reports WHERE month = '" + req.query.month + "'", ...`

**データフロー:** req.query.month (orders.js:17) → db.query (orders.js:17)

**推奨対策 (Recommendation):** Use placeholders supported by the driver ('?' for mysql, $1 for pg).

```
db.query("SELECT * FROM reports WHERE month = ?", [String(req.query.month)], cb)
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: orders.js:16 ensureLoggedIn (login only), orders.js:17 quoted concatenation of req.query.month into db.query, whole file for escaping (none), ../db wrapper (absent; cannot sanitize an already concatenated string). Fully traced source to sink in one statement. Any logged-in user. No DB account privilege visible, so high not critical.

### INJ-I-0023-1 — /search builds Mongo $where JavaScript from req.query.n

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** NoSQLインジェクション (NoSQLi) (js_injection) — CWE-943 A03:2021  
- **対象エンドポイント:** GET /search  
- **該当箇所:** `node-express/routes/orders.js:24`

**攻撃シナリオ:** A logged-in user closes the quote in n and adds JavaScript that makes the predicate always true or burns CPU.

**影響度 (Impact):** Dump all items; denial of service on the DB server.

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/orders.js:25` — string concatenated into server-side JS  
  `db.collection('items').find({ $where: "this.name == '" + req.query.n + "'" })`

**データフロー:** req.query.n (orders.js:25) → $where (orders.js:25) → collection('items').find (orders.js:25)

**推奨対策 (Recommendation):** Remove $where; use a normal equality filter with a string-cast value.

```
db.collection('items').find({ name: String(req.query.n) })
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: orders.js:24 ensureLoggedIn (login only), orders.js:25 req.query.n concatenated into $where JS string, whole file for cast/escape (none). Fully traced. Only possible outside control is MongoDB server-side JS disabled (security.javascriptEnabled=false) or a server version that removed $where; neither visible in repo.

### INJ-I-0026-1 — CodeIgniter invoice view interpolates URI segment into db->query

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_interpolation) — CWE-89 A03:2021  
- **対象エンドポイント:** ANY /invoice/view/{id}  
- **該当箇所:** `php-codeigniter/application/controllers/Invoice.php:9`

**攻撃シナリオ:** A user puts SQL after the id in the URL path to change the WHERE clause.

**影響度 (Impact):** Read any data the DB user can access.

**脆弱性の根拠コード (Evidence):**

- `php-codeigniter/application/controllers/Invoice.php:9` — source: URI segment /invoice/view/<id>  
  `public function view($id) {`
- `php-codeigniter/application/controllers/Invoice.php:10` — interpolated in unquoted numeric context, sink without binding  
  `$q = $this->db->query("SELECT * FROM invoices WHERE id = $id");`

**データフロー:** URI segment 3 (Invoice.php:9) → $id → $this->db->query (Invoice.php:10)

**推奨対策 (Recommendation):** Use query bindings or get_where with an int cast, as done in mine() and update().

```
$q = $this->db->query('SELECT * FROM invoices WHERE id = ?', array((int)$id));
```

*検証結果 (Verifier):* likely — 確認対象: Invoice.php:9-10 $id from URI segment interpolated unquoted into db->query, no (int)/is_numeric/escape on $id, MY_Controller, config/config.php (permitted_uri_chars), routes.php not in repo. Sink and source confirmed. CodeIgniter's permitted_uri_chars (config not in repo; default allows letters, digits, space, ~%.:_-) filters URI segments and blocks quotes/parentheses/commas, so payloads are restricted, but numeric-context boolean injection (e.g. '1 OR 1') fits the default set. Not certain of exact CI version decoding behavior -> medium.

### INJ-I-0028-1 — admin.php delete interpolates POST id into mysql_query

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_interpolation) — CWE-89 A03:2021  
- **対象エンドポイント:** POST /php-plain/admin.php?action=delete  
- **該当箇所:** `php-plain/admin.php:11`

**攻撃シナリオ:** Any logged-in user (no admin role check) sends a crafted id that deletes all users.

**影響度 (Impact):** Mass deletion of users; boolean/time-based data read.

**脆弱性の根拠コード (Evidence):**

- `php-plain/admin.php:11` — source, no cast  
  `$id = $_POST['id'];`
- `php-plain/admin.php:12` — interpolated unquoted, mysql_query sink  
  `mysql_query("DELETE FROM users WHERE id = $id");`

**データフロー:** $_POST['id'] (admin.php:11) → $id → mysql_query (admin.php:12)

**推奨対策 (Recommendation):** Cast to int as on line 7, or use PDO prepared statements.

```
$st = $pdo->prepare('DELETE FROM users WHERE id = ?'); $st->execute([(int)$_POST['id']]);
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: admin.php:11-12 $_POST['id'] interpolated unquoted, no cast (contrast (int) at :7), inc/auth.php login required, no role, inc/db.php DB user 'app' (not root/sa). Reachable by any logged-in user, no sanitizer -> high. Not critical: repo does not show an admin DB account.

### INJ-I-0030-1 — mongo_find.php builds $where JavaScript from GET n

- **重要度 / 確信度:** 高 (High) / 低 (Low)  
- **ステータス:** likely  
- **脆弱性分類:** NoSQLインジェクション (NoSQLi) (js_injection) — CWE-943 A03:2021  
- **対象エンドポイント:** GET /php-plain/mongo_find.php  
- **該当箇所:** `php-plain/mongo_find.php:6`

**攻撃シナリオ:** A logged-in user closes the quote in n and adds JavaScript that returns every member or loops.

**影響度 (Impact):** Dump the members collection; DB denial of service.

**脆弱性の根拠コード (Evidence):**

- `php-plain/mongo_find.php:6` — request value concatenated into server-side JS  
  `$docs = $coll->find(array('$where' => "this.name == '" . $_GET['n'] . "'"));`

**データフロー:** $_GET['n'] (mongo_find.php:6) → $where (mongo_find.php:6) → MongoCollection::find (mongo_find.php:6)

**推奨対策 (Recommendation):** Drop $where; use an equality filter with a string cast.

```
$docs = $coll->find(['name' => (string)$_GET['n']]);
```

*検証結果 (Verifier):* likely — 確認対象: mongo_find.php:6 $_GET['n'] concatenated into $where JS, inc/auth.php login required, use of $docs after :6 (none; file ends). Taint into $where is real and unsanitized. However legacy MongoCollection::find returns a lazy MongoCursor that is not sent to the server until iterated, and $docs is never iterated, so the query likely never executes today. Driver behavior stated from knowledge, not repo -> low confidence. If lazy execution is confirmed, rate low (latent); if any code iterates $docs, high.

### INJ-I-0031-1 — Order detail query concatenates unquoted GET id

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89 A03:2021  
- **対象エンドポイント:** GET /php-plain/order_detail.php  
- **該当箇所:** `php-plain/order_detail.php:5`

**攻撃シナリオ:** A logged-in user supplies an id value with extra SQL that changes the WHERE clause (e.g. UNION-based read of other tables).

**影響度 (Impact):** Read any data the 'app' DB user can access; also bypasses any notion of order ownership.

**脆弱性の根拠コード (Evidence):**

- `php-plain/order_detail.php:2` — login-only gate (inc/auth.php:4-6); any logged-in user reaches the sink  
  `require_once 'inc/auth.php';`
- `php-plain/order_detail.php:5` — source: query string, no cast  
  `$id = $_GET['id'];`
- `php-plain/order_detail.php:6` — concatenated in numeric (unquoted) context and sent to mysql_query  
  `$res = mysql_query("SELECT * FROM orders WHERE id = " . $id);`

**データフロー:** $_GET['id'] (order_detail.php:5) → $id → mysql_query (order_detail.php:6)

**推奨対策 (Recommendation):** Use a PDO prepared statement with a bound integer parameter (the $pdo handle already exists in inc/db.php:4).

```
$st = $pdo->prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?'); $st->execute([(int)$_GET['id'], $_SESSION['user_id']]);
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: php-plain/order_detail.php:5-6 (no cast, unquoted numeric context), php-plain/inc/db.php:2 (raw mysql_query, DB user 'app', not root), php-plain/inc/auth.php (login-only gate). Unquoted numeric context, so even magic_quotes_gpc (PHP 5 config not in repo) would not help. Reachable by any logged-in user -> high.

### INJ-I-0032-1 — Product search LIKE clause relies on addslashes only

- **重要度 / 確信度:** 高 (High) / 低 (Low)  
- **ステータス:** likely  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89 A03:2021  
- **対象エンドポイント:** GET /php-plain/search.php  
- **該当箇所:** `php-plain/search.php:5`

**攻撃シナリオ:** If the connection charset is a multibyte charset such as SJIS/GBK, a crafted byte sequence swallows the added backslash and breaks out of the quoted string.

**影響度 (Impact):** Read data via the products query; same sink is already injectable via sort (INJ-I-0033-1).

**脆弱性の根拠コード (Evidence):**

- `php-plain/search.php:5` — source: query string; addslashes is a weak sanitizer (multibyte bypass with SJIS/GBK)  
  `$kw = addslashes($_GET['q']);`
- `php-plain/search.php:8` — concatenated inside quotes  
  `$sql .= " AND name LIKE '%" . $kw . "%'";`
- `php-plain/search.php:11` — sink, no binding  
  `$res = mysql_query($sql);`

**データフロー:** $_GET['q'] (search.php:5) → addslashes → $kw → $sql (search.php:8) → mysql_query (search.php:11)

**推奨対策 (Recommendation):** Bind the keyword as a parameter (PDO) instead of addslashes; build the LIKE pattern in code.

```
$st = $pdo->prepare('SELECT id, name FROM products WHERE name LIKE ?'); $st->execute(['%'.$_GET['q'].'%']);
```

*検証結果 (Verifier):* likely — 確認対象: php-plain/search.php:5,8,11, php-plain/inc/db.php:2-3 (no SET NAMES / mysql_set_charset), repo-wide grep for charset settings (none). addslashes inside quotes is exploitable only if the connection charset is a multibyte one (SJIS/GBK/Big5). No charset is set in code; server/my.cnf default not in repo. Keep as likely pending charset confirmation. Same query is already injectable via sort (INJ-I-0033-1), so remediation overlaps.

### INJ-I-0033-1 — ORDER BY clause taken directly from GET sort

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (dynamic_identifier) — CWE-89 A03:2021  
- **対象エンドポイント:** GET /php-plain/search.php  
- **該当箇所:** `php-plain/search.php:6`

**攻撃シナリオ:** A logged-in user puts an SQL expression in sort to infer data from other tables through result ordering (blind injection).

**影響度 (Impact):** Read any data the 'app' DB user can access.

**脆弱性の根拠コード (Evidence):**

- `php-plain/search.php:6` — source: query string, no allow-list  
  `$sort = $_GET['sort'];`
- `php-plain/search.php:9` — raw identifier/expression appended  
  `$sql .= " ORDER BY " . $sort;`
- `php-plain/search.php:11` — sink  
  `$res = mysql_query($sql);`

**データフロー:** $_GET['sort'] (search.php:6) → $sort → $sql (search.php:9) → mysql_query (search.php:11)

**推奨対策 (Recommendation):** Map sort to an exact allow-list of column names; default otherwise.

```
$cols = ['id'=>'id','name'=>'name']; $sort = isset($cols[$_GET['sort']]) ? $cols[$_GET['sort']] : 'id';
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: php-plain/search.php:6,9,11 (no allow-list, no cast), php-plain/inc/db.php (no wrapper), php-plain/inc/auth.php (login-only gate). Raw ORDER BY expression from GET reaches mysql_query; quoting-based controls (magic_quotes) do not apply to an identifier context.

### INJ-I-0034-1 — Category filter interpolates $_GET['cat'] in heredoc SQL

- **重要度 / 確信度:** 高 (High) / 中 (Medium)  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_interpolation) — CWE-89 A03:2021  
- **対象エンドポイント:** GET /php-plain/search.php  
- **該当箇所:** `php-plain/search.php:12`

**攻撃シナリオ:** A logged-in user closes the quote in cat and appends SQL that changes the query.

**影響度 (Impact):** Read any data the 'app' DB user can access.

**脆弱性の根拠コード (Evidence):**

- `php-plain/search.php:14` — request value interpolated directly into quoted SQL, no escaping at all  
  `WHERE category = '{$_GET['cat']}'`
- `php-plain/search.php:16` — sink  
  `$res2 = mysql_query($q);`

**データフロー:** $_GET['cat'] (search.php:14) → $q heredoc (search.php:12-15) → mysql_query (search.php:16)

**推奨対策 (Recommendation):** Use a prepared statement with a bound parameter.

```
$st = $pdo->prepare('SELECT * FROM products WHERE category = ?'); $st->execute([$_GET['cat']]);
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: php-plain/search.php:12-16 (heredoc interpolation of $_GET['cat'], executed at :16), php-plain/inc/db.php (no wrapper), php.ini / .htaccess / .user.ini in repo (none found). No escaping in code. Confidence medium only because this is PHP 5-era code and magic_quotes_gpc (php.ini, not in repo) could auto-escape $_GET in PHP < 5.4; even then the multibyte caveat of INJ-I-0032-1 applies. Note: :10 ($sql2 with constant STATUS_ACTIVE) is a constant-only concat and never executed - not a finding.

### INJ-I-0036-1 — Flask search builds LIKE query with f-string

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_interpolation) — CWE-89 A03:2021  
- **対象エンドポイント:** GET|POST /search  
- **該当箇所:** `python-flask/app.py:27`

**攻撃シナリオ:** A logged-in user closes the quote in q and appends SQL (e.g. UNION) to read other tables.

**影響度 (Impact):** Read any data the DB user can access.

**脆弱性の根拠コード (Evidence):**

- `python-flask/app.py:25` — login-only gate  
  `@login_required`
- `python-flask/app.py:27` — source: query string  
  `q = request.args.get('q', '')`
- `python-flask/app.py:29` — f-string interpolation into SQL, sink without parameters  
  `cur.execute(f"SELECT * FROM products WHERE name LIKE '%{q}%'")`

**データフロー:** request.args['q'] (app.py:27) → q → cur.execute f-string (app.py:29)

**推奨対策 (Recommendation):** Pass q as a bound parameter.

```
cur.execute("SELECT * FROM products WHERE name LIKE %s", ('%' + q + '%',))
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: python-flask/app.py:24-30, request.args.get with no validation (:27), cur.execute with no params tuple (:29), db module not in repo (does not affect: string is built before execute). f-string interpolation of request value into quoted SQL; any logged-in user.

### BOLA-R-0010-1 — Order note writable on any order via client-controlled hidden field

- **重要度 / 確信度:** 中 (Medium) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **対象エンドポイント:** POST /Orders/EditOrder.aspx  
- **該当箇所:** `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:6`

**攻撃シナリオ:** User A edits own order, changes hfOrderId in the postback to <order id of user B>, saves; B's order note is overwritten.

**影響度 (Impact):** Modify a field (Note) on other customers' orders.

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Orders/EditOrder.aspx:2` — Order id held in a hidden field (client-controlled, not protected by ViewState MAC)  
  `<asp:HiddenField ID="hfOrderId" runat="server" />`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8` — UPDATE by hidden-field id; no UserId filter  
  `sql &= " WHERE OrderId = " & hfOrderId.Value`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:12` — Write executes with no prior ownership check  
  `cmd.ExecuteNonQuery()`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:4` — BasePage not in repo; assumed login only  
  `Inherits BasePage`

**データフロー:** hfOrderId.Value (EditOrder.aspx.vb:8) → UPDATE Orders SET Note ... WHERE OrderId = <value> (EditOrder.aspx.vb:7-8) → ExecuteNonQuery (EditOrder.aspx.vb:12)

**推奨対策 (Recommendation):** Add AND UserId = @uid bound to Session["UserID"]; check rows affected; use parameters.

```
UPDATE Orders SET Note = @note WHERE OrderId = @id AND UserId = @uid
```

*検証結果 (Verifier):* likely — 確認対象: EditOrder.aspx:2 (hfOrderId is a posted hidden field), EditOrder.aspx.vb:7-14 (UPDATE by OrderId only, rows affected not checked), BasePage (not in repo), Web.config:3-9. No owner filter on the write; note field is low-impact -> medium. Same reachability gap as INJ-I-0009-1 (btnSave not in markup) and BasePage unknown, hence likely/medium.

### BOLA-R-0013-1 — Unfiltered JSP loads any order by order_no without login

- **重要度 / 確信度:** 中 (Medium) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (no_authentication) — CWE-306, CWE-639 API1:2023, API2:2023  
- **対象エンドポイント:** ANY /order/detail.jsp  
- **該当箇所:** `java-legacy/WebContent/order/detail.jsp:3`

**攻撃シナリオ:** Anonymous attacker sends GET /order/detail.jsp?no=<any order number>; the order is loaded with no login or owner check.

**影響度 (Impact):** Order lookup by any order number without authentication; result set is not rendered in visible code, so disclosure is not proven.

**脆弱性の根拠コード (Evidence):**

- `java-legacy/WebContent/WEB-INF/web.xml:9` — LoginFilter covers *.do only; detail.jsp outside WEB-INF is directly reachable  
  `<url-pattern>*.do</url-pattern>`
- `java-legacy/WebContent/order/detail.jsp:3` — ID from request  
  `String no = request.getParameter("no");`
- `java-legacy/WebContent/order/detail.jsp:5` — Lookup by order_no only; no session user referenced  
  `executeQuery("SELECT * FROM orders WHERE order_no = '" + no + "'")`

**データフロー:** request.getParameter("no") (detail.jsp:3) → SELECT * FROM orders WHERE order_no = ... (detail.jsp:5)

**推奨対策 (Recommendation):** Move the JSP under WEB-INF or extend LoginFilter to it; add AND user_id = ? bound to the session user; use PreparedStatement parameters.

```
SELECT * FROM orders WHERE order_no = ? AND user_id = ?
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: web.xml filter-mapping (only *.do, web.xml:7-10), web.xml for security-constraint / login-config (none), detail.jsp full file (lines 1-7), repo-wide grep for LoginFilter/security-constraint/other filters, post-query use of rs (none; only ${param.no} at :7). Evidence matches. JSP is outside WEB-INF and not covered by LoginFilter; query uses order_no only. rs is never rendered, so per BOLA guide: unexposed read = low, +1 unauthenticated = medium. Severity kept. The same line is also concatenated SQL (separate injection issue, not this finding).

### BOLA-R-0017-1 — Order row loaded by request orderId on unauthenticated servlet, no owner filter

- **重要度 / 確信度:** 中 (Medium) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (no_authentication) — CWE-306, CWE-639 API1:2023, API2:2023  
- **対象エンドポイント:** GET /order/view  
- **該当箇所:** `java-legacy/src/com/acme/web/OrderServlet.java:8`

**攻撃シナリオ:** Anonymous client sends GET /order/view?orderId=<any order id>; the servlet loads that order with no login and no owner check.

**影響度 (Impact):** Any order row can be loaded without authentication. In the visible code the ResultSet is never rendered (doGet ends at :22), so actual exposure depends on code not shown; items/notes queries (:16-19) are built but never executed.

**脆弱性の根拠コード (Evidence):**

- `java-legacy/WebContent/WEB-INF/web.xml:9` — LoginFilter covers only *.do; /order/view (web.xml:17) is not filtered  
  `<url-pattern>*.do</url-pattern>`
- `java-legacy/src/com/acme/web/OrderServlet.java:10` — Session user read but never tested; no stop when null  
  `Object loginUser = session.getAttribute("loginUser");`
- `java-legacy/src/com/acme/web/OrderServlet.java:11` — ID from query string or form body (attacker-controlled)  
  `String id = request.getParameter("orderId");`
- `java-legacy/src/com/acme/web/OrderServlet.java:15` — Executed query filters on id only; no user_id / loginUser binding  
  `stmt.executeQuery("SELECT * FROM orders WHERE id = '" + id + "'");`

**データフロー:** request.getParameter("orderId") :11 → -> concatenated SQL :15 → -> executeQuery (no owner column)

**推奨対策 (Recommendation):** Map LoginFilter to /order/view (or /*), stop when loginUser is null, and add AND user_id = ? bound to the session user's id.

```
PreparedStatement ps = conn.prepareStatement("SELECT * FROM orders WHERE id = ? AND user_id = ?"); ps.setString(1, id); ps.setLong(2, loginUser.getId());
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: web.xml filter coverage for /order/view (not covered), OrderServlet.doGet (:8-23) incl. loginUser never tested, executed query (:15) has no user_id predicate, use of rs after query (none; method ends at :23, nothing written to response). Lookup by request id with no auth and no owner filter is confirmed. Severity lowered high -> medium: rs is never returned or used, so per BOLA guide an unexposed read is low, +1 for unauthenticated = medium. The concurrent SQLi (INJ-I-0018-1) is the real exposure.

### BOLA-R-0020-1 — Reports selected by month with no owner/tenant filter; per-user scope unknown

- **重要度 / 確信度:** 中 (Medium) / 低 (Low)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **対象エンドポイント:** GET /reports  
- **該当箇所:** `node-express/routes/orders.js:16`

**攻撃シナリオ:** Logged-in user sends GET /reports?month=<month> and receives every report row for that month, including other users' if reports are per-user.

**影響度 (Impact):** Possible read of other users'/shops' reports. Whether reports are per-user is not visible (no schema, auth-model §4). SQL injection at :17 is a separate concern for the injection auditor.

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/orders.js:16` — Login check only  
  `router.get('/reports', ensureLoggedIn, function (req, res) {`
- `node-express/routes/orders.js:17` — Returns all reports of the month to any logged-in user; no owner column  
  `db.query("SELECT * FROM reports WHERE month = '" + req.query.month + "'", ...`

**推奨対策 (Recommendation):** Confirm with the owner whether reports are per-user/per-shop. If so, add AND owner_id = ? bound to req.user._id (and use a bound parameter for month).

```
db.query('SELECT * FROM reports WHERE month = ? AND owner_id = ?', [req.query.month, req.user._id], ...)
```

*検証結果 (Verifier):* likely — 確認対象: orders.js:16-18 handler and query, auth-model §4 data model (reports has no visible owner column; per-user scope unknown), ../db (absent; no shared WHERE builder visible). No owner filter exists, but whether reports are per-user/per-shop data is not determinable. Kept as needs-owner-confirmation. Overlaps INJ-I-0020-1 at the same line.

### BOLA-R-0022-1 — Item search returns all matching items with no owner filter; ownership of items unknown

- **重要度 / 確信度:** 中 (Medium) / 低 (Low)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **対象エンドポイント:** GET /search  
- **該当箇所:** `node-express/routes/orders.js:24`

**攻撃シナリオ:** Logged-in user sends GET /search?n=<name> (or an injected $where that is always true) and receives all items.

**影響度 (Impact):** If items are per-user (not a public catalog), other users' items are readable. Not determinable from repo. $where injection is for the injection auditor.

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/orders.js:24` — Login check only  
  `router.get('/search', ensureLoggedIn, function (req, res) {`
- `node-express/routes/orders.js:25` — Filter on name only; no owner field. $where injection allows dropping the name filter entirely  
  `db.collection('items').find({ $where: "this.name == '" + req.query.n + "'" })`

**推奨対策 (Recommendation):** Confirm whether items are public catalog data. If per-user, add owner: req.user._id to the filter and replace $where with a field match.

```
db.collection('items').find({ name: String(req.query.n), owner: req.user._id })
```

*検証結果 (Verifier):* likely — 確認対象: orders.js:24-26 handler and filter, auth-model §4 (items has no visible owner field anywhere), whole file for post-query filtering (none). No owner filter, but items may be a public catalog; ownership model unknown. If catalog data, this should be dropped. Overlaps INJ-I-0023-1.

### BOLA-R-0023-1 — Unauthenticated per-shop order count via request-controlled shop id

- **重要度 / 確信度:** 中 (Medium) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (no_authentication) — CWE-306, CWE-639 API1:2023, API2:2023  
- **対象エンドポイント:** GET /stats  
- **該当箇所:** `node-express/routes/orders.js:28`

**攻撃シナリオ:** Anonymous client sends GET /stats?shop=<other shop id> and gets that shop's order count; can iterate shop ids.

**影響度 (Impact):** Cross-tenant leak of business metrics (order volume). Low-value aggregate, raised one level for no authentication. A global app.use() auth may exist outside repo (auth-model §6).

**脆弱性の根拠コード (Evidence):**

- `node-express/routes/orders.js:28` — No ensureLoggedIn on this route (unlike the others in the file)  
  `router.get('/stats', function (req, res) {`
- `node-express/routes/orders.js:29` — Tenant key shop_id taken from query string; not bound to any session value  
  `db.query('SELECT COUNT(*) AS n FROM orders WHERE shop_id = ${req.query.shop}', ...`

**推奨対策 (Recommendation):** Add ensureLoggedIn and derive shop_id from req.user (server-side), not from the query string.

```
router.get('/stats', ensureLoggedIn, (req, res) => db.query('SELECT COUNT(*) AS n FROM orders WHERE shop_id = ?', [req.user.shopId], ...))
```

*検証結果 (Verifier):* likely — 確認対象: orders.js:28 no ensureLoggedIn, orders.js:29 shop_id taken from req.query, not from req.user, auth-model §4 tenant model (shop_id multi-shop unconfirmed), app entry for global auth (absent). Evidence matches. Order count is low-value aggregate (low), +1 for no authentication = medium. Tenant model and global auth both unconfirmed, so likely. Same line as INJ-I-0021-1, whose impact dominates.

### BOLA-R-0027-1 — Invoice note writable for any invoice id from POST (Invoice::update)

- **重要度 / 確信度:** 中 (Medium) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **対象エンドポイント:** POST /invoice/update  
- **該当箇所:** `php-codeigniter/application/controllers/Invoice.php:20`

**攻撃シナリオ:** User A POSTs invoice_id=<invoice id of user B>&note=... to /invoice/update and overwrites B's invoice note.

**影響度 (Impact):** Modify one field (note) on other customers' invoices. Rated medium per 'write limited fields'; reviewers may raise to high given invoices are financial records.

**脆弱性の根拠コード (Evidence):**

- `php-codeigniter/application/controllers/Invoice.php:21` — ID from POST body  
  `$id = $this->input->post('invoice_id');`
- `php-codeigniter/application/controllers/Invoice.php:23` — Bound (no SQLi) but WHERE has no user_id; no prior ownership lookup  
  `$this->db->query("UPDATE invoices SET note = ? WHERE id = ?", array($note, $id));`

**推奨対策 (Recommendation):** Add AND user_id = ? bound to the session user and check affected_rows(); return 404/403 when 0.

```
UPDATE invoices SET note = ? WHERE id = ? AND user_id = ?  -- array($note, $id, $this->session->userdata('user_id'))
```

*検証結果 (Verifier):* likely — 確認対象: Invoice.php:20-24 update(): invoice_id from POST, bound UPDATE with no user_id, no prior ownership lookup in update(), MY_Controller / hooks not in repo, CI default routing makes public method reachable (routes.php absent). Bound query (no SQLi) but WHERE id = ? only. Writes a single low-impact field (note) -> medium per bola-patterns §6. Likely rather than confirmed because MY_Controller is not visible.

### INJ-I-0015-1 — MyBatis list query uses ${orderBy} (caller not in repo)

- **重要度 / 確信度:** 中 (Medium) / 低 (Low)  
- **ステータス:** likely  
- **脆弱性分類:** SQLインジェクション (SQLi) (template_placeholder) — CWE-89 A03:2021  
- **対象エンドポイント:** - -  
- **該当箇所:** `java-legacy/src/com/acme/mapper/OrderMapper.xml:7`

**攻撃シナリオ:** If any caller passes a request value as orderBy, that user can inject an SQL expression into ORDER BY.

**影響度 (Impact):** Read data the DB user can access (blind).

**脆弱性の根拠コード (Evidence):**

- `java-legacy/src/com/acme/mapper/OrderMapper.xml:9` — ${} is raw text substitution in MyBatis; no allow-list visible  
  `ORDER BY ${orderBy}`
- `java-legacy/src/com/acme/mapper/OrderMapper.xml:8` — #{userId} is bound (safe); only orderBy is raw  
  `SELECT * FROM orders WHERE user_id = #{userId}`

**データフロー:** orderBy (caller unknown) → ${orderBy} (OrderMapper.xml:9)

**推奨対策 (Recommendation):** Find the Java caller of OrderMapper.list; validate orderBy against an allow-list there or use <choose> in the mapper.

```
<choose><when test="orderBy == 'date'">ORDER BY created_at</when><otherwise>ORDER BY id</otherwise></choose>
```

*検証結果 (Verifier):* likely — 確認対象: OrderMapper.xml full file (#{} at :5,:8 bound; ${orderBy} at :9 raw), repo-wide grep for orderBy / OrderMapper callers (none outside mapper), injection FP trap #{} vs ${}. ${orderBy} is raw substitution, evidence correct. No Java caller in repo, so taint source and any allow-list are unknown. Keep as likely, low confidence.

### INJ-I-0029-1 — mongo_find.php uses GET login/pass directly in Mongo filter

- **重要度 / 確信度:** 中 (Medium) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** NoSQLインジェクション (NoSQLi) (operator_injection) — CWE-943 A03:2021  
- **対象エンドポイント:** GET /php-plain/mongo_find.php  
- **該当箇所:** `php-plain/mongo_find.php:5`

**攻撃シナリオ:** A logged-in user sends array-style parameters with a not-equal operator so the credential check matches any member.

**影響度 (Impact):** Credential check bypass; member data enumeration.

**脆弱性の根拠コード (Evidence):**

- `php-plain/mongo_find.php:5` — PHP turns pass[$ne]= into an array operator  
  `$doc = $coll->findOne(array('login' => $_GET['login'], 'pass' => $_GET['pass']));`

**データフロー:** $_GET['login'], $_GET['pass'] (mongo_find.php:5) → MongoCollection::findOne (mongo_find.php:5)

**推奨対策 (Recommendation):** Cast both values to string (or reject arrays) and compare a password hash.

```
$doc = $coll->findOne(['login' => (string)$_GET['login']]); $ok = $doc && password_verify((string)$_GET['pass'], $doc['hash']);
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: mongo_find.php:1-6 whole file, inc/auth.php login required, no (string) cast / is_string check on login or pass, use of $doc after :5. Operator injection is real (PHP parses pass[$ne]=x into an array; findOne executes immediately). But $doc is never used - there is no credential check that the bypass would defeat, and the page already requires login. Realistic impact is data probing / $regex ReDoS -> medium (injection-patterns §4). Attack scenario overstates impact.

### INJ-I-0037-1 — sp_search_orders builds and EXECs dynamic SQL from @Customer and @Sort

- **重要度 / 確信度:** 中 (Medium) / 低 (Low)  
- **ステータス:** likely  
- **脆弱性分類:** SQLインジェクション (SQLi) (stored_procedure_dynamic_sql) — CWE-89 A03:2021  
- **対象エンドポイント:** - -  
- **該当箇所:** `sql-procs/sp_search_orders.sql:5`

**攻撃シナリオ:** If any application caller passes user input as @Customer or @Sort, that user can inject SQL even when the call itself is parameterized.

**影響度 (Impact):** Read/modify data with the proc owner's rights; stacked statements possible.

**脆弱性の根拠コード (Evidence):**

- `sql-procs/sp_search_orders.sql:5` — @Customer concatenated in quotes without REPLACE/QUOTENAME; @Sort raw identifier  
  `SET @sql = 'SELECT * FROM Orders WHERE Customer = ''' + @Customer + ''' ORDER BY ' + @Sort`
- `sql-procs/sp_search_orders.sql:6` — dynamic SQL sink inside the DB; caller-side binding does not protect it  
  `EXEC(@sql)`

**データフロー:** @Customer, @Sort (proc parameters, caller unknown) → @sql (sp_search_orders.sql:5) → EXEC (sp_search_orders.sql:6)

**推奨対策 (Recommendation):** Use sp_executesql with @Customer as a parameter and map @Sort through an allow-list (or QUOTENAME on an allowed column).

```
EXEC sp_executesql N'SELECT * FROM Orders WHERE Customer = @c ORDER BY ' + QUOTENAME(@SortAllowed), N'@c NVARCHAR(100)', @c=@Customer
```

*検証結果 (Verifier):* likely — 確認対象: sql-procs/sp_search_orders.sql:1-7 (no REPLACE/QUOTENAME/allow-list), repo-wide grep for callers of sp_search_orders (none), auth-model §6 (no caller, DB permissions unknown). Dynamic EXEC with both params concatenated is real. Reachability from HTTP is unproven (no caller in repo), so severity stays medium with low confidence until callers are found.

### BOLA-R-0011-1 — Order detail loaded by query id without owner filter (owner-bound command never executed)

- **重要度 / 確信度:** 低 (Low) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **対象エンドポイント:** ANY /Orders/OrderDetail.aspx  
- **該当箇所:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10`

**攻撃シナリオ:** User A sends GET /Orders/OrderDetail.aspx?id=<order id of user B>; B's order row is loaded with no ownership check.

**影響度 (Impact):** Read other customers' orders, if the reader result is rendered (rendering not visible in repo).

**脆弱性の根拠コード (Evidence):**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10` — ID from query string  
  `string id = Request.QueryString["id"];`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13` — Executed query (line 15) has no UserId filter  
  `var cmd = new SqlCommand("SELECT * FROM Orders WHERE OrderId = " + id, conn);`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:16` — Owner-bound command is built but never executed  
  `var safe = new SqlCommand("SELECT * FROM Orders WHERE OrderId = @id AND UserId = @uid", conn);`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx:2` — Page has an address label; its population is not visible in repo  
  `<asp:Label ID="lblAddress" runat="server" />`

**データフロー:** Request.QueryString["id"] (OrderDetail.aspx.cs:10) → SELECT * FROM Orders WHERE OrderId = <id> (OrderDetail.aspx.cs:13) → ExecuteReader (OrderDetail.aspx.cs:15)

**推奨対策 (Recommendation):** Execute the parameterized owner-bound command (line 16-18) instead of cmd; return 404 when no row.

```
var r = safe.ExecuteReader(); if (!r.Read()) { Response.StatusCode = 404; return; }
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: OrderDetail.aspx.cs:10-22 (full method), use of reader r after :15 (none; local variable goes out of scope), safe command :16-18 (never executed), OrderDetail.aspx:2 lblAddress (never assigned in visible code), Web.config:5 login required. No owner filter on the executed query, but the result r is never read or returned and lblAddress is never set. Per bola-patterns §6, an unexposed read is low; downgraded from high. Becomes high if output code is added. lines 19-20 (sql2, sql3) are built but never executed: not findings.

### BOLA-R-0024-2 — Order loaded by request id without owner filter (line 13) on unauthenticated CGI

- **重要度 / 確信度:** 低 (Low) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (no_authentication) — CWE-306, CWE-639 API1:2023, API2:2023  
- **対象エンドポイント:** GET /perl-cgi/cgi-bin/order.cgi  
- **該当箇所:** `perl-cgi/cgi-bin/order.cgi:11`

**攻撃シナリオ:** Anonymous client sends GET /cgi-bin/order.cgi?id=<any order id>; the order row is fetched with no owner check.

**影響度 (Impact):** Unrestricted order read. Visible code never fetches/prints rows (only $q->header at :20), so actual exposure depends on code not shown. The :16-17 query is owner-bound; with undef $uid it matches no rows (user_id = NULL).

**脆弱性の根拠コード (Evidence):**

- `perl-cgi/cgi-bin/order.cgi:11` — ID from query or POST body  
  `my $id = $q->param('id');`
- `perl-cgi/cgi-bin/order.cgi:13` — Executed (:14) with id only; the owner-bound variant is the separate query at :16-17  
  `my $sth = $dbh->prepare("SELECT * FROM orders WHERE id = $id");`

**推奨対策 (Recommendation):** Remove the unbound query at :13 and use only the bound query at :16-17 after checking $uid is defined.

```
my $sth = $dbh->prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?'); $sth->execute($id, $uid);
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: order.cgi:11-14 id from request, query executed with id only, order.cgi:16-17 owner-bound variant (separate statement, does not guard :13), order.cgi:14-20 whether $sth result is fetched or printed, CGI::Session login behavior (auth-model §2), no .htaccess in repo. No owner filter at :13, but $sth is never fetched; the script prints only $q->header (:20). Per bola-patterns §6, a read whose result is not exposed is low (raise for no-auth already capped by non-exposure). Attack scenario overstates: the order row is not returned to the client. :13 is also an SQLi sink (interpolated $id) - separate category.

### BOLA-R-0028-1 — Any logged-in user can load any user record via admin.php?action=view&uid=

- **重要度 / 確信度:** 低 (Low) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **対象エンドポイント:** GET /php-plain/admin.php?action=view  
- **該当箇所:** `php-plain/admin.php:5`

**攻撃シナリオ:** Ordinary user requests /admin.php?action=view&uid=<other user id> and the admin view loads that user's record.

**影響度 (Impact):** Read other users' account data (personal data, possibly credentials). Visible code does not render $r, so exposure depends on code not shown. Admin page lacks any role check (function-level gap too).

**脆弱性の根拠コード (Evidence):**

- `php-plain/inc/auth.php:4` — Login check only; no role check anywhere (auth-model §3)  
  `if (empty($_SESSION['user_id'])) {`
- `php-plain/admin.php:7` — Target user id from query string (cast only prevents SQLi)  
  `$uid = (int)$_GET['uid'];`
- `php-plain/admin.php:8` — Loads any user row; no admin role or self check  
  `$r = mysql_query("SELECT * FROM users WHERE id = " . $uid);`

**推奨対策 (Recommendation):** Enforce an admin role check (from session) at the top of admin.php and exit on failure; if non-admins may view, restrict to uid = $_SESSION['user_id'].

```
if (empty($_SESSION['is_admin'])) { http_response_code(403); exit; }
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: inc/auth.php:4-7 login only, admin.php:6-9 uid from GET, query by id only, admin.php:8-14 whether $r is fetched or output. No role or self check, but $r is never fetched or echoed; the script ends after the switch (:14). Per bola-patterns §6 an unexposed read is low. Attack scenario claim that the record is shown is not supported by the code. Subtype better classed missing_role_check / id_from_request_used_as_identity.

### BOLA-R-0030-1 — mongo_find.php queries any member record by request-supplied login/name, not bound to session user

- **重要度 / 確信度:** 低 (Low) / 中 (Medium)  
- **ステータス:** likely  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023  
- **対象エンドポイント:** GET /mongo_find.php  
- **該当箇所:** `php-plain/mongo_find.php:5`

**攻撃シナリオ:** A logged-in user sends GET /mongo_find.php?n=<other member name> (or login=<victim>&pass[$ne]=x). The other member's record is loaded. In the visible file the result is not echoed, so no data is returned today.

**影響度 (Impact):** No exposure in the visible code (results unused). If this file is included elsewhere or completed later to output $doc/$docs, other members' records (including password field) would leak. Main risk here is the NoSQL injection, handled by the injection auditor.

**脆弱性の根拠コード (Evidence):**

- `php-plain/mongo_find.php:2` — Login check only (inc/auth.php:2-7 says so); no ownership logic  
  `require_once 'inc/auth.php';`
- `php-plain/mongo_find.php:5` — Member selected by request login+pass; not bound to $_SESSION['user_id']  
  `$doc = $coll->findOne(array('login' => $_GET['login'], 'pass' => $_GET['pass']));`
- `php-plain/mongo_find.php:6` — Members selected by request name; no session binding  
  `$docs = $coll->find(array('$where' => "this.name == '" . $_GET['n'] . "'"));`

**データフロー:** $_GET login/pass/n (mongo_find.php:5-6) → shop.members findOne/find (mongo_find.php:5-6) → results assigned to $doc/$docs, never output in visible code

**推奨対策 (Recommendation):** Confirm the intended purpose of this page. If it returns member data, restrict lookups to the session user (_id = $_SESSION['user_id']) or an enforced admin role; cast inputs to strings and drop $where.

```
$doc = $coll->findOne(array('_id' => new MongoId($_SESSION['user_id'])));
```

*検証結果 (Verifier):* likely — 確認対象: php-plain/mongo_find.php:1-6 (whole file), php-plain/inc/auth.php:2-7 (login only), repo-wide grep for includes of mongo_find.php (none), post-query use of $doc/$docs (none). Evidence lines match. No ownership filter on members lookups, but neither $doc nor $docs is output or used anywhere, and no file includes this page. Line 5 is a credential lookup (login+pass), closer to an auth flow than BOLA. Per bola-patterns §6 an unexposed read is low. Real risk is the NoSQL injection at :5-6 (operator/$where), owned by the injection finding.

## 4. 根本的恒久対策

<!-- LLM: reporter agent writes max 5 systemic fixes here (日本語で記載: 共通認可ヘルパー、パラメータバインディングDAO等のアーキテクチャ改修案と工数見積 S/M/L) -->

## 5. 調査範囲と制約事項

- missing from inventory: 0
- bola routes without verdict: 0
- injection candidates without verdict: 0
- findings without verification: 0

<!-- LLM: reporter agent lists limitations here (日本語で記載: ストアドプロシージャ、動的インクルード、設定による除外パス等) -->

## 付録A — 検証により棄却された検出事項

| ID | 該当箇所 | 棄却理由 |
|---|---|---|
| BOLA-R-0007-1 | `dotnet-legacy/Web/Controllers/InvoiceController.cs:17` | Owner-bound query plus stop on mismatch (:20-21). The claimed bypass has no supporting code: nothing shows CurrentUserId() reads request data. Residual: reviewer should confirm CurrentUserId() source (not in repo); reopen only if it reads request input. |
| BOLA-R-0015-1 | `java-legacy/src/com/acme/web/InvoiceController.java:21` | No evidence of a flaw: the object id is paired with a server-side Principal and passed to an owner-scoped lookup. The only argument is that the DAO source is missing. Rejected by name with medium confidence; reopen if InvoiceDao source shows no owner predicate. |

## 付録B — 監査手法とプロセス

1. **決定論的静的事前スキャン**: 技術スタック判定、エンドポイント候補抽出、クエリ生成箇所抽出。
2. **独立したAI監査エージェント群**: 認可モデル抽出、エンドポイント詳細精査、BOLA監査、インジェクション監査。
3. **懐疑的AI検証エージェント（Skeptic）**: 検出事項に対する反論テストを実施し、既存の防御制御による誤検知を排除。
4. **人間のエンジニアによる最終確認と承認**: `review-log.md` による判定記録とサインオフ。

**免責事項:** 本監査は侵入テスト（ペネトレーションテスト）ではありません。脆弱性が検出されなかったことは、脆弱性の非存在を証明するものではありません。
