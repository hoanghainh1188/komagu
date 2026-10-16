# Security Audit Report — LSA eval repo

> **Classification: CONFIDENTIAL.** AI-assisted static review. All findings require human review (see `review-log.md`) before they are shared outside the team.

| Item | Value |
|---|---|
| Date | 2026-10-16 |
| Kit version | 0.1.0 |
| Scope | BOLA/IDOR; SQL/HQL/NoSQL queries built from input |
| Stacks | php, php-codeigniter, java-servlet, java-jsp, java-struts1, java-spring-mvc, java-mybatis, java-hibernate, dotnet-webforms, dotnet-handlers, dotnet-mvc, classic-asp, perl-cgi, coldfusion, node-express, python-flask |
| Endpoints inventoried | 36 (candidates: 36) |
| Endpoints audited for BOLA | 34 |
| Injection candidates reviewed | 38 |

## 1. Executive summary

- **Overall risk: critical.** The review found 57 active findings: 13 critical, 30 high, 10 medium, 4 low. 34 are confirmed and 23 are likely. Both target classes, broken object-level authorization and SQL/NoSQL injection, occur in every one of the 10 sub-applications.
- **Unauthenticated SQL injection on order endpoints.** `/order/view` (INJ-I-0018-1), `order/detail.jsp` (INJ-I-0014-1), the remote ColdFusion `getOrder` method (INJ-I-0006-1) and `order.cgi` (INJ-I-0024-1, INJ-I-0025-1) build SQL from request input and require no login. An anonymous attacker could read or change database contents.
- **Any user can delete or change other users' accounts.** `member.asp?mode=delete` (BOLA-R-0002-1), `admin.php?action=delete` (BOLA-R-0029-1) and `/user/edit.do` (BOLA-R-0012-1) take the target user id from the request and check neither ownership nor an admin role. Business impact: account takeover and data loss.
- **Customer data is exposed without login.** `GetFile.ashx` serves files by `file_id` to anonymous users (BOLA-R-0009-1), and `OrderService.cfc?method=getOrder` returns any order (BOLA-R-0004-1). Order addresses and invoices are readable by any logged-in user on most stacks (for example BOLA-R-0003-1, BOLA-R-0031-1, BOLA-R-0034-1).
- **Root cause 1: no shared ownership check.** Each page checks ownership inline or not at all. Safe variants exist next to unsafe ones in the same files (auth-model.md §3, §7). No sub-application has a reusable ownership or role helper.
- **Root cause 2: login checks are treated as authorization.** Every guard found checks only that a user is logged in. No role or function-level check exists, including on admin functions (auth-model.md §3).
- **Root cause 3: queries are built by string concatenation.** Data access code across PHP, Java, .NET, Classic ASP, ColdFusion, Perl, Node and Python concatenates or interpolates request values instead of using parameter binding.
- **Root cause 4: authentication coverage has gaps.** Login is enforced per page or by narrow filter mappings (`*.do` only, `Handlers` folder allowed for all, remote CFCs, `/stats`), so several endpoints are reachable anonymously (auth-model.md §5).

## 2. Findings overview

| Severity | critical | high | medium | low | info |
|---|---|---|---|---|---|
| Count | 13 | 30 | 10 | 4 | 0 |

| Category | Count |
|---|---|
| bola | 28 |
| sql_injection | 25 |
| nosql_injection | 4 |

Status: unverified=0, confirmed=34, likely=23, rejected=2, needs_review=0

## 3. Findings

| ID | Sev | Conf | Status | Category | Endpoint | Location | Title |
|---|---|---|---|---|---|---|---|
| BOLA-R-0002-1 | critical | high | confirmed | bola | ANY /shop/member.asp?mode=delete | `classic-asp/shop/member.asp:9` | Any logged-in user can delete any member via GET member_id |
| BOLA-R-0004-1 | critical | medium | likely | bola | ANY /app/OrderService.cfc?method=getOrder | `coldfusion/app/OrderService.cfc:2` | Remote CFC getOrder returns any order to anonymous callers |
| BOLA-R-0009-1 | critical | medium | likely | bola | ANY /Handlers/GetFile.ashx | `dotnet-legacy/Web/Handlers/GetFile.ashx:6` | Anonymous file download by file_id in GetFile.ashx (Handlers folder allows all users) |
| BOLA-R-0012-1 | critical | medium | likely | bola | ANY /user/edit.do | `java-legacy/src/com/acme/struts/EditUserAction.java:10` | Any user's email can be changed via user_id request parameter |
| BOLA-R-0024-1 | critical | high | confirmed | bola | GET /perl-cgi/cgi-bin/order.cgi | `perl-cgi/cgi-bin/order.cgi:8` | Any client can delete any cart by cart id (no login, no owner filter) |
| BOLA-R-0029-1 | critical | high | confirmed | bola | POST /php-plain/admin.php?action=delete | `php-plain/admin.php:10` | Any logged-in user can delete any user via admin.php?action=delete |
| INJ-I-0006-1 | critical | high | confirmed | sql_injection | ANY /coldfusion/app/OrderService.cfc?method=getOrder | `coldfusion/app/OrderService.cfc:2` | Remote CFC getOrder puts orderId into cfquery without cfqueryparam |
| INJ-I-0014-1 | critical | high | confirmed | sql_injection | GET /java-legacy/WebContent/order/detail.jsp | `java-legacy/WebContent/order/detail.jsp:3` | detail.jsp executes Statement query with concatenated order_no |
| INJ-I-0018-1 | critical | high | confirmed | sql_injection | GET /order/view | `java-legacy/src/com/acme/web/OrderServlet.java:11` | Unauthenticated order servlet concatenates orderId into JDBC Statement |
| INJ-I-0021-1 | critical | medium | confirmed | sql_injection | GET /stats | `node-express/routes/orders.js:28` | /stats interpolates req.query.shop into SQL without login |
| INJ-I-0022-1 | critical | medium | likely | nosql_injection | POST /login | `node-express/routes/orders.js:20` | POST /login passes req.body directly as Mongo filter |
| INJ-I-0024-1 | critical | high | confirmed | sql_injection | GET /perl-cgi/cgi-bin/order.cgi | `perl-cgi/cgi-bin/order.cgi:11` | order.cgi interpolates id param into prepared SQL with no binds |
| INJ-I-0025-1 | critical | high | confirmed | sql_injection | POST /perl-cgi/cgi-bin/order.cgi | `perl-cgi/cgi-bin/order.cgi:19` | order.cgi DELETE concatenates cart param |
| BOLA-R-0001-1 | high | high | confirmed | bola | ANY /shop/member.asp?mode=edit | `classic-asp/shop/member.asp:4` | Any logged-in user can rename any member via form member_id |
| BOLA-R-0003-1 | high | high | confirmed | bola | ANY /shop/order.asp | `classic-asp/shop/order.asp:5` | Order address readable by any logged-in user via id |
| BOLA-R-0005-1 | high | high | confirmed | bola | ANY /app/order.cfm | `coldfusion/app/order.cfm:2` | order.cfm renders unscoped qOrder instead of owner-bound qMine |
| BOLA-R-0006-1 | high | medium | likely | bola | ANY /Invoice/Details/{id} | `dotnet-legacy/Web/Controllers/InvoiceController.cs:11` | Invoice details readable by any logged-in user via id |
| BOLA-R-0008-1 | high | medium | likely | bola | POST /Invoice/Search | `dotnet-legacy/Web/Controllers/InvoiceController.cs:25` | Invoice search returns any customer's invoices to any logged-in user |
| BOLA-R-0014-1 | high | medium | likely | bola | GET /invoices/{id} | `java-legacy/src/com/acme/web/InvoiceController.java:15` | Invoice readable by id via Spring show() with no owner or login check visible |
| BOLA-R-0016-1 | high | medium | likely | bola | GET /invoices/search | `java-legacy/src/com/acme/web/InvoiceController.java:27` | Invoice search by customer returns any customer's invoices |
| BOLA-R-0018-1 | high | medium | confirmed | bola | GET /orders/:id | `node-express/routes/orders.js:8` | Any logged-in user can read any order via /orders/:id (findById) |
| BOLA-R-0025-1 | high | medium | likely | bola | GET /invoice/view/{id} | `php-codeigniter/application/controllers/Invoice.php:9` | Invoice readable by id with no owner filter (Invoice::view) |
| BOLA-R-0031-1 | high | high | confirmed | bola | GET /php-plain/order_detail.php | `php-plain/order_detail.php:5` | Order detail (address) readable for any order id by any logged-in user |
| BOLA-R-0034-1 | high | high | confirmed | bola | GET /orders/<int:order_id> | `python-flask/app.py:8` | Any logged-in user can read any order via /orders/<order_id> |
| INJ-I-0002-1 | high | high | confirmed | sql_injection | POST /classic-asp/shop/member.asp?mode=edit | `classic-asp/shop/member.asp:6` | Member UPDATE concatenates unquoted member_id from POST |
| INJ-I-0003-1 | high | high | confirmed | sql_injection | GET /classic-asp/shop/member.asp?mode=delete | `classic-asp/shop/member.asp:10` | Member DELETE concatenates unquoted member_id from query string |
| INJ-I-0004-1 | high | high | confirmed | sql_injection | GET /classic-asp/shop/order.asp | `classic-asp/shop/order.asp:5` | Order SELECT concatenates unvalidated id from Request() |
| INJ-I-0007-1 | high | high | confirmed | sql_injection | GET /coldfusion/app/order.cfm | `coldfusion/app/order.cfm:2` | order.cfm qOrder puts url.id into cfquery without cfqueryparam |
| INJ-I-0008-1 | high | high | confirmed | sql_injection | POST /Invoice/Search | `dotnet-legacy/Web/Controllers/InvoiceController.cs:26` | Invoice search concatenates customer into EF SqlQuery |
| INJ-I-0009-1 | high | medium | likely | sql_injection | POST /dotnet-legacy/Web/Orders/EditOrder.aspx | `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7` | EditOrder UPDATE concatenates txtNote.Text and hidden field hfOrderId |
| INJ-I-0011-1 | high | high | confirmed | sql_injection | GET /dotnet-legacy/Web/Orders/OrderDetail.aspx | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10` | OrderDetail executes SELECT concatenated with query-string id |
| INJ-I-0016-1 | high | medium | likely | sql_injection | POST /user/edit.do | `java-legacy/src/com/acme/struts/EditUserAction.java:10` | EditUserAction prepareStatement built by concatenating email and user_id |
| INJ-I-0017-1 | high | medium | likely | sql_injection | GET /invoices/search | `java-legacy/src/com/acme/web/InvoiceController.java:27` | Invoice search builds HQL by concatenating customer parameter |
| INJ-I-0020-1 | high | high | confirmed | sql_injection | GET /reports | `node-express/routes/orders.js:16` | /reports concatenates req.query.month into SQL |
| INJ-I-0023-1 | high | high | confirmed | nosql_injection | GET /search | `node-express/routes/orders.js:24` | /search builds Mongo $where JavaScript from req.query.n |
| INJ-I-0026-1 | high | medium | likely | sql_injection | ANY /invoice/view/{id} | `php-codeigniter/application/controllers/Invoice.php:9` | CodeIgniter invoice view interpolates URI segment into db->query |
| INJ-I-0028-1 | high | high | confirmed | sql_injection | POST /php-plain/admin.php?action=delete | `php-plain/admin.php:11` | admin.php delete interpolates POST id into mysql_query |
| INJ-I-0030-1 | high | low | likely | nosql_injection | GET /php-plain/mongo_find.php | `php-plain/mongo_find.php:6` | mongo_find.php builds $where JavaScript from GET n |
| INJ-I-0031-1 | high | high | confirmed | sql_injection | GET /php-plain/order_detail.php | `php-plain/order_detail.php:5` | Order detail query concatenates unquoted GET id |
| INJ-I-0032-1 | high | low | likely | sql_injection | GET /php-plain/search.php | `php-plain/search.php:5` | Product search LIKE clause relies on addslashes only |
| INJ-I-0033-1 | high | high | confirmed | sql_injection | GET /php-plain/search.php | `php-plain/search.php:6` | ORDER BY clause taken directly from GET sort |
| INJ-I-0034-1 | high | medium | confirmed | sql_injection | GET /php-plain/search.php | `php-plain/search.php:12` | Category filter interpolates $_GET['cat'] in heredoc SQL |
| INJ-I-0036-1 | high | high | confirmed | sql_injection | GET\|POST /search | `python-flask/app.py:27` | Flask search builds LIKE query with f-string |
| BOLA-R-0010-1 | medium | medium | likely | bola | POST /Orders/EditOrder.aspx | `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:6` | Order note writable on any order via client-controlled hidden field |
| BOLA-R-0013-1 | medium | high | confirmed | bola | ANY /order/detail.jsp | `java-legacy/WebContent/order/detail.jsp:3` | Unfiltered JSP loads any order by order_no without login |
| BOLA-R-0017-1 | medium | high | confirmed | bola | GET /order/view | `java-legacy/src/com/acme/web/OrderServlet.java:8` | Order row loaded by request orderId on unauthenticated servlet, no owner filter |
| BOLA-R-0020-1 | medium | low | likely | bola | GET /reports | `node-express/routes/orders.js:16` | Reports selected by month with no owner/tenant filter; per-user scope unknown |
| BOLA-R-0022-1 | medium | low | likely | bola | GET /search | `node-express/routes/orders.js:24` | Item search returns all matching items with no owner filter; ownership of items unknown |
| BOLA-R-0023-1 | medium | medium | likely | bola | GET /stats | `node-express/routes/orders.js:28` | Unauthenticated per-shop order count via request-controlled shop id |
| BOLA-R-0027-1 | medium | medium | likely | bola | POST /invoice/update | `php-codeigniter/application/controllers/Invoice.php:20` | Invoice note writable for any invoice id from POST (Invoice::update) |
| INJ-I-0015-1 | medium | low | likely | sql_injection |   | `java-legacy/src/com/acme/mapper/OrderMapper.xml:7` | MyBatis list query uses ${orderBy} (caller not in repo) |
| INJ-I-0029-1 | medium | high | confirmed | nosql_injection | GET /php-plain/mongo_find.php | `php-plain/mongo_find.php:5` | mongo_find.php uses GET login/pass directly in Mongo filter |
| INJ-I-0037-1 | medium | low | likely | sql_injection |   | `sql-procs/sp_search_orders.sql:5` | sp_search_orders builds and EXECs dynamic SQL from @Customer and @Sort |
| BOLA-R-0011-1 | low | high | confirmed | bola | ANY /Orders/OrderDetail.aspx | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10` | Order detail loaded by query id without owner filter (owner-bound command never executed) |
| BOLA-R-0024-2 | low | high | confirmed | bola | GET /perl-cgi/cgi-bin/order.cgi | `perl-cgi/cgi-bin/order.cgi:11` | Order loaded by request id without owner filter (line 13) on unauthenticated CGI |
| BOLA-R-0028-1 | low | high | confirmed | bola | GET /php-plain/admin.php?action=view | `php-plain/admin.php:5` | Any logged-in user can load any user record via admin.php?action=view&uid= |
| BOLA-R-0030-1 | low | medium | likely | bola | GET /mongo_find.php | `php-plain/mongo_find.php:5` | mongo_find.php queries any member record by request-supplied login/name, not bound to session user |

### BOLA-R-0002-1 — Any logged-in user can delete any member via GET member_id

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bola (id_from_request_used_as_identity) — CWE-639, CWE-566 API1:2023  
- **Endpoint:** ANY /shop/member.asp?mode=delete  
- **Location:** `classic-asp/shop/member.asp:9`

**Scenario.** User A sends GET /shop/member.asp?mode=delete&member_id=<member id of user B>; B's member record is deleted.

**Impact.** Delete any member account (data loss, denial of service for other users).

**Evidence.**

- `classic-asp/shop/inc/auth.asp:2` — Login check only  
  `If Session("UserID") = "" Then Response.Redirect "/login.asp"`
- `classic-asp/shop/member.asp:10` — DELETE by query-string id; no owner/role binding  
  `conn.Execute "DELETE FROM members WHERE member_id = " & Request.QueryString("member_id")`

**Data flow.** Request.QueryString("member_id") (member.asp:10) → DELETE FROM members WHERE member_id = <value> (member.asp:10)

**Recommendation.** Restrict deletion to the session member (or an enforced admin role); bind member_id to Session("UserID"); require POST.

```
"DELETE FROM members WHERE member_id = " & CLng(Session("UserID"))
```

*Verifier:* confirmed — checked: evidence lines member.asp:9-10 and inc/auth.asp:2 re-read (match), inc/conn.asp, global.asa / web.config / .htaccess for classic-asp (none in repo), role check before delete (none). DELETE by query-string member_id after login-only include. Deleting other users' objects is critical per bola-patterns §6. Reachable via GET.

### BOLA-R-0004-1 — Remote CFC getOrder returns any order to anonymous callers

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bola (no_authentication) — CWE-306, CWE-639 API1:2023, API2:2023  
- **Endpoint:** ANY /app/OrderService.cfc?method=getOrder  
- **Location:** `coldfusion/app/OrderService.cfc:2`

**Scenario.** Anonymous attacker sends GET /app/OrderService.cfc?method=getOrder&orderId=<any id> and receives the full order.

**Impact.** Unauthenticated read of all orders (personal and order data); trivially enumerable.

**Evidence.**

- `coldfusion/app/OrderService.cfc:2` — Remotely callable over URL/form; no login check in the component  
  `<cffunction name="getOrder" access="remote" returnformat="json">`
- `coldfusion/app/OrderService.cfc:5` — Lookup by caller-supplied id only; no owner filter  
  `SELECT * FROM orders WHERE id = #arguments.orderId#`
- `coldfusion/app/OrderService.cfc:7` — Full order row(s) returned as JSON  
  `<cfreturn q>`
- `coldfusion/app/OrderService.cfc:1` — No Application.cfc/.cfm in repo; server-level restriction unknown (reason for medium confidence)  
  `<cfcomponent>`

**Data flow.** arguments.orderId (OrderService.cfc:3) → SELECT * FROM orders WHERE id = ... (OrderService.cfc:5) → cfreturn q as JSON (OrderService.cfc:7)

**Recommendation.** Change access to public/private, or check session.userID and bind user_id = <cfqueryparam value="#session.userID#"> in the query.

```
WHERE id = <cfqueryparam value="#arguments.orderId#" cfsqltype="cf_sql_integer"> AND user_id = <cfqueryparam value="#session.userID#" cfsqltype="cf_sql_integer">
```

*Verifier:* likely — checked: OrderService.cfc:1-12 re-read (match), searched whole repo for Application.cfc/.cfm (none; would hold onCFCRequest/onRequestStart guard), roles= attribute on cffunction (absent), owner filter or post-query check before cfreturn (none), auth-model §5/§6 (remote CFC unauthenticated; CF Admin restrictions unknown). Every in-repo path is unguarded: access="remote", no roles, no session check, id-only lookup, full row returned. Kept critical (personal data read, +1 for no auth). 'likely' only because an Application.cfc or server/CF Admin restriction outside the repo cannot be ruled out.

### BOLA-R-0009-1 — Anonymous file download by file_id in GetFile.ashx (Handlers folder allows all users)

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bola (no_authentication) — CWE-306, CWE-639 API1:2023, API2:2023  
- **Endpoint:** ANY /Handlers/GetFile.ashx  
- **Location:** `dotnet-legacy/Web/Handlers/GetFile.ashx:6`

**Scenario.** An unauthenticated client sends GET /Handlers/GetFile.ashx?file_id=<any file id> and receives the stored document.

**Impact.** Anyone on the network can download any user's stored documents if DocStore.PathFor resolves the ID without an access check.

**Evidence.**

- `dotnet-legacy/Web/Web.config:7` — Overrides global <deny users="?"/> (Web.config:5); handler is reachable anonymously  
  `<location path="Handlers">
  <system.web><authorization><allow users="*" /></authorization></system.web>`
- `dotnet-legacy/Web/Handlers/GetFile.ashx:8` — Object ID from query string  
  `string fileId = context.Request.QueryString["file_id"];`
- `dotnet-legacy/Web/Handlers/GetFile.ashx:9` — Only the request ID is passed; no user identity passed to the helper. Helper source not in repo  
  `string path = DocStore.PathFor(fileId);`
- `dotnet-legacy/Web/Handlers/GetFile.ashx:10` — File streamed with no authn check, no owner check, no stop path in the handler  
  `context.Response.TransmitFile(path);`

**Data flow.** query file_id (GetFile.ashx:8) → DocStore.PathFor(fileId) -> path (GetFile.ashx:9, helper not visible) → Response.TransmitFile(path) (GetFile.ashx:10)

**Recommendation.** Remove the <location path="Handlers"> allow-all rule (or scope it to truly public handlers), require an authenticated user in ProcessRequest, and look up the file by id AND owner = Session/User identity, returning 404 on mismatch. Confirm what DocStore.PathFor does.

```
if (!context.User.Identity.IsAuthenticated) { context.Response.StatusCode = 401; return; }
string path = DocStore.PathForOwner(fileId, CurrentUserId());
if (path == null) { context.Response.StatusCode = 404; return; }
```

*Verifier:* likely — checked: Web.config:5 global deny ?, Web.config:7-9 <location path="Handlers"> allow * (overrides deny; path matches Web/Handlers), GetFile.ashx:6-11 (no IsAuthenticated, no owner check, no stop), repo search for DocStore (not in repo), Global.asax / IIS config (absent). Anonymous reach is confirmed from Web.config. Only DocStore.PathFor (not in repo) could enforce anything; it receives only fileId, and the caller is anonymous, so an ownership check there is implausible but not provable. Out of scope: file_id flows into a file path -> possible path traversal depending on DocStore.

### BOLA-R-0012-1 — Any user's email can be changed via user_id request parameter

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bola (id_from_request_used_as_identity) — CWE-639, CWE-566 API1:2023  
- **Endpoint:** ANY /user/edit.do  
- **Location:** `java-legacy/src/com/acme/struts/EditUserAction.java:10`

**Scenario.** User A sends POST /user/edit.do with user_id=<id of user B>&email=<A's address>; B's email changes, enabling password-reset takeover.

**Impact.** Change any user's email (account takeover path).

**Evidence.**

- `java-legacy/WebContent/WEB-INF/struts-config.xml:4` — Struts action mapping  
  `<action path="/user/edit" type="com.acme.struts.EditUserAction" name="userForm" scope="request"/>`
- `java-legacy/src/com/acme/struts/EditUserAction.java:10` — Target user identity taken from request; no session lookup  
  `String userId = request.getParameter("user_id");`
- `java-legacy/src/com/acme/struts/EditUserAction.java:13` — UPDATE by request id, no ownership/role check  
  `prepareStatement("UPDATE users SET email = '" + email + "' WHERE id = " + userId)`
- `java-legacy/WebContent/WEB-INF/web.xml:9` — LoginFilter source missing (assumed login only); no ActionServlet mapping, so reachability assumed  
  `<url-pattern>*.do</url-pattern>`

**Data flow.** request.getParameter("user_id") (EditUserAction.java:10) → UPDATE users ... WHERE id = <user_id> (EditUserAction.java:13) → executeUpdate (EditUserAction.java:14)

**Recommendation.** Take the user id from session.getAttribute("loginUser"); ignore user_id from the request; use bound parameters.

```
ps = conn.prepareStatement("UPDATE users SET email = ? WHERE id = ?"); ps.setString(1, email); ps.setLong(2, loginUser.getId());
```

*Verifier:* likely — checked: EditUserAction.execute full method (:8-16), struts-config.xml action mapping (:4; no form-beans section, no roles attribute), web.xml for ActionServlet mapping (absent) and LoginFilter (*.do, source missing), session use in action (none). Target user taken from request user_id (:10), UPDATE email by that id (:13-14), no session or role check in visible code. Writing another user's email = critical. Not confirmed only because ActionServlet is not mapped in web.xml and userForm/LoginFilter sources are missing, so reachability and any ActionForm validate() are unproven.

### BOLA-R-0024-1 — Any client can delete any cart by cart id (no login, no owner filter)

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bola (no_authentication) — CWE-306, CWE-639 API1:2023, API2:2023  
- **Endpoint:** GET /perl-cgi/cgi-bin/order.cgi  
- **Location:** `perl-cgi/cgi-bin/order.cgi:8`

**Scenario.** Anonymous client sends GET /cgi-bin/order.cgi?cart=<victim cart id> (or POST body) and the victim's cart is deleted.

**Impact.** Delete other users' carts without authentication (integrity / availability). SQL injection on the same line is for the injection auditor.

**Evidence.**

- `perl-cgi/cgi-bin/order.cgi:8` — load() returns an empty session when none exists; not a login check (auth-model §2)  
  `my $session = CGI::Session->load() or die;`
- `perl-cgi/cgi-bin/order.cgi:9` — uid read but never tested  
  `my $uid = $session->param('user_id');`
- `perl-cgi/cgi-bin/order.cgi:19` — Delete by request cart id only; no user_id binding; runs on every request  
  `$dbh->do("DELETE FROM carts WHERE cart_id = " . $q->param('cart'));`

**Recommendation.** Stop when $uid is undefined (print 401/redirect and exit), and delete with a bound owner filter.

```
die unless defined $uid; $dbh->do('DELETE FROM carts WHERE cart_id = ? AND user_id = ?', undef, scalar $q->param('cart'), $uid);
```

*Verifier:* confirmed — checked: order.cgi:8 CGI::Session->load() or die (dies only on load failure, not on missing login), order.cgi:9 $uid never tested, order.cgi:10 DBI->connect without RaiseError, so failing statements at :13-17 do not stop execution, order.cgi:19 DELETE by request cart only, unconditional, web server auth (.htaccess) absent from repo. Delete of other users' objects is critical even for logged-in users, so severity holds regardless of web-server auth. Minor: endpoint.path '/perl-cgi/cgi-bin/order.cgi' and attack_scenario '/cgi-bin/order.cgi' disagree; URL mapping unknown.

### BOLA-R-0029-1 — Any logged-in user can delete any user via admin.php?action=delete

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **Endpoint:** POST /php-plain/admin.php?action=delete  
- **Location:** `php-plain/admin.php:10`

**Scenario.** Ordinary user POSTs id=<any user id> to /admin.php?action=delete and that account is deleted.

**Impact.** Delete arbitrary user accounts. SQL injection on the same line is for the injection auditor.

**Evidence.**

- `php-plain/inc/auth.php:4` — Login check only; no role check  
  `if (empty($_SESSION['user_id'])) {`
- `php-plain/admin.php:11` — Target id from POST body  
  `$id = $_POST['id'];`
- `php-plain/admin.php:12` — Deletes any user row; no admin role, no owner/self binding  
  `mysql_query("DELETE FROM users WHERE id = $id");`

**Recommendation.** Enforce an admin role check from the session and exit on failure; use a bound, int-cast id.

```
if (empty($_SESSION['is_admin'])) { http_response_code(403); exit; } $st = $pdo->prepare('DELETE FROM users WHERE id = ?'); $st->execute(array((int)$_POST['id']));
```

*Verifier:* confirmed — checked: php-plain/inc/auth.php:1-7 login only, exit on fail, no role check, php-plain/inc/db.php:1-4 connection only, no auth, admin.php:1-14 no role/self check before DELETE, auth-model §3: no role checks anywhere, no .htaccess / auto_prepend in repo. Any logged-in user can delete any user row. Subtype is better classed missing_role_check (CWE-285, API5:2023) than missing_ownership_check. Deleting other users' objects -> critical. Web-server auth on admin.php is not in repo and would be the only possible compensating control.

### INJ-I-0006-1 — Remote CFC getOrder puts orderId into cfquery without cfqueryparam

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (template_placeholder) — CWE-89 A03:2021  
- **Endpoint:** ANY /coldfusion/app/OrderService.cfc?method=getOrder  
- **Location:** `coldfusion/app/OrderService.cfc:2`

**Scenario.** An anonymous caller passes a crafted orderId that changes the WHERE clause or appends a UNION.

**Impact.** Unauthenticated read of any data the 'shop' datasource can access.

**Evidence.**

- `coldfusion/app/OrderService.cfc:2` — remotely callable, no login check (auth-model §2/§5)  
  `<cffunction name="getOrder" access="remote" returnformat="json">`
- `coldfusion/app/OrderService.cfc:3` — type string: no numeric validation  
  `<cfargument name="orderId" type="string" required="true">`
- `coldfusion/app/OrderService.cfc:5` — unquoted numeric context; CF quote-escaping does not help  
  `SELECT * FROM orders WHERE id = #arguments.orderId#`

**Data flow.** URL/form arg orderId (OrderService.cfc:3) → #arguments.orderId# (OrderService.cfc:5) → cfquery (OrderService.cfc:4)

**Recommendation.** Use cfqueryparam with cf_sql_integer and declare the argument type numeric; add an auth check.

```
<cfqueryparam value="#arguments.orderId#" cfsqltype="cf_sql_integer">
```

*Verifier:* confirmed — checked: OrderService.cfc:2-6 re-read (match), cfargument type="string" (no numeric validation), cfqueryparam (absent), CF quote auto-escape: does not apply in unquoted numeric context (knowledge/stacks/coldfusion.md), Application.cfc anywhere in repo (none). Source->sink traced fully. Critical as remotely callable without login. If an out-of-repo Application.cfc enforced login, severity would drop to high; the injection itself remains.

### INJ-I-0014-1 — detail.jsp executes Statement query with concatenated order_no

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89 A03:2021  
- **Endpoint:** GET /java-legacy/WebContent/order/detail.jsp  
- **Location:** `java-legacy/WebContent/order/detail.jsp:3`

**Scenario.** An anonymous user closes the quote in 'no' and appends SQL; LoginFilter covers only *.do (web.xml:15).

**Impact.** Unauthenticated read of any data the shared connection can access.

**Evidence.**

- `java-legacy/WebContent/order/detail.jsp:3` — source: request parameter  
  `String no = request.getParameter("no");`
- `java-legacy/WebContent/order/detail.jsp:5` — concatenated in quotes, no escaping; Statement sink  
  `ResultSet rs = c.createStatement().executeQuery("SELECT * FROM orders WHERE order_no = '" + no + "'");`

**Data flow.** request.getParameter("no") (detail.jsp:3) → no → Statement.executeQuery (detail.jsp:5)

**Recommendation.** Use PreparedStatement with a bound parameter; move DB access out of the JSP.

```
PreparedStatement ps = c.prepareStatement("SELECT * FROM orders WHERE order_no = ?"); ps.setString(1, no);
```

*Verifier:* confirmed — checked: detail.jsp:3-5 (no escaping, Statement.executeQuery), web.xml:3-10 LoginFilter mapped to *.do only (JSP not covered), web.xml security-constraint (none), auth-model §5 java-legacy exclusions. Unauthenticated, tainted, no sanitizer -> critical. Out of scope: ${param.no} reflected at detail.jsp:7 (XSS).

### INJ-I-0018-1 — Unauthenticated order servlet concatenates orderId into JDBC Statement

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89 A03:2021  
- **Endpoint:** GET /order/view  
- **Location:** `java-legacy/src/com/acme/web/OrderServlet.java:11`

**Scenario.** An anonymous user closes the quote in orderId and appends SQL that changes the query.

**Impact.** Unauthenticated read (and possibly modification, driver-dependent) of any data the DB user can access.

**Evidence.**

- `java-legacy/WebContent/WEB-INF/web.xml:9` — LoginFilter covers *.do only; /order/view (web.xml:17) is not filtered  
  `<url-pattern>*.do</url-pattern>`
- `java-legacy/src/com/acme/web/OrderServlet.java:10` — read but never checked  
  `Object loginUser = session.getAttribute("loginUser");`
- `java-legacy/src/com/acme/web/OrderServlet.java:11` — source: request parameter  
  `String id = request.getParameter("orderId");`
- `java-legacy/src/com/acme/web/OrderServlet.java:15` — concatenated into Statement.executeQuery, sink  
  `ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE id = '" + id + "'");`

**Data flow.** request.getParameter("orderId") (OrderServlet.java:11) → id → Statement.executeQuery (OrderServlet.java:15)

**Recommendation.** Use PreparedStatement with setString/setLong (as already done on line 18-19), and add the servlet path to the login filter.

```
PreparedStatement ps = conn.prepareStatement("SELECT * FROM orders WHERE id = ?"); ps.setString(1, id);
```

*Verifier:* confirmed — checked: web.xml servlet-mapping /order/view (:15-18) and filter-mapping *.do (:9), OrderServlet.doGet full method (:8-23), loginUser use (read at :10, never tested), sink Statement.executeQuery (:15) and any cast/validation of id (none). Unauthenticated, tainted orderId concatenated into an executed Statement query. Critical per injection guide. Line 16-17 StringBuilder is never executed (not part of this finding); line 18-19 is bound.

### INJ-I-0021-1 — /stats interpolates req.query.shop into SQL without login

- **Severity / confidence:** critical / medium  
- **Status:** confirmed  
- **Category:** sql_injection (string_interpolation) — CWE-89 A03:2021  
- **Endpoint:** GET /stats  
- **Location:** `node-express/routes/orders.js:28`

**Scenario.** An anonymous user sends a crafted shop value that adds a UNION or boolean condition to read other data.

**Impact.** Unauthenticated read of any data the DB user can access.

**Evidence.**

- `node-express/routes/orders.js:28` — no ensureLoggedIn  
  `router.get('/stats', function (req, res) {`
- `node-express/routes/orders.js:29` — template literal, numeric context  
  `db.query('SELECT COUNT(*) AS n FROM orders WHERE shop_id = ${req.query.shop}', ...`

**Data flow.** req.query.shop (orders.js:29) → db.query (orders.js:29)

**Recommendation.** Use a placeholder and parse the value as integer.

```
db.query('SELECT COUNT(*) AS n FROM orders WHERE shop_id = ?', [parseInt(req.query.shop, 10)], cb)
```

*Verifier:* confirmed — checked: orders.js:28-30 route has no ensureLoggedIn, whole file for parseInt/cast of req.query.shop (none), app entry for global app.use auth (absent, auth-model §6). Template literal interpolates req.query.shop unquoted into db.query; no cast or binding on any visible path. Injection itself is fully traced. Confidence medium only because a global auth middleware outside repo could lower severity to high.

### INJ-I-0022-1 — POST /login passes req.body directly as Mongo filter

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** nosql_injection (operator_injection) — CWE-943 A03:2021  
- **Endpoint:** POST /login  
- **Location:** `node-express/routes/orders.js:20`

**Scenario.** An anonymous user sends operator objects (e.g. not-equal) for the password field so the login check returns true.

**Impact.** Authentication bypass and user enumeration; arbitrary filter keys on the users collection.

**Evidence.**

- `node-express/routes/orders.js:20` — no auth by design  
  `router.post('/login', function (req, res) {`
- `node-express/routes/orders.js:21` — whole request body is the filter  
  `db.collection('users').findOne(req.body, function (e, u) { res.json(!!u); });`

**Data flow.** req.body (orders.js:21) → collection('users').findOne (orders.js:21)

**Recommendation.** Build the filter from typed string fields and compare a password hash in code.

```
const u = String(req.body.user), p = String(req.body.pass); db.collection('users').findOne({ user: u }, (e, doc) => res.json(!!doc && bcrypt.compareSync(p, doc.hash)));
```

*Verifier:* likely — checked: orders.js:20-22 route has no ensureLoggedIn, whole file for any sanitizer or type cast of req.body, app entry / body-parser config (absent from repo, auth-model §6), ../db module (absent). Evidence matches. req.body is passed as the whole filter. Operator injection needs a body parser that yields objects (express.json or urlencoded extended:true); app entry not in repo, so kept medium. Even with plain strings, arbitrary filter keys allow user enumeration. Critical: unauthenticated by design.

### INJ-I-0024-1 — order.cgi interpolates id param into prepared SQL with no binds

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_interpolation) — CWE-89 A03:2021  
- **Endpoint:** GET /perl-cgi/cgi-bin/order.cgi  
- **Location:** `perl-cgi/cgi-bin/order.cgi:11`

**Scenario.** An anonymous user sends a crafted id that rewrites the WHERE clause or adds a UNION.

**Impact.** Unauthenticated read of the shop DB.

**Evidence.**

- `perl-cgi/cgi-bin/order.cgi:8` — not a login check (auth-model §2)  
  `my $session = CGI::Session->load() or die;`
- `perl-cgi/cgi-bin/order.cgi:11` — source  
  `my $id = $q->param('id');`
- `perl-cgi/cgi-bin/order.cgi:13` — interpolated, numeric context  
  `my $sth = $dbh->prepare("SELECT * FROM orders WHERE id = $id");`
- `perl-cgi/cgi-bin/order.cgi:14` — executed with no binds  
  `$sth->execute();`

**Data flow.** $q->param('id') (order.cgi:11) → $id → $dbh->prepare (order.cgi:13) → execute (order.cgi:14)

**Recommendation.** Use the bound form already on line 16-17.

```
my $sth = $dbh->prepare('SELECT * FROM orders WHERE id = ?'); $sth->execute($id);
```

*Verifier:* confirmed — checked: order.cgi:11 $id from $q->param, no validation, order.cgi:13-14 interpolated prepare, execute with no binds, order.cgi:8-9 no effective login stop, order.cgi:16-17 bound variant for contrast. Fully traced. Note: order.cgi:19 also concatenates $q->param('cart') into a DELETE (separate SQLi, more severe as a write); not in this batch as an INJ finding - check it exists elsewhere.

### INJ-I-0025-1 — order.cgi DELETE concatenates cart param

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89 A03:2021  
- **Endpoint:** POST /perl-cgi/cgi-bin/order.cgi  
- **Location:** `perl-cgi/cgi-bin/order.cgi:19`

**Scenario.** An anonymous user widens the DELETE condition to remove every cart.

**Impact.** Unauthenticated mass deletion of carts; possible further SQL.

**Evidence.**

- `perl-cgi/cgi-bin/order.cgi:19` — request param concatenated, numeric context, do() sink  
  `$dbh->do("DELETE FROM carts WHERE cart_id = " . $q->param('cart'));`

**Data flow.** $q->param('cart') (order.cgi:19) → $dbh->do (order.cgi:19)

**Recommendation.** Bind the value.

```
$dbh->do('DELETE FROM carts WHERE cart_id = ?', undef, scalar $q->param('cart'));
```

*Verifier:* confirmed — checked: perl-cgi/cgi-bin/order.cgi:1-20 (whole file), order.cgi:8-9 CGI::Session->load() / $uid never tested (auth-model §2), no cast, regex or quote() on param('cart') before :19, no .htaccess / Apache auth config in repo (auth-model §6), only file in perl-cgi/. Evidence matches. param('cart') concatenated unquoted into $dbh->do at :19; no sanitizer on any path. Critical relies on the endpoint being unauthenticated: load() does not reject missing sessions (library behavior, per auth-model) and Apache-level auth is not in repo. The DELETE also has no owner filter (cart BOLA, not raised in this batch). Line 13 has the same unbound pattern for 'id'.

### BOLA-R-0001-1 — Any logged-in user can rename any member via form member_id

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (id_from_request_used_as_identity) — CWE-639, CWE-566 API1:2023  
- **Endpoint:** ANY /shop/member.asp?mode=edit  
- **Location:** `classic-asp/shop/member.asp:4`

**Scenario.** User A posts mode=edit&name=x&member_id=<member id of user B> to /shop/member.asp; B's name is overwritten.

**Impact.** Modify other members' profile data (name).

**Evidence.**

- `classic-asp/shop/inc/auth.asp:2` — Login check only; no object scope  
  `If Session("UserID") = "" Then Response.Redirect "/login.asp"`
- `classic-asp/shop/member.asp:7` — Target member chosen by request field; Session("UserID") never used  
  `sql = sql & " WHERE member_id = " & Request.Form("member_id")`
- `classic-asp/shop/member.asp:8` — UPDATE runs with no owner binding and no later check  
  `conn.Execute sql`

**Data flow.** Request.Form("member_id") (member.asp:7) → UPDATE members ... WHERE member_id = <value> (member.asp:7) → conn.Execute (member.asp:8)

**Recommendation.** Do not take the member id from the request; use Session("UserID"), or add AND member_id = CLng(Session("UserID")) and use a parameterized ADO Command.

```
" WHERE member_id = " & CLng(Session("UserID"))
```

*Verifier:* confirmed — checked: evidence lines member.asp:4-8 and inc/auth.asp:2 re-read (match), inc/conn.asp:1-3 (connection only, no filter), searched repo for global.asa / web.config / .htaccess covering classic-asp (none), code after conn.Execute (none; no owner comparison), role checks (auth-model §3: none). member_id taken from Request.Form; Session("UserID") never used in member.asp. Severity lowered critical->high: only `name` is written, which bola-patterns §6 rates as 'other non-sensitive field' (high). The SQLi on the same line (INJ-I-0002-1) can widen impact but is rated separately.

### BOLA-R-0003-1 — Order address readable by any logged-in user via id

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **Endpoint:** ANY /shop/order.asp  
- **Location:** `classic-asp/shop/order.asp:5`

**Scenario.** User A sends GET /shop/order.asp?id=<order id of user B> and receives B's delivery address.

**Impact.** Read other customers' order addresses (personal data).

**Evidence.**

- `classic-asp/shop/order.asp:5` — ID from QueryString/Form/Cookie  
  `id = Request("id")`
- `classic-asp/shop/order.asp:6` — No user_id filter (contrast line 12 which binds Session("UserID"))  
  `Set rs = conn.Execute("SELECT * FROM orders WHERE id = " & id)`
- `classic-asp/shop/order.asp:7` — Address of the loaded order is returned to the caller  
  `Response.Write Server.HTMLEncode(rs("address"))`

**Data flow.** Request("id") (order.asp:5) → SELECT * FROM orders WHERE id = <id> (order.asp:6) → rs("address") written to response (order.asp:7)

**Recommendation.** Use the same pattern as line 12: CLng the id and add AND user_id = CLng(Session("UserID")); return 404 if no row.

```
"SELECT * FROM orders WHERE id = " & CLng(id) & " AND user_id = " & CLng(Session("UserID"))
```

*Verifier:* confirmed — checked: order.asp:5-7 re-read (match), order.asp:10-12 safe variant uses a different variable (sid) and result rs2; does not guard line 6-7, post-query owner comparison before Response.Write (none), inc/auth.asp, inc/conn.asp, global.asa/IIS config (not in repo). Address (personal data) of any order returned to any logged-in user. High per bola-patterns §6.

### BOLA-R-0005-1 — order.cfm renders unscoped qOrder instead of owner-bound qMine

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **Endpoint:** ANY /app/order.cfm  
- **Location:** `coldfusion/app/order.cfm:2`

**Scenario.** User A sends GET /app/order.cfm?id=<order id of user B> and sees B's address.

**Impact.** Read other customers' order addresses.

**Evidence.**

- `coldfusion/app/order.cfm:1` — Login check only  
  `<cfif NOT structKeyExists(session, "userID")><cflocation url="/login.cfm"></cfif>`
- `coldfusion/app/order.cfm:3` — qOrder: id only, no owner filter  
  `SELECT * FROM orders WHERE id = #url.id#`
- `coldfusion/app/order.cfm:8` — Owner binding exists only in qMine, whose result is never used  
  `AND user_id = <cfqueryparam value="#session.userID#" cfsqltype="cf_sql_integer">`
- `coldfusion/app/order.cfm:10` — Output comes from the unscoped query  
  `<cfoutput>#qOrder.address#</cfoutput>`

**Data flow.** url.id (order.cfm:3) → qOrder (order.cfm:2-4) → qOrder.address output (order.cfm:10)

**Recommendation.** Remove qOrder and render qMine; stop with 404 when qMine.recordCount is 0.

```
<cfif qMine.recordCount EQ 0><cfheader statuscode="404"><cfabort></cfif><cfoutput>#qMine.address#</cfoutput>
```

*Verifier:* confirmed — checked: order.cfm:1-10 re-read (match), qMine (lines 5-9) is executed but never read; output at :10 uses qOrder, no recordCount check / cfabort on qMine, Application.cfc/.cfm (none in repo). Owner-bound query exists but its result is ignored; the unscoped qOrder.address is rendered. High (personal data).

### BOLA-R-0006-1 — Invoice details readable by any logged-in user via id

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **Endpoint:** ANY /Invoice/Details/{id}  
- **Location:** `dotnet-legacy/Web/Controllers/InvoiceController.cs:11`

**Scenario.** User A requests GET /Invoice/Details/<invoice id of user B> and sees B's invoice.

**Impact.** Read other customers' invoices (financial data).

**Evidence.**

- `dotnet-legacy/Web/Controllers/InvoiceController.cs:6` — Login only, no Roles/Policy  
  `[Authorize]`
- `dotnet-legacy/Web/Controllers/InvoiceController.cs:13` — Load by primary key only; no owner comparison before View(inv) (contrast Mine, line 20)  
  `var inv = db.Invoices.Find(id);`
- `dotnet-legacy/Web/Controllers/InvoiceController.cs:9` — ShopDb source not in repo (auth-model Unknowns); a global filter is unlikely for Find but not provable  
  `private ShopDb db = new ShopDb();`

**Data flow.** int id (route/query/form) (InvoiceController.cs:11) → db.Invoices.Find(id) (InvoiceController.cs:13) → View(inv) (InvoiceController.cs:14)

**Recommendation.** Filter by owner as in Mine: FirstOrDefault(i => i.Id == id && i.UserId == CurrentUserId()) and return HttpNotFound() when null.

```
var inv = db.Invoices.FirstOrDefault(i => i.Id == id && i.UserId == uid); if (inv == null) return HttpNotFound();
```

*Verifier:* likely — checked: InvoiceController.cs:6-15 (class [Authorize] has no Roles/Policy), Web.config:3-9 (login only, no role/location rule for Invoice), search for ShopDb / Global.asax / filters in repo (none present), post-query comparison before View(inv) at :14 (none). Evidence matches. Find(id) by PK, no owner comparison; contrast Mine :20-21. Only ShopDb (not in repo) or the Details view could add a check; EF6 (System.Web.Mvc) has no built-in global query filter, so a hidden control is unlikely but not provable.

### BOLA-R-0008-1 — Invoice search returns any customer's invoices to any logged-in user

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **Endpoint:** POST /Invoice/Search  
- **Location:** `dotnet-legacy/Web/Controllers/InvoiceController.cs:25`

**Scenario.** User A posts customer=<name of customer B> to /Invoice/Search and receives B's invoice list.

**Impact.** Read other customers' invoices (financial data) in bulk.

**Evidence.**

- `dotnet-legacy/Web/Controllers/InvoiceController.cs:6` — Login only, no Roles/Policy  
  `[Authorize]`
- `dotnet-legacy/Web/Controllers/InvoiceController.cs:28` — Selector from request; no UserId filter  
  `SqlQuery<Invoice>("SELECT * FROM Invoices WHERE Customer = '" + customer + "'")`
- `dotnet-legacy/Web/Controllers/InvoiceController.cs:26` — No role check; business intent (staff search vs customer self-search) unknown, hence medium confidence  
  `public ActionResult Search(string customer)`

**Data flow.** string customer (form/query) (InvoiceController.cs:26) → raw SQL by Customer (InvoiceController.cs:28) → View(list) (InvoiceController.cs:29)

**Recommendation.** Add AND UserId = @uid bound to the current user (or require an enforced staff role); use SqlQuery with parameters.

```
db.Database.SqlQuery<Invoice>("SELECT * FROM Invoices WHERE Customer = @p0 AND UserId = @p1", customer, uid)
```

*Verifier:* likely — checked: InvoiceController.cs:6,25-30, Web.config:3-9, auth-model §3 (no role checks anywhere), post-query filtering before View(list) (none). Any logged-in user lists invoices of any Customer value; no UserId filter and no staff role. Business intent (staff search vs self-search) is not visible, so likely rather than confirmed. Same sink as INJ-I-0008-1.

### BOLA-R-0014-1 — Invoice readable by id via Spring show() with no owner or login check visible

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **Endpoint:** GET /invoices/{id}  
- **Location:** `java-legacy/src/com/acme/web/InvoiceController.java:15`

**Scenario.** User A requests GET /invoices/<invoice id of user B> and sees B's invoice.

**Impact.** Read other customers' invoices (financial data); possibly unauthenticated (no Spring Security / filter coverage visible).

**Evidence.**

- `java-legacy/src/com/acme/web/InvoiceController.java:16` — ID from path  
  `public String show(@PathVariable("id") Long id, Model model) {`
- `java-legacy/src/com/acme/web/InvoiceController.java:17` — DAO lookup by id only (contrast findByIdAndOwner at line 23); InvoiceDao source not in repo  
  `model.addAttribute("invoice", invoiceDao.findById(id));`

**Data flow.** @PathVariable id (InvoiceController.java:16) → invoiceDao.findById(id) (InvoiceController.java:17) → view invoice/show (InvoiceController.java:18)

**Recommendation.** Use invoiceDao.findByIdAndOwner(id, principal.getName()) and return 404 on null; add authentication for /invoices/*.

```
Invoice inv = invoiceDao.findByIdAndOwner(id, principal.getName()); if (inv == null) throw new ResourceNotFoundException();
```

*Verifier:* likely — checked: InvoiceController.show (:15-19; no Principal, no post-query check), contrast with mine() owner-bound call (:23), repo-wide grep for InvoiceDao source (absent), Spring Security / interceptor config (none in repo), class-level annotations (:8-9 only @Controller/@RequestMapping). findById(id) receives no user context, so an owner filter inside the DAO is improbable but unverifiable. Spring wiring: InvoiceController fields invoiceDao/session (InvoiceController.java:12-13) have no @Autowired/setters and no DispatcherServlet or Spring config is in repo; wiring and reachability assumed outside visible code. Severity high (financial data); would be critical if /invoices/* is unauthenticated.

### BOLA-R-0016-1 — Invoice search by customer returns any customer's invoices

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **Endpoint:** GET /invoices/search  
- **Location:** `java-legacy/src/com/acme/web/InvoiceController.java:27`

**Scenario.** User A sends GET /invoices/search?customer=<customer B> and receives B's invoices.

**Impact.** Bulk read of other customers' invoices; possibly unauthenticated (no auth coverage visible for /invoices/*).

**Evidence.**

- `java-legacy/src/com/acme/web/InvoiceController.java:28` — Selector from query string; no Principal used  
  `public String search(@RequestParam("customer") String customer, Model model) {`
- `java-legacy/src/com/acme/web/InvoiceController.java:29` — HQL filters by customer only; no owner binding  
  `session.createQuery("from Invoice i where i.customer = '" + customer + "'").list()`

**Data flow.** @RequestParam customer (InvoiceController.java:28) → HQL from Invoice where customer = ... (InvoiceController.java:29) → view invoice/list (InvoiceController.java:30)

**Recommendation.** Bind the owner from Principal in the HQL (and i.owner = :owner) with named parameters, or restrict to an enforced staff role.

```
session.createQuery("from Invoice i where i.customer = :c and i.owner = :o").setParameter("c", customer).setParameter("o", principal.getName())
```

*Verifier:* likely — checked: InvoiceController.search (:27-31; no Principal, no owner predicate), HQL text at :29 (filters i.customer only), Spring Security / role config (none in repo), post-query filtering before view (none). Customer selector from query string returns that customer's invoices with no owner/role binding. Bulk financial read = high. Spring wiring: InvoiceController fields invoiceDao/session (InvoiceController.java:12-13) have no @Autowired/setters and no DispatcherServlet or Spring config is in repo; wiring and reachability assumed outside visible code.

### BOLA-R-0018-1 — Any logged-in user can read any order via /orders/:id (findById)

- **Severity / confidence:** high / medium  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **Endpoint:** GET /orders/:id  
- **Location:** `node-express/routes/orders.js:8`

**Scenario.** User A sends GET /orders/<order id of user B> and receives B's order as JSON.

**Impact.** Read other customers' full order documents.

**Evidence.**

- `node-express/routes/orders.js:6` — Login check only  
  `function ensureLoggedIn(req, res, next) { if (!req.user) return res.redirect('/login'); next(); }`
- `node-express/routes/orders.js:9` — Loads by path id only and returns the full document; no owner comparison  
  `Order.findById(req.params.id, function (err, order) { res.json(order); });`

**Recommendation.** Use the scoped lookup already used in /orders/:id/mine: findOne({_id: req.params.id, owner: req.user._id}); return 404 when null.

```
Order.findOne({ _id: req.params.id, owner: req.user._id }, ...)
```

*Verifier:* confirmed — checked: orders.js:6 ensureLoggedIn (login only), orders.js:9 findById by path id, response returned without owner comparison, orders.js:12-14 scoped sibling route for contrast, ../models/order (absent; could hold a scoping plugin, auth-model §6). No owner check in the handler or after the query. The safe sibling /orders/:id/mine shows ownership is expected. Confidence medium per auth-model §7 because the Order model source is missing.

### BOLA-R-0025-1 — Invoice readable by id with no owner filter (Invoice::view)

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **Endpoint:** GET /invoice/view/{id}  
- **Location:** `php-codeigniter/application/controllers/Invoice.php:9`

**Scenario.** User A requests /invoice/view/<invoice id of user B> and sees B's invoice.

**Impact.** Read other customers' invoices (financial data). MY_Controller (:2, source not in repo) may add a login check; an object-level check there is unlikely but unverified.

**Evidence.**

- `php-codeigniter/application/controllers/Invoice.php:9` — ID from URI segment  
  `public function view($id) {`
- `php-codeigniter/application/controllers/Invoice.php:10` — No user_id filter (compare mine() at :16)  
  `$q = $this->db->query("SELECT * FROM invoices WHERE id = $id");`
- `php-codeigniter/application/controllers/Invoice.php:11` — Row rendered without owner comparison  
  `$this->load->view('invoice', array('inv' => $q->row()));`

**Recommendation.** Use the mine() pattern: get_where('invoices', ['id' => $id, 'user_id' => $this->session->userdata('user_id')]); show_404() when no row.

```
$q = $this->db->get_where('invoices', array('id' => $id, 'user_id' => $this->session->userdata('user_id')));
```

*Verifier:* likely — checked: Invoice.php:9-12 view(): query by id only, row passed to view, Invoice.php:2-7 constructor; MY_Controller source not in repo, Invoice.php:14-18 mine() shows owner-bound pattern exists but view() does not use it, config/routes.php and hooks.php absent (auth-model §6), no post-query owner comparison before load->view. Code says what the finding claims. Only place a control could hide is MY_Controller / hooks (not in repo); an object-level check there is unlikely but cannot be excluded. Invoices are financial data -> high.

### BOLA-R-0031-1 — Order detail (address) readable for any order id by any logged-in user

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **Endpoint:** GET /php-plain/order_detail.php  
- **Location:** `php-plain/order_detail.php:5`

**Scenario.** User A requests /order_detail.php?id=<order id of user B> and sees B's delivery address.

**Impact.** Read other customers' personal data (address).

**Evidence.**

- `php-plain/order_detail.php:5` — ID from query string  
  `$id = $_GET['id'];`
- `php-plain/order_detail.php:6` — No user_id filter  
  `$res = mysql_query("SELECT * FROM orders WHERE id = " . $id);`
- `php-plain/order_detail.php:8` — Other user's address printed; no comparison with $_SESSION['user_id']  
  `echo htmlspecialchars($order['address']);`

**Recommendation.** Use the order_detail_safe.php pattern: PDO with WHERE id = ? AND user_id = ? bound to $_SESSION['user_id'].

```
$st = $pdo->prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?'); $st->execute(array($_GET['id'], $_SESSION['user_id']));
```

*Verifier:* confirmed — checked: php-plain/order_detail.php:1-8 (whole file), php-plain/inc/auth.php:2-7 (login only), php-plain/inc/db.php:1-4 (no query wrapper), post-query owner comparison (none before echo at :8), auth-model §3/§5: no global prepend or role layer. Lookup by request id only; address of any order echoed. Contrast order_detail_safe.php binds user_id. Personal data read -> high.

### BOLA-R-0034-1 — Any logged-in user can read any order via /orders/<order_id>

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **Endpoint:** GET /orders/<int:order_id>  
- **Location:** `python-flask/app.py:8`

**Scenario.** User A, logged in, sends GET /orders/<order id of user B> and receives B's full order row as JSON. IDs are sequential integers, so enumeration is trivial.

**Impact.** Read other customers' orders (all columns of orders table; likely personal and financial data).

**Evidence.**

- `python-flask/app.py:8` — Object ID taken from the URL path (attacker-controlled)  
  `@app.route('/orders/<int:order_id>')`
- `python-flask/app.py:9` — Login check only (Flask-Login); not an ownership check  
  `@login_required`
- `python-flask/app.py:12` — Lookup by id only; no user_id filter, unlike the safe variant at line 20  
  `cur.execute("SELECT * FROM orders WHERE id = %s" % order_id)`
- `python-flask/app.py:13` — Row returned to caller with no post-load owner comparison  
  `return jsonify(cur.fetchone())`

**Data flow.** path order_id (app.py:8) → % formatted into SELECT ... WHERE id (app.py:12) → full row returned as JSON (app.py:13)

**Recommendation.** Bind the order to the current principal in the query (as my_order does at app.py:20), or load and compare owner and return 404 on mismatch. Also switch to parameter binding.

```
cur.execute("SELECT * FROM orders WHERE id = %s AND user_id = %s", (order_id, current_user.id))
```

*Verifier:* confirmed — checked: python-flask/app.py:8-13, python-flask/app.py:9 @login_required (login only), python-flask/app.py:16-21 safe variant for contrast, post-query owner comparison (none; row returned directly), auth-model §6: db module and user_loader absent (irrelevant to the missing filter). Lookup by path id only, full row returned as JSON. The <int:> converter prevents SQLi at :12 but not BOLA.

### INJ-I-0002-1 — Member UPDATE concatenates unquoted member_id from POST

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89 A03:2021  
- **Endpoint:** POST /classic-asp/shop/member.asp?mode=edit  
- **Location:** `classic-asp/shop/member.asp:6`

**Scenario.** A crafted member_id changes the WHERE clause so the UPDATE hits other or all rows, or appends extra SQL.

**Impact.** Modify any members row; read/modify other tables the DB user can access.

**Evidence.**

- `classic-asp/shop/member.asp:7` — source: form field, numeric context, no cast  
  `sql = sql & " WHERE member_id = " & Request.Form("member_id")`
- `classic-asp/shop/member.asp:6` — name part is escaped in quoted context (enough for that part only)  
  `sql = "UPDATE members SET name = '" & Replace(Request.Form("name"), "'", "''") & "'"`
- `classic-asp/shop/member.asp:8` — sink, no parameters  
  `conn.Execute sql`

**Data flow.** Request.Form("member_id") (member.asp:7) → sql (member.asp:7) → conn.Execute (member.asp:8)

**Recommendation.** Use ADODB.Command with ? parameters, or CLng() the id after IsNumeric with failure stopping the page.

```
cmd.CommandText = "UPDATE members SET name = ? WHERE member_id = ?" : cmd.Parameters.Append cmd.CreateParameter("n",202,1,100,name) ...
```

*Verifier:* confirmed — checked: member.asp:6-8 re-read (match), casts/IsNumeric/CLng on member_id (none), inc/conn.asp: plain ADODB.Connection, no Command/parameters, DB account privileges (conn string from Application("ConnStr"), not visible; so no raise to critical). Unquoted numeric context; Replace("'","''") applies only to `name`. Login required -> high per injection-patterns §5.

### INJ-I-0003-1 — Member DELETE concatenates unquoted member_id from query string

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89 A03:2021  
- **Endpoint:** GET /classic-asp/shop/member.asp?mode=delete  
- **Location:** `classic-asp/shop/member.asp:10`

**Scenario.** A crafted member_id widens the DELETE condition so many or all member rows are removed.

**Impact.** Mass deletion of members; possible further SQL on the same connection.

**Evidence.**

- `classic-asp/shop/member.asp:10` — source query string concatenated into sink, numeric context  
  `conn.Execute "DELETE FROM members WHERE member_id = " & Request.QueryString("member_id")`

**Data flow.** Request.QueryString("member_id") (member.asp:10) → conn.Execute (member.asp:10)

**Recommendation.** Bind member_id via ADODB.Command parameter or CLng() after IsNumeric check.

```
conn.Execute "DELETE FROM members WHERE member_id = " & CLng(id)  ' only after IsNumeric(id) else stop
```

*Verifier:* confirmed — checked: member.asp:10 re-read (match), casts/validation on QueryString("member_id") (none), inc/conn.asp (no parameter binding), auth include member.asp:1 -> login required. QueryString concatenated directly into DELETE. High (authenticated).

### INJ-I-0004-1 — Order SELECT concatenates unvalidated id from Request()

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89 A03:2021  
- **Endpoint:** GET /classic-asp/shop/order.asp  
- **Location:** `classic-asp/shop/order.asp:5`

**Scenario.** A crafted id adds conditions or UNION parts to read data beyond the requested order.

**Impact.** Read any table the DB user can access.

**Evidence.**

- `classic-asp/shop/order.asp:5` — source: query/form/cookie collection  
  `id = Request("id")`
- `classic-asp/shop/order.asp:6` — concatenated in numeric context, sink  
  `Set rs = conn.Execute("SELECT * FROM orders WHERE id = " & id)`

**Data flow.** Request("id") (order.asp:5) → id → conn.Execute (order.asp:6)

**Recommendation.** Use the pattern already on line 10-12 (IsNumeric + CLng) or ADODB.Command parameters.

```
If Not IsNumeric(Request("id")) Then Response.End
Set rs = conn.Execute("SELECT * FROM orders WHERE id = " & CLng(Request("id")))
```

*Verifier:* confirmed — checked: order.asp:4-6 re-read (match), `Dim id` is untyped Variant; no IsNumeric/CLng on id (only on sid at :10-11), inc/conn.asp (no parameters). Request("id") also reads Form and Cookies. Authenticated -> high.

### INJ-I-0007-1 — order.cfm qOrder puts url.id into cfquery without cfqueryparam

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** sql_injection (template_placeholder) — CWE-89 A03:2021  
- **Endpoint:** GET /coldfusion/app/order.cfm  
- **Location:** `coldfusion/app/order.cfm:2`

**Scenario.** A logged-in user sends a crafted id that changes the query and leaks other rows via qOrder.address output.

**Impact.** Read any data the 'shop' datasource can access.

**Evidence.**

- `coldfusion/app/order.cfm:1` — login required only  
  `<cfif NOT structKeyExists(session, "userID")><cflocation url="/login.cfm"></cfif>`
- `coldfusion/app/order.cfm:3` — url.id in numeric context, no cfqueryparam  
  `SELECT * FROM orders WHERE id = #url.id#`

**Data flow.** url.id (order.cfm:3) → cfquery qOrder (order.cfm:2)

**Recommendation.** Remove qOrder and use the parameterized qMine query (order.cfm:5-9).

```
<cfqueryparam value="#url.id#" cfsqltype="cf_sql_integer">
```

*Verifier:* confirmed — checked: order.cfm:1-4 re-read (match), validation of url.id before qOrder (none; isNumeric/cfparam type absent), qMine cf_sql_integer at :7 runs AFTER qOrder, so it cannot block the injected query, Application.cfc (none in repo). url.id in unquoted numeric context. Login required -> high.

### INJ-I-0008-1 — Invoice search concatenates customer into EF SqlQuery

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89 A03:2021  
- **Endpoint:** POST /Invoice/Search  
- **Location:** `dotnet-legacy/Web/Controllers/InvoiceController.cs:26`

**Scenario.** A logged-in user closes the quote in customer and appends SQL; SQL Server allows stacked statements.

**Impact.** Read invoices of all customers and other tables; possibly modify data (stacked queries).

**Evidence.**

- `dotnet-legacy/Web/Controllers/InvoiceController.cs:6` — login-only gate, no Roles  
  `[Authorize]`
- `dotnet-legacy/Web/Controllers/InvoiceController.cs:26` — source: model-bound POST/query value  
  `public ActionResult Search(string customer)`
- `dotnet-legacy/Web/Controllers/InvoiceController.cs:28` — concatenated into raw EF SQL, sink  
  `db.Database.SqlQuery<Invoice>("SELECT * FROM Invoices WHERE Customer = '" + customer + "'")`

**Data flow.** customer action parameter (InvoiceController.cs:26) → string concat (InvoiceController.cs:28) → Database.SqlQuery (InvoiceController.cs:28)

**Recommendation.** Use SqlQuery with a SqlParameter, or LINQ (db.Invoices.Where(i => i.Customer == customer)).

```
db.Database.SqlQuery<Invoice>("SELECT * FROM Invoices WHERE Customer = @c", new SqlParameter("@c", customer))
```

*Verifier:* confirmed — checked: InvoiceController.cs:26-28 (string param, no cast/allow-list), Database.SqlQuery called with no parameters argument, reachability: [Authorize] :6 + Web.config:5 (login required), DB account privilege (not shown in repo). Quoted string concatenation into raw EF SQL, executed via ToList(). Login required -> high; no evidence of sa/admin DB account.

### INJ-I-0009-1 — EditOrder UPDATE concatenates txtNote.Text and hidden field hfOrderId

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89 A03:2021  
- **Endpoint:** POST /dotnet-legacy/Web/Orders/EditOrder.aspx  
- **Location:** `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7`

**Scenario.** A logged-in user puts a quote in the note or edits the hidden OrderId to rewrite the UPDATE (all rows or extra statements).

**Impact.** Modify any Orders rows; SQL Server allows stacked statements, so further writes are possible.

**Evidence.**

- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7` — TextBox value, quoted, not escaped (I-0009)  
  `Dim sql As String = "UPDATE Orders SET Note = '" & txtNote.Text & "'"`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8` — hidden field, client-controlled, numeric context (I-0010)  
  `sql &= " WHERE OrderId = " & hfOrderId.Value`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:10` — command built from string  
  `Dim cmd As New SqlCommand(sql, conn)`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:12` — sink, no parameters  
  `cmd.ExecuteNonQuery()`

**Data flow.** txtNote.Text / hfOrderId.Value (EditOrder.aspx.vb:7-8) → sql → SqlCommand (EditOrder.aspx.vb:10) → ExecuteNonQuery (EditOrder.aspx.vb:12)

**Recommendation.** Use SqlCommand parameters for both values.

```
cmd = New SqlCommand("UPDATE Orders SET Note = @n WHERE OrderId = @id", conn): cmd.Parameters.AddWithValue("@n", txtNote.Text): cmd.Parameters.AddWithValue("@id", CInt(hfOrderId.Value))
```

*Verifier:* likely — checked: EditOrder.aspx.vb:6-13 (no escaping, no CInt, no parameters), EditOrder.aspx:1-2 (controls declared), Web.config:5 login required for /Orders, BasePage (not in repo). Taint and sink are correct. Reachability gap: handler is wired via 'Handles btnSave.Click' but EditOrder.aspx:2 declares no btnSave control and no designer file exists, so the visible code would not compile/fire as-is; markup may be truncated. Also Inherits="Web.Orders.EditOrder" vs class EditOrder without namespace. Keep high severity; confidence lowered.

### INJ-I-0011-1 — OrderDetail executes SELECT concatenated with query-string id

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89 A03:2021  
- **Endpoint:** GET /dotnet-legacy/Web/Orders/OrderDetail.aspx  
- **Location:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10`

**Scenario.** A logged-in user sends a crafted id that appends conditions, UNION or stacked statements.

**Impact.** Read/modify any data the connection's DB login can access.

**Evidence.**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10` — source: query string  
  `string id = Request.QueryString["id"];`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13` — concatenated, numeric context  
  `var cmd = new SqlCommand("SELECT * FROM Orders WHERE OrderId = " + id, conn);`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:15` — sink executed  
  `var r = cmd.ExecuteReader();`

**Data flow.** Request.QueryString["id"] (OrderDetail.aspx.cs:10) → id → SqlCommand (OrderDetail.aspx.cs:13) → ExecuteReader (OrderDetail.aspx.cs:15)

**Recommendation.** Execute the parameterized 'safe' command from line 16-18 instead of line 13.

```
var cmd = new SqlCommand("SELECT * FROM Orders WHERE OrderId = @id AND UserId = @uid", conn); cmd.Parameters.AddWithValue("@id", int.Parse(id));
```

*Verifier:* confirmed — checked: OrderDetail.aspx.cs:10-15 (string id, no int.Parse/cast before :13), ExecuteReader :15 executes the tainted command, reachability: Web.config:5 deny ? applies to /Orders; not under Handlers exclusion, BasePage (not in repo; at most login). Numeric-context concatenation executed. Unused result does not reduce injection impact (SqlClient allows batched statements / blind techniques). Login required -> high.

### INJ-I-0016-1 — EditUserAction prepareStatement built by concatenating email and user_id

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89 A03:2021  
- **Endpoint:** POST /user/edit.do  
- **Location:** `java-legacy/src/com/acme/struts/EditUserAction.java:10`

**Scenario.** A logged-in user crafts email or user_id to rewrite the UPDATE, e.g. changing every user's email.

**Impact.** Modify any users rows (account takeover via email change); read data via error/boolean techniques.

**Evidence.**

- `java-legacy/src/com/acme/struts/EditUserAction.java:10` — source  
  `String userId = request.getParameter("user_id");`
- `java-legacy/src/com/acme/struts/EditUserAction.java:11` — source  
  `String email = request.getParameter("email");`
- `java-legacy/src/com/acme/struts/EditUserAction.java:13` — prepared but concatenated; no placeholders  
  `PreparedStatement ps = conn.prepareStatement("UPDATE users SET email = '" + email + "' WHERE id = " + userId);`
- `java-legacy/src/com/acme/struts/EditUserAction.java:14` — sink  
  `ps.executeUpdate();`

**Data flow.** request params user_id/email (EditUserAction.java:10-11) → SQL string (EditUserAction.java:13) → executeUpdate (EditUserAction.java:14)

**Recommendation.** Use ? placeholders and setString/setLong.

```
PreparedStatement ps = conn.prepareStatement("UPDATE users SET email = ? WHERE id = ?"); ps.setString(1, email); ps.setLong(2, Long.parseLong(userId));
```

*Verifier:* likely — checked: EditUserAction.java:10-14 (email quoted-concat, userId unquoted-concat, no setX calls), casts/validation between source and sink (none), struts-config.xml userForm (form-bean undefined, validate() unknown), web.xml ActionServlet mapping (absent). prepareStatement with concatenated values and no placeholders is not parameterized; both params tainted. High = after login (LoginFilter on *.do). Likely, not confirmed: reachability (no ActionServlet mapping) and ActionForm validation are not visible.

### INJ-I-0017-1 — Invoice search builds HQL by concatenating customer parameter

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-564, CWE-89 A03:2021  
- **Endpoint:** GET /invoices/search  
- **Location:** `java-legacy/src/com/acme/web/InvoiceController.java:27`

**Scenario.** A crafted customer value closes the quote and adds 'or 1=1'-style HQL conditions to list all invoices.

**Impact.** Read every Invoice entity; HQL injection can sometimes reach native SQL functions.

**Evidence.**

- `java-legacy/src/com/acme/web/InvoiceController.java:28` — source: request parameter  
  `public String search(@RequestParam("customer") String customer, Model model) {`
- `java-legacy/src/com/acme/web/InvoiceController.java:29` — concatenated HQL, Hibernate sink  
  `session.createQuery("from Invoice i where i.customer = '" + customer + "'").list()`

**Data flow.** @RequestParam customer (InvoiceController.java:28) → HQL string (InvoiceController.java:29) → Session.createQuery().list() (InvoiceController.java:29)

**Recommendation.** Use a named HQL parameter.

```
session.createQuery("from Invoice i where i.customer = :c").setParameter("c", customer).list()
```

*Verifier:* likely — checked: InvoiceController.java:28-29 (String param concatenated in quotes into createQuery), setParameter / validation (none), Spring auth coverage for /invoices/* (unknown). HQL injection evidence correct; String type gives no protection. Spring wiring: InvoiceController fields invoiceDao/session (InvoiceController.java:12-13) have no @Autowired/setters and no DispatcherServlet or Spring config is in repo; wiring and reachability assumed outside visible code. Rated high (assumed login); critical if unauthenticated.

### INJ-I-0020-1 — /reports concatenates req.query.month into SQL

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89 A03:2021  
- **Endpoint:** GET /reports  
- **Location:** `node-express/routes/orders.js:16`

**Scenario.** A logged-in user closes the quote in month and appends SQL (UNION) to read other tables.

**Impact.** Read any data the DB user can access.

**Evidence.**

- `node-express/routes/orders.js:16` — login only  
  `router.get('/reports', ensureLoggedIn, function (req, res) {`
- `node-express/routes/orders.js:17` — concatenated, quoted, no escaping; db.query sink  
  `db.query("SELECT * FROM reports WHERE month = '" + req.query.month + "'", ...`

**Data flow.** req.query.month (orders.js:17) → db.query (orders.js:17)

**Recommendation.** Use placeholders supported by the driver ('?' for mysql, $1 for pg).

```
db.query("SELECT * FROM reports WHERE month = ?", [String(req.query.month)], cb)
```

*Verifier:* confirmed — checked: orders.js:16 ensureLoggedIn (login only), orders.js:17 quoted concatenation of req.query.month into db.query, whole file for escaping (none), ../db wrapper (absent; cannot sanitize an already concatenated string). Fully traced source to sink in one statement. Any logged-in user. No DB account privilege visible, so high not critical.

### INJ-I-0023-1 — /search builds Mongo $where JavaScript from req.query.n

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** nosql_injection (js_injection) — CWE-943 A03:2021  
- **Endpoint:** GET /search  
- **Location:** `node-express/routes/orders.js:24`

**Scenario.** A logged-in user closes the quote in n and adds JavaScript that makes the predicate always true or burns CPU.

**Impact.** Dump all items; denial of service on the DB server.

**Evidence.**

- `node-express/routes/orders.js:25` — string concatenated into server-side JS  
  `db.collection('items').find({ $where: "this.name == '" + req.query.n + "'" })`

**Data flow.** req.query.n (orders.js:25) → $where (orders.js:25) → collection('items').find (orders.js:25)

**Recommendation.** Remove $where; use a normal equality filter with a string-cast value.

```
db.collection('items').find({ name: String(req.query.n) })
```

*Verifier:* confirmed — checked: orders.js:24 ensureLoggedIn (login only), orders.js:25 req.query.n concatenated into $where JS string, whole file for cast/escape (none). Fully traced. Only possible outside control is MongoDB server-side JS disabled (security.javascriptEnabled=false) or a server version that removed $where; neither visible in repo.

### INJ-I-0026-1 — CodeIgniter invoice view interpolates URI segment into db->query

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** sql_injection (string_interpolation) — CWE-89 A03:2021  
- **Endpoint:** ANY /invoice/view/{id}  
- **Location:** `php-codeigniter/application/controllers/Invoice.php:9`

**Scenario.** A user puts SQL after the id in the URL path to change the WHERE clause.

**Impact.** Read any data the DB user can access.

**Evidence.**

- `php-codeigniter/application/controllers/Invoice.php:9` — source: URI segment /invoice/view/<id>  
  `public function view($id) {`
- `php-codeigniter/application/controllers/Invoice.php:10` — interpolated in unquoted numeric context, sink without binding  
  `$q = $this->db->query("SELECT * FROM invoices WHERE id = $id");`

**Data flow.** URI segment 3 (Invoice.php:9) → $id → $this->db->query (Invoice.php:10)

**Recommendation.** Use query bindings or get_where with an int cast, as done in mine() and update().

```
$q = $this->db->query('SELECT * FROM invoices WHERE id = ?', array((int)$id));
```

*Verifier:* likely — checked: Invoice.php:9-10 $id from URI segment interpolated unquoted into db->query, no (int)/is_numeric/escape on $id, MY_Controller, config/config.php (permitted_uri_chars), routes.php not in repo. Sink and source confirmed. CodeIgniter's permitted_uri_chars (config not in repo; default allows letters, digits, space, ~%.:_-) filters URI segments and blocks quotes/parentheses/commas, so payloads are restricted, but numeric-context boolean injection (e.g. '1 OR 1') fits the default set. Not certain of exact CI version decoding behavior -> medium.

### INJ-I-0028-1 — admin.php delete interpolates POST id into mysql_query

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_interpolation) — CWE-89 A03:2021  
- **Endpoint:** POST /php-plain/admin.php?action=delete  
- **Location:** `php-plain/admin.php:11`

**Scenario.** Any logged-in user (no admin role check) sends a crafted id that deletes all users.

**Impact.** Mass deletion of users; boolean/time-based data read.

**Evidence.**

- `php-plain/admin.php:11` — source, no cast  
  `$id = $_POST['id'];`
- `php-plain/admin.php:12` — interpolated unquoted, mysql_query sink  
  `mysql_query("DELETE FROM users WHERE id = $id");`

**Data flow.** $_POST['id'] (admin.php:11) → $id → mysql_query (admin.php:12)

**Recommendation.** Cast to int as on line 7, or use PDO prepared statements.

```
$st = $pdo->prepare('DELETE FROM users WHERE id = ?'); $st->execute([(int)$_POST['id']]);
```

*Verifier:* confirmed — checked: admin.php:11-12 $_POST['id'] interpolated unquoted, no cast (contrast (int) at :7), inc/auth.php login required, no role, inc/db.php DB user 'app' (not root/sa). Reachable by any logged-in user, no sanitizer -> high. Not critical: repo does not show an admin DB account.

### INJ-I-0030-1 — mongo_find.php builds $where JavaScript from GET n

- **Severity / confidence:** high / low  
- **Status:** likely  
- **Category:** nosql_injection (js_injection) — CWE-943 A03:2021  
- **Endpoint:** GET /php-plain/mongo_find.php  
- **Location:** `php-plain/mongo_find.php:6`

**Scenario.** A logged-in user closes the quote in n and adds JavaScript that returns every member or loops.

**Impact.** Dump the members collection; DB denial of service.

**Evidence.**

- `php-plain/mongo_find.php:6` — request value concatenated into server-side JS  
  `$docs = $coll->find(array('$where' => "this.name == '" . $_GET['n'] . "'"));`

**Data flow.** $_GET['n'] (mongo_find.php:6) → $where (mongo_find.php:6) → MongoCollection::find (mongo_find.php:6)

**Recommendation.** Drop $where; use an equality filter with a string cast.

```
$docs = $coll->find(['name' => (string)$_GET['n']]);
```

*Verifier:* likely — checked: mongo_find.php:6 $_GET['n'] concatenated into $where JS, inc/auth.php login required, use of $docs after :6 (none; file ends). Taint into $where is real and unsanitized. However legacy MongoCollection::find returns a lazy MongoCursor that is not sent to the server until iterated, and $docs is never iterated, so the query likely never executes today. Driver behavior stated from knowledge, not repo -> low confidence. If lazy execution is confirmed, rate low (latent); if any code iterates $docs, high.

### INJ-I-0031-1 — Order detail query concatenates unquoted GET id

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89 A03:2021  
- **Endpoint:** GET /php-plain/order_detail.php  
- **Location:** `php-plain/order_detail.php:5`

**Scenario.** A logged-in user supplies an id value with extra SQL that changes the WHERE clause (e.g. UNION-based read of other tables).

**Impact.** Read any data the 'app' DB user can access; also bypasses any notion of order ownership.

**Evidence.**

- `php-plain/order_detail.php:2` — login-only gate (inc/auth.php:4-6); any logged-in user reaches the sink  
  `require_once 'inc/auth.php';`
- `php-plain/order_detail.php:5` — source: query string, no cast  
  `$id = $_GET['id'];`
- `php-plain/order_detail.php:6` — concatenated in numeric (unquoted) context and sent to mysql_query  
  `$res = mysql_query("SELECT * FROM orders WHERE id = " . $id);`

**Data flow.** $_GET['id'] (order_detail.php:5) → $id → mysql_query (order_detail.php:6)

**Recommendation.** Use a PDO prepared statement with a bound integer parameter (the $pdo handle already exists in inc/db.php:4).

```
$st = $pdo->prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?'); $st->execute([(int)$_GET['id'], $_SESSION['user_id']]);
```

*Verifier:* confirmed — checked: php-plain/order_detail.php:5-6 (no cast, unquoted numeric context), php-plain/inc/db.php:2 (raw mysql_query, DB user 'app', not root), php-plain/inc/auth.php (login-only gate). Unquoted numeric context, so even magic_quotes_gpc (PHP 5 config not in repo) would not help. Reachable by any logged-in user -> high.

### INJ-I-0032-1 — Product search LIKE clause relies on addslashes only

- **Severity / confidence:** high / low  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89 A03:2021  
- **Endpoint:** GET /php-plain/search.php  
- **Location:** `php-plain/search.php:5`

**Scenario.** If the connection charset is a multibyte charset such as SJIS/GBK, a crafted byte sequence swallows the added backslash and breaks out of the quoted string.

**Impact.** Read data via the products query; same sink is already injectable via sort (INJ-I-0033-1).

**Evidence.**

- `php-plain/search.php:5` — source: query string; addslashes is a weak sanitizer (multibyte bypass with SJIS/GBK)  
  `$kw = addslashes($_GET['q']);`
- `php-plain/search.php:8` — concatenated inside quotes  
  `$sql .= " AND name LIKE '%" . $kw . "%'";`
- `php-plain/search.php:11` — sink, no binding  
  `$res = mysql_query($sql);`

**Data flow.** $_GET['q'] (search.php:5) → addslashes → $kw → $sql (search.php:8) → mysql_query (search.php:11)

**Recommendation.** Bind the keyword as a parameter (PDO) instead of addslashes; build the LIKE pattern in code.

```
$st = $pdo->prepare('SELECT id, name FROM products WHERE name LIKE ?'); $st->execute(['%'.$_GET['q'].'%']);
```

*Verifier:* likely — checked: php-plain/search.php:5,8,11, php-plain/inc/db.php:2-3 (no SET NAMES / mysql_set_charset), repo-wide grep for charset settings (none). addslashes inside quotes is exploitable only if the connection charset is a multibyte one (SJIS/GBK/Big5). No charset is set in code; server/my.cnf default not in repo. Keep as likely pending charset confirmation. Same query is already injectable via sort (INJ-I-0033-1), so remediation overlaps.

### INJ-I-0033-1 — ORDER BY clause taken directly from GET sort

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** sql_injection (dynamic_identifier) — CWE-89 A03:2021  
- **Endpoint:** GET /php-plain/search.php  
- **Location:** `php-plain/search.php:6`

**Scenario.** A logged-in user puts an SQL expression in sort to infer data from other tables through result ordering (blind injection).

**Impact.** Read any data the 'app' DB user can access.

**Evidence.**

- `php-plain/search.php:6` — source: query string, no allow-list  
  `$sort = $_GET['sort'];`
- `php-plain/search.php:9` — raw identifier/expression appended  
  `$sql .= " ORDER BY " . $sort;`
- `php-plain/search.php:11` — sink  
  `$res = mysql_query($sql);`

**Data flow.** $_GET['sort'] (search.php:6) → $sort → $sql (search.php:9) → mysql_query (search.php:11)

**Recommendation.** Map sort to an exact allow-list of column names; default otherwise.

```
$cols = ['id'=>'id','name'=>'name']; $sort = isset($cols[$_GET['sort']]) ? $cols[$_GET['sort']] : 'id';
```

*Verifier:* confirmed — checked: php-plain/search.php:6,9,11 (no allow-list, no cast), php-plain/inc/db.php (no wrapper), php-plain/inc/auth.php (login-only gate). Raw ORDER BY expression from GET reaches mysql_query; quoting-based controls (magic_quotes) do not apply to an identifier context.

### INJ-I-0034-1 — Category filter interpolates $_GET['cat'] in heredoc SQL

- **Severity / confidence:** high / medium  
- **Status:** confirmed  
- **Category:** sql_injection (string_interpolation) — CWE-89 A03:2021  
- **Endpoint:** GET /php-plain/search.php  
- **Location:** `php-plain/search.php:12`

**Scenario.** A logged-in user closes the quote in cat and appends SQL that changes the query.

**Impact.** Read any data the 'app' DB user can access.

**Evidence.**

- `php-plain/search.php:14` — request value interpolated directly into quoted SQL, no escaping at all  
  `WHERE category = '{$_GET['cat']}'`
- `php-plain/search.php:16` — sink  
  `$res2 = mysql_query($q);`

**Data flow.** $_GET['cat'] (search.php:14) → $q heredoc (search.php:12-15) → mysql_query (search.php:16)

**Recommendation.** Use a prepared statement with a bound parameter.

```
$st = $pdo->prepare('SELECT * FROM products WHERE category = ?'); $st->execute([$_GET['cat']]);
```

*Verifier:* confirmed — checked: php-plain/search.php:12-16 (heredoc interpolation of $_GET['cat'], executed at :16), php-plain/inc/db.php (no wrapper), php.ini / .htaccess / .user.ini in repo (none found). No escaping in code. Confidence medium only because this is PHP 5-era code and magic_quotes_gpc (php.ini, not in repo) could auto-escape $_GET in PHP < 5.4; even then the multibyte caveat of INJ-I-0032-1 applies. Note: :10 ($sql2 with constant STATUS_ACTIVE) is a constant-only concat and never executed - not a finding.

### INJ-I-0036-1 — Flask search builds LIKE query with f-string

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_interpolation) — CWE-89 A03:2021  
- **Endpoint:** GET|POST /search  
- **Location:** `python-flask/app.py:27`

**Scenario.** A logged-in user closes the quote in q and appends SQL (e.g. UNION) to read other tables.

**Impact.** Read any data the DB user can access.

**Evidence.**

- `python-flask/app.py:25` — login-only gate  
  `@login_required`
- `python-flask/app.py:27` — source: query string  
  `q = request.args.get('q', '')`
- `python-flask/app.py:29` — f-string interpolation into SQL, sink without parameters  
  `cur.execute(f"SELECT * FROM products WHERE name LIKE '%{q}%'")`

**Data flow.** request.args['q'] (app.py:27) → q → cur.execute f-string (app.py:29)

**Recommendation.** Pass q as a bound parameter.

```
cur.execute("SELECT * FROM products WHERE name LIKE %s", ('%' + q + '%',))
```

*Verifier:* confirmed — checked: python-flask/app.py:24-30, request.args.get with no validation (:27), cur.execute with no params tuple (:29), db module not in repo (does not affect: string is built before execute). f-string interpolation of request value into quoted SQL; any logged-in user.

### BOLA-R-0010-1 — Order note writable on any order via client-controlled hidden field

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **Endpoint:** POST /Orders/EditOrder.aspx  
- **Location:** `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:6`

**Scenario.** User A edits own order, changes hfOrderId in the postback to <order id of user B>, saves; B's order note is overwritten.

**Impact.** Modify a field (Note) on other customers' orders.

**Evidence.**

- `dotnet-legacy/Web/Orders/EditOrder.aspx:2` — Order id held in a hidden field (client-controlled, not protected by ViewState MAC)  
  `<asp:HiddenField ID="hfOrderId" runat="server" />`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8` — UPDATE by hidden-field id; no UserId filter  
  `sql &= " WHERE OrderId = " & hfOrderId.Value`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:12` — Write executes with no prior ownership check  
  `cmd.ExecuteNonQuery()`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:4` — BasePage not in repo; assumed login only  
  `Inherits BasePage`

**Data flow.** hfOrderId.Value (EditOrder.aspx.vb:8) → UPDATE Orders SET Note ... WHERE OrderId = <value> (EditOrder.aspx.vb:7-8) → ExecuteNonQuery (EditOrder.aspx.vb:12)

**Recommendation.** Add AND UserId = @uid bound to Session["UserID"]; check rows affected; use parameters.

```
UPDATE Orders SET Note = @note WHERE OrderId = @id AND UserId = @uid
```

*Verifier:* likely — checked: EditOrder.aspx:2 (hfOrderId is a posted hidden field), EditOrder.aspx.vb:7-14 (UPDATE by OrderId only, rows affected not checked), BasePage (not in repo), Web.config:3-9. No owner filter on the write; note field is low-impact -> medium. Same reachability gap as INJ-I-0009-1 (btnSave not in markup) and BasePage unknown, hence likely/medium.

### BOLA-R-0013-1 — Unfiltered JSP loads any order by order_no without login

- **Severity / confidence:** medium / high  
- **Status:** confirmed  
- **Category:** bola (no_authentication) — CWE-306, CWE-639 API1:2023, API2:2023  
- **Endpoint:** ANY /order/detail.jsp  
- **Location:** `java-legacy/WebContent/order/detail.jsp:3`

**Scenario.** Anonymous attacker sends GET /order/detail.jsp?no=<any order number>; the order is loaded with no login or owner check.

**Impact.** Order lookup by any order number without authentication; result set is not rendered in visible code, so disclosure is not proven.

**Evidence.**

- `java-legacy/WebContent/WEB-INF/web.xml:9` — LoginFilter covers *.do only; detail.jsp outside WEB-INF is directly reachable  
  `<url-pattern>*.do</url-pattern>`
- `java-legacy/WebContent/order/detail.jsp:3` — ID from request  
  `String no = request.getParameter("no");`
- `java-legacy/WebContent/order/detail.jsp:5` — Lookup by order_no only; no session user referenced  
  `executeQuery("SELECT * FROM orders WHERE order_no = '" + no + "'")`

**Data flow.** request.getParameter("no") (detail.jsp:3) → SELECT * FROM orders WHERE order_no = ... (detail.jsp:5)

**Recommendation.** Move the JSP under WEB-INF or extend LoginFilter to it; add AND user_id = ? bound to the session user; use PreparedStatement parameters.

```
SELECT * FROM orders WHERE order_no = ? AND user_id = ?
```

*Verifier:* confirmed — checked: web.xml filter-mapping (only *.do, web.xml:7-10), web.xml for security-constraint / login-config (none), detail.jsp full file (lines 1-7), repo-wide grep for LoginFilter/security-constraint/other filters, post-query use of rs (none; only ${param.no} at :7). Evidence matches. JSP is outside WEB-INF and not covered by LoginFilter; query uses order_no only. rs is never rendered, so per BOLA guide: unexposed read = low, +1 unauthenticated = medium. Severity kept. The same line is also concatenated SQL (separate injection issue, not this finding).

### BOLA-R-0017-1 — Order row loaded by request orderId on unauthenticated servlet, no owner filter

- **Severity / confidence:** medium / high  
- **Status:** confirmed  
- **Category:** bola (no_authentication) — CWE-306, CWE-639 API1:2023, API2:2023  
- **Endpoint:** GET /order/view  
- **Location:** `java-legacy/src/com/acme/web/OrderServlet.java:8`

**Scenario.** Anonymous client sends GET /order/view?orderId=<any order id>; the servlet loads that order with no login and no owner check.

**Impact.** Any order row can be loaded without authentication. In the visible code the ResultSet is never rendered (doGet ends at :22), so actual exposure depends on code not shown; items/notes queries (:16-19) are built but never executed.

**Evidence.**

- `java-legacy/WebContent/WEB-INF/web.xml:9` — LoginFilter covers only *.do; /order/view (web.xml:17) is not filtered  
  `<url-pattern>*.do</url-pattern>`
- `java-legacy/src/com/acme/web/OrderServlet.java:10` — Session user read but never tested; no stop when null  
  `Object loginUser = session.getAttribute("loginUser");`
- `java-legacy/src/com/acme/web/OrderServlet.java:11` — ID from query string or form body (attacker-controlled)  
  `String id = request.getParameter("orderId");`
- `java-legacy/src/com/acme/web/OrderServlet.java:15` — Executed query filters on id only; no user_id / loginUser binding  
  `stmt.executeQuery("SELECT * FROM orders WHERE id = '" + id + "'");`

**Data flow.** request.getParameter("orderId") :11 → -> concatenated SQL :15 → -> executeQuery (no owner column)

**Recommendation.** Map LoginFilter to /order/view (or /*), stop when loginUser is null, and add AND user_id = ? bound to the session user's id.

```
PreparedStatement ps = conn.prepareStatement("SELECT * FROM orders WHERE id = ? AND user_id = ?"); ps.setString(1, id); ps.setLong(2, loginUser.getId());
```

*Verifier:* confirmed — checked: web.xml filter coverage for /order/view (not covered), OrderServlet.doGet (:8-23) incl. loginUser never tested, executed query (:15) has no user_id predicate, use of rs after query (none; method ends at :23, nothing written to response). Lookup by request id with no auth and no owner filter is confirmed. Severity lowered high -> medium: rs is never returned or used, so per BOLA guide an unexposed read is low, +1 for unauthenticated = medium. The concurrent SQLi (INJ-I-0018-1) is the real exposure.

### BOLA-R-0020-1 — Reports selected by month with no owner/tenant filter; per-user scope unknown

- **Severity / confidence:** medium / low  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **Endpoint:** GET /reports  
- **Location:** `node-express/routes/orders.js:16`

**Scenario.** Logged-in user sends GET /reports?month=<month> and receives every report row for that month, including other users' if reports are per-user.

**Impact.** Possible read of other users'/shops' reports. Whether reports are per-user is not visible (no schema, auth-model §4). SQL injection at :17 is a separate concern for the injection auditor.

**Evidence.**

- `node-express/routes/orders.js:16` — Login check only  
  `router.get('/reports', ensureLoggedIn, function (req, res) {`
- `node-express/routes/orders.js:17` — Returns all reports of the month to any logged-in user; no owner column  
  `db.query("SELECT * FROM reports WHERE month = '" + req.query.month + "'", ...`

**Recommendation.** Confirm with the owner whether reports are per-user/per-shop. If so, add AND owner_id = ? bound to req.user._id (and use a bound parameter for month).

```
db.query('SELECT * FROM reports WHERE month = ? AND owner_id = ?', [req.query.month, req.user._id], ...)
```

*Verifier:* likely — checked: orders.js:16-18 handler and query, auth-model §4 data model (reports has no visible owner column; per-user scope unknown), ../db (absent; no shared WHERE builder visible). No owner filter exists, but whether reports are per-user/per-shop data is not determinable. Kept as needs-owner-confirmation. Overlaps INJ-I-0020-1 at the same line.

### BOLA-R-0022-1 — Item search returns all matching items with no owner filter; ownership of items unknown

- **Severity / confidence:** medium / low  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **Endpoint:** GET /search  
- **Location:** `node-express/routes/orders.js:24`

**Scenario.** Logged-in user sends GET /search?n=<name> (or an injected $where that is always true) and receives all items.

**Impact.** If items are per-user (not a public catalog), other users' items are readable. Not determinable from repo. $where injection is for the injection auditor.

**Evidence.**

- `node-express/routes/orders.js:24` — Login check only  
  `router.get('/search', ensureLoggedIn, function (req, res) {`
- `node-express/routes/orders.js:25` — Filter on name only; no owner field. $where injection allows dropping the name filter entirely  
  `db.collection('items').find({ $where: "this.name == '" + req.query.n + "'" })`

**Recommendation.** Confirm whether items are public catalog data. If per-user, add owner: req.user._id to the filter and replace $where with a field match.

```
db.collection('items').find({ name: String(req.query.n), owner: req.user._id })
```

*Verifier:* likely — checked: orders.js:24-26 handler and filter, auth-model §4 (items has no visible owner field anywhere), whole file for post-query filtering (none). No owner filter, but items may be a public catalog; ownership model unknown. If catalog data, this should be dropped. Overlaps INJ-I-0023-1.

### BOLA-R-0023-1 — Unauthenticated per-shop order count via request-controlled shop id

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** bola (no_authentication) — CWE-306, CWE-639 API1:2023, API2:2023  
- **Endpoint:** GET /stats  
- **Location:** `node-express/routes/orders.js:28`

**Scenario.** Anonymous client sends GET /stats?shop=<other shop id> and gets that shop's order count; can iterate shop ids.

**Impact.** Cross-tenant leak of business metrics (order volume). Low-value aggregate, raised one level for no authentication. A global app.use() auth may exist outside repo (auth-model §6).

**Evidence.**

- `node-express/routes/orders.js:28` — No ensureLoggedIn on this route (unlike the others in the file)  
  `router.get('/stats', function (req, res) {`
- `node-express/routes/orders.js:29` — Tenant key shop_id taken from query string; not bound to any session value  
  `db.query('SELECT COUNT(*) AS n FROM orders WHERE shop_id = ${req.query.shop}', ...`

**Recommendation.** Add ensureLoggedIn and derive shop_id from req.user (server-side), not from the query string.

```
router.get('/stats', ensureLoggedIn, (req, res) => db.query('SELECT COUNT(*) AS n FROM orders WHERE shop_id = ?', [req.user.shopId], ...))
```

*Verifier:* likely — checked: orders.js:28 no ensureLoggedIn, orders.js:29 shop_id taken from req.query, not from req.user, auth-model §4 tenant model (shop_id multi-shop unconfirmed), app entry for global auth (absent). Evidence matches. Order count is low-value aggregate (low), +1 for no authentication = medium. Tenant model and global auth both unconfirmed, so likely. Same line as INJ-I-0021-1, whose impact dominates.

### BOLA-R-0027-1 — Invoice note writable for any invoice id from POST (Invoice::update)

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **Endpoint:** POST /invoice/update  
- **Location:** `php-codeigniter/application/controllers/Invoice.php:20`

**Scenario.** User A POSTs invoice_id=<invoice id of user B>&note=... to /invoice/update and overwrites B's invoice note.

**Impact.** Modify one field (note) on other customers' invoices. Rated medium per 'write limited fields'; reviewers may raise to high given invoices are financial records.

**Evidence.**

- `php-codeigniter/application/controllers/Invoice.php:21` — ID from POST body  
  `$id = $this->input->post('invoice_id');`
- `php-codeigniter/application/controllers/Invoice.php:23` — Bound (no SQLi) but WHERE has no user_id; no prior ownership lookup  
  `$this->db->query("UPDATE invoices SET note = ? WHERE id = ?", array($note, $id));`

**Recommendation.** Add AND user_id = ? bound to the session user and check affected_rows(); return 404/403 when 0.

```
UPDATE invoices SET note = ? WHERE id = ? AND user_id = ?  -- array($note, $id, $this->session->userdata('user_id'))
```

*Verifier:* likely — checked: Invoice.php:20-24 update(): invoice_id from POST, bound UPDATE with no user_id, no prior ownership lookup in update(), MY_Controller / hooks not in repo, CI default routing makes public method reachable (routes.php absent). Bound query (no SQLi) but WHERE id = ? only. Writes a single low-impact field (note) -> medium per bola-patterns §6. Likely rather than confirmed because MY_Controller is not visible.

### INJ-I-0015-1 — MyBatis list query uses ${orderBy} (caller not in repo)

- **Severity / confidence:** medium / low  
- **Status:** likely  
- **Category:** sql_injection (template_placeholder) — CWE-89 A03:2021  
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/mapper/OrderMapper.xml:7`

**Scenario.** If any caller passes a request value as orderBy, that user can inject an SQL expression into ORDER BY.

**Impact.** Read data the DB user can access (blind).

**Evidence.**

- `java-legacy/src/com/acme/mapper/OrderMapper.xml:9` — ${} is raw text substitution in MyBatis; no allow-list visible  
  `ORDER BY ${orderBy}`
- `java-legacy/src/com/acme/mapper/OrderMapper.xml:8` — #{userId} is bound (safe); only orderBy is raw  
  `SELECT * FROM orders WHERE user_id = #{userId}`

**Data flow.** orderBy (caller unknown) → ${orderBy} (OrderMapper.xml:9)

**Recommendation.** Find the Java caller of OrderMapper.list; validate orderBy against an allow-list there or use <choose> in the mapper.

```
<choose><when test="orderBy == 'date'">ORDER BY created_at</when><otherwise>ORDER BY id</otherwise></choose>
```

*Verifier:* likely — checked: OrderMapper.xml full file (#{} at :5,:8 bound; ${orderBy} at :9 raw), repo-wide grep for orderBy / OrderMapper callers (none outside mapper), injection FP trap #{} vs ${}. ${orderBy} is raw substitution, evidence correct. No Java caller in repo, so taint source and any allow-list are unknown. Keep as likely, low confidence.

### INJ-I-0029-1 — mongo_find.php uses GET login/pass directly in Mongo filter

- **Severity / confidence:** medium / high  
- **Status:** confirmed  
- **Category:** nosql_injection (operator_injection) — CWE-943 A03:2021  
- **Endpoint:** GET /php-plain/mongo_find.php  
- **Location:** `php-plain/mongo_find.php:5`

**Scenario.** A logged-in user sends array-style parameters with a not-equal operator so the credential check matches any member.

**Impact.** Credential check bypass; member data enumeration.

**Evidence.**

- `php-plain/mongo_find.php:5` — PHP turns pass[$ne]= into an array operator  
  `$doc = $coll->findOne(array('login' => $_GET['login'], 'pass' => $_GET['pass']));`

**Data flow.** $_GET['login'], $_GET['pass'] (mongo_find.php:5) → MongoCollection::findOne (mongo_find.php:5)

**Recommendation.** Cast both values to string (or reject arrays) and compare a password hash.

```
$doc = $coll->findOne(['login' => (string)$_GET['login']]); $ok = $doc && password_verify((string)$_GET['pass'], $doc['hash']);
```

*Verifier:* confirmed — checked: mongo_find.php:1-6 whole file, inc/auth.php login required, no (string) cast / is_string check on login or pass, use of $doc after :5. Operator injection is real (PHP parses pass[$ne]=x into an array; findOne executes immediately). But $doc is never used - there is no credential check that the bypass would defeat, and the page already requires login. Realistic impact is data probing / $regex ReDoS -> medium (injection-patterns §4). Attack scenario overstates impact.

### INJ-I-0037-1 — sp_search_orders builds and EXECs dynamic SQL from @Customer and @Sort

- **Severity / confidence:** medium / low  
- **Status:** likely  
- **Category:** sql_injection (stored_procedure_dynamic_sql) — CWE-89 A03:2021  
- **Endpoint:** - -  
- **Location:** `sql-procs/sp_search_orders.sql:5`

**Scenario.** If any application caller passes user input as @Customer or @Sort, that user can inject SQL even when the call itself is parameterized.

**Impact.** Read/modify data with the proc owner's rights; stacked statements possible.

**Evidence.**

- `sql-procs/sp_search_orders.sql:5` — @Customer concatenated in quotes without REPLACE/QUOTENAME; @Sort raw identifier  
  `SET @sql = 'SELECT * FROM Orders WHERE Customer = ''' + @Customer + ''' ORDER BY ' + @Sort`
- `sql-procs/sp_search_orders.sql:6` — dynamic SQL sink inside the DB; caller-side binding does not protect it  
  `EXEC(@sql)`

**Data flow.** @Customer, @Sort (proc parameters, caller unknown) → @sql (sp_search_orders.sql:5) → EXEC (sp_search_orders.sql:6)

**Recommendation.** Use sp_executesql with @Customer as a parameter and map @Sort through an allow-list (or QUOTENAME on an allowed column).

```
EXEC sp_executesql N'SELECT * FROM Orders WHERE Customer = @c ORDER BY ' + QUOTENAME(@SortAllowed), N'@c NVARCHAR(100)', @c=@Customer
```

*Verifier:* likely — checked: sql-procs/sp_search_orders.sql:1-7 (no REPLACE/QUOTENAME/allow-list), repo-wide grep for callers of sp_search_orders (none), auth-model §6 (no caller, DB permissions unknown). Dynamic EXEC with both params concatenated is real. Reachability from HTTP is unproven (no caller in repo), so severity stays medium with low confidence until callers are found.

### BOLA-R-0011-1 — Order detail loaded by query id without owner filter (owner-bound command never executed)

- **Severity / confidence:** low / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **Endpoint:** ANY /Orders/OrderDetail.aspx  
- **Location:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10`

**Scenario.** User A sends GET /Orders/OrderDetail.aspx?id=<order id of user B>; B's order row is loaded with no ownership check.

**Impact.** Read other customers' orders, if the reader result is rendered (rendering not visible in repo).

**Evidence.**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10` — ID from query string  
  `string id = Request.QueryString["id"];`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13` — Executed query (line 15) has no UserId filter  
  `var cmd = new SqlCommand("SELECT * FROM Orders WHERE OrderId = " + id, conn);`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:16` — Owner-bound command is built but never executed  
  `var safe = new SqlCommand("SELECT * FROM Orders WHERE OrderId = @id AND UserId = @uid", conn);`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx:2` — Page has an address label; its population is not visible in repo  
  `<asp:Label ID="lblAddress" runat="server" />`

**Data flow.** Request.QueryString["id"] (OrderDetail.aspx.cs:10) → SELECT * FROM Orders WHERE OrderId = <id> (OrderDetail.aspx.cs:13) → ExecuteReader (OrderDetail.aspx.cs:15)

**Recommendation.** Execute the parameterized owner-bound command (line 16-18) instead of cmd; return 404 when no row.

```
var r = safe.ExecuteReader(); if (!r.Read()) { Response.StatusCode = 404; return; }
```

*Verifier:* confirmed — checked: OrderDetail.aspx.cs:10-22 (full method), use of reader r after :15 (none; local variable goes out of scope), safe command :16-18 (never executed), OrderDetail.aspx:2 lblAddress (never assigned in visible code), Web.config:5 login required. No owner filter on the executed query, but the result r is never read or returned and lblAddress is never set. Per bola-patterns §6, an unexposed read is low; downgraded from high. Becomes high if output code is added. lines 19-20 (sql2, sql3) are built but never executed: not findings.

### BOLA-R-0024-2 — Order loaded by request id without owner filter (line 13) on unauthenticated CGI

- **Severity / confidence:** low / high  
- **Status:** confirmed  
- **Category:** bola (no_authentication) — CWE-306, CWE-639 API1:2023, API2:2023  
- **Endpoint:** GET /perl-cgi/cgi-bin/order.cgi  
- **Location:** `perl-cgi/cgi-bin/order.cgi:11`

**Scenario.** Anonymous client sends GET /cgi-bin/order.cgi?id=<any order id>; the order row is fetched with no owner check.

**Impact.** Unrestricted order read. Visible code never fetches/prints rows (only $q->header at :20), so actual exposure depends on code not shown. The :16-17 query is owner-bound; with undef $uid it matches no rows (user_id = NULL).

**Evidence.**

- `perl-cgi/cgi-bin/order.cgi:11` — ID from query or POST body  
  `my $id = $q->param('id');`
- `perl-cgi/cgi-bin/order.cgi:13` — Executed (:14) with id only; the owner-bound variant is the separate query at :16-17  
  `my $sth = $dbh->prepare("SELECT * FROM orders WHERE id = $id");`

**Recommendation.** Remove the unbound query at :13 and use only the bound query at :16-17 after checking $uid is defined.

```
my $sth = $dbh->prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?'); $sth->execute($id, $uid);
```

*Verifier:* confirmed — checked: order.cgi:11-14 id from request, query executed with id only, order.cgi:16-17 owner-bound variant (separate statement, does not guard :13), order.cgi:14-20 whether $sth result is fetched or printed, CGI::Session login behavior (auth-model §2), no .htaccess in repo. No owner filter at :13, but $sth is never fetched; the script prints only $q->header (:20). Per bola-patterns §6, a read whose result is not exposed is low (raise for no-auth already capped by non-exposure). Attack scenario overstates: the order row is not returned to the client. :13 is also an SQLi sink (interpolated $id) - separate category.

### BOLA-R-0028-1 — Any logged-in user can load any user record via admin.php?action=view&uid=

- **Severity / confidence:** low / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **Endpoint:** GET /php-plain/admin.php?action=view  
- **Location:** `php-plain/admin.php:5`

**Scenario.** Ordinary user requests /admin.php?action=view&uid=<other user id> and the admin view loads that user's record.

**Impact.** Read other users' account data (personal data, possibly credentials). Visible code does not render $r, so exposure depends on code not shown. Admin page lacks any role check (function-level gap too).

**Evidence.**

- `php-plain/inc/auth.php:4` — Login check only; no role check anywhere (auth-model §3)  
  `if (empty($_SESSION['user_id'])) {`
- `php-plain/admin.php:7` — Target user id from query string (cast only prevents SQLi)  
  `$uid = (int)$_GET['uid'];`
- `php-plain/admin.php:8` — Loads any user row; no admin role or self check  
  `$r = mysql_query("SELECT * FROM users WHERE id = " . $uid);`

**Recommendation.** Enforce an admin role check (from session) at the top of admin.php and exit on failure; if non-admins may view, restrict to uid = $_SESSION['user_id'].

```
if (empty($_SESSION['is_admin'])) { http_response_code(403); exit; }
```

*Verifier:* confirmed — checked: inc/auth.php:4-7 login only, admin.php:6-9 uid from GET, query by id only, admin.php:8-14 whether $r is fetched or output. No role or self check, but $r is never fetched or echoed; the script ends after the switch (:14). Per bola-patterns §6 an unexposed read is low. Attack scenario claim that the record is shown is not supported by the code. Subtype better classed missing_role_check / id_from_request_used_as_identity.

### BOLA-R-0030-1 — mongo_find.php queries any member record by request-supplied login/name, not bound to session user

- **Severity / confidence:** low / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023  
- **Endpoint:** GET /mongo_find.php  
- **Location:** `php-plain/mongo_find.php:5`

**Scenario.** A logged-in user sends GET /mongo_find.php?n=<other member name> (or login=<victim>&pass[$ne]=x). The other member's record is loaded. In the visible file the result is not echoed, so no data is returned today.

**Impact.** No exposure in the visible code (results unused). If this file is included elsewhere or completed later to output $doc/$docs, other members' records (including password field) would leak. Main risk here is the NoSQL injection, handled by the injection auditor.

**Evidence.**

- `php-plain/mongo_find.php:2` — Login check only (inc/auth.php:2-7 says so); no ownership logic  
  `require_once 'inc/auth.php';`
- `php-plain/mongo_find.php:5` — Member selected by request login+pass; not bound to $_SESSION['user_id']  
  `$doc = $coll->findOne(array('login' => $_GET['login'], 'pass' => $_GET['pass']));`
- `php-plain/mongo_find.php:6` — Members selected by request name; no session binding  
  `$docs = $coll->find(array('$where' => "this.name == '" . $_GET['n'] . "'"));`

**Data flow.** $_GET login/pass/n (mongo_find.php:5-6) → shop.members findOne/find (mongo_find.php:5-6) → results assigned to $doc/$docs, never output in visible code

**Recommendation.** Confirm the intended purpose of this page. If it returns member data, restrict lookups to the session user (_id = $_SESSION['user_id']) or an enforced admin role; cast inputs to strings and drop $where.

```
$doc = $coll->findOne(array('_id' => new MongoId($_SESSION['user_id'])));
```

*Verifier:* likely — checked: php-plain/mongo_find.php:1-6 (whole file), php-plain/inc/auth.php:2-7 (login only), repo-wide grep for includes of mongo_find.php (none), post-query use of $doc/$docs (none). Evidence lines match. No ownership filter on members lookups, but neither $doc nor $docs is output or used anywhere, and no file includes this page. Line 5 is a credential lookup (login+pass), closer to an auth flow than BOLA. Per bola-patterns §6 an unexposed read is low. Real risk is the NoSQL injection at :5-6 (operator/$where), owned by the injection finding.

## 4. Systemic fixes

1. **Mandatory parameter binding in all data access code** — effort **M** per sub-application. Replace concatenated or interpolated SQL/HQL with bound parameters (`PreparedStatement`, `SqlParameter`, PDO/CI bindings, `cfqueryparam`, DBI placeholders, driver placeholders, `#{}` in MyBatis). Add a code-review or lint rule that rejects string-built queries. Closes: INJ-I-0002-1, INJ-I-0003-1, INJ-I-0004-1, INJ-I-0006-1, INJ-I-0007-1, INJ-I-0008-1, INJ-I-0009-1, INJ-I-0011-1, INJ-I-0014-1, INJ-I-0016-1, INJ-I-0017-1, INJ-I-0018-1, INJ-I-0020-1, INJ-I-0021-1, INJ-I-0024-1, INJ-I-0025-1, INJ-I-0026-1, INJ-I-0028-1, INJ-I-0031-1, INJ-I-0032-1, INJ-I-0034-1, INJ-I-0036-1.
2. **Allowlists for identifiers, and binding inside stored procedures** — effort **S**. Map sort and column inputs to a fixed list of allowed names; never pass them through as text. Rewrite dynamic `EXEC(@sql)` to use `sp_executesql` with parameters and `QUOTENAME` for allowlisted identifiers. Closes: INJ-I-0015-1, INJ-I-0033-1, INJ-I-0037-1.
3. **Safe NoSQL query construction** — effort **S**. Cast filter inputs to scalar strings or ObjectIds, reject operator keys (`$`-prefixed) from request bodies, and remove `$where` JavaScript filters. Closes: INJ-I-0022-1, INJ-I-0023-1, INJ-I-0029-1, INJ-I-0030-1.
4. **One owner-scoped data access helper per sub-application, plus identity from session only** — effort **M–L**. Load every user-owned object through a helper that adds the session-bound owner column (for example `findByIdAndOwner(id, currentUser)`) and stops with 403/404 on mismatch. Take the acting user id only from the session, never from request or hidden fields. Add an explicit admin role check to admin functions. Closes: BOLA-R-0001-1, BOLA-R-0002-1, BOLA-R-0003-1, BOLA-R-0005-1, BOLA-R-0006-1, BOLA-R-0008-1, BOLA-R-0010-1, BOLA-R-0011-1, BOLA-R-0012-1, BOLA-R-0014-1, BOLA-R-0016-1, BOLA-R-0018-1, BOLA-R-0020-1, BOLA-R-0022-1, BOLA-R-0025-1, BOLA-R-0027-1, BOLA-R-0028-1, BOLA-R-0029-1, BOLA-R-0030-1, BOLA-R-0031-1, BOLA-R-0034-1; ownership part of BOLA-R-0004-1, BOLA-R-0009-1, BOLA-R-0013-1, BOLA-R-0017-1, BOLA-R-0024-1, BOLA-R-0024-2.
5. **Default-deny authentication at each application entry point** — effort **S–M**. Map the Java login filter to `/*`, remove `<allow users="*"/>` for `Handlers`, require login in remote CFCs (or `Application.cfc`), add a real session check to `order.cgi`, and register the Node login middleware at router level with explicit public exceptions. Closes: BOLA-R-0023-1; together with fix 4 closes BOLA-R-0004-1, BOLA-R-0009-1, BOLA-R-0013-1, BOLA-R-0017-1, BOLA-R-0024-1, BOLA-R-0024-2. It also removes anonymous reachability of INJ-I-0006-1, INJ-I-0014-1, INJ-I-0018-1, INJ-I-0021-1, INJ-I-0024-1 and INJ-I-0025-1, but does not fix them; fix 1 is still required.

## 5. Coverage and limitations

- missing from inventory: 0
- bola routes without verdict: 0
- injection candidates without verdict: 0
- findings without verification: 0

- **Results are AI-generated.** All findings, severities and recommendations come from automated pre-scan plus AI agents and an AI verifier. They require human review and sign-off before use or distribution.
- **Static review only.** No application, test or request was run. Exploitability, database privileges and stacked-query behaviour are not confirmed by testing.
- **Code missing from the repository.** Security-relevant helpers and configuration are referenced but absent: `LoginFilter`, `InvoiceDao`, `DataSourceHolder`, `ActionServlet`/`DispatcherServlet` wiring, `BasePage`, `CurrentUserId()`, `ShopDb`, `DocStore.PathFor`, `Global.asax`, `MY_Controller`, CodeIgniter routes/hooks, the Node app entry, `../db`, `../models/order`, Flask `db` and `user_loader`, and ColdFusion `Application.cfc` (auth-model.md §6). Findings that depend on them have `medium` or `low` confidence. The two rejected findings (Appendix A) should be reopened if `CurrentUserId()` or `InvoiceDao` prove unsafe.
- **External controls not visible.** IIS, Apache (`.htaccess`), ColdFusion Administrator, API gateway, WAF and database row-level security or permissions were not reviewed. They may reduce or change exposure.
- **Stored procedures and unwired code.** Only one stored procedure (`sp_search_orders`) was in the repository, and it has no caller in the repository. The MyBatis mapper `OrderMapper.xml` also has no visible caller. Other database-side code was not reviewed.
- **Coverage.** 36 endpoints were inventoried; 34 were audited for BOLA. `/search` (Flask) and `/search.php` were reviewed for injection only, as public catalog searches. Reachability of Struts and Spring URLs is unknown because servlet wiring is absent. Paths matching the configured excludes (for example `vendor/`, `node_modules/`, `test/`, `tests/`, `docs/`, `*.min.js`) were not scanned. Dynamic includes were not resolved.
- **Status `likely`.** 23 findings are `likely`, not `confirmed`. No item is `needs_review`, although the BOLA auditor flagged BOLA-R-0030-1 for review before the verifier rated it `likely`.
- **Out of scope.** Agents noted, but did not investigate: reflected XSS (`detail.jsp:7`, `order.cfm:10`), a possible path traversal in `GetFile.ashx` via `DocStore.PathFor`, a state-changing DELETE over GET (`member.asp:10`), credentials in a GET query string, and an implied plaintext password comparison (`mongo_find.php:5`).

## Appendix A — Findings rejected by the verifier

| ID | Location | Reason |
|---|---|---|
| BOLA-R-0007-1 | `dotnet-legacy/Web/Controllers/InvoiceController.cs:17` | Owner-bound query plus stop on mismatch (:20-21). The claimed bypass has no supporting code: nothing shows CurrentUserId() reads request data. Residual: reviewer should confirm CurrentUserId() source (not in repo); reopen only if it reads request input. |
| BOLA-R-0015-1 | `java-legacy/src/com/acme/web/InvoiceController.java:21` | No evidence of a flaw: the object id is paired with a server-side Principal and passed to an owner-scoped lookup. The only argument is that the DAO source is missing. Rejected by name with medium confidence; reopen if InvoiceDao source shows no owner predicate. |

## Appendix B — Method

1. Deterministic pre-scan (stack detection, endpoint candidates, query-building candidates).
2. AI agents: auth-model extraction, route inventory, BOLA audit, injection audit.
3. Independent AI verifier tries to refute each finding.
4. Human review and sign-off (`review-log.md`).

This is not a penetration test. Absence of findings does not prove absence of vulnerabilities.
