# Security Audit Report — repo

> **Classification: CONFIDENTIAL.** AI-assisted static review. All findings require human review (record decisions in `review-log.md`, created from `templates/review-log.md`) before they are shared outside the team.

| Item | Value |
|---|---|
| Date | 2026-10-31 |
| Kit version | 0.3.1 |
| Scope | BOLA/IDOR; SQL/HQL/NoSQL queries built from input; BFLA (missing role checks); mass assignment |
| Stacks | php, php-codeigniter, php-laravel, java-servlet, java-jsp, java-struts1, java-spring-mvc, java-mybatis, java-hibernate, dotnet-webforms, dotnet-handlers, dotnet-mvc, classic-asp, perl-cgi, coldfusion, node-express, python-flask, sql-procedures |
| Endpoints inventoried | 74 (candidates: 74) |
| Endpoints audited for BOLA | 74 |
| Injection candidates reviewed | 38 |
| Privileged routes audited for BFLA | 0 |
| Mass assignment candidates reviewed | 15 |

## 1. Executive summary

<!-- LLM: reporter agent writes max 8 bullets here -->

## 2. Findings overview

| Severity | critical | high | medium | low | info |
|---|---|---|---|---|---|
| Count | 50 | 43 | 6 | 0 | 0 |

| Category | Count |
|---|---|
| bola | 42 |
| sql_injection | 30 |
| nosql_injection | 5 |
| bfla | 12 |
| mass_assignment | 10 |

Status: unverified=0, confirmed=57, likely=42, rejected=2, needs_review=0

## Trend and time to fix

| Date | Open | New | Regressed | Fixed | Suppressed |
|---|---|---|---|---|---|
| 2026-10-31 | 99 | 99 | 0 | 0 | 0 |

No findings fixed yet.

## 3. Findings

| ID | Sev | Conf | Status | Category | Endpoint | Location | Title |
|---|---|---|---|---|---|---|---|
| BFLA-R-0003-1 | critical | high | confirmed | bfla |   | `classic-asp/shop/member.asp:9` | Unrestricted member deletion in classic‑ASP |
| BFLA-R-0007-1 | critical | high | confirmed | bfla |   | `dotnet-legacy/Web/Controllers/AdminController.cs:12` | Unrestricted user deletion in ASP.NET MVC |
| BFLA-R-0009-1 | critical | high | confirmed | bfla |   | `dotnet-legacy/Web/Controllers/AdminController.cs:30` | Export endpoint controlled by request parameter |
| BFLA-R-0023-1 | critical | medium | likely | bfla |   | `java-legacy/src/com/acme/web/AdminUserController.java:13` | Unrestricted user deletion in Spring MVC |
| BFLA-R-0030-1 | critical | medium | likely | bfla |   | `node-express/routes/admin.js:8` | Unrestricted user deletion in Express.js |
| BFLA-R-0032-1 | critical | medium | likely | bfla |   | `node-express/routes/admin.js:16` | Export endpoint controlled by query parameter in Express.js |
| BFLA-R-0057-1 | critical | medium | likely | bfla |   | `php-plain/admin.php:6` | Unrestricted user view in PHP |
| BFLA-R-0058-1 | critical | medium | likely | bfla |   | `php-plain/admin.php:10` | Unrestricted user deletion in PHP |
| BFLA-R-0059-1 | critical | medium | likely | bfla |   | `php-plain/manage_users.php:1` | Client‑side admin check allows user deletion in PHP |
| BFLA-R-0063-1 | critical | medium | likely | bfla |   | `php-plain/profile.php:1` | Privilege escalation via role field in profile update |
| BFLA-R-0066-1 | critical | medium | likely | bfla |   | `php-plain/admin/delete_user.php:1` | Unrestricted user deletion in PHP |
| BFLA-R-0067-1 | critical | medium | likely | bfla |   | `php-plain/admin/promote.php:1` | Privilege escalation via role promotion in PHP |
| INJ-I-0001 | critical | high | confirmed | sql_injection |   | `classic-asp/shop/member.asp:6` | SQL Injection in classic-asp/shop/member.asp:6 |
| INJ-I-0002 | critical | high | confirmed | sql_injection |   | `classic-asp/shop/member.asp:7` | SQL Injection in classic-asp/shop/member.asp:7 |
| INJ-I-0003 | critical | high | confirmed | sql_injection |   | `classic-asp/shop/member.asp:10` | SQL Injection in classic-asp/shop/member.asp:10 |
| INJ-I-0004 | critical | high | confirmed | sql_injection |   | `classic-asp/shop/order.asp:6` | SQL Injection in classic-asp/shop/order.asp:6 |
| INJ-I-0006 | critical | high | confirmed | sql_injection |   | `coldfusion/app/OrderService.cfc:5` | SQL Injection in coldfusion/app/OrderService.cfc:5 |
| INJ-I-0007 | critical | high | confirmed | sql_injection |   | `coldfusion/app/order.cfm:3` | SQL Injection in coldfusion/app/order.cfm:3 |
| INJ-I-0008-1 | critical | medium | likely | sql_injection |   | `dotnet-legacy/Web/Controllers/InvoiceController.cs:28` | SQL Injection in dotnet-legacy/Web/Controllers/InvoiceController.cs:28 |
| INJ-I-0009 | critical | high | confirmed | sql_injection |   | `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7` | SQL Injection in dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7 |
| INJ-I-0010 | critical | high | confirmed | sql_injection |   | `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8` | SQL Injection in dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8 |
| INJ-I-0011-1 | critical | high | confirmed | sql_injection |   | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13` | SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13 |
| INJ-I-0011-3 | critical | high | confirmed | sql_injection |   | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13` | SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20 |
| INJ-I-0012 | critical | high | confirmed | sql_injection |   | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19` | SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19 |
| INJ-I-0013 | critical | high | confirmed | sql_injection |   | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20` | SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20 |
| INJ-I-0014 | critical | medium | likely | sql_injection |   | `java-legacy/WebContent/order/detail.jsp:5` | SQL Injection in java-legacy/WebContent/order/detail.jsp:5 |
| INJ-I-0015-1 | critical | medium | likely | sql_injection |   | `java-legacy/src/com/acme/mapper/OrderMapper.xml:9` | SQL Injection in java-legacy/src/com/acme/mapper/OrderMapper.xml:9 |
| INJ-I-0016 | critical | medium | likely | sql_injection |   | `java-legacy/src/com/acme/struts/EditUserAction.java:13` | SQL Injection in java-legacy/src/com/acme/struts/EditUserAction.java:13 |
| INJ-I-0017 | critical | medium | likely | sql_injection |   | `java-legacy/src/com/acme/web/InvoiceController.java:29` | SQL Injection in java-legacy/src/com/acme/web/InvoiceController.java:29 |
| INJ-I-0018-1 | critical | medium | likely | sql_injection |   | `java-legacy/src/com/acme/web/OrderServlet.java:15` | SQL Injection in java-legacy/src/com/acme/web/OrderServlet.java:15 |
| INJ-I-0020-1 | critical | medium | likely | sql_injection |   | `node-express/routes/orders.js:17` | SQL Injection in node-express/routes/orders.js:17 |
| INJ-I-0020-3 | critical | high | confirmed | nosql_injection |   | `node-express/routes/orders.js:17` | NoSQL Injection in node-express/routes/orders.js:25 |
| INJ-I-0020-4 | critical | high | confirmed | sql_injection |   | `node-express/routes/orders.js:17` | SQL Injection in node-express/routes/orders.js:29 |
| INJ-I-0021 | critical | high | confirmed | sql_injection |   | `node-express/routes/orders.js:29` | SQL Injection in node-express/routes/orders.js:29 |
| INJ-I-0022 | critical | high | confirmed | nosql_injection |   | `node-express/routes/orders.js:21` | NoSQL Injection in node-express/routes/orders.js:21 |
| INJ-I-0023 | critical | high | confirmed | nosql_injection |   | `node-express/routes/orders.js:25` | NoSQL Injection in node-express/routes/orders.js:25 |
| INJ-I-0024-1 | critical | high | confirmed | sql_injection |   | `perl-cgi/cgi-bin/order.cgi:13` | SQL Injection in perl-cgi/cgi-bin/order.cgi:13 |
| INJ-I-0025 | critical | high | confirmed | sql_injection |   | `perl-cgi/cgi-bin/order.cgi:19` | SQL Injection in perl-cgi/cgi-bin/order.cgi:19 |
| INJ-I-0026-1 | critical | high | confirmed | sql_injection |   | `php-codeigniter/application/controllers/Invoice.php:10` | SQL Injection in php-codeigniter/application/controllers/Invoice.php:10 |
| INJ-I-0028 | critical | high | confirmed | sql_injection |   | `php-plain/admin.php:12` | SQL Injection in php-plain/admin.php:12 |
| INJ-I-0029-2 | critical | high | confirmed | nosql_injection |   | `php-plain/mongo_find.php:5` | NoSQL Injection in php-plain/mongo_find.php:6 |
| INJ-I-0030 | critical | high | confirmed | nosql_injection |   | `php-plain/mongo_find.php:6` | NoSQL Injection in php-plain/mongo_find.php:6 |
| INJ-I-0031-1 | critical | high | confirmed | sql_injection |   | `php-plain/order_detail.php:6` | SQL Injection in php-plain/order_detail.php:6 |
| INJ-I-0032-1 | critical | high | confirmed | sql_injection |   | `php-plain/search.php:8` | SQL Injection in php-plain/search.php:7 |
| INJ-I-0032-2 | critical | high | confirmed | sql_injection |   | `php-plain/search.php:8` | SQL Injection in php-plain/search.php:12 |
| INJ-I-0036-1 | critical | high | confirmed | sql_injection |   | `python-flask/app.py:29` | SQL Injection in python-flask/app.py:29 |
| INJ-I-0037-1 | critical | high | confirmed | sql_injection |   | `sql-procs/sp_search_orders.sql:5` | SQL Injection in sql-procs/sp_search_orders.sql:5 |
| MASS-M-0003-1 | critical | medium | likely | mass_assignment |   | `java-legacy/src/com/acme/web/AccountController.java:14` | Unrestricted role binding in Spring MVC |
| MASS-M-0004-1 | critical | medium | likely | mass_assignment |   | `java-legacy/src/com/acme/web/AccountController.java:27` | Unrestricted role binding in Spring MVC (duplicate) |
| MASS-M-0005-1 | critical | medium | likely | mass_assignment |   | `java-legacy/src/com/acme/web/ProfileServlet.java:12` | Unrestricted role binding via BeanUtils in Java Servlet |
| BOLA-R-0001 | high | high | confirmed | bola | ANY /user/edit.do | `java-legacy/src/com/acme/struts/EditUserAction.java:10` | BOLA in ANY /user/edit.do: missing owner verification |
| BOLA-R-0002 | high | high | confirmed | bola | ANY /classic-asp/shop/member.asp?mode=edit | `classic-asp/shop/member.asp:6` | BOLA in ANY /classic-asp/shop/member.asp?mode=edit: missing owner verification |
| BOLA-R-0003 | high | high | confirmed | bola | ANY /classic-asp/shop/member.asp?mode=delete | `classic-asp/shop/member.asp:9` | BOLA in ANY /classic-asp/shop/member.asp?mode=delete: missing owner verification |
| BOLA-R-0004 | high | high | confirmed | bola | ANY /classic-asp/shop/order.asp | `classic-asp/shop/order.asp:5` | BOLA in ANY /classic-asp/shop/order.asp: missing owner verification on first query |
| BOLA-R-0005 | high | high | confirmed | bola | ANY /coldfusion/app/OrderService.cfc?method=getOrder | `coldfusion/app/OrderService.cfc:4` | BOLA in ANY /coldfusion/app/OrderService.cfc?method=getOrder: missing owner verification |
| BOLA-R-0006 | high | high | confirmed | bola | ANY /coldfusion/app/order.cfm | `coldfusion/app/order.cfm:2` | BOLA in ANY /coldfusion/app/order.cfm: missing owner verification on first query |
| BOLA-R-0007 | high | high | confirmed | bola | POST /Admin/DeleteUser | `dotnet-legacy/Web/Controllers/AdminController.cs:12` | BOLA in POST /Admin/DeleteUser: missing owner verification |
| BOLA-R-0009 | high | high | confirmed | bola | POST /Admin/Export | `dotnet-legacy/Web/Controllers/AdminController.cs:30` | BOLA in POST /Admin/Export: missing role check allows data exposure |
| BOLA-R-0010 | high | medium | likely | bola | POST /Customer/Edit | `dotnet-legacy/Web/Controllers/CustomerController.cs:12` | BOLA in POST /Customer/Edit: missing owner verification |
| BOLA-R-0011 | high | medium | likely | bola | POST /Customer/EditName | `dotnet-legacy/Web/Controllers/CustomerController.cs:20` | BOLA in POST /Customer/EditName: missing owner verification |
| BOLA-R-0012 | high | medium | likely | bola | POST /Customer/Refresh | `dotnet-legacy/Web/Controllers/CustomerController.cs:27` | BOLA in POST /Customer/Refresh: missing owner verification |
| BOLA-R-0013 | high | high | confirmed | bola | ANY /Invoice/Details | `dotnet-legacy/Web/Controllers/InvoiceController.cs:11` | BOLA in GET /Invoice/Details: missing owner verification |
| BOLA-R-0015 | high | high | confirmed | bola | POST /Invoice/Search | `dotnet-legacy/Web/Controllers/InvoiceController.cs:26` | BOLA in POST /Invoice/Search: missing owner verification |
| BOLA-R-0016 | high | high | confirmed | bola | ANY /dotnet-legacy/Web/Handlers/GetFile.ashx | `dotnet-legacy/Web/Handlers/GetFile.ashx:8` | BOLA in ANY /dotnet-legacy/Web/Handlers/GetFile.ashx: missing owner verification |
| BOLA-R-0017 | high | high | confirmed | bola | ANY /dotnet-legacy/Web/Orders/EditOrder.aspx | `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7` | BOLA in ANY /dotnet-legacy/Web/Orders/EditOrder.aspx.vb: missing owner verification |
| BOLA-R-0018 | high | high | confirmed | bola | ANY /dotnet-legacy/Web/Orders/OrderDetail.aspx | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10` | BOLA in ANY /dotnet-legacy/Web/Orders/OrderDetail.aspx.cs: missing owner verification |
| BOLA-R-0019 | high | high | confirmed | bola | ANY /java-legacy/WebContent/order/detail.jsp | `java-legacy/WebContent/order/detail.jsp:3` | BOLA in ANY /java-legacy/WebContent/order/detail.jsp: missing owner verification |
| BOLA-R-0020 | high | high | confirmed | bola | POST /account/save | `java-legacy/src/com/acme/web/AccountController.java:14` | BOLA in POST /account/save: missing owner verification |
| BOLA-R-0021 | high | high | confirmed | bola | POST /account/rename | `java-legacy/src/com/acme/web/AccountController.java:20` | BOLA in POST /account/rename: missing owner verification |
| BOLA-R-0022 | high | medium | likely | bola | PUT /account/api | `java-legacy/src/com/acme/web/AccountController.java:27` | BOLA in PUT /account/api: missing owner verification |
| BOLA-R-0023 | high | medium | likely | bola | POST /admin/users/{id}/delete | `java-legacy/src/com/acme/web/AdminUserController.java:13` | BOLA in POST /admin/users/{id}/delete: missing owner verification |
| BOLA-R-0025 | high | medium | likely | bola | GET /invoices/{id} | `java-legacy/src/com/acme/web/InvoiceController.java:15` | BOLA in GET /invoices/{id}: missing owner verification |
| BOLA-R-0027 | high | medium | likely | bola | GET /invoices/search | `java-legacy/src/com/acme/web/InvoiceController.java:27` | BOLA in GET /invoices/search: missing owner verification |
| BOLA-R-0028 | high | medium | likely | bola | GET /order/view | `java-legacy/src/com/acme/web/OrderServlet.java:11` | BOLA in GET /order/view: missing owner verification |
| BOLA-R-0029 | high | high | confirmed | bola | POST <see web.xml servlet-mapping> | `java-legacy/src/com/acme/web/ProfileServlet.java:9` | BOLA in POST /ProfileServlet: missing owner verification |
| BOLA-R-0030 | high | high | confirmed | bola | POST /admin/users/:id/delete | `node-express/routes/admin.js:8` | BOLA in POST /admin/users/:id/delete: missing owner verification |
| BOLA-R-0033 | high | high | confirmed | bola | GET /orders/:id | `node-express/routes/orders.js:8` | BOLA in GET /orders/:id: missing owner verification |
| BOLA-R-0038 | high | high | confirmed | bola | GET /stats | `node-express/routes/orders.js:28` | BOLA in GET /stats: missing owner verification |
| BOLA-R-0043 | high | high | confirmed | bola | ANY /perl-cgi/cgi-bin/order.cgi | `perl-cgi/cgi-bin/order.cgi:13` | BOLA in ANY /perl-cgi/cgi-bin/order.cgi: missing owner verification |
| BOLA-R-0044 | high | high | confirmed | bola | ANY /invoice/view/{id} | `php-codeigniter/application/controllers/Invoice.php:10` | BOLA in ANY /invoice/view/{id}: missing owner verification |
| BOLA-R-0046 | high | medium | likely | bola | ANY /invoice/update | `php-codeigniter/application/controllers/Invoice.php:23` | BOLA in ANY /invoice/update: missing owner verification |
| BOLA-R-0057-1 | high | medium | likely | bola | GET /php-plain/admin.php?action=view | `php-plain/admin.php:8` | BOLA in GET /php-plain/admin.php?action=view: missing admin authorization |
| BOLA-R-0057-2 | high | medium | likely | bola | POST /php-plain/admin.php?action=delete | `php-plain/admin.php:6` | BOLA in POST /php-plain/admin.php?action=delete: missing admin authorization |
| BOLA-R-0058-1 | high | medium | likely | bola | GET /php-plain/admin.php?action=view | `php-plain/admin.php:10` | BOLA in GET /php-plain/admin.php?action=view: missing admin authorization |
| BOLA-R-0058-2 | high | medium | likely | bola | POST /php-plain/admin.php?action=delete | `php-plain/admin.php:12` | BOLA in POST /php-plain/admin.php?action=delete: missing admin authorization |
| BOLA-R-0059-1 | high | high | confirmed | bola | POST /php-plain/manage_users.php | `php-plain/manage_users.php:6` | BOLA in POST /php-plain/manage_users.php: missing admin authorization |
| BOLA-R-0061-1 | high | medium | likely | bola | GET /php-plain/order_detail.php | `php-plain/order_detail.php:6` | BOLA in GET /php-plain/order_detail.php: missing ownership verification |
| BOLA-R-0066-1 | high | high | confirmed | bola | POST /php-plain/admin/delete_user.php | `php-plain/admin/delete_user.php:6` | BOLA in POST /php-plain/admin/delete_user.php: missing admin authorization |
| BOLA-R-0067-1 | high | high | confirmed | bola | POST /php-plain/admin/promote.php | `php-plain/admin/promote.php:6` | BOLA in POST /php-plain/admin/promote.php: missing admin authorization |
| BOLA-R-0069-1 | high | high | confirmed | bola | GET /orders/<int:order_id> | `python-flask/app.py:12` | BOLA in GET /orders/<int:order_id>: missing ownership verification |
| BOLA-R-0073 | high | medium | likely | bola | POST /users/<int:uid>/name | `python-flask/profile.py:16` | BOLA in POST /users/<uid>/name: missing owner verification |
| BOLA-R-0074 | high | medium | likely | bola | PATCH /users/<int:uid> | `python-flask/profile.py:24` | BOLA in PATCH /users/<uid>: missing owner verification |
| MASS-M-0009-1 | high | medium | likely | mass_assignment |   | `php-laravel/app/Http/Controllers/AccountController.php:23` | Team creation allows owner_id to be set by any user |
| MASS-M-0006-1 | medium | medium | likely | mass_assignment |   | `node-express/routes/profile.js:8` | Profile update binds entire request body to User model |
| MASS-M-0007-1 | medium | medium | likely | mass_assignment |   | `node-express/routes/profile.js:16` | Profile update binds entire request body to User model |
| MASS-M-0008-1 | medium | medium | likely | mass_assignment |   | `php-laravel/app/Http/Controllers/AccountController.php:13` | User registration binds entire request body to User model |
| MASS-M-0010-1 | medium | medium | likely | mass_assignment |   | `php-laravel/app/Http/Controllers/AccountController.php:36` | Team creation binds entire request body to Team model |
| MASS-M-0014-1 | medium | medium | likely | mass_assignment |   | `python-flask/profile.py:10` | User creation binds entire request JSON to User model |
| MASS-M-0015-1 | medium | medium | likely | mass_assignment |   | `python-flask/profile.py:27` | PATCH endpoint sets arbitrary attributes from request JSON |

### BFLA-R-0003-1 — Unrestricted member deletion in classic‑ASP

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `classic-asp/shop/member.asp:9`

**Impact.** Any authenticated user can delete any member record

**Evidence.**

- `classic-asp/shop/member.asp:10` — DELETE statement executed without admin check
- `classic-asp/shop/member.asp:1` — only session login check, no role verification

**Recommendation.** Add an admin role check before executing the DELETE

*Verifier:* confirmed — checked: classic-asp/shop/member.asp:1-10, classic-asp/shop/inc/auth.asp:1-3. The included auth.asp only verifies a logged‑in session; it does not enforce an admin role. The delete case uses the member_id from the query string without any role check.

### BFLA-R-0007-1 — Unrestricted user deletion in ASP.NET MVC

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Controllers/AdminController.cs:12`

**Impact.** Any authenticated user can delete any user account

**Evidence.**

- `dotnet-legacy/Web/Controllers/AdminController.cs:12` — DeleteUser action lacks [Authorize(Roles="Admin")]

**Recommendation.** Add [Authorize(Roles="Admin")] to DeleteUser action

*Verifier:* confirmed — checked: dotnet-legacy/Web/Controllers/AdminController.cs:6-12. The controller is marked with [Authorize], allowing any authenticated user. The DeleteUser action lacks a role restriction, so any authenticated user can delete any account.

### BFLA-R-0009-1 — Export endpoint controlled by request parameter

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bfla (role_from_request) — CWE-285   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Controllers/AdminController.cs:30`

**Impact.** Any authenticated user can export all user data

**Evidence.**

- `dotnet-legacy/Web/Controllers/AdminController.cs:32` — Request.QueryString["isAdmin"] == "true" allows export
- `dotnet-legacy/Web/Controllers/AdminController.cs:30` — no server‑side role check

**Recommendation.** Validate admin role from session before allowing export

*Verifier:* confirmed — checked: dotnet-legacy/Web/Controllers/AdminController.cs:30-34. Export logic relies solely on a request query string parameter. No server‑side role validation is performed, allowing any authenticated user to trigger the export.

### BFLA-R-0023-1 — Unrestricted user deletion in Spring MVC

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/web/AdminUserController.java:13`

**Impact.** Any authenticated user can delete any user

**Evidence.**

- `java-legacy/src/com/acme/web/AdminUserController.java:13` — delete method lacks @PreAuthorize
- `java-legacy/src/com/acme/web/AdminUserController.java:19` — other actions have @PreAuthorize, but not this one

**Recommendation.** Add @PreAuthorize("hasRole('ADMIN')") to delete method

*Verifier:* likely — checked: java-legacy/src/com/acme/web/AdminUserController.java lines 13-15, java-legacy/src/com/acme/web/AdminUserController.java lines 19-21. The delete method lacks any @PreAuthorize or other role guard in the visible code. No global filter or security configuration is shown in the provided context, so a compensating control cannot be confirmed.

### BFLA-R-0030-1 — Unrestricted user deletion in Express.js

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `node-express/routes/admin.js:8`

**Impact.** Any authenticated user can delete any user

**Evidence.**

- `node-express/routes/admin.js:8` — no requireAdmin middleware applied

**Recommendation.** Add requireAdmin middleware to the delete route

*Verifier:* likely — checked: node-express/routes/admin.js lines 8-9. The delete route uses only ensureLoggedIn; the requireAdmin middleware is not applied in the visible snippet, and no other role check is present.

### BFLA-R-0032-1 — Export endpoint controlled by query parameter in Express.js

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bfla (role_from_request) — CWE-285   
- **Endpoint:** - -  
- **Location:** `node-express/routes/admin.js:16`

**Impact.** Any authenticated user can export all user data

**Evidence.**

- `node-express/routes/admin.js:17` — req.query.isAdmin === 'true' allows export
- `node-express/routes/admin.js:16` — no role check before export

**Recommendation.** Validate admin role from session before allowing export

*Verifier:* likely — checked: node-express/routes/admin.js lines 16-18. The export endpoint checks only a query parameter for admin status; no session‑based role verification is shown in the snippet.

### BFLA-R-0057-1 — Unrestricted user view in PHP

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `php-plain/admin.php:6`

**Impact.** Any authenticated user can view any user record

**Evidence.**

- `php-plain/admin.php:6` — SELECT * FROM users WHERE id = ... executed without admin check
- `php-plain/admin.php:2` — only session login check, no role verification

**Recommendation.** Add admin role check before executing the SELECT

*Verifier:* likely — checked: php-plain/admin.php lines 2-8, php-plain/inc/auth.php lines 1-7. The included auth file performs only a login check; there is no admin role guard before the SELECT statement in the visible code.

### BFLA-R-0058-1 — Unrestricted user deletion in PHP

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `php-plain/admin.php:10`

**Impact.** Any authenticated user can delete any user record

**Evidence.**

- `php-plain/admin.php:10` — DELETE executed without admin check
- `php-plain/admin.php:2` — only session login check, no role verification

**Recommendation.** Add admin role check before executing the DELETE

*Verifier:* likely — checked: php-plain/admin.php lines 10-12, php-plain/inc/auth.php lines 1-7. The DELETE statement is executed without any admin role check in the visible code, and the included auth file does not provide such a guard.

### BFLA-R-0059-1 — Client‑side admin check allows user deletion in PHP

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bfla (client_side_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `php-plain/manage_users.php:1`

**Impact.** Any authenticated user can delete any user record

**Evidence.**

- `php-plain/manage_users.php:5` — DELETE executed without server‑side admin check
- `php-plain/manage_users.php:11` — role check only in HTML, not in handler

**Recommendation.** Add server‑side admin check before executing the DELETE

*Verifier:* likely — checked: php-plain/manage_users.php, php-plain/inc/auth.php, php-plain/inc/db.php. Deletion is performed on POST without a server‑side role check; the role check appears only in the HTML output.

### BFLA-R-0063-1 — Privilege escalation via role field in profile update

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bfla (role_from_request) — CWE-285   
- **Endpoint:** - -  
- **Location:** `php-plain/profile.php:1`

**Impact.** Any authenticated user can change their own role

**Evidence.**

- `php-plain/profile.php:10` — role set from $_POST['role'] without admin check
- `php-plain/profile.php:2` — only session login check, no role verification

**Recommendation.** Validate role changes against allowed values and enforce admin checks

*Verifier:* likely — checked: php-plain/profile.php, php-plain/inc/auth.php, php-plain/inc/db.php. The role field is updated directly from POST data with no admin verification in the visible code.

### BFLA-R-0066-1 — Unrestricted user deletion in PHP

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `php-plain/admin/delete_user.php:1`

**Impact.** Any authenticated user can delete any user record

**Evidence.**

- `php-plain/admin/delete_user.php:6` — DELETE executed without admin check
- `php-plain/admin/delete_user.php:2` — only session login check, no role verification

**Recommendation.** Add admin role check before executing the DELETE

*Verifier:* likely — checked: php-plain/admin/delete_user.php, php-plain/inc/auth.php, php-plain/inc/db.php. No role or ownership check is present in the visible code. The included auth file only verifies session existence.

### BFLA-R-0067-1 — Privilege escalation via role promotion in PHP

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bfla (role_from_request) — CWE-285   
- **Endpoint:** - -  
- **Location:** `php-plain/admin/promote.php:1`

**Impact.** Any authenticated user can promote themselves to admin

**Evidence.**

- `php-plain/admin/promote.php:5` — role set from $_POST['is_admin'] without admin check
- `php-plain/admin/promote.php:2` — only session login check, no role verification

**Recommendation.** Validate admin role from session before allowing role changes

*Verifier:* likely — checked: php-plain/admin/promote.php, php-plain/inc/auth.php, php-plain/inc/db.php. The code sets the role directly from POST data without any server‑side admin check. No compensating control is visible.

### INJ-I-0001 — SQL Injection in classic-asp/shop/member.asp:6

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `classic-asp/shop/member.asp:6`

**Evidence.**

- `classic-asp/shop/member.asp:6` — Unsanitized input concatenated into query (member_id later)  
  `sql = "UPDATE members SET name = '" & Replace(Request.Form("name"), "'", "''") & "'"`
- `classic-asp/shop/member.asp:7` — Unsanitized input concatenated into query  
  `sql = sql & " WHERE member_id = " & Request.Form("member_id")`
- `classic-asp/shop/member.asp:8` — Query executed without parameter binding  
  `conn.Execute sql`

**Recommendation.** Use parameterized queries

*Verifier:* confirmed — checked: classic-asp/shop/member.asp:6-8, classic-asp/shop/inc/auth.asp:1-3. The SQL UPDATE statement is built via string concatenation with unsanitized form values. The included auth.asp only verifies that a user is logged in; it does not provide parameter binding or sanitization.

### INJ-I-0002 — SQL Injection in classic-asp/shop/member.asp:7

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `classic-asp/shop/member.asp:7`

**Evidence.**

- `classic-asp/shop/member.asp:7` — Unsanitized input concatenated into query  
  `sql = sql & " WHERE member_id = " & Request.Form("member_id")`
- `classic-asp/shop/member.asp:8` — Query executed without parameter binding  
  `conn.Execute sql`

**Recommendation.** Use parameterized queries

*Verifier:* confirmed — checked: classic-asp/shop/member.asp:7-8, classic-asp/shop/inc/auth.asp:1-3. The WHERE clause is concatenated with an unsanitized form value. No parameter binding or integer cast is present.

### INJ-I-0003 — SQL Injection in classic-asp/shop/member.asp:10

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `classic-asp/shop/member.asp:10`

**Evidence.**

- `classic-asp/shop/member.asp:10` — Unsanitized input concatenated into query  
  `conn.Execute "DELETE FROM members WHERE member_id = " & Request.QueryString("member_id")`

**Recommendation.** Use parameterized queries

*Verifier:* confirmed — checked: classic-asp/shop/member.asp:10, classic-asp/shop/inc/auth.asp:1-3. The DELETE statement concatenates an unsanitized query string value. No sanitization or parameter binding is visible.

### INJ-I-0004 — SQL Injection in classic-asp/shop/order.asp:6

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `classic-asp/shop/order.asp:6`

**Evidence.**

- `classic-asp/shop/order.asp:6` — Unsanitized input concatenated into query  
  `Set rs = conn.Execute("SELECT * FROM orders WHERE id = " & id)`

**Recommendation.** Use parameterized queries

*Verifier:* confirmed — checked: classic-asp/shop/order.asp lines 5-6, classic-asp/shop/order.asp line 12. The query at line 6 concatenates the unsanitized request parameter directly into the SQL statement. No ownership check or parameter binding is performed before execution. The subsequent query at line 12 includes a user_id filter, but it does not mitigate the vulnerability in the first query.

### INJ-I-0006 — SQL Injection in coldfusion/app/OrderService.cfc:5

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `coldfusion/app/OrderService.cfc:5`

**Evidence.**

- `coldfusion/app/OrderService.cfc:5` — Unsanitized input concatenated into query  
  `SELECT * FROM orders WHERE id = #arguments.orderId#`

**Recommendation.** Use cfqueryparam to bind parameters

*Verifier:* confirmed — checked: coldfusion/app/OrderService.cfc lines 3-6. The query at line 5 directly interpolates the unvalidated argument `orderId` into the SQL string. No parameter binding, type casting, or ownership check is present.

### INJ-I-0007 — SQL Injection in coldfusion/app/order.cfm:3

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `coldfusion/app/order.cfm:3`

**Evidence.**

- `coldfusion/app/order.cfm:3` — Unsanitized input concatenated into query  
  `SELECT * FROM orders WHERE id = #url.id#`

**Recommendation.** Use cfqueryparam to bind parameters

*Verifier:* confirmed — checked: coldfusion/app/order.cfm lines 2-4. The query at line 3 concatenates the unsanitized `url.id` into the SQL statement. Although a subsequent query uses `cfqueryparam` and a user_id filter, the first query remains vulnerable.

### INJ-I-0008-1 — SQL Injection in dotnet-legacy/Web/Controllers/InvoiceController.cs:28

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Controllers/InvoiceController.cs:28`

**Evidence.**

- `dotnet-legacy/Web/Controllers/InvoiceController.cs:27` — source: POST body  
  `var customer = Request.Form["customer"];`
- `dotnet-legacy/Web/Controllers/InvoiceController.cs:28` — unsanitized concatenation  
  `var list = db.Database.SqlQuery<Invoice>("SELECT * FROM Invoices WHERE Customer = '" + customer + "'").ToList();`

**Recommendation.** Use parameterized queries

*Verifier:* likely — checked: dotnet-legacy/Web/Controllers/InvoiceController.cs lines 25-29 (Search action). No parameter binding, casting, or allow‑list is visible in the provided code context. The raw concatenation of `customer` into the SQL string remains a potential injection vector.

### INJ-I-0009 — SQL Injection in dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7`

**Evidence.**

- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7` — Unsanitized input concatenated into query  
  `Dim sql As String = "UPDATE Orders SET Note = '" & txtNote.Text & "'"`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8` — Unsanitized input concatenated into query  
  `sql &= " WHERE OrderId = " & hfOrderId.Value`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:10` — Query executed without parameter binding  
  `cmd.ExecuteNonQuery()`

**Recommendation.** Use parameterized queries

*Verifier:* confirmed — checked: dotnet-legacy/Web/Orders/EditOrder.aspx.vb lines 6-8. The SQL string is built by concatenating `txtNote.Text` and `hfOrderId.Value` without any parameterization or type casting. No ownership check is performed before execution.

### INJ-I-0010 — SQL Injection in dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8`

**Evidence.**

- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8` — Unsanitized input concatenated into query  
  `sql &= " WHERE OrderId = " & hfOrderId.Value`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:10` — Query executed without parameter binding  
  `cmd.ExecuteNonQuery()`

**Recommendation.** Use parameterized queries

*Verifier:* confirmed — checked: dotnet-legacy/Web/Orders/EditOrder.aspx.vb lines 7-8. Same as INJ-I-0009: the query is constructed via string concatenation with user-supplied values and executed without parameter binding or ownership validation.

### INJ-I-0011-1 — SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13`

**Evidence.**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13` — Unsanitized input concatenated into query  
  `var cmd = new SqlCommand("SELECT * FROM Orders WHERE OrderId = " + id, conn);`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:14` — Query executed without parameter binding  
  `conn.Open();`

**Recommendation.** Use parameterized queries

*Verifier:* confirmed — checked: line 13. The query at line 13 concatenates the unsanitized request parameter "id" directly into the SQL string and is executed immediately. No ownership, role check, integer cast, or allow‑list is present in the visible code.

### INJ-I-0011-3 — SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_interpolation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13`

**Evidence.**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20` — Unsanitized input concatenated into query  
  `string sql3 = $"DELETE FROM Carts WHERE CartId = {Request.Form["cart"]}";`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:22` — Query executed without parameter binding  
  `new SqlCommand(sql3, conn).ExecuteNonQuery();`

**Recommendation.** Use parameterized queries

*Verifier:* confirmed — checked: line 20. The interpolated string at line 20 directly injects the unsanitized form parameter "cart" into a DELETE statement, executed at line 22. No protection is evident.

### INJ-I-0012 — SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19`

**Evidence.**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19` — Unsanitized input concatenated into query  
  `string sql2 = string.Format("SELECT * FROM Logs WHERE Ref = '{0}'", Request["ref"]);`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:21` — Query executed without parameter binding  
  `new SqlCommand(sql2, conn).ExecuteReader();`

**Recommendation.** Use parameterized queries

*Verifier:* confirmed — checked: line 19. Same as INJ-I-0011-2: unsanitized "ref" is concatenated into SQL and executed without parameter binding.

### INJ-I-0013 — SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_interpolation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20`

**Evidence.**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20` — Unsanitized input concatenated into query  
  `string sql3 = $"DELETE FROM Carts WHERE CartId = {Request.Form["cart"]}";`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:22` — Query executed without parameter binding  
  `new SqlCommand(sql3, conn).ExecuteNonQuery();`

**Recommendation.** Use parameterized queries

*Verifier:* confirmed — checked: line 20. Duplicate finding ID; same issue as INJ-I-0011-3.

### INJ-I-0014 — SQL Injection in java-legacy/WebContent/order/detail.jsp:5

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `java-legacy/WebContent/order/detail.jsp:5`

**Evidence.**

- `java-legacy/WebContent/order/detail.jsp:5` — Unsanitized input concatenated into query  
  `ResultSet rs = c.createStatement().executeQuery("SELECT * FROM orders WHERE order_no = '" + no + "'");`

**Recommendation.** Use PreparedStatement with parameters

*Verifier:* likely — checked: java-legacy/WebContent/order/detail.jsp lines 1-7. The JSP page concatenates the request parameter directly into a SQL query without any parameter binding, casting, or ownership check visible in the provided code context.

### INJ-I-0015-1 — SQL Injection in java-legacy/src/com/acme/mapper/OrderMapper.xml:9

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (template_placeholder) — CWE-89   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/mapper/OrderMapper.xml:9`

**Evidence.**

- `java-legacy/src/com/acme/mapper/OrderMapper.xml:9` — raw string substitution unsanitized  
  `ORDER BY ${orderBy}`

**Recommendation.** Use parameterized queries or allow-list ORDER BY columns

*Verifier:* likely — checked: java-legacy/src/com/acme/mapper/OrderMapper.xml lines 8-10 (ORDER BY clause). The `${orderBy}` placeholder is substituted directly into the SQL string with no visible allow‑list or type enforcement in the provided snippet.

### INJ-I-0016 — SQL Injection in java-legacy/src/com/acme/struts/EditUserAction.java:13

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/struts/EditUserAction.java:13`

**Evidence.**

- `java-legacy/src/com/acme/struts/EditUserAction.java:13` — Unsanitized input concatenated into query  
  `PreparedStatement ps = conn.prepareStatement("UPDATE users SET email = '" + email + "' WHERE id = " + userId);`
- `java-legacy/src/com/acme/struts/EditUserAction.java:14` — Query executed without parameter binding  
  `ps.executeUpdate();`

**Recommendation.** Use PreparedStatement with parameters

*Verifier:* likely — checked: java-legacy/src/com/acme/struts/EditUserAction.java lines 1-17. The action builds an UPDATE statement by concatenating user-supplied values without using prepared statement parameters or any ownership verification in the visible code.

### INJ-I-0017 — SQL Injection in java-legacy/src/com/acme/web/InvoiceController.java:29

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/web/InvoiceController.java:29`

**Evidence.**

- `java-legacy/src/com/acme/web/InvoiceController.java:29` — Unsanitized input concatenated into query  
  `model.addAttribute("list", session.createQuery("from Invoice i where i.customer = '" + customer + "'").list());`

**Recommendation.** Use parameterized HQL/JPQL

*Verifier:* likely — checked: java-legacy/src/com/acme/web/InvoiceController.java lines 9-31. The controller concatenates the 'customer' request parameter into an HQL query without parameter binding or ownership checks in the shown snippet.

### INJ-I-0018-1 — SQL Injection in java-legacy/src/com/acme/web/OrderServlet.java:15

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/web/OrderServlet.java:15`

**Evidence.**

- `java-legacy/src/com/acme/web/OrderServlet.java:11` — source: request parameter  
  `String id = request.getParameter("orderId");`
- `java-legacy/src/com/acme/web/OrderServlet.java:15` — unsanitized concatenation  
  `ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE id = '" + id + "'");`

**Recommendation.** Use prepared statements

*Verifier:* likely — checked: java-legacy/src/com/acme/web/OrderServlet.java lines 13-15 (first query). The `id` parameter is concatenated into the SQL string without any casting or validation in the shown code.

### INJ-I-0020-1 — SQL Injection in node-express/routes/orders.js:17

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `node-express/routes/orders.js:17`

**Evidence.**

- `node-express/routes/orders.js:17` — Unsanitized input concatenated into query  
  `db.query("SELECT * FROM reports WHERE month = '" + req.query.month + "'", function (e, rows) { res.json(rows); });`

**Recommendation.** Use parameterized queries

*Verifier:* likely — checked: node-express/routes/orders.js lines 1-32. The route constructs a raw SQL query by concatenating req.query.month without any type casting, parameter binding, or ownership verification in the visible code.

### INJ-I-0020-3 — NoSQL Injection in node-express/routes/orders.js:25

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** nosql_injection (operator_injection) — CWE-89   
- **Endpoint:** - -  
- **Location:** `node-express/routes/orders.js:17`

**Evidence.**

- `node-express/routes/orders.js:25` — Unescaped string used in $where expression  
  `db.collection('items').find({ $where: "this.name == '" + req.query.n + "'" }).toArray(function (e, r) { res.json(r); });`

**Recommendation.** Avoid $where; use parameterized queries or safe operators

*Verifier:* confirmed — checked: lines 24-26 of node-express/routes/orders.js. The query concatenates user input into a $where expression with no sanitization or allow‑list. The only guard is ensureLoggedIn, which only verifies authentication, not ownership or input validation.

### INJ-I-0020-4 — SQL Injection in node-express/routes/orders.js:29

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_interpolation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `node-express/routes/orders.js:17`

**Evidence.**

- `node-express/routes/orders.js:29` — Unsanitized input interpolated into query  
  `db.query('SELECT COUNT(*) AS n FROM orders WHERE shop_id = ${req.query.shop}', function (e, r) { res.json(r); });`

**Recommendation.** Use parameterized queries

*Verifier:* confirmed — checked: lines 28-30 of node-express/routes/orders.js. The SQL statement interpolates req.query.shop directly into the query string. No cast, parameter binding, or ownership check is present.

### INJ-I-0021 — SQL Injection in node-express/routes/orders.js:29

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_interpolation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `node-express/routes/orders.js:29`

**Evidence.**

- `node-express/routes/orders.js:29` — Unsanitized input interpolated into query  
  `db.query('SELECT COUNT(*) AS n FROM orders WHERE shop_id = ${req.query.shop}', function (e, r) { res.json(r); });`

**Recommendation.** Use parameterized queries

*Verifier:* confirmed — checked: lines 28-30 of node-express/routes/orders.js. Same as INJ-I-0020-4; the route is identical and lacks any compensating control.

### INJ-I-0022 — NoSQL Injection in node-express/routes/orders.js:21

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** nosql_injection (operator_injection) — CWE-89   
- **Endpoint:** - -  
- **Location:** `node-express/routes/orders.js:21`

**Evidence.**

- `node-express/routes/orders.js:21` — Unvalidated request body used directly as query filter  
  `db.collection('users').findOne(req.body, function (e, u) { res.json(!!u); });`

**Recommendation.** Validate and whitelist query parameters; avoid passing raw request body to findOne

*Verifier:* confirmed — checked: lines 20-22 of node-express/routes/orders.js. The request body is passed directly to findOne without validation or sanitization. No authentication guard is applied to this POST /login route.

### INJ-I-0023 — NoSQL Injection in node-express/routes/orders.js:25

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** nosql_injection (operator_injection) — CWE-89   
- **Endpoint:** - -  
- **Location:** `node-express/routes/orders.js:25`

**Evidence.**

- `node-express/routes/orders.js:25` — Unescaped string used in $where expression  
  `db.collection('items').find({ $where: "this.name == '" + req.query.n + "'" }).toArray(function (e, r) { res.json(r); });`

**Recommendation.** Avoid $where; use parameterized queries or safe operators

*Verifier:* confirmed — checked: lines 24-26 of node-express/routes/orders.js. Identical to INJ-I-0020-3; no sanitization or allow‑list is present.

### INJ-I-0024-1 — SQL Injection in perl-cgi/cgi-bin/order.cgi:13

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `perl-cgi/cgi-bin/order.cgi:13`

**Evidence.**

- `perl-cgi/cgi-bin/order.cgi:13` — Unsanitized input concatenated into query  
  `my $sth = $dbh->prepare("SELECT * FROM orders WHERE id = $id");`

**Recommendation.** Use parameterized queries

*Verifier:* confirmed — checked: perl-cgi/cgi-bin/order.cgi line 13, perl-cgi/cgi-bin/order.cgi line 11-14. The query concatenates the unsanitized $id directly into the SQL string. No integer cast, parameter binding, or ownership check is present in the visible code.

### INJ-I-0025 — SQL Injection in perl-cgi/cgi-bin/order.cgi:19

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `perl-cgi/cgi-bin/order.cgi:19`

**Evidence.**

- `perl-cgi/cgi-bin/order.cgi:19` — Unsanitized input concatenated into query  
  `$dbh->do("DELETE FROM carts WHERE cart_id = " . $q->param('cart'));`

**Recommendation.** Use parameterized queries

*Verifier:* confirmed — checked: perl-cgi/cgi-bin/order.cgi line 19, perl-cgi/cgi-bin/order.cgi line 18-20. Same as INJ-I-0024-2; unsanitized input used in a DELETE statement with no protection.

### INJ-I-0026-1 — SQL Injection in php-codeigniter/application/controllers/Invoice.php:10

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-codeigniter/application/controllers/Invoice.php:10`

**Evidence.**

- `php-codeigniter/application/controllers/Invoice.php:9` — source: URL segment  
  `$id = $this->uri->segment(3);`
- `php-codeigniter/application/controllers/Invoice.php:10` — unsanitized concatenation  
  `$q = $this->db->query("SELECT * FROM invoices WHERE id = $id");`

**Recommendation.** Use parameterized queries

*Verifier:* confirmed — checked: php-codeigniter/application/controllers/Invoice.php:9-10. The query concatenates the raw $id parameter without any sanitization, casting, or parameter binding. No ownership or role check is present in the visible code.

### INJ-I-0028 — SQL Injection in php-plain/admin.php:12

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-plain/admin.php:12`

**Evidence.**

- `php-plain/admin.php:12` — Unsanitized input concatenated into query  
  `mysql_query("DELETE FROM users WHERE id = $id");`

**Recommendation.** Use parameterized queries

*Verifier:* confirmed — checked: php-plain/admin.php line 12, php-plain/admin.php lines 5-13. The DELETE query uses the raw $_POST['id'] value. No cast, parameter binding, or ownership check is present. The included auth.php only verifies login, not admin role.

### INJ-I-0029-2 — NoSQL Injection in php-plain/mongo_find.php:6

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** nosql_injection (operator_injection) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-plain/mongo_find.php:5`

**Evidence.**

- `php-plain/mongo_find.php:6` — Unescaped string used in $where expression  
  `$docs = $coll->find(array('$where' => "this.name == '" . $_GET['n'] . "'"));`

**Recommendation.** Avoid $where; use parameterized queries or safe operators

*Verifier:* confirmed — checked: php-plain/mongo_find.php line 6, php-plain/mongo_find.php lines 1-6. The $where expression concatenates the unsanitized $_GET['n'] value. No sanitization or ownership check is visible.

### INJ-I-0030 — NoSQL Injection in php-plain/mongo_find.php:6

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** nosql_injection (operator_injection) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-plain/mongo_find.php:6`

**Evidence.**

- `php-plain/mongo_find.php:6` — Unescaped string used in $where expression  
  `$docs = $coll->find(array('$where' => "this.name == '" . $_GET['n'] . "'"));`

**Recommendation.** Avoid $where; use parameterized queries or safe operators

*Verifier:* confirmed — checked: php-plain/mongo_find.php, php-plain/inc/auth.php. The query concatenates user input into a $where expression with no sanitisation or ownership check. The included auth file only verifies login, not object ownership.

### INJ-I-0031-1 — SQL Injection in php-plain/order_detail.php:6

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-plain/order_detail.php:6`

**Evidence.**

- `php-plain/order_detail.php:5` — source: GET parameter  
  `$id = $_GET['id'];`
- `php-plain/order_detail.php:6` — unsanitized input concatenated into query  
  `$res = mysql_query("SELECT * FROM orders WHERE id = " . $id);`

**Recommendation.** Use parameterized queries

*Verifier:* confirmed — checked: php-plain/order_detail.php, php-plain/inc/auth.php. The SQL statement concatenates the GET id directly. No ownership or role guard is present in the visible code.

### INJ-I-0032-1 — SQL Injection in php-plain/search.php:7

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-plain/search.php:8`

**Evidence.**

- `php-plain/search.php:5` — source: GET parameter  
  `$kw = addslashes($_GET['q']);`
- `php-plain/search.php:6` — source: GET parameter  
  `$sort = $_GET['sort'];`
- `php-plain/search.php:7` — query start  
  `$sql = "SELECT id, name FROM products WHERE 1=1";`
- `php-plain/search.php:8` — unsanitized input concatenated  
  `$sql .= " AND name LIKE '%" . $kw . "%'";`
- `php-plain/search.php:9` — unsanitized ORDER BY  
  `$sql .= " ORDER BY " . $sort;`
- `php-plain/search.php:11` — sink  
  `$res = mysql_query($sql);`

**Recommendation.** Use parameterized queries and allow-list ORDER BY

*Verifier:* confirmed — checked: php-plain/search.php, php-plain/inc/auth.php, php-plain/inc/db.php. Both the keyword and ORDER BY values are unsanitised and no allow‑list or ownership check is visible.

### INJ-I-0032-2 — SQL Injection in php-plain/search.php:12

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_interpolation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-plain/search.php:8`

**Evidence.**

- `php-plain/search.php:14` — unsanitized interpolation  
  `WHERE category = '{$_GET['cat']}'`
- `php-plain/search.php:16` — sink  
  `$res2 = mysql_query($q);`

**Recommendation.** Use parameterized queries

*Verifier:* confirmed — checked: php-plain/search.php, php-plain/inc/auth.php, php-plain/inc/db.php. The interpolated category value is used directly in the query with no sanitisation or ownership guard.

### INJ-I-0036-1 — SQL Injection in python-flask/app.py:29

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_interpolation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `python-flask/app.py:29`

**Evidence.**

- `python-flask/app.py:27` — source: query parameter  
  `q = request.args.get('q', '')`
- `python-flask/app.py:29` — unsanitized interpolation  
  `cur.execute(f"SELECT * FROM products WHERE name LIKE '%{q}%'")`

**Recommendation.** Use parameterized queries

*Verifier:* confirmed — checked: python-flask/app.py. The f‑string interpolates the query parameter directly into the SQL. The @login_required decorator only ensures authentication, not ownership or parameter validation.

### INJ-I-0037-1 — SQL Injection in sql-procs/sp_search_orders.sql:5

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (stored_procedure_dynamic_sql) — CWE-89   
- **Endpoint:** - -  
- **Location:** `sql-procs/sp_search_orders.sql:5`

**Evidence.**

- `sql-procs/sp_search_orders.sql:5` — unsanitized dynamic SQL  
  `SET @sql = 'SELECT * FROM Orders WHERE Customer = ''' + @Customer + ''' ORDER BY ' + @Sort`
- `sql-procs/sp_search_orders.sql:6` — sink  
  `EXEC(@sql)`

**Recommendation.** Use sp_executesql with parameters

*Verifier:* confirmed — checked: sql-procs/sp_search_orders.sql:5-6. Dynamic SQL is built by concatenating @Customer and @Sort directly into the statement. No allow‑list, integer cast, or parameterized execution is visible.

### MASS-M-0003-1 — Unrestricted role binding in Spring MVC

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** mass_assignment (privileged_field_writable) — CWE-915   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/web/AccountController.java:14`

**Impact.** Any authenticated user can set the role field of an Account

**Evidence.**

- `java-legacy/src/com/acme/web/AccountController.java:14` — Location taken from the Tier 1 inventory

**Recommendation.** Bind only allowed fields or set role server‑side

*Verifier:* likely — checked: java-legacy/src/com/acme/web/AccountController.java. The controller accepts a full Account model via @ModelAttribute and persists it without any field‑level binding or role restrictions shown.

### MASS-M-0004-1 — Unrestricted role binding in Spring MVC (duplicate)

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** mass_assignment (privileged_field_writable) — CWE-915   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/web/AccountController.java:27`

**Impact.** Any authenticated user can set the role field of an Account

**Evidence.**

- `java-legacy/src/com/acme/web/AccountController.java:27` — Location taken from the Tier 1 inventory

**Recommendation.** Bind only allowed fields or set role server‑side

*Verifier:* likely — checked: AccountController.update method (lines 13-28), AccountDao.save invocation. No ownership or role check, no allow‑list, and no type cast is visible in the provided code context.

### MASS-M-0005-1 — Unrestricted role binding via BeanUtils in Java Servlet

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** mass_assignment (privileged_field_writable) — CWE-915   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/web/ProfileServlet.java:12`

**Impact.** Any authenticated user can set the role field of an Account

**Evidence.**

- `java-legacy/src/com/acme/web/ProfileServlet.java:12` — BeanUtils.populate binds all request parameters including role
- `java-legacy/src/com/acme/web/ProfileServlet.java:10` — no field filtering or role check

**Recommendation.** Bind only allowed fields or set role server‑side

*Verifier:* likely — checked: ProfileServlet.doPost method (lines 9-16), BeanUtils.populate usage. The code shows direct population of all request parameters into the Account object with no filtering or role enforcement.

### BOLA-R-0001 — BOLA in ANY /user/edit.do: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /user/edit.do  
- **Location:** `java-legacy/src/com/acme/struts/EditUserAction.java:10`

**Evidence.**

- `java-legacy/src/com/acme/struts/EditUserAction.java:10` — ID from request  
  `String userId = request.getParameter("user_id");`
- `java-legacy/src/com/acme/struts/EditUserAction.java:13` — Query does not bind to user_id  
  `PreparedStatement ps = conn.prepareStatement("UPDATE users SET email = '" + email + "' WHERE id = " + userId);`

**Recommendation.** Verify user ownership before update

*Verifier:* confirmed — checked: java-legacy/src/com/acme/struts/EditUserAction.java. The UPDATE statement uses the user_id from the request without any ownership verification or parameter binding.

### BOLA-R-0002 — BOLA in ANY /classic-asp/shop/member.asp?mode=edit: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /classic-asp/shop/member.asp?mode=edit  
- **Location:** `classic-asp/shop/member.asp:6`

**Evidence.**

- `classic-asp/shop/member.asp:6` — ID from request, no ownership check  
  `sql = "UPDATE members SET name = '" & Replace(Request.Form("name"), "'", "''") & "'"`
- `classic-asp/shop/member.asp:7` — ID from request, no ownership check  
  `sql = sql & " WHERE member_id = " & Request.Form("member_id")`
- `classic-asp/shop/member.asp:8` — Executes query without owner check  
  `conn.Execute sql`

**Recommendation.** Bind query to current session user

*Verifier:* confirmed — checked: classic-asp/shop/member.asp lines 6-8, classic-asp/shop/inc/auth.asp line 2. The code updates a member record using the member_id from the request without any ownership verification. The only visible check is authentication in inc/auth.asp, which does not enforce ownership.

### BOLA-R-0003 — BOLA in ANY /classic-asp/shop/member.asp?mode=delete: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /classic-asp/shop/member.asp?mode=delete  
- **Location:** `classic-asp/shop/member.asp:9`

**Evidence.**

- `classic-asp/shop/member.asp:9` — ID from request, no ownership check  
  `conn.Execute "DELETE FROM members WHERE member_id = " & Request.QueryString("member_id")`

**Recommendation.** Bind delete to current session user

*Verifier:* confirmed — checked: classic-asp/shop/member.asp line 9, classic-asp/shop/inc/auth.asp line 2. The delete statement uses the member_id from the query string directly. No ownership check is present in the visible code.

### BOLA-R-0004 — BOLA in ANY /classic-asp/shop/order.asp: missing owner verification on first query

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /classic-asp/shop/order.asp  
- **Location:** `classic-asp/shop/order.asp:5`

**Evidence.**

- `classic-asp/shop/order.asp:5` — ID from request, no ownership check  
  `id = Request("id")`
- `classic-asp/shop/order.asp:6` — Query does not bind to user_id  
  `Set rs = conn.Execute("SELECT * FROM orders WHERE id = " & id)`

**Recommendation.** Bind order query to current session user

*Verifier:* confirmed — checked: classic-asp/shop/order.asp lines 5-6, classic-asp/shop/inc/auth.asp line 2. The first query selects an order by id from the request without binding to the current user. The later query includes a user_id check, but the initial query remains vulnerable.

### BOLA-R-0005 — BOLA in ANY /coldfusion/app/OrderService.cfc?method=getOrder: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /coldfusion/app/OrderService.cfc?method=getOrder  
- **Location:** `coldfusion/app/OrderService.cfc:4`

**Evidence.**

- `coldfusion/app/OrderService.cfc:4` — Query starts here  
  `<cfquery name="q" datasource="shop">`
- `coldfusion/app/OrderService.cfc:5` — ID from request, no ownership check  
  `SELECT * FROM orders WHERE id = #arguments.orderId#`

**Recommendation.** Bind order query to current session user

*Verifier:* confirmed — checked: coldfusion/app/OrderService.cfc lines 4-5. The cfquery directly interpolates the orderId argument into the SQL without any ownership verification or parameter binding.

### BOLA-R-0006 — BOLA in ANY /coldfusion/app/order.cfm: missing owner verification on first query

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /coldfusion/app/order.cfm  
- **Location:** `coldfusion/app/order.cfm:2`

**Evidence.**

- `coldfusion/app/order.cfm:2` — Query starts here  
  `<cfquery name="qOrder" datasource="shop">`
- `coldfusion/app/order.cfm:3` — ID from request, no ownership check  
  `SELECT * FROM orders WHERE id = #url.id#`

**Recommendation.** Bind order query to current session user

*Verifier:* confirmed — checked: coldfusion/app/order.cfm lines 2-3, coldfusion/app/order.cfm lines 5-8. The first query qOrder selects an order by id from the URL without checking the current user. The subsequent qMine query includes a user_id check, but the initial query is still exposed.

### BOLA-R-0007 — BOLA in POST /Admin/DeleteUser: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /Admin/DeleteUser  
- **Location:** `dotnet-legacy/Web/Controllers/AdminController.cs:12`

**Evidence.**

- `dotnet-legacy/Web/Controllers/AdminController.cs:11` — Method signature  
  `public ActionResult DeleteUser(int id)`
- `dotnet-legacy/Web/Controllers/AdminController.cs:12` — Finds user by id from request  
  `var u = db.Users.Find(id);`
- `dotnet-legacy/Web/Controllers/AdminController.cs:13` — Deletes user without ownership check  
  `db.Users.Remove(u);`

**Recommendation.** Restrict to admin role and verify ownership

*Verifier:* confirmed — checked: dotnet-legacy/Web/Controllers/AdminController.cs lines 6-13. The DeleteUser action lacks any ownership or role check; the controller is only marked with [Authorize], allowing any authenticated user to delete any user.

### BOLA-R-0009 — BOLA in POST /Admin/Export: missing role check allows data exposure

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_role_check) — CWE-284, CWE-285   
- **Endpoint:** POST /Admin/Export  
- **Location:** `dotnet-legacy/Web/Controllers/AdminController.cs:30`

**Evidence.**

- `dotnet-legacy/Web/Controllers/AdminController.cs:30` — Method signature  
  `public ActionResult Export()`
- `dotnet-legacy/Web/Controllers/AdminController.cs:32` — Checks query string, not role  
  `if (Request.QueryString["isAdmin"] == "true")`
- `dotnet-legacy/Web/Controllers/AdminController.cs:33` — Returns all users  
  `return Json(db.Users.ToList(), JsonRequestBehavior.AllowGet);`

**Recommendation.** Add role-based authorization

*Verifier:* confirmed — checked: dotnet-legacy/Web/Controllers/AdminController.cs lines 30-35. Export is protected only by class-level [Authorize] and a query‑string flag; no role or ownership verification is performed.

### BOLA-R-0010 — BOLA in POST /Customer/Edit: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /Customer/Edit  
- **Location:** `dotnet-legacy/Web/Controllers/CustomerController.cs:12`

**Evidence.**

- `dotnet-legacy/Web/Controllers/CustomerController.cs:14` — Marks the supplied customer entity as modified without checking that the current user owns it  
  `db.Entry(customer).State = System.Data.Entity.EntityState.Modified;`
- `dotnet-legacy/Web/Controllers/CustomerController.cs:15` — Persists the changes, allowing any authenticated user to modify any customer record  
  `db.SaveChanges();`

**Recommendation.** Load the customer by ID and verify ownership before applying changes

*Verifier:* likely — checked: dotnet-legacy/Web/Controllers/CustomerController.cs lines 11-15. The Edit action marks the supplied Customer entity as Modified and saves it without checking ownership. The controller is decorated with [Authorize], which only ensures authentication, not ownership.

### BOLA-R-0011 — BOLA in POST /Customer/EditName: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /Customer/EditName  
- **Location:** `dotnet-legacy/Web/Controllers/CustomerController.cs:20`

**Evidence.**

- `dotnet-legacy/Web/Controllers/CustomerController.cs:22` — Saves changes to the customer entity without verifying that the current user owns it  
  `db.SaveChanges();`

**Recommendation.** Verify ownership before saving changes

*Verifier:* likely — checked: dotnet-legacy/Web/Controllers/CustomerController.cs lines 20-23. EditName receives a Customer with only Id and Name bound, then calls SaveChanges without verifying that the current user owns the customer.

### BOLA-R-0012 — BOLA in POST /Customer/Refresh: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /Customer/Refresh  
- **Location:** `dotnet-legacy/Web/Controllers/CustomerController.cs:27`

**Evidence.**

- `dotnet-legacy/Web/Controllers/CustomerController.cs:29` — Loads customer by ID supplied in the request without checking ownership  
  `var customer = db.Customers.Find(id);`
- `dotnet-legacy/Web/Controllers/CustomerController.cs:30` — Updates the customer entity without verifying that the current user owns it  
  `TryUpdateModel(customer);`
- `dotnet-legacy/Web/Controllers/CustomerController.cs:31` — Persists the changes, allowing any authenticated user to modify any customer record  
  `db.SaveChanges();`

**Recommendation.** Load the customer and verify ownership before updating

*Verifier:* likely — checked: dotnet-legacy/Web/Controllers/CustomerController.cs lines 27-32. Refresh loads a Customer by id and applies TryUpdateModel before saving, with no ownership check. The [Authorize] attribute only guarantees authentication.

### BOLA-R-0013 — BOLA in GET /Invoice/Details: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /Invoice/Details  
- **Location:** `dotnet-legacy/Web/Controllers/InvoiceController.cs:11`

**Evidence.**

- `dotnet-legacy/Web/Controllers/InvoiceController.cs:11` — Method signature  
  `public ActionResult Details(int id)`
- `dotnet-legacy/Web/Controllers/InvoiceController.cs:13` — Finds invoice by id from request  
  `var inv = db.Invoices.Find(id);`
- `dotnet-legacy/Web/Controllers/InvoiceController.cs:14` — Returns invoice without ownership check  
  `return View(inv);`

**Recommendation.** Verify invoice ownership

*Verifier:* confirmed — checked: dotnet-legacy/Web/Controllers/InvoiceController.cs lines 6-14. Details retrieves an invoice by id without checking that the invoice belongs to the current user.

### BOLA-R-0015 — BOLA in POST /Invoice/Search: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /Invoice/Search  
- **Location:** `dotnet-legacy/Web/Controllers/InvoiceController.cs:26`

**Evidence.**

- `dotnet-legacy/Web/Controllers/InvoiceController.cs:26` — Method signature  
  `public ActionResult Search(string customer)`
- `dotnet-legacy/Web/Controllers/InvoiceController.cs:28` — Raw query uses customer from request, no ownership check  
  `var list = db.Database.SqlQuery<Invoice>("SELECT * FROM Invoices WHERE Customer = '" + customer + "'").ToList();`

**Recommendation.** Add ownership filter to query

*Verifier:* confirmed — checked: dotnet-legacy/Web/Controllers/InvoiceController.cs lines 25-29. Search builds a raw SQL query from user input and returns all matching invoices, with no ownership filter.

### BOLA-R-0016 — BOLA in ANY /dotnet-legacy/Web/Handlers/GetFile.ashx: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /dotnet-legacy/Web/Handlers/GetFile.ashx  
- **Location:** `dotnet-legacy/Web/Handlers/GetFile.ashx:8`

**Evidence.**

- `dotnet-legacy/Web/Handlers/GetFile.ashx:8` — Takes file identifier directly from the request  
  `string fileId = context.Request.QueryString["file_id"];`
- `dotnet-legacy/Web/Handlers/GetFile.ashx:9` — Builds file path without checking that the current user owns the file  
  `string path = DocStore.PathFor(fileId);`
- `dotnet-legacy/Web/Handlers/GetFile.ashx:10` — Serves the file to the requester, enabling download of any file  
  `context.Response.TransmitFile(path);`

**Recommendation.** Verify that the current user owns the requested file before transmitting

*Verifier:* confirmed — checked: dotnet-legacy/Web/Handlers/GetFile.ashx:8-10. The handler reads the file identifier directly from the query string, builds a path without any ownership verification, and transmits the file. No ownership or tenant check is present in the visible code.

### BOLA-R-0017 — BOLA in ANY /dotnet-legacy/Web/Orders/EditOrder.aspx.vb: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /dotnet-legacy/Web/Orders/EditOrder.aspx  
- **Location:** `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7`

**Evidence.**

- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7` — SQL built from request data  
  `Dim sql As String = "UPDATE Orders SET Note = '" & txtNote.Text & "'"`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8` — OrderId from hidden field, no ownership check  
  `sql &= " WHERE OrderId = " & hfOrderId.Value`

**Recommendation.** Verify order ownership before update

*Verifier:* confirmed — checked: dotnet-legacy/Web/Orders/EditOrder.aspx.vb lines 6-13. The update statement uses the OrderId from a hidden field without verifying that the current user owns the order.

### BOLA-R-0018 — BOLA in ANY /dotnet-legacy/Web/Orders/OrderDetail.aspx.cs: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /dotnet-legacy/Web/Orders/OrderDetail.aspx  
- **Location:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10`

**Evidence.**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10` — ID from request  
  `string id = Request.QueryString["id"];`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13` — Query does not bind to user_id  
  `var cmd = new SqlCommand("SELECT * FROM Orders WHERE OrderId = " + id, conn);`

**Recommendation.** Bind order query to current session user

*Verifier:* confirmed — checked: dotnet-legacy/Web/Orders/OrderDetail.aspx.cs. The unsafe query at line 13 is executed before any ownership check or parameter binding. No role or ownership guard is visible in the provided code.

### BOLA-R-0019 — BOLA in ANY /java-legacy/WebContent/order/detail.jsp: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /java-legacy/WebContent/order/detail.jsp  
- **Location:** `java-legacy/WebContent/order/detail.jsp:3`

**Evidence.**

- `java-legacy/WebContent/order/detail.jsp:3` — ID from request  
  `String no = request.getParameter("no");`
- `java-legacy/WebContent/order/detail.jsp:5` — Query does not bind to user_id  
  `ResultSet rs = c.createStatement().executeQuery("SELECT * FROM orders WHERE order_no = '" + no + "'");`

**Recommendation.** Bind order query to current session user

*Verifier:* confirmed — checked: java-legacy/WebContent/order/detail.jsp. The query concatenates the request parameter directly into the SQL string with no ownership check or parameter binding.

### BOLA-R-0020 — BOLA in POST /account/save: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /account/save  
- **Location:** `java-legacy/src/com/acme/web/AccountController.java:14`

**Evidence.**

- `java-legacy/src/com/acme/web/AccountController.java:14` — Account object is bound directly from the request; attacker can set any id  
  `public String save(@ModelAttribute Account account) {`
- `java-legacy/src/com/acme/web/AccountController.java:15` — No check that the account belongs to the current user  
  `    accountDao.save(account);`

**Recommendation.** Bind the save operation to the authenticated user

*Verifier:* confirmed — checked: java-legacy/src/com/acme/web/AccountController.java. The Account object is bound directly from the request and passed to the DAO without any ownership check.

### BOLA-R-0021 — BOLA in POST /account/rename: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /account/rename  
- **Location:** `java-legacy/src/com/acme/web/AccountController.java:20`

**Evidence.**

- `java-legacy/src/com/acme/web/AccountController.java:20` — Form contains an id that can be set by the attacker  
  `public String rename(@ModelAttribute RenameForm form) {`
- `java-legacy/src/com/acme/web/AccountController.java:21` — No check that the id belongs to the current user  
  `    accountDao.rename(form.getId(), form.getName());`

**Recommendation.** Verify ownership before renaming

*Verifier:* confirmed — checked: java-legacy/src/com/acme/web/AccountController.java. The RenameForm contains an id that is used directly in the DAO call with no ownership verification.

### BOLA-R-0022 — BOLA in PUT /account/api: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** PUT /account/api  
- **Location:** `java-legacy/src/com/acme/web/AccountController.java:27`

**Evidence.**

- `java-legacy/src/com/acme/web/AccountController.java:27` — Account object is deserialized from the request; attacker can set any id  
  `public Account update(@RequestBody Account account) {`
- `java-legacy/src/com/acme/web/AccountController.java:28` — No ownership check before saving  
  `    return accountDao.save(account);`

**Recommendation.** Bind update to the authenticated user

*Verifier:* likely — checked: java-legacy/src/com/acme/web/AccountController.java:25-28. The update method deserializes an Account object and directly passes it to accountDao.save without any ownership or role check visible in the provided code. No global filter or cast is shown.

### BOLA-R-0023 — BOLA in POST /admin/users/{id}/delete: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /admin/users/{id}/delete  
- **Location:** `java-legacy/src/com/acme/web/AdminUserController.java:13`

**Evidence.**

- `java-legacy/src/com/acme/web/AdminUserController.java:13` — Endpoint accepts any user id  
  `@RequestMapping(value = "/{id}/delete", method = RequestMethod.POST)`
- `java-legacy/src/com/acme/web/AdminUserController.java:15` — No authentication or role check; any logged‑in user can delete any account  
  `    userDao.deleteById(id);`

**Recommendation.** Require admin role before deleting a user

*Verifier:* likely — checked: java-legacy/src/com/acme/web/AdminUserController.java:13-15. The delete method accepts any user id and calls userDao.deleteById without a role or ownership guard. The @PreAuthorize annotation is present only on a different method.

### BOLA-R-0025 — BOLA in GET /invoices/{id}: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /invoices/{id}  
- **Location:** `java-legacy/src/com/acme/web/InvoiceController.java:15`

**Evidence.**

- `java-legacy/src/com/acme/web/InvoiceController.java:15` — Endpoint accepts any invoice id  
  `@RequestMapping(value = "/{id}", method = RequestMethod.GET)`
- `java-legacy/src/com/acme/web/InvoiceController.java:17` — No check that the invoice belongs to the current user  
  `        model.addAttribute("invoice", invoiceDao.findById(id));`

**Recommendation.** Bind invoice lookup to the authenticated user

*Verifier:* likely — checked: java-legacy/src/com/acme/web/InvoiceController.java:15-17. The show method retrieves an invoice by id without verifying that the invoice belongs to the current user. No ownership check or role guard is visible.

### BOLA-R-0027 — BOLA in GET /invoices/search: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /invoices/search  
- **Location:** `java-legacy/src/com/acme/web/InvoiceController.java:27`

**Evidence.**

- `java-legacy/src/com/acme/web/InvoiceController.java:27` — Endpoint accepts any customer string  
  `@RequestMapping(value = "/search", method = RequestMethod.GET)`
- `java-legacy/src/com/acme/web/InvoiceController.java:29` — Query is built from user input without binding to current user  
  `        model.addAttribute("list", session.createQuery("from Invoice i where i.customer = '" + customer + "'").list());`

**Recommendation.** Restrict search to invoices owned by the current user

*Verifier:* likely — checked: java-legacy/src/com/acme/web/InvoiceController.java:27-29. The search method builds a query from a customer string without binding to the current user or applying an allow‑list. No ownership or role check is shown.

### BOLA-R-0028 — BOLA in GET /order/view: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /order/view  
- **Location:** `java-legacy/src/com/acme/web/OrderServlet.java:11`

**Evidence.**

- `java-legacy/src/com/acme/web/OrderServlet.java:11` — Order id comes directly from the request  
  `String id = request.getParameter("orderId");`
- `java-legacy/src/com/acme/web/OrderServlet.java:15` — No check that the order belongs to the current user  
  `ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE id = '" + id + "'");`

**Recommendation.** Bind order lookup to the authenticated user

*Verifier:* likely — checked: java-legacy/src/com/acme/web/OrderServlet.java:11-15. The servlet retrieves an order by id directly from the request and queries the database without verifying ownership. No role or ownership guard is visible in the provided snippet.

### BOLA-R-0029 — BOLA in POST /ProfileServlet: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST <see web.xml servlet-mapping>  
- **Location:** `java-legacy/src/com/acme/web/ProfileServlet.java:9`

**Evidence.**

- `java-legacy/src/com/acme/web/ProfileServlet.java:12` — Populates an Account object with all request parameters without checking ownership  
  `BeanUtils.populate(account, request.getParameterMap());`
- `java-legacy/src/com/acme/web/ProfileServlet.java:13` — No authentication or ownership check is performed before persisting the account  
  `/* no further processing shown */`

**Recommendation.** Load the account by ID and verify that the current user owns it before updating

*Verifier:* confirmed — checked: java-legacy/src/com/acme/web/ProfileServlet.java:12-13. The servlet populates an Account object with all request parameters and does not perform any ownership check before persisting. No compensating control is visible.

### BOLA-R-0030 — BOLA in POST /admin/users/:id/delete: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /admin/users/:id/delete  
- **Location:** `node-express/routes/admin.js:8`

**Evidence.**

- `node-express/routes/admin.js:8` — Endpoint accepts any user id  
  `router.post('/admin/users/:id/delete', ensureLoggedIn, function (req, res) {`
- `node-express/routes/admin.js:9` — No role check; any logged‑in user can delete any account  
  `  User.deleteOne({ _id: req.params.id }, function () { res.sendStatus(204); });`

**Recommendation.** Require admin role before deleting a user

*Verifier:* confirmed — checked: router.post('/admin/users/:id/delete', ensureLoggedIn, function (req, res) {,   User.deleteOne({ _id: req.params.id }, function () { res.sendStatus(204); });. No admin role or ownership check is performed before deleting a user.

### BOLA-R-0033 — BOLA in GET /orders/:id: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /orders/:id  
- **Location:** `node-express/routes/orders.js:8`

**Evidence.**

- `node-express/routes/orders.js:8` — The order ID comes from the request and the query does not filter by the authenticated user.  
  `router.get('/orders/:id', ensureLoggedIn, function (req, res) { Order.findById(req.params.id, function (err, order) { res.json(order); }); });`

**Recommendation.** Bind the query to the current session user.

*Verifier:* confirmed — checked: router.get('/orders/:id', ensureLoggedIn, function (req, res) {,   Order.findById(req.params.id, function (err, order) { res.json(order); });. The order is retrieved by ID without filtering by the authenticated user.

### BOLA-R-0038 — BOLA in GET /stats: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /stats  
- **Location:** `node-express/routes/orders.js:28`

**Evidence.**

- `node-express/routes/orders.js:28` — The shop_id is taken from the request and the query is not filtered by the authenticated user.  
  `router.get('/stats', function (req, res) { db.query('SELECT COUNT(*) AS n FROM orders WHERE shop_id = ${req.query.shop}', function (e, r) { res.json(r); }); });`

**Recommendation.** Add authentication guard and filter by the current user’s shop.

*Verifier:* confirmed — checked: router.get('/stats', function (req, res) {,   db.query(`SELECT COUNT(*) AS n FROM orders WHERE shop_id = ${req.query.shop}`, function (e, r) { res.json(r); });. The shop_id is taken directly from the request and no authentication guard is present.

### BOLA-R-0043 — BOLA in ANY /perl-cgi/cgi-bin/order.cgi: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /perl-cgi/cgi-bin/order.cgi  
- **Location:** `perl-cgi/cgi-bin/order.cgi:13`

**Evidence.**

- `perl-cgi/cgi-bin/order.cgi:13` — The order ID comes from the request and the query does not filter by the authenticated user.  
  `my $sth = $dbh->prepare("SELECT * FROM orders WHERE id = $id");`

**Recommendation.** Use a parameterized query that includes the user_id.

*Verifier:* confirmed — checked: my $sth = $dbh->prepare("SELECT * FROM orders WHERE id = $id");, $sth->execute();. An insecure query is executed before the safe query that includes user_id.

### BOLA-R-0044 — BOLA in ANY /invoice/view/{id}: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /invoice/view/{id}  
- **Location:** `php-codeigniter/application/controllers/Invoice.php:10`

**Evidence.**

- `php-codeigniter/application/controllers/Invoice.php:10` — The invoice ID comes from the request and the query does not filter by the authenticated user.  
  `$q = $this->db->query("SELECT * FROM invoices WHERE id = $id");`

**Recommendation.** Add an owner check to the query.

*Verifier:* confirmed — checked: $q = $this->db->query("SELECT * FROM invoices WHERE id = $id");, $this->load->view('invoice', array('inv' => $q->row()));. The invoice is fetched by ID without filtering by the authenticated user.

### BOLA-R-0046 — BOLA in ANY /invoice/update: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /invoice/update  
- **Location:** `php-codeigniter/application/controllers/Invoice.php:23`

**Evidence.**

- `php-codeigniter/application/controllers/Invoice.php:23` — The invoice ID comes from the request and the update does not filter by the authenticated user.  
  `$this->db->query("UPDATE invoices SET note = ? WHERE id = ?", array($note, $id));`

**Recommendation.** Add an owner check to the update query.

*Verifier:* likely — checked: php-codeigniter/application/controllers/Invoice.php lines 20-24. No ownership or role check, integer cast, or allow‑list is visible in the update method. The controller does not include any auth guard in the provided context.

### BOLA-R-0057-1 — BOLA in GET /php-plain/admin.php?action=view: missing admin authorization

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_role_check) — CWE-285   
- **Endpoint:** GET /php-plain/admin.php?action=view  
- **Location:** `php-plain/admin.php:8`

**Evidence.**

- `php-plain/admin.php:8` — No admin check; any logged-in user can view any user record by supplying uid  
  `$r = mysql_query("SELECT * FROM users WHERE id = " . $uid);`

**Recommendation.** Restrict admin actions to users with admin role

*Verifier:* likely — checked: php-plain/admin.php lines 5-9, php-plain/inc/auth.php lines 1-7. The included auth file only verifies a logged‑in session; there is no admin role check before the SELECT query.

### BOLA-R-0057-2 — BOLA in POST /php-plain/admin.php?action=delete: missing admin authorization

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_role_check) — CWE-285   
- **Endpoint:** POST /php-plain/admin.php?action=delete  
- **Location:** `php-plain/admin.php:6`

**Evidence.**

- `php-plain/admin.php:12` — No admin check; any logged-in user can delete any user record by supplying id  
  `mysql_query("DELETE FROM users WHERE id = $id");`

**Recommendation.** Restrict admin actions to users with admin role

*Verifier:* likely — checked: php-plain/admin.php lines 10-13, php-plain/inc/auth.php lines 1-7. No admin role check is present before the DELETE statement; the auth file does not enforce role.

### BOLA-R-0058-1 — BOLA in GET /php-plain/admin.php?action=view: missing admin authorization

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_role_check) — CWE-285   
- **Endpoint:** GET /php-plain/admin.php?action=view  
- **Location:** `php-plain/admin.php:10`

**Evidence.**

- `php-plain/admin.php:8` — No admin check; any logged-in user can view any user record by supplying uid  
  `$r = mysql_query("SELECT * FROM users WHERE id = " . $uid);`

**Recommendation.** Restrict admin actions to users with admin role

*Verifier:* likely — checked: php-plain/admin.php lines 5-9, php-plain/inc/auth.php lines 1-7. Same as BOLA-R-0057-1: only a login check is performed, no admin guard before the SELECT.

### BOLA-R-0058-2 — BOLA in POST /php-plain/admin.php?action=delete: missing admin authorization

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_role_check) — CWE-285   
- **Endpoint:** POST /php-plain/admin.php?action=delete  
- **Location:** `php-plain/admin.php:12`

**Evidence.**

- `php-plain/admin.php:12` — No admin check; any logged-in user can delete any user record by supplying id  
  `mysql_query("DELETE FROM users WHERE id = $id");`

**Recommendation.** Restrict admin actions to users with admin role

*Verifier:* likely — checked: php-plain/admin.php lines 10-13, php-plain/inc/auth.php lines 1-7. Same as BOLA-R-0057-2: no admin role check before the DELETE.

### BOLA-R-0059-1 — BOLA in POST /php-plain/manage_users.php: missing admin authorization

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_role_check) — CWE-285   
- **Endpoint:** POST /php-plain/manage_users.php  
- **Location:** `php-plain/manage_users.php:6`

**Evidence.**

- `php-plain/manage_users.php:6` — No admin check; any logged-in user can delete any user record by supplying id  
  `$stmt = $db->prepare("DELETE FROM users WHERE id = ?");`
- `php-plain/manage_users.php:7` — No admin check; any logged-in user can delete any user record by supplying id  
  `$stmt->execute(array((int)$_POST['id']));`

**Recommendation.** Restrict admin actions to users with admin role

*Verifier:* confirmed — checked: Checked lines 1-12 of php-plain/manage_users.php. The script performs a delete operation after a POST request but contains only a login check. No admin role check is present; the integer cast on $_POST['id'] is insufficient.

### BOLA-R-0061-1 — BOLA in GET /php-plain/order_detail.php: missing ownership verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /php-plain/order_detail.php  
- **Location:** `php-plain/order_detail.php:6`

**Evidence.**

- `php-plain/order_detail.php:6` — No ownership check; any logged-in user can view any order by supplying id  
  `$res = mysql_query("SELECT * FROM orders WHERE id = " . $id);`

**Recommendation.** Bind query to current session user

*Verifier:* likely — checked: Checked lines 1-8 of php-plain/order_detail.php. The visible code performs a direct query on the order id without any ownership verification. The auth model indicates a check exists elsewhere, but it is not shown in the provided context.

### BOLA-R-0066-1 — BOLA in POST /php-plain/admin/delete_user.php: missing admin authorization

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_role_check) — CWE-285   
- **Endpoint:** POST /php-plain/admin/delete_user.php  
- **Location:** `php-plain/admin/delete_user.php:6`

**Evidence.**

- `php-plain/admin/delete_user.php:6` — No admin check; any logged-in user can delete any user record by supplying id  
  `$stmt = $db->prepare("DELETE FROM users WHERE id = ?");`
- `php-plain/admin/delete_user.php:7` — No admin check; any logged-in user can delete any user record by supplying id  
  `$stmt->execute(array($id));`

**Recommendation.** Restrict admin actions to users with admin role

*Verifier:* confirmed — checked: Checked lines 1-8 of php-plain/admin/delete_user.php. The file includes only a login check via inc/auth.php; no admin role check is present. The integer cast on $_POST['id'] does not provide authorization.

### BOLA-R-0067-1 — BOLA in POST /php-plain/admin/promote.php: missing admin authorization

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_role_check) — CWE-285   
- **Endpoint:** POST /php-plain/admin/promote.php  
- **Location:** `php-plain/admin/promote.php:6`

**Evidence.**

- `php-plain/admin/promote.php:6` — No admin check; any logged-in user can promote any user to admin  
  `$stmt = $db->prepare("UPDATE users SET role = 'admin' WHERE id = ?");`
- `php-plain/admin/promote.php:7` — No admin check; any logged-in user can promote any user to admin  
  `$stmt->execute(array((int)$_POST['uid']));`

**Recommendation.** Restrict admin actions to users with admin role

*Verifier:* confirmed — checked: Checked lines 1-8 of php-plain/admin/promote.php. Only a login check is performed; there is no admin role verification. The cast to int on $_POST['uid'] does not mitigate the missing authorization.

### BOLA-R-0069-1 — BOLA in GET /orders/<int:order_id>: missing ownership verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /orders/<int:order_id>  
- **Location:** `python-flask/app.py:12`

**Evidence.**

- `python-flask/app.py:12` — No ownership check; any logged-in user can view any order by supplying order_id  
  `cur.execute("SELECT * FROM orders WHERE id = %s" % order_id);`

**Recommendation.** Bind query to current user

*Verifier:* confirmed — checked: Checked lines 8-13 of python-flask/app.py. The /orders/<int:order_id> route executes a query based solely on the order id with no user‑ownership filter. Only the login_required decorator is present.

### BOLA-R-0073 — BOLA in POST /users/<uid>/name: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /users/<int:uid>/name  
- **Location:** `python-flask/profile.py:16`

**Evidence.**

- `python-flask/profile.py:18` — Loads user by ID supplied in the URL without checking ownership  
  `user = User.query.get(uid)`
- `python-flask/profile.py:19` — Updates the user record without verifying that the current session user owns it  
  `user.name = request.json["name"]`

**Recommendation.** Bind the update to the current session user

*Verifier:* likely — checked: python-flask/profile.py lines 16-20. The rename endpoint loads a User by the supplied uid and updates the name without any ownership or role check. No cast or allow‑list is present in the visible code.

### BOLA-R-0074 — BOLA in PATCH /users/<uid>: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** PATCH /users/<int:uid>  
- **Location:** `python-flask/profile.py:24`

**Evidence.**

- `python-flask/profile.py:26` — Loads user by ID supplied in the URL without ownership check  
  `user = User.query.get(uid)`
- `python-flask/profile.py:27` — Updates arbitrary fields of the user record without verifying ownership  
  `for key, value in request.json.items():
    setattr(user, key, value)`

**Recommendation.** Verify that the current session user owns the target user before updating

*Verifier:* likely — checked: python-flask/profile.py lines 24-29. The patch endpoint retrieves a User by uid and applies arbitrary updates without verifying that the current session user owns the record. No ownership guard is visible.

### MASS-M-0009-1 — Team creation allows owner_id to be set by any user

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** mass_assignment (privileged_field_writable) — CWE-915   
- **Endpoint:** - -  
- **Location:** `php-laravel/app/Http/Controllers/AccountController.php:23`

**Impact.** owner_id field writable by any authenticated user

**Evidence.**

- `php-laravel/app/Http/Controllers/AccountController.php:21` — Team::create($request->all()) binds all request fields, including owner_id which is writable

**Recommendation.** Restrict mass assignment to non-privileged fields or set guarded/fillable to exclude owner_id

*Verifier:* likely — checked: php-laravel/app/Http/Controllers/AccountController.php lines 21-23. The controller calls Team::create($request->all()) with no visible mass‑assignment guard. The Team model definition (fillable/guarded) is not shown, so a compensating control cannot be confirmed.

### MASS-M-0006-1 — Profile update binds entire request body to User model

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `node-express/routes/profile.js:8`

**Impact.** Unknown privileged fields may be writable

**Evidence.**

- `node-express/routes/profile.js:8` — Location taken from the Tier 1 inventory

**Recommendation.** Review model definition to ensure no privileged fields are mass assignable

*Verifier:* likely — checked: profile.js router.put('/profile') handler (lines 7-9), User.findByIdAndUpdate with req.body. The handler updates the user document with the entire request body without any field filtering or privilege checks.

### MASS-M-0007-1 — Profile update binds entire request body to User model

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `node-express/routes/profile.js:16`

**Impact.** Unknown privileged fields may be writable

**Evidence.**

- `node-express/routes/profile.js:16` — Location taken from the Tier 1 inventory

**Recommendation.** Review model definition to ensure no privileged fields are mass assignable

*Verifier:* likely — checked: profile.js router.post('/signup') handler (lines 15-17), new User(req.body) and user.save(). The signup route creates a new user from the full request body, exposing all fields to the client.

### MASS-M-0008-1 — User registration binds entire request body to User model

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `php-laravel/app/Http/Controllers/AccountController.php:13`

**Impact.** Unknown privileged fields may be writable

**Evidence.**

- `php-laravel/app/Http/Controllers/AccountController.php:13` — Location taken from the Tier 1 inventory

**Recommendation.** Review model definition to ensure no privileged fields are mass assignable

*Verifier:* likely — checked: AccountController.register method (lines 11-14), User::create($request->all()). The register action mass‑assigns all request fields to the User model without any explicit field filtering.

### MASS-M-0010-1 — Team creation binds entire request body to Team model

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `php-laravel/app/Http/Controllers/AccountController.php:36`

**Impact.** Unknown privileged fields may be writable

**Evidence.**

- `php-laravel/app/Http/Controllers/AccountController.php:36` — Location taken from the Tier 1 inventory

**Recommendation.** Review model definition to ensure no privileged fields are mass assignable

*Verifier:* likely — checked: php-laravel/app/Http/Controllers/AccountController.php lines 21-23. Same as finding 1: the entire request body is bound to the Team model with no visible guard. The model’s mass‑assignment configuration is not visible.

### MASS-M-0014-1 — User creation binds entire request JSON to User model

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `python-flask/profile.py:10`

**Impact.** Unknown privileged fields may be writable

**Evidence.**

- `python-flask/profile.py:10` — Location taken from the Tier 1 inventory

**Recommendation.** Review model definition to ensure no privileged fields are mass assignable

*Verifier:* likely — checked: python-flask/profile.py lines 8-12. User creation uses User(**request.json) to bind all fields. No visible guard is present in the shown code, and the model’s mass‑assignment configuration is not visible.

### MASS-M-0015-1 — PATCH endpoint sets arbitrary attributes from request JSON

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `python-flask/profile.py:27`

**Impact.** Unknown privileged fields may be writable

**Evidence.**

- `python-flask/profile.py:27` — Location taken from the Tier 1 inventory

**Recommendation.** Review model definition to ensure no privileged fields are mass assignable

*Verifier:* likely — checked: python-flask/profile.py lines 24-29. The PATCH endpoint iterates over request.json and sets attributes on the User object without any visible guard. The User model’s mass‑assignment restrictions are not shown.

## 4. Systemic fixes

<!-- LLM: reporter agent writes max 5 systemic fixes here -->

## 5. Coverage and limitations

- missing from inventory: 0
- bola routes without verdict: 0
- injection candidates without verdict: 0
- bfla routes without verdict: 0
- mass candidates without verdict: 0
- findings without verification: 0

<!-- LLM: reporter agent lists limitations here -->

## Appendix A — Findings rejected by the verifier

| ID | Location | Reason |
|---|---|---|
| INJ-I-0035-1 | `python-flask/app.py:12` | The Flask route converter `<int:order_id>` guarantees that `order_id` is an integer before it reaches the handler, preventing SQL injection via the string formatting used in the query. |
| MASS-M-0013-1 | `php-plain/register.php:4` | The code extracts $_POST but only inserts the email and name columns into the users table. No mass assignment of privileged fields occurs, so the evidence does not support the finding. |

## Appendix B — Method

1. Deterministic pre-scan (stack detection, endpoint candidates, query-building candidates).
2. AI agents: auth-model extraction, route inventory, BOLA audit, injection audit.
3. Independent AI verifier tries to refute each finding.
4. Human review and sign-off (`review-log.md`).

This is not a penetration test. Absence of findings does not prove absence of vulnerabilities.
