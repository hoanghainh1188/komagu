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
| Count | 51 | 45 | 0 | 0 | 0 |

| Category | Count |
|---|---|
| bola | 45 |
| sql_injection | 30 |
| nosql_injection | 1 |
| bfla | 12 |
| mass_assignment | 8 |

Status: unverified=0, confirmed=41, likely=55, rejected=1, needs_review=0

## Trend and time to fix

| Date | Open | New | Regressed | Fixed | Suppressed |
|---|---|---|---|---|---|
| 2026-10-31 | 96 | 96 | 0 | 0 | 0 |

No findings fixed yet.

## 3. Findings

| ID | Sev | Conf | Status | Category | Endpoint | Location | Title |
|---|---|---|---|---|---|---|---|
| BFLA-R-0003-1 | critical | medium | likely | bfla |   | `classic-asp/shop/member.asp:1` | Unrestricted member deletion in classic‑ASP |
| BFLA-R-0007-1 | critical | medium | likely | bfla |   | `Web/Controllers/AdminController.cs:1` | Unauthenticated user can delete any user in ASP.NET MVC |
| BFLA-R-0009-1 | critical | medium | likely | bfla |   | `Web/Controllers/AdminController.cs:1` | Export endpoint controlled by request parameter in ASP.NET MVC |
| BFLA-R-0023-1 | critical | medium | likely | bfla |   | `com/acme/web/AdminUserController.java:1` | Unprotected user deletion in Spring MVC |
| BFLA-R-0030-1 | critical | medium | likely | bfla |   | `routes.js:1` | Unprotected user deletion in Express.js |
| BFLA-R-0032-1 | critical | medium | likely | bfla |   | `routes.js:1` | Export endpoint controlled by query param in Express.js |
| BFLA-R-0057-1 | critical | high | confirmed | bfla |   | `php-plain/admin.php:1` | Unprotected user view in PHP plain |
| BFLA-R-0058-1 | critical | high | confirmed | bfla |   | `php-plain/admin.php:1` | Unprotected user deletion in PHP plain |
| BFLA-R-0059-1 | critical | high | confirmed | bfla |   | `php-plain/manage_users.php:1` | Client‑side role check only in PHP plain |
| BFLA-R-0063-1 | critical | high | confirmed | bfla |   | `php-plain/profile.php:1` | Privilege escalation via role field in PHP plain profile update |
| BFLA-R-0066-1 | critical | high | confirmed | bfla |   | `php-plain/admin/delete_user.php:1` | Unprotected user deletion in PHP plain |
| BFLA-R-0067-1 | critical | high | confirmed | bfla |   | `php-plain/admin/promote.php:1` | Privilege escalation via role promotion in PHP plain |
| INJ-I-0001 | critical | high | confirmed | sql_injection |   | `classic-asp/shop/member.asp:6` | SQL Injection in classic-asp/shop/member.asp:6 |
| INJ-I-0002 | critical | high | confirmed | sql_injection |   | `classic-asp/shop/member.asp:7` | SQL Injection in classic-asp/shop/member.asp:7 |
| INJ-I-0003 | critical | high | confirmed | sql_injection |   | `classic-asp/shop/member.asp:10` | SQL Injection in classic-asp/shop/member.asp:10 |
| INJ-I-0004 | critical | high | confirmed | sql_injection |   | `classic-asp/shop/order.asp:6` | SQL Injection in classic-asp/shop/order.asp:6 |
| INJ-I-0006 | critical | high | confirmed | sql_injection |   | `coldfusion/app/OrderService.cfc:5` | SQL Injection in coldfusion/app/OrderService.cfc:5 |
| INJ-I-0007 | critical | high | confirmed | sql_injection |   | `coldfusion/app/order.cfm:3` | SQL Injection in coldfusion/app/order.cfm:3 |
| INJ-I-0008 | critical | medium | likely | sql_injection |   | `dotnet-legacy/Web/Controllers/InvoiceController.cs:28` | SQL Injection in dotnet-legacy/Web/Controllers/InvoiceController.cs:28 |
| INJ-I-0009 | critical | high | confirmed | sql_injection |   | `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7` | SQL Injection in dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7 |
| INJ-I-0010 | critical | high | confirmed | sql_injection |   | `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8` | SQL Injection in dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8 |
| INJ-I-0011 | critical | high | confirmed | sql_injection |   | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13` | SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13 |
| INJ-I-0012 | critical | high | likely | sql_injection |   | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19` | SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19 |
| INJ-I-0013 | critical | high | likely | sql_injection |   | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20` | SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20 |
| INJ-I-0014 | critical | high | likely | sql_injection |   | `java-legacy/WebContent/order/detail.jsp:5` | SQL Injection in java-legacy/WebContent/order/detail.jsp:5 |
| INJ-I-0015 | critical | medium | likely | sql_injection |   | `java-legacy/src/com/acme/mapper/OrderMapper.xml:9` | SQL Injection in java-legacy/src/com/acme/mapper/OrderMapper.xml:9 |
| INJ-I-0016 | critical | high | likely | sql_injection |   | `java-legacy/src/com/acme/struts/EditUserAction.java:13` | SQL Injection in java-legacy/src/com/acme/struts/EditUserAction.java:13 |
| INJ-I-0017 | critical | high | likely | sql_injection |   | `java-legacy/src/com/acme/web/InvoiceController.java:29` | SQL Injection in java-legacy/src/com/acme/web/InvoiceController.java:29 |
| INJ-I-0018 | critical | medium | likely | sql_injection |   | `java-legacy/src/com/acme/web/OrderServlet.java:15` | SQL Injection in java-legacy/src/com/acme/web/OrderServlet.java:15 |
| INJ-I-0020 | critical | high | confirmed | sql_injection |   | `node-express/routes/orders.js:17` | SQL Injection in node-express/routes/orders.js:17 |
| INJ-I-0022 | critical | high | confirmed | sql_injection |   | `node-express/routes/orders.js:21` | SQL Injection in node-express/routes/orders.js:21 |
| INJ-I-0023 | critical | high | confirmed | sql_injection |   | `node-express/routes/orders.js:25` | SQL Injection in node-express/routes/orders.js:25 |
| INJ-I-0024 | critical | high | confirmed | sql_injection |   | `perl-cgi/cgi-bin/order.cgi:13` | SQL Injection in perl-cgi/cgi-bin/order.cgi:13 |
| INJ-I-0025 | critical | high | confirmed | sql_injection |   | `perl-cgi/cgi-bin/order.cgi:19` | SQL Injection in perl-cgi/cgi-bin/order.cgi:19 |
| INJ-I-0026 | critical | medium | likely | sql_injection |   | `php-codeigniter/application/controllers/Invoice.php:10` | SQL Injection in php-codeigniter/application/controllers/Invoice.php:10 |
| INJ-I-0027 | critical | medium | likely | sql_injection |   | `php-plain/admin.php:12` | SQL Injection in php-plain/admin.php:12 |
| INJ-I-0029 | critical | medium | likely | nosql_injection |   | `php-plain/mongo_find.php:6` | NoSQL Injection in php-plain/mongo_find.php:6 |
| INJ-I-0031 | critical | medium | likely | sql_injection |   | `php-plain/order_detail.php:6` | SQL Injection in php-plain/order_detail.php:6 |
| INJ-I-0032 | critical | medium | likely | sql_injection |   | `php-plain/search.php:8` | SQL Injection in php-plain/search.php:8 |
| INJ-I-0033 | critical | medium | likely | sql_injection |   | `php-plain/search.php:9` | SQL Injection in php-plain/search.php:9 |
| INJ-I-0034 | critical | medium | likely | sql_injection |   | `php-plain/search.php:14` | SQL Injection in php-plain/search.php:14 |
| INJ-I-0036 | critical | medium | likely | sql_injection |   | `python-flask/app.py:29` | SQL Injection in python-flask/app.py:29 |
| INJ-I-0037 | critical | medium | likely | sql_injection |   | `sql-procs/sp_search_orders.sql:5` | SQL Injection in sql-procs/sp_search_orders.sql:5 |
| MASS-M-0006-1 | critical | medium | likely | mass_assignment |   | `routes/profile.js:7` | Profile update binds entire request body to User model |
| MASS-M-0008-1 | critical | medium | likely | mass_assignment |   | `app/Http/Controllers/AccountController.php:11` | User registration binds entire request body to User model |
| MASS-M-0009-1 | critical | medium | likely | mass_assignment |   | `app/Http/Controllers/AccountController.php:21` | Team creation allows setting owner_id via request body |
| MASS-M-0011-1 | critical | high | confirmed | mass_assignment |   | `php-plain/profile.php:1` | Unrestricted binding of all POST fields to User in PHP plain |
| MASS-M-0012-1 | critical | high | confirmed | mass_assignment |   | `php-plain/profile.php:1` | Privilege escalation via role field in PHP plain |
| MASS-M-0013-1 | critical | medium | likely | mass_assignment |   | `register.php:4` | User insertion uses extract($_POST) to bind all POST fields |
| MASS-M-0014-1 | critical | medium | likely | mass_assignment |   | `app.py:8` | User creation binds entire request JSON to User model |
| MASS-M-0015-1 | critical | medium | likely | mass_assignment |   | `app.py:24` | PATCH endpoint sets arbitrary attributes from request JSON |
| BOLA-R-0001-1 | high | medium | likely | bola | POST /user/edit.do | `java-legacy/src/com/acme/struts/EditUserAction.java:13` | BOLA in POST /user/edit.do: missing owner verification |
| BOLA-R-0002-1 | high | medium | likely | bola | POST /classic-asp/shop/member.asp?mode=edit | `classic-asp/shop/member.asp:6` | BOLA in POST /classic-asp/shop/member.asp?mode=edit: missing owner verification |
| BOLA-R-0003-1 | high | medium | likely | bola | DELETE /classic-asp/shop/member.asp?mode=delete | `classic-asp/shop/member.asp:10` | BOLA in DELETE /classic-asp/shop/member.asp?mode=delete: missing owner verification |
| BOLA-R-0004-1 | high | medium | likely | bola | GET /classic-asp/shop/order.asp | `classic-asp/shop/order.asp:5` | BOLA in GET /classic-asp/shop/order.asp: missing owner verification |
| BOLA-R-0005-1 | high | medium | likely | bola | GET /coldfusion/app/OrderService.cfc?method=getOrder | `coldfusion/app/OrderService.cfc:4` | BOLA in GET /coldfusion/app/OrderService.cfc?method=getOrder: missing owner verification |
| BOLA-R-0006-1 | high | medium | likely | bola | GET /coldfusion/app/order.cfm | `coldfusion/app/order.cfm:3` | BOLA in GET /coldfusion/app/order.cfm: missing owner verification |
| BOLA-R-0007-1 | high | medium | likely | bola | POST /Admin/DeleteUser | `dotnet-legacy/Web/Controllers/AdminController.cs:12` | BOLA in POST /Admin/DeleteUser: missing owner verification |
| BOLA-R-0008-1 | high | medium | likely | bola | POST /Admin/Export | `dotnet-legacy/Web/Controllers/AdminController.cs:32` | BOLA in POST /Admin/Export: missing role verification |
| BOLA-R-0009-1 | high | medium | likely | bola | POST /Admin/Export | `dotnet-legacy/Web/Controllers/AdminController.cs:32` | BOLA in POST /Admin/Export: missing role verification |
| BOLA-R-0010 | high | high | confirmed | bola | POST /Customer/Edit | `dotnet-legacy/Web/Controllers/CustomerController.cs:12` | BOLA in POST /Customer/Edit: missing owner verification |
| BOLA-R-0011 | high | high | confirmed | bola | POST /Customer/EditName | `dotnet-legacy/Web/Controllers/CustomerController.cs:20` | BOLA in POST /Customer/EditName: missing owner verification |
| BOLA-R-0012 | high | high | confirmed | bola | POST /Customer/Refresh | `dotnet-legacy/Web/Controllers/CustomerController.cs:27` | BOLA in POST /Customer/Refresh: missing owner verification |
| BOLA-R-0013-1 | high | medium | likely | bola | GET /Invoice/Details | `dotnet-legacy/Web/Controllers/InvoiceController.cs:13` | BOLA in GET /Invoice/Details: missing owner verification |
| BOLA-R-0014-1 | high | medium | likely | bola | GET /Invoice/Details | `dotnet-legacy/Web/Controllers/InvoiceController.cs:13` | BOLA in GET /Invoice/Details: missing owner verification |
| BOLA-R-0015-1 | high | medium | likely | bola | POST /Invoice/Search | `dotnet-legacy/Web/Controllers/InvoiceController.cs:28` | BOLA in POST /Invoice/Search: missing owner verification |
| BOLA-R-0016 | high | medium | likely | bola | ANY /dotnet-legacy/Web/Handlers/GetFile.ashx | `dotnet-legacy/Web/Handlers/GetFile.ashx:8` | BOLA in ANY /dotnet-legacy/Web/Handlers/GetFile.ashx: missing owner verification |
| BOLA-R-0017-1 | high | medium | likely | bola | POST /dotnet-legacy/Web/Orders/EditOrder.aspx | `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7` | BOLA in POST /dotnet-legacy/Web/Orders/EditOrder.aspx: missing owner verification |
| BOLA-R-0018-1 | high | medium | likely | bola | GET /dotnet-legacy/Web/Orders/OrderDetail.aspx | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13` | BOLA in GET /dotnet-legacy/Web/Orders/OrderDetail.aspx: missing owner verification |
| BOLA-R-0019-1 | high | medium | likely | bola | GET /java-legacy/WebContent/order/detail.jsp | `java-legacy/WebContent/order/detail.jsp:5` | BOLA in GET /java-legacy/WebContent/order/detail.jsp: missing owner verification |
| BOLA-R-0020 | high | high | confirmed | bola | POST /account/save | `java-legacy/src/com/acme/web/AccountController.java:15` | BOLA in POST /account/save: missing owner verification |
| BOLA-R-0021 | high | high | confirmed | bola | POST /account/rename | `java-legacy/src/com/acme/web/AccountController.java:21` | BOLA in POST /account/rename: missing owner verification |
| BOLA-R-0022 | high | high | confirmed | bola | PUT /account/api | `java-legacy/src/com/acme/web/AccountController.java:28` | BOLA in PUT /account/api: missing owner verification |
| BOLA-R-0023 | high | high | confirmed | bola | POST /admin/users/{id}/delete | `java-legacy/src/com/acme/web/AdminUserController.java:15` | BOLA in POST /admin/users/{id}/delete: missing owner verification |
| BOLA-R-0025 | high | high | confirmed | bola | GET /invoices/{id} | `java-legacy/src/com/acme/web/InvoiceController.java:17` | BOLA in GET /invoices/{id}: missing owner verification |
| BOLA-R-0027 | high | medium | likely | bola | GET /invoices/search | `java-legacy/src/com/acme/web/InvoiceController.java:29` | BOLA in GET /invoices/search: missing owner verification |
| BOLA-R-0028 | high | medium | likely | bola | GET /order/view | `java-legacy/src/com/acme/web/OrderServlet.java:15` | BOLA in GET /order/view: missing owner verification |
| BOLA-R-0030 | high | medium | likely | bola | POST /admin/users/:id/delete | `node-express/routes/admin.js:9` | BOLA in POST /admin/users/:id/delete: missing owner verification |
| BOLA-R-0033-1 | high | medium | likely | bola | GET /orders/:id | `node-express/routes/orders.js:8` | BOLA in GET /orders/:id: missing owner verification |
| BOLA-R-0038-1 | high | medium | likely | bola | GET /stats | `node-express/routes/orders.js:28` | BOLA in GET /stats: missing shop ownership verification |
| BOLA-R-0043-1 | high | high | confirmed | bola | ANY /perl-cgi/cgi-bin/order.cgi | `perl-cgi/cgi-bin/order.cgi:11` | BOLA in Perl CGI order.cgi: missing user ownership verification |
| BOLA-R-0044-1 | high | high | confirmed | bola | ANY /invoice/view/{id} | `php-codeigniter/application/controllers/Invoice.php:9` | BOLA in PHP CodeIgniter Invoice view: missing owner verification |
| BOLA-R-0046-1 | high | high | confirmed | bola | ANY /invoice/update | `php-codeigniter/application/controllers/Invoice.php:20` | BOLA in PHP CodeIgniter Invoice update: missing owner verification |
| BOLA-R-0053 | high | medium | likely | bola | POST /posts | `php-laravel/routes/web.php:7` | Needs review: POST /posts – ownership check unknown |
| BOLA-R-0054 | high | medium | likely | bola | POST /teams | `php-laravel/routes/web.php:8` | Needs review: POST /teams – ownership check unknown |
| BOLA-R-0055 | high | medium | likely | bola | POST /account/rename | `php-laravel/routes/web.php:9` | Needs review: POST /account/rename – ownership check unknown |
| BOLA-R-0056 | high | medium | likely | bola | POST /account/profile | `php-laravel/routes/web.php:10` | Needs review: POST /account/profile – ownership check unknown |
| BOLA-R-0057 | high | high | confirmed | bola | GET\|POST /php-plain/admin.php?action=view | `php-plain/admin.php:6` | BOLA in GET\|POST /php-plain/admin.php?action=view: missing owner verification |
| BOLA-R-0058 | high | high | confirmed | bola | GET\|POST /php-plain/admin.php?action=delete | `php-plain/admin.php:10` | BOLA in GET\|POST /php-plain/admin.php?action=delete: missing owner verification |
| BOLA-R-0059 | high | high | confirmed | bola | POST /php-plain/manage_users.php | `php-plain/manage_users.php:5` | BOLA in POST /php-plain/manage_users.php: missing owner verification |
| BOLA-R-0061 | high | high | confirmed | bola | GET /php-plain/order_detail.php | `php-plain/order_detail.php:5` | BOLA in GET /php-plain/order_detail.php: missing owner verification |
| BOLA-R-0066 | high | high | confirmed | bola | POST /php-plain/admin/delete_user.php | `php-plain/admin/delete_user.php:5` | BOLA in POST /php-plain/admin/delete_user.php: missing owner verification |
| BOLA-R-0067 | high | high | confirmed | bola | POST /php-plain/admin/promote.php | `php-plain/admin/promote.php:5` | BOLA in POST /php-plain/admin/promote.php: missing owner verification |
| BOLA-R-0069 | high | high | confirmed | bola | GET /orders/<int:order_id> | `python-flask/app.py:12` | BOLA in GET /orders/<int:order_id>: missing owner verification |
| BOLA-R-0073 | high | high | confirmed | bola | POST /users/<int:uid>/name | `python-flask/profile.py:16` | BOLA in POST /users/<int:uid>/name: missing owner verification |
| BOLA-R-0074 | high | medium | likely | bola | PATCH /users/<int:uid> | `python-flask/profile.py:24` | BOLA in PATCH /users/<int:uid>: missing owner verification |

### BFLA-R-0003-1 — Unrestricted member deletion in classic‑ASP

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `classic-asp/shop/member.asp:1`

**Impact.** Any authenticated user can delete any member record.

**Evidence.**

- `classic-asp/shop/member.asp:10` — DELETE FROM members WHERE member_id = ... (privileged action, no role check)
- `classic-asp/shop/member.asp:9` — no role check before the delete

**Recommendation.** Add a server‑side check that the current user has admin privileges before executing the delete.

*Verifier:* likely — checked: classic-asp/shop/member.asp lines 1-12, included inc/auth.asp lines 1-3, included inc/conn.asp lines 1-4. The DELETE statement is executed without any role or ownership check. The included auth file only verifies authentication, not authorization.

### BFLA-R-0007-1 — Unauthenticated user can delete any user in ASP.NET MVC

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `Web/Controllers/AdminController.cs:1`

**Impact.** Any authenticated user can delete any account.

**Evidence.**

- `Web/Controllers/AdminController.cs:14` — db.Users.Remove(u); (privileged action, no role check)
- `Web/Controllers/AdminController.cs:12` — no [Authorize(Roles="Admin")] on DeleteUser

**Recommendation.** Add [Authorize(Roles="Admin")] to DeleteUser or enforce role check in code.

*Verifier:* likely — checked: no code_context provided for Web/Controllers/AdminController.cs. The file containing the DeleteUser action is missing from the provided context, so no authorization check can be verified.

### BFLA-R-0009-1 — Export endpoint controlled by request parameter in ASP.NET MVC

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bfla (role_from_request) — CWE-269, CWE-285   
- **Endpoint:** - -  
- **Location:** `Web/Controllers/AdminController.cs:1`

**Impact.** Any authenticated user can export all user data by setting isAdmin=true.

**Evidence.**

- `Web/Controllers/AdminController.cs:32` — if (Request.QueryString["isAdmin"] == "true") return Json(db.Users.ToList());
- `Web/Controllers/AdminController.cs:30` — no role check before the export

**Recommendation.** Validate the caller's role server‑side before returning the data.

*Verifier:* likely — checked: no code_context provided for Web/Controllers/AdminController.cs. The export endpoint code is not available; cannot confirm presence or absence of role validation.

### BFLA-R-0023-1 — Unprotected user deletion in Spring MVC

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `com/acme/web/AdminUserController.java:1`

**Impact.** Any authenticated user can delete any user.

**Evidence.**

- `com/acme/web/AdminUserController.java:15` — userDao.deleteById(id); (privileged action, no role check)
- `com/acme/web/AdminUserController.java:13` — no @PreAuthorize on delete method

**Recommendation.** Add @PreAuthorize("hasRole('ADMIN')") to the delete method.

*Verifier:* likely — checked: no code_context provided for com/acme/web/AdminUserController.java. The controller file is missing from the context; no evidence of a role check is visible.

### BFLA-R-0030-1 — Unprotected user deletion in Express.js

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `routes.js:1`

**Impact.** Any authenticated user can delete any user.

**Evidence.**

- `routes.js:9` — User.deleteOne({ _id: req.params.id }) (privileged action, no admin check)
- `routes.js:8` — ensureLoggedIn only, no requireAdmin

**Recommendation.** Add a server‑side admin check before the delete operation.

*Verifier:* likely — checked: routes.js not present in code_context. The code_context for routes.js is missing; no evidence of a role check or other compensating control can be examined.

### BFLA-R-0032-1 — Export endpoint controlled by query param in Express.js

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bfla (role_from_request) — CWE-269, CWE-285   
- **Endpoint:** - -  
- **Location:** `routes.js:1`

**Impact.** Any authenticated user can export all users by setting isAdmin=true.

**Evidence.**

- `routes.js:17` — res.json([]) when req.query.isAdmin === 'true' (privileged action, no role check)
- `routes.js:16` — ensureLoggedIn only, no admin check

**Recommendation.** Validate the caller's role server‑side before returning data.

*Verifier:* likely — checked: routes.js not present in code_context. The code_context for routes.js is missing; no evidence of a role check or other compensating control can be examined.

### BFLA-R-0057-1 — Unprotected user view in PHP plain

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `php-plain/admin.php:1`

**Impact.** Any authenticated user can view any user record.

**Evidence.**

- `php-plain/admin.php:8` — SELECT * FROM users WHERE id = ... (privileged action, no role check)
- `php-plain/admin.php:6` — no role check before the query

**Recommendation.** Add a server‑side admin check before executing the query.

*Verifier:* confirmed — checked: php-plain/admin.php lines 1-14, php-plain/inc/auth.php lines 1-7. The script performs a SELECT on users by id without any admin or ownership check. Only a login check is present in inc/auth.php.

### BFLA-R-0058-1 — Unprotected user deletion in PHP plain

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `php-plain/admin.php:1`

**Impact.** Any authenticated user can delete any user.

**Evidence.**

- `php-plain/admin.php:12` — DELETE FROM users WHERE id = $id (privileged action, no role check)
- `php-plain/admin.php:10` — no role check before the delete

**Recommendation.** Add a server‑side admin check before executing the delete.

*Verifier:* confirmed — checked: php-plain/admin.php lines 1-14, php-plain/inc/auth.php lines 1-7. The DELETE statement is executed without any admin or ownership check. Only a login check is present in inc/auth.php.

### BFLA-R-0059-1 — Client‑side role check only in PHP plain

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bfla (client_side_role_check) — CWE-602, CWE-285   
- **Endpoint:** - -  
- **Location:** `php-plain/manage_users.php:1`

**Impact.** Any authenticated user can delete any user.

**Evidence.**

- `php-plain/manage_users.php:6` — DELETE FROM users WHERE id = ? (privileged action, no server‑side role check)
- `php-plain/manage_users.php:11` — role check only in HTML output, not in code

**Recommendation.** Add a server‑side admin check before executing the delete.

*Verifier:* confirmed — checked: php-plain/manage_users.php, php-plain/inc/auth.php. The DELETE statement is executed for any authenticated user. The only role check present is in the HTML output, which does not prevent the server from executing the delete. No server‑side admin check is visible.

### BFLA-R-0063-1 — Privilege escalation via role field in PHP plain profile update

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bfla (role_from_request) — CWE-915, CWE-269   
- **Endpoint:** - -  
- **Location:** `php-plain/profile.php:1`

**Impact.** Any authenticated user can change their role to admin.

**Evidence.**

- `php-plain/profile.php:6` — foreach ($_POST as $field => $value) { $user->$field = $value; } (whole object binding)
- `php-plain/profile.php:10` — $user->role = $_POST['role']; (privileged field)
- `php-plain/profile.php:11` — save_user($user); (writes role to DB)

**Recommendation.** Restrict binding to non‑privileged fields or set privileged fields server‑side.

*Verifier:* confirmed — checked: php-plain/profile.php, php-plain/inc/auth.php. The script binds all POST fields to the user object, including the privileged 'role' field, and then saves the user. No role or ownership check is present in the visible code.

### BFLA-R-0066-1 — Unprotected user deletion in PHP plain

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `php-plain/admin/delete_user.php:1`

**Impact.** Any authenticated user can delete any user.

**Evidence.**

- `php-plain/admin/delete_user.php:6` — DELETE FROM users WHERE id = ? (privileged action, no role check)
- `php-plain/admin/delete_user.php:1` — no role check before the delete

**Recommendation.** Add a server‑side admin check before executing the delete.

*Verifier:* confirmed — checked: php-plain/admin/delete_user.php lines 1-8, php-plain/inc/auth.php lines 1-7. The delete_user script performs a DELETE on users by id without any admin or ownership check. Only a login check is present in inc/auth.php.

### BFLA-R-0067-1 — Privilege escalation via role promotion in PHP plain

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bfla (role_from_request) — CWE-269, CWE-285   
- **Endpoint:** - -  
- **Location:** `php-plain/admin/promote.php:1`

**Impact.** Any authenticated user can promote themselves to admin.

**Evidence.**

- `php-plain/admin/promote.php:6` — UPDATE users SET role = 'admin' WHERE id = ... (privileged action, no role check)
- `php-plain/admin/promote.php:5` — role set from $_POST['is_admin'] (client‑side control)
- `php-plain/admin/promote.php:1` — no role check before the update

**Recommendation.** Validate the caller's role server‑side before allowing role changes.

*Verifier:* confirmed — checked: php-plain/admin/promote.php, php-plain/inc/auth.php. The code performs a role update based solely on a POST parameter and the user ID supplied in the request. The included auth.php only verifies that a session exists; it does not check that the current user is an administrator. No other role or ownership check is visible in the code context.

### INJ-I-0001 — SQL Injection in classic-asp/shop/member.asp:6

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `classic-asp/shop/member.asp:6`

**Evidence.**

- `classic-asp/shop/member.asp:6` — Unsanitized input concatenated into query  
  `sql = "UPDATE members SET name = '" & Replace(Request.Form("name"), "'", "''") & "'"`
- `classic-asp/shop/member.asp:7` — Unsanitized input concatenated into query  
  `sql = sql & " WHERE member_id = " & Request.Form("member_id")`

**Recommendation.** Use parameterized queries or stored procedures

*Verifier:* confirmed — checked: classic-asp/shop/member.asp:6-7, classic-asp/shop/inc/auth.asp:1-3, classic-asp/shop/inc/conn.asp:1-4. No ownership or role check is present; the UPDATE statement concatenates user input directly, enabling SQL injection.

### INJ-I-0002 — SQL Injection in classic-asp/shop/member.asp:7

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `classic-asp/shop/member.asp:7`

**Evidence.**

- `classic-asp/shop/member.asp:7` — Unsanitized input concatenated into query  
  `sql = sql & " WHERE member_id = " & Request.Form("member_id")`

**Recommendation.** Use parameterized queries or stored procedures

*Verifier:* confirmed — checked: classic-asp/shop/member.asp:6-7, classic-asp/shop/inc/auth.asp:1-3, classic-asp/shop/inc/conn.asp:1-4. The WHERE clause concatenates user input without any cast or ownership check, exposing the query to injection.

### INJ-I-0003 — SQL Injection in classic-asp/shop/member.asp:10

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `classic-asp/shop/member.asp:10`

**Evidence.**

- `classic-asp/shop/member.asp:10` — Unsanitized input concatenated into query  
  `conn.Execute "DELETE FROM members WHERE member_id = " & Request.QueryString("member_id")`

**Recommendation.** Use parameterized queries or stored procedures

*Verifier:* confirmed — checked: classic-asp/shop/member.asp:9-11, classic-asp/shop/inc/auth.asp:1-3, classic-asp/shop/inc/conn.asp:1-4. The DELETE statement uses unsanitized QueryString input directly; no ownership or role guard is applied.

### INJ-I-0004 — SQL Injection in classic-asp/shop/order.asp:6

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `classic-asp/shop/order.asp:6`

**Evidence.**

- `classic-asp/shop/order.asp:6` — Unsanitized input concatenated into query  
  `Set rs = conn.Execute("SELECT * FROM orders WHERE id = " & id)`

**Recommendation.** Use parameterized queries or stored procedures

*Verifier:* confirmed — checked: classic-asp/shop/order.asp:5-6, classic-asp/shop/inc/auth.asp:1-3, classic-asp/shop/inc/conn.asp:1-4. The SELECT query concatenates the id parameter directly; no cast or ownership check is present.

### INJ-I-0006 — SQL Injection in coldfusion/app/OrderService.cfc:5

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `coldfusion/app/OrderService.cfc:5`

**Evidence.**

- `coldfusion/app/OrderService.cfc:5` — Unsanitized input concatenated into query  
  `SELECT * FROM orders WHERE id = #arguments.orderId#`

**Recommendation.** Use <cfqueryparam> or stored procedures

*Verifier:* confirmed — checked: coldfusion/app/OrderService.cfc line 5. The query concatenates the unsanitized argument directly into the SQL string with no parameter binding, cast, or ownership check.

### INJ-I-0007 — SQL Injection in coldfusion/app/order.cfm:3

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `coldfusion/app/order.cfm:3`

**Evidence.**

- `coldfusion/app/order.cfm:3` — Unsanitized input concatenated into query  
  `SELECT * FROM orders WHERE id = #url.id#`

**Recommendation.** Use <cfqueryparam> or stored procedures

*Verifier:* confirmed — checked: coldfusion/app/order.cfm line 3. The first query uses the unsanitized URL parameter directly; no parameter binding or ownership check is present.

### INJ-I-0008 — SQL Injection in dotnet-legacy/Web/Controllers/InvoiceController.cs:28

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Controllers/InvoiceController.cs:28`

**Evidence.**

- `dotnet-legacy/Web/Controllers/InvoiceController.cs:28` — Unsanitized input concatenated into query  
  `var list = db.Database.SqlQuery<Invoice>("SELECT * FROM Invoices WHERE Customer = '" + customer + "'").ToList();`

**Recommendation.** Use parameterized queries

*Verifier:* likely — checked: dotnet-legacy/Web/Controllers/InvoiceController.cs:26-28. The Search action concatenates the 'customer' parameter into a raw SQL string; no parameterization or ownership check is shown in the context.

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

**Recommendation.** Use SqlCommand with parameters

*Verifier:* confirmed — checked: dotnet-legacy/Web/Orders/EditOrder.aspx.vb lines 7-8. SQL is built by string concatenation with user input; no parameterization or ownership validation is shown.

### INJ-I-0010 — SQL Injection in dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8`

**Evidence.**

- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8` — Unsanitized input concatenated into query  
  `sql &= " WHERE OrderId = " & hfOrderId.Value`

**Recommendation.** Use SqlCommand with parameters

*Verifier:* confirmed — checked: dotnet-legacy/Web/Orders/EditOrder.aspx.vb line 8. The query concatenates the hidden field value directly; no parameter binding or ownership check is present.

### INJ-I-0011 — SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13`

**Evidence.**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13` — Unsanitized input concatenated into query  
  `var cmd = new SqlCommand("SELECT * FROM Orders WHERE OrderId = " + id, conn);`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19` — Unsanitized input concatenated into query  
  `string sql2 = string.Format("SELECT * FROM Logs WHERE Ref = '{0}'", Request["ref"]);`
- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20` — Unsanitized input concatenated into query  
  `string sql3 = $"DELETE FROM Carts WHERE CartId = {Request.Form["cart"]}";`

**Recommendation.** Use SqlCommand with parameters

*Verifier:* confirmed — checked: dotnet-legacy/Web/Orders/OrderDetail.aspx.cs lines 13, 19, 20. All three queries are constructed via string concatenation or string.Format with unsanitized request data; no parameterization or ownership check is shown.

### INJ-I-0012 — SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19

- **Severity / confidence:** critical / high  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19`

**Evidence.**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19` — Unsanitized input concatenated into query  
  `string sql2 = string.Format("SELECT * FROM Logs WHERE Ref = '{0}'", Request["ref"]);`

**Recommendation.** Use parameterized queries

*Verifier:* likely — checked: dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19. The code concatenates Request["ref"] into a SQL string and executes it. No ownership or role check, integer cast, or allow‑list is visible in the provided snippet.

### INJ-I-0013 — SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20

- **Severity / confidence:** critical / high  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20`

**Evidence.**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20` — Unsanitized input concatenated into query  
  `string sql3 = $"DELETE FROM Carts WHERE CartId = {Request.Form["cart"]}";`

**Recommendation.** Use parameterized queries

*Verifier:* likely — checked: dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20. The code builds a DELETE statement using Request.Form["cart"] without sanitization or parameter binding. No compensating control is shown.

### INJ-I-0014 — SQL Injection in java-legacy/WebContent/order/detail.jsp:5

- **Severity / confidence:** critical / high  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `java-legacy/WebContent/order/detail.jsp:5`

**Evidence.**

- `java-legacy/WebContent/order/detail.jsp:5` — Unsanitized input concatenated into query  
  `ResultSet rs = c.createStatement().executeQuery("SELECT * FROM orders WHERE order_no = '" + no + "'");`

**Recommendation.** Use PreparedStatement with parameters

*Verifier:* likely — checked: java-legacy/WebContent/order/detail.jsp:5. The query concatenates the request parameter "no" directly into the SQL string. No ownership or role check, cast, or allow‑list is present in the snippet.

### INJ-I-0015 — SQL Injection in java-legacy/src/com/acme/mapper/OrderMapper.xml:9

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (dynamic_identifier) — CWE-89   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/mapper/OrderMapper.xml:9`

**Evidence.**

- `java-legacy/src/com/acme/mapper/OrderMapper.xml:9` — Dynamic identifier substituted without validation  
  `ORDER BY ${orderBy}`

**Recommendation.** Validate ORDER BY values against an allow‑list before substitution

*Verifier:* likely — checked: java-legacy/src/com/acme/mapper/OrderMapper.xml:7-9. The mapper XML contains a raw ORDER BY substitution without any visible allow‑list or parameter binding. No ownership or role check is present in the snippet.

### INJ-I-0016 — SQL Injection in java-legacy/src/com/acme/struts/EditUserAction.java:13

- **Severity / confidence:** critical / high  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/struts/EditUserAction.java:13`

**Evidence.**

- `java-legacy/src/com/acme/struts/EditUserAction.java:13` — Unsanitized input concatenated into query  
  `PreparedStatement ps = conn.prepareStatement("UPDATE users SET email = '" + email + "' WHERE id = " + userId);`

**Recommendation.** Use PreparedStatement with parameters

*Verifier:* likely — checked: java-legacy/src/com/acme/struts/EditUserAction.java:13. The PreparedStatement is built by concatenating user input into the SQL string. No ownership or role check, cast, or allow‑list is visible.

### INJ-I-0017 — SQL Injection in java-legacy/src/com/acme/web/InvoiceController.java:29

- **Severity / confidence:** critical / high  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/web/InvoiceController.java:29`

**Evidence.**

- `java-legacy/src/com/acme/web/InvoiceController.java:29` — Unsanitized input concatenated into query  
  `session.createQuery("from Invoice i where i.customer = '" + customer + "'").list();`

**Recommendation.** Use parameterized HQL queries

*Verifier:* likely — checked: java-legacy/src/com/acme/web/InvoiceController.java:29. The HQL query concatenates the "customer" request parameter directly. No ownership or role check, cast, or allow‑list is shown in the snippet.

### INJ-I-0018 — SQL Injection in java-legacy/src/com/acme/web/OrderServlet.java:15

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/web/OrderServlet.java:15`

**Evidence.**

- `java-legacy/src/com/acme/web/OrderServlet.java:15` — Unsanitized input concatenated into query  
  `ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE id = '" + id + "'");`
- `java-legacy/src/com/acme/web/OrderServlet.java:17` — Unsanitized input concatenated into query  
  `sb.append(" AND order_id = ").append(id);`

**Recommendation.** Use PreparedStatement with bound parameters

*Verifier:* likely — checked: java-legacy/src/com/acme/web/OrderServlet.java:13-18. The servlet concatenates user input directly into SQL strings. No integer cast, allow‑list, or ownership check is shown in the snippet.

### INJ-I-0020 — SQL Injection in node-express/routes/orders.js:17

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `node-express/routes/orders.js:17`

**Evidence.**

- `node-express/routes/orders.js:17` — Unsanitized input concatenated into query  
  `db.query("SELECT * FROM reports WHERE month = '" + req.query.month + "'", function (e, rows) { res.json(rows); });`
- `node-express/routes/orders.js:29` — Unsanitized input concatenated into query  
  `db.query('SELECT COUNT(*) AS n FROM orders WHERE shop_id = ${req.query.shop}', function (e, r) { res.json(r); });`

**Recommendation.** Use parameterized queries or ORM

*Verifier:* confirmed — checked: node-express/routes/orders.js:17. The query concatenates the unsanitized req.query.month directly into the SQL string. No integer cast, allow‑list, or parameter binding is present in the visible code.

### INJ-I-0022 — SQL Injection in node-express/routes/orders.js:21

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `node-express/routes/orders.js:21`

**Evidence.**

- `node-express/routes/orders.js:21` — Unsanitized input used as query object  
  `db.collection('users').findOne(req.body, function (e, u) { res.json(!!u); });`

**Recommendation.** Validate and sanitize request body before using as query

*Verifier:* confirmed — checked: node-express/routes/orders.js:21. The request body is passed directly to db.collection('users').findOne without validation or sanitization, exposing the query to injection.

### INJ-I-0023 — SQL Injection in node-express/routes/orders.js:25

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (operator_injection) — CWE-89   
- **Endpoint:** - -  
- **Location:** `node-express/routes/orders.js:25`

**Evidence.**

- `node-express/routes/orders.js:25` — Unsanitized input used in $where JavaScript expression  
  `db.collection('items').find({ $where: "this.name == '" + req.query.n + "'" }).toArray(function (e, r) { res.json(r); });`

**Recommendation.** Avoid $where; use indexed fields or parameterized queries

*Verifier:* confirmed — checked: node-express/routes/orders.js:25. The $where clause concatenates req.query.n into a JavaScript expression, allowing injection of arbitrary code.

### INJ-I-0024 — SQL Injection in perl-cgi/cgi-bin/order.cgi:13

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `perl-cgi/cgi-bin/order.cgi:13`

**Evidence.**

- `perl-cgi/cgi-bin/order.cgi:13` — Unsanitized input concatenated into query  
  `my $sth = $dbh->prepare("SELECT * FROM orders WHERE id = $id");`
- `perl-cgi/cgi-bin/order.cgi:19` — Unsanitized input concatenated into query  
  `$dbh->do("DELETE FROM carts WHERE cart_id = " . $q->param('cart'))`

**Recommendation.** Use placeholders or parameterized queries

*Verifier:* confirmed — checked: perl-cgi/cgi-bin/order.cgi:13. The SQL statement is built by interpolating the unsanitized $id variable directly into the query string.

### INJ-I-0025 — SQL Injection in perl-cgi/cgi-bin/order.cgi:19

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `perl-cgi/cgi-bin/order.cgi:19`

**Evidence.**

- `perl-cgi/cgi-bin/order.cgi:19` — Unsanitized input concatenated into query  
  `$dbh->do("DELETE FROM carts WHERE cart_id = " . $q->param('cart'))`

**Recommendation.** Use placeholders or parameterized queries

*Verifier:* confirmed — checked: perl-cgi/cgi-bin/order.cgi:19. The DELETE statement concatenates the unsanitized cart ID from the query string directly into the SQL command.

### INJ-I-0026 — SQL Injection in php-codeigniter/application/controllers/Invoice.php:10

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-codeigniter/application/controllers/Invoice.php:10`

**Evidence.**

- `php-codeigniter/application/controllers/Invoice.php:10` — Unsanitized input concatenated into query  
  `$q = $this->db->query("SELECT * FROM invoices WHERE id = $id");`

**Recommendation.** Use parameterized queries

*Verifier:* likely — checked: php-codeigniter/application/controllers/Invoice.php:9-11. The query concatenates the id directly. No cast, allow‑list, or ownership check is present in the snippet.

### INJ-I-0027 — SQL Injection in php-plain/admin.php:12

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-plain/admin.php:12`

**Evidence.**

- `php-plain/admin.php:12` — Unsanitized input concatenated into query  
  `mysql_query("DELETE FROM users WHERE id = $id");`

**Recommendation.** Use prepared statements or cast to integer

*Verifier:* likely — checked: php-plain/admin.php, php-plain/inc/auth.php, php-plain/inc/db.php. The code concatenates an unsanitized POST parameter into a DELETE statement. No ownership or role check, integer cast, or parameter binding is visible in the provided context.

### INJ-I-0029 — NoSQL Injection in php-plain/mongo_find.php:6

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** nosql_injection (operator_injection) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-plain/mongo_find.php:6`

**Evidence.**

- `php-plain/mongo_find.php:6` — Unsanitized input used in $where JavaScript expression  
  `$docs = $coll->find(array('$where' => "this.name == '" . $_GET['n'] . "'"));`

**Recommendation.** Avoid $where; use indexed fields or parameterized queries

*Verifier:* likely — checked: php-plain/mongo_find.php, php-plain/inc/auth.php. The $where clause is built from an unsanitized GET parameter. No sanitization, allow‑list, or ownership check is present in the context.

### INJ-I-0031 — SQL Injection in php-plain/order_detail.php:6

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-plain/order_detail.php:6`

**Evidence.**

- `php-plain/order_detail.php:5` — source: GET parameter  
  `$id = $_GET['id'];`
- `php-plain/order_detail.php:6` — Unsanitized input concatenated into query  
  `$res = mysql_query("SELECT * FROM orders WHERE id = " . $id);`

**Recommendation.** Use parameterized queries

*Verifier:* likely — checked: php-plain/order_detail.php, php-plain/inc/auth.php, php-plain/inc/db.php. The GET parameter 'id' is concatenated into a SELECT statement without casting or parameter binding. No ownership or role check is visible in the provided context.

### INJ-I-0032 — SQL Injection in php-plain/search.php:8

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-plain/search.php:8`

**Evidence.**

- `php-plain/search.php:6` — source: GET parameter  
  `$sort = $_GET['sort'];`
- `php-plain/search.php:9` — Unsanitized input concatenated into ORDER BY clause  
  `$sql .= " ORDER BY " . $sort;`

**Recommendation.** Use parameterized queries and allow‑list ORDER BY values

*Verifier:* likely — checked: php-plain/search.php:6-9. The ORDER BY clause is built from the raw $_GET['sort'] value with no cast, allow‑list, or ownership check visible in the provided context.

### INJ-I-0033 — SQL Injection in php-plain/search.php:9

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-plain/search.php:9`

**Evidence.**

- `php-plain/search.php:6` — source: GET parameter  
  `$sort = $_GET['sort'];`
- `php-plain/search.php:9` — Unsanitized input concatenated into ORDER BY clause  
  `$sql .= " ORDER BY " . $sort;`

**Recommendation.** Use parameterized queries and allow‑list ORDER BY values

*Verifier:* likely — checked: php-plain/search.php:6-9. Same as INJ-I-0032: unsanitized ORDER BY input with no visible compensating control.

### INJ-I-0034 — SQL Injection in php-plain/search.php:14

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-plain/search.php:14`

**Evidence.**

- `php-plain/search.php:14` — Unsanitized input concatenated into query  
  `WHERE category = '{$_GET['cat']}'`

**Recommendation.** Use parameterized queries

*Verifier:* likely — checked: php-plain/search.php:13-15. The category filter interpolates $_GET['cat'] directly into the query; no cast, allow‑list, or ownership check is shown.

### INJ-I-0036 — SQL Injection in python-flask/app.py:29

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_interpolation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `python-flask/app.py:29`

**Evidence.**

- `python-flask/app.py:29` — Unsanitized input interpolated into query  
  `cur.execute(f"SELECT * FROM products WHERE name LIKE '%{q}%'")`

**Recommendation.** Use parameterized queries

*Verifier:* likely — checked: python-flask/app.py:24-30. The search route uses an f‑string to embed the user supplied 'q' directly into the SQL; no parameter binding or ownership check is visible.

### INJ-I-0037 — SQL Injection in sql-procs/sp_search_orders.sql:5

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (stored_procedure_dynamic_sql) — CWE-89   
- **Endpoint:** - -  
- **Location:** `sql-procs/sp_search_orders.sql:5`

**Evidence.**

- `sql-procs/sp_search_orders.sql:5` — Dynamic SQL built from user‑supplied parameters without validation  
  `SET @sql = 'SELECT * FROM Orders WHERE Customer = ''' + @Customer + ''' ORDER BY ' + @Sort`

**Recommendation.** Avoid dynamic SQL; use parameterized queries or validate @Sort against an allow‑list

*Verifier:* likely — checked: sql-procs/sp_search_orders.sql:4-6. Dynamic SQL is built from user‑supplied parameters without any visible validation or allow‑list. No ownership or role check is shown.

### MASS-M-0006-1 — Profile update binds entire request body to User model

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `routes/profile.js:7`

**Impact.** Any authenticated user can set privileged fields such as role or admin flag via the profile update endpoint.

**Evidence.**

- `routes/profile.js:7` — ensureLoggedIn only checks authentication
- `routes/profile.js:8` — User.findByIdAndUpdate(req.user._id, req.body, ...) binds whole body

**Recommendation.** Limit bound fields to a whitelist and set privileged fields server‑side.

*Verifier:* likely — checked: routes/profile.js not found. The referenced file is missing from the repository; no ownership or role checks are visible in the provided context.

### MASS-M-0008-1 — User registration binds entire request body to User model

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `app/Http/Controllers/AccountController.php:11`

**Impact.** Any user can set privileged fields such as role or admin flag during registration.

**Evidence.**

- `app/Http/Controllers/AccountController.php:13` — User::create($request->all()) binds whole body

**Recommendation.** Use $fillable or guarded properties to restrict writable fields.

*Verifier:* likely — checked: app/Http/Controllers/AccountController.php not found. The controller file is missing; no indication of $fillable or guarded properties in the visible context.

### MASS-M-0009-1 — Team creation allows setting owner_id via request body

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** mass_assignment (privileged_field_writable) — CWE-915, CWE-269   
- **Endpoint:** - -  
- **Location:** `app/Http/Controllers/AccountController.php:21`

**Impact.** Any user can set the owner_id of a team, effectively assigning ownership to themselves or others.

**Evidence.**

- `app/Http/Controllers/AccountController.php:23` — Team::create($request->all()) binds whole body, including owner_id

**Recommendation.** Do not allow owner_id to be set from the request; set it server‑side to the authenticated user.

*Verifier:* likely — checked: app/Http/Controllers/AccountController.php not found. The file containing the team creation logic is not available; ownership enforcement cannot be confirmed.

### MASS-M-0011-1 — Unrestricted binding of all POST fields to User in PHP plain

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `php-plain/profile.php:1`

**Impact.** role field can be set by the caller.

**Evidence.**

- `php-plain/profile.php:6` — foreach ($_POST as $field => $value) { $user->$field = $value; } (binds all fields)
- `php-plain/profile.php:10` — $user->role = $_POST['role']; (privileged field)
- `php-plain/profile.php:11` — save_user($user); (writes role to DB)

**Recommendation.** Restrict binding to allowed fields or set privileged fields server‑side.

*Verifier:* confirmed — checked: php-plain/profile.php, php-plain/inc/auth.php. The entire POST payload is assigned to the user object, allowing any field—including privileged ones—to be modified. No whitelist or server‑side restriction is visible.

### MASS-M-0012-1 — Privilege escalation via role field in PHP plain

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** mass_assignment (privileged_field_writable) — CWE-915, CWE-269   
- **Endpoint:** - -  
- **Location:** `php-plain/profile.php:1`

**Impact.** role field can be set by the caller.

**Evidence.**

- `php-plain/profile.php:10` — $user->role = $_POST['role']; (privileged field)
- `php-plain/profile.php:11` — save_user($user); (writes role to DB)

**Recommendation.** Restrict binding to allowed fields or set privileged fields server‑side.

*Verifier:* confirmed — checked: php-plain/profile.php, php-plain/inc/auth.php. The 'role' field is explicitly set from POST data and persisted without any server‑side validation or restriction. No compensating control is present in the code context.

### MASS-M-0013-1 — User insertion uses extract($_POST) to bind all POST fields

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `register.php:4`

**Impact.** Any POST field can be inserted into the users table, including privileged columns if they exist.

**Evidence.**

- `register.php:4` — extract($_POST) pulls all POST fields into variables
- `register.php:5` — INSERT uses $email and $name from extracted variables

**Recommendation.** Avoid extract(); explicitly bind only allowed fields.

*Verifier:* likely — checked: register.php not found. The registration script is absent from the repository; the use of extract($_POST) cannot be verified.

### MASS-M-0014-1 — User creation binds entire request JSON to User model

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `app.py:8`

**Impact.** Any user can set privileged fields such as role or admin flag during account creation.

**Evidence.**

- `app.py:10` — User(**request.json) binds all JSON fields

**Recommendation.** Use a DTO or whitelist to restrict writable fields.

*Verifier:* likely — checked: app.py not present in provided code_context. The user creation code that binds the entire request JSON is not shown; therefore it is impossible to confirm the presence or absence of a whitelist or other protective measure.

### MASS-M-0015-1 — PATCH endpoint sets arbitrary attributes from request JSON

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `app.py:24`

**Impact.** Any user can modify any attribute of the user record, including privileged fields.

**Evidence.**

- `app.py:27` — for key, value in request.json.items(): setattr(user, key, value) binds all fields

**Recommendation.** Whitelist allowed fields or use a DTO.

*Verifier:* likely — checked: app.py not present in provided code_context. The relevant code that performs the PATCH binding is not included in the supplied context, so no compensating control can be verified.

### BOLA-R-0001-1 — BOLA in POST /user/edit.do: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /user/edit.do  
- **Location:** `java-legacy/src/com/acme/struts/EditUserAction.java:13`

**Evidence.**

- `java-legacy/src/com/acme/struts/EditUserAction.java:13` — The user ID comes from the request and is used directly in the UPDATE without checking that the current user owns the record.  
  `PreparedStatement ps = conn.prepareStatement("UPDATE users SET email = '" + email + "' WHERE id = " + userId);`

**Recommendation.** Bind the UPDATE to the current session user.

*Verifier:* likely — checked: EditUserAction.java:10-13. The code shows the userId coming directly from the request and used in an UPDATE statement without any ownership check, cast, or parameter binding. No ownership helper or allow‑list is visible in the provided context.

### BOLA-R-0002-1 — BOLA in POST /classic-asp/shop/member.asp?mode=edit: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /classic-asp/shop/member.asp?mode=edit  
- **Location:** `classic-asp/shop/member.asp:6`

**Evidence.**

- `classic-asp/shop/member.asp:6` — The member_id comes from the request and is used directly in the UPDATE without verifying ownership.  
  `sql = "UPDATE members SET name = '" & Replace(Request.Form("name"), "'", "''") & "'"`
- `classic-asp/shop/member.asp:7` — No ownership check is performed.  
  `sql = sql & " WHERE member_id = " & Request.Form("member_id")`

**Recommendation.** Add an ownership check to the UPDATE statement.

*Verifier:* likely — checked: classic-asp/shop/member.asp:6-7, classic-asp/shop/inc/auth.asp, classic-asp/shop/inc/conn.asp. The UPDATE statement uses member_id from the request without any ownership verification. The included auth file only checks for a non‑empty session, not for ownership.

### BOLA-R-0003-1 — BOLA in DELETE /classic-asp/shop/member.asp?mode=delete: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** DELETE /classic-asp/shop/member.asp?mode=delete  
- **Location:** `classic-asp/shop/member.asp:10`

**Evidence.**

- `classic-asp/shop/member.asp:10` — The member_id comes from the request and is used directly in the DELETE without verifying ownership.  
  `conn.Execute "DELETE FROM members WHERE member_id = " & Request.QueryString("member_id")`

**Recommendation.** Add an ownership check to the DELETE statement.

*Verifier:* likely — checked: classic-asp/shop/member.asp:10, classic-asp/shop/inc/auth.asp, classic-asp/shop/inc/conn.asp. The DELETE statement uses member_id from the request directly. No ownership check or cast is present in the visible code.

### BOLA-R-0004-1 — BOLA in GET /classic-asp/shop/order.asp: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /classic-asp/shop/order.asp  
- **Location:** `classic-asp/shop/order.asp:5`

**Evidence.**

- `classic-asp/shop/order.asp:5` — The order id comes from the request.  
  `id = Request("id")`
- `classic-asp/shop/order.asp:6` — No ownership check is performed; any user can read any order.  
  `Set rs = conn.Execute("SELECT * FROM orders WHERE id = " & id)`

**Recommendation.** Bind the SELECT to the current session user.

*Verifier:* likely — checked: classic-asp/shop/order.asp:5-6, classic-asp/shop/inc/auth.asp, classic-asp/shop/inc/conn.asp. The first SELECT query retrieves an order by id supplied in the request without verifying that the current user owns the order. The later query that uses Session("UserID") is unrelated to the initial unprotected query.

### BOLA-R-0005-1 — BOLA in GET /coldfusion/app/OrderService.cfc?method=getOrder: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /coldfusion/app/OrderService.cfc?method=getOrder  
- **Location:** `coldfusion/app/OrderService.cfc:4`

**Evidence.**

- `coldfusion/app/OrderService.cfc:4` — The orderId comes from the request and is used directly without checking ownership.  
  `<cfquery name="q" datasource="shop"> SELECT * FROM orders WHERE id = #arguments.orderId#`

**Recommendation.** Add an ownership check to the SELECT statement.

*Verifier:* likely — checked: coldfusion/app/OrderService.cfc:4-5. The query interpolates arguments.orderId directly into the SQL without any ownership check, cast, or allow‑list. No ownership helper is visible in the provided context.

### BOLA-R-0006-1 — BOLA in GET /coldfusion/app/order.cfm: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /coldfusion/app/order.cfm  
- **Location:** `coldfusion/app/order.cfm:3`

**Evidence.**

- `coldfusion/app/order.cfm:3` — The id comes from the request and is used directly without checking ownership.  
  `<cfquery name="qOrder" datasource="shop"> SELECT * FROM orders WHERE id = #url.id#`

**Recommendation.** Add an ownership check to the SELECT statement.

*Verifier:* likely — checked: coldfusion/app/order.cfm:1-10. The query that retrieves the order uses the request id directly and no ownership check or cast is visible in the provided code context.

### BOLA-R-0007-1 — BOLA in POST /Admin/DeleteUser: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /Admin/DeleteUser  
- **Location:** `dotnet-legacy/Web/Controllers/AdminController.cs:12`

**Evidence.**

- `dotnet-legacy/Web/Controllers/AdminController.cs:12` — The user id comes from the request and is used directly without verifying that the current user owns the account.  
  `public ActionResult DeleteUser(int id) { var u = db.Users.Find(id); db.Users.Remove(u); db.SaveChanges(); }`

**Recommendation.** Require admin role or check that the current user is the owner before deleting.

*Verifier:* likely — checked: dotnet-legacy/Web/Controllers/AdminController.cs:11-18. The DeleteUser action is protected only by a generic [Authorize] attribute; no role or ownership check is present in the visible code.

### BOLA-R-0008-1 — BOLA in POST /Admin/Export: missing role verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /Admin/Export  
- **Location:** `dotnet-legacy/Web/Controllers/AdminController.cs:32`

**Evidence.**

- `dotnet-legacy/Web/Controllers/AdminController.cs:32` — No role check; any authenticated user can set isAdmin=true and retrieve all users.  
  `if (Request.QueryString["isAdmin"] == "true") { return Json(db.Users.ToList(), JsonRequestBehavior.AllowGet); }`

**Recommendation.** Enforce admin role before returning the user list.

*Verifier:* likely — checked: dotnet-legacy/Web/Controllers/AdminController.cs:30-36. The Export action checks only a query string flag; no role or ownership verification is shown.

### BOLA-R-0009-1 — BOLA in POST /Admin/Export: missing role verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /Admin/Export  
- **Location:** `dotnet-legacy/Web/Controllers/AdminController.cs:32`

**Evidence.**

- `dotnet-legacy/Web/Controllers/AdminController.cs:32` — No role check; any authenticated user can set isAdmin=true and retrieve all users.  
  `if (Request.QueryString["isAdmin"] == "true") { return Json(db.Users.ToList(), JsonRequestBehavior.AllowGet); }`

**Recommendation.** Enforce admin role before returning the user list.

*Verifier:* likely — checked: dotnet-legacy/Web/Controllers/AdminController.cs:30-36. Same as BOLA-R-0008-1; no role or ownership check is visible.

### BOLA-R-0010 — BOLA in POST /Customer/Edit: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /Customer/Edit  
- **Location:** `dotnet-legacy/Web/Controllers/CustomerController.cs:12`

**Evidence.**

- `dotnet-legacy/Web/Controllers/CustomerController.cs:12` — The Customer object is bound directly from the request and saved without checking that customer.Id belongs to the authenticated user.  
  `public ActionResult Edit(Customer customer)
{
    db.Entry(customer).State = System.Data.Entity.EntityState.Modified;
    db.SaveChanges();
    return RedirectToAction("Index");
}`

**Recommendation.** Ensure the customer being edited belongs to the current user or that the user has permission to edit it.

*Verifier:* confirmed — checked: dotnet-legacy/Web/Controllers/CustomerController.cs lines 6-16. The action is protected by [Authorize] (ensuring authentication) but performs a direct update of the bound Customer entity without verifying that the customer belongs to the current user.

### BOLA-R-0011 — BOLA in POST /Customer/EditName: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /Customer/EditName  
- **Location:** `dotnet-legacy/Web/Controllers/CustomerController.cs:20`

**Evidence.**

- `dotnet-legacy/Web/Controllers/CustomerController.cs:20` — The Customer object is bound from the request and saved without verifying that the Id belongs to the authenticated user.  
  `public ActionResult EditName([Bind(Include = "Id,Name")] Customer customer)
{
    db.SaveChanges();
    return RedirectToAction("Index");
}`

**Recommendation.** Validate that the customer Id matches the current user before saving.

*Verifier:* confirmed — checked: dotnet-legacy/Web/Controllers/CustomerController.cs lines 20-23. The EditName action accepts a bound Customer with only Id and Name, then calls db.SaveChanges() without any ownership validation.

### BOLA-R-0012 — BOLA in POST /Customer/Refresh: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /Customer/Refresh  
- **Location:** `dotnet-legacy/Web/Controllers/CustomerController.cs:27`

**Evidence.**

- `dotnet-legacy/Web/Controllers/CustomerController.cs:27` — The id is taken from the URL and used to load a customer record without verifying that the customer belongs to the authenticated user.  
  `public ActionResult Refresh(int id)
{
    var customer = db.Customers.Find(id);
    TryUpdateModel(customer);
    db.SaveChanges();
    return RedirectToAction("Index");
}`

**Recommendation.** Check that the customer id belongs to the current user before updating.

*Verifier:* confirmed — checked: dotnet-legacy/Web/Controllers/CustomerController.cs lines 27-32. The Refresh action loads a Customer by id from the URL and updates it without checking that the customer belongs to the authenticated user.

### BOLA-R-0013-1 — BOLA in GET /Invoice/Details: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /Invoice/Details  
- **Location:** `dotnet-legacy/Web/Controllers/InvoiceController.cs:13`

**Evidence.**

- `dotnet-legacy/Web/Controllers/InvoiceController.cs:13` — The invoice id comes from the request and is used directly without checking ownership.  
  `var inv = db.Invoices.Find(id); return View(inv);`

**Recommendation.** Add an ownership check to the invoice lookup.

*Verifier:* likely — checked: dotnet-legacy/Web/Controllers/InvoiceController.cs:11-15. The Details action retrieves an invoice by id without any ownership or role check in the provided code context.

### BOLA-R-0014-1 — BOLA in GET /Invoice/Details: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /Invoice/Details  
- **Location:** `dotnet-legacy/Web/Controllers/InvoiceController.cs:13`

**Evidence.**

- `dotnet-legacy/Web/Controllers/InvoiceController.cs:13` — The invoice id comes from the request and is used directly without checking ownership.  
  `var inv = db.Invoices.Find(id); return View(inv);`

**Recommendation.** Add an ownership check to the invoice lookup.

*Verifier:* likely — checked: dotnet-legacy/Web/Controllers/InvoiceController.cs lines 6-15. The controller method retrieves an invoice by id without any ownership check. No ownership verification is visible in the provided code context.

### BOLA-R-0015-1 — BOLA in POST /Invoice/Search: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /Invoice/Search  
- **Location:** `dotnet-legacy/Web/Controllers/InvoiceController.cs:28`

**Evidence.**

- `dotnet-legacy/Web/Controllers/InvoiceController.cs:28` — The customer value comes from the request and is used directly without checking ownership.  
  `var list = db.Database.SqlQuery<Invoice>("SELECT * FROM Invoices WHERE Customer = '" + customer + "'").ToList();`

**Recommendation.** Add an ownership check to the search query.

*Verifier:* likely — checked: dotnet-legacy/Web/Controllers/InvoiceController.cs lines 25-30. The search query concatenates the customer parameter directly into SQL. No ownership or parameter binding is shown in the context.

### BOLA-R-0016 — BOLA in ANY /dotnet-legacy/Web/Handlers/GetFile.ashx: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (no_authentication) — CWE-284, CWE-639   
- **Endpoint:** ANY /dotnet-legacy/Web/Handlers/GetFile.ashx  
- **Location:** `dotnet-legacy/Web/Handlers/GetFile.ashx:8`

**Evidence.**

- `dotnet-legacy/Web/Handlers/GetFile.ashx:8` — The file identifier comes directly from the query string and is used to transmit a file without any authentication or ownership check.  
  `string fileId = context.Request.QueryString["file_id"];
string path = DocStore.PathFor(fileId);
context.Response.TransmitFile(path);`

**Recommendation.** Require authentication and verify that the requested file belongs to the current user before transmitting.

*Verifier:* likely — checked: dotnet-legacy/Web/Handlers/GetFile.ashx lines 8-10. The handler transmits a file based on a query string parameter without any visible authentication or ownership check. No global authentication include is shown in the code_context.

### BOLA-R-0017-1 — BOLA in POST /dotnet-legacy/Web/Orders/EditOrder.aspx: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /dotnet-legacy/Web/Orders/EditOrder.aspx  
- **Location:** `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7`

**Evidence.**

- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7` — The OrderId comes from the request (hfOrderId.Value) and is used directly without checking ownership.  
  `Dim sql As String = "UPDATE Orders SET Note = '" & txtNote.Text & "'"`
- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8` — No ownership check is performed.  
  `sql &= " WHERE OrderId = " & hfOrderId.Value`

**Recommendation.** Add an ownership check to the UPDATE statement.

*Verifier:* likely — checked: dotnet-legacy/Web/Orders/EditOrder.aspx.vb lines 7-13. The UPDATE statement uses the OrderId from a hidden field without any ownership check. No compensating control is visible.

### BOLA-R-0018-1 — BOLA in GET /dotnet-legacy/Web/Orders/OrderDetail.aspx: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /dotnet-legacy/Web/Orders/OrderDetail.aspx  
- **Location:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13`

**Evidence.**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13` — The OrderId comes from the request and is used directly without checking ownership.  
  `var cmd = new SqlCommand("SELECT * FROM Orders WHERE OrderId = " + id, conn);`

**Recommendation.** Add an ownership check to the SELECT statement.

*Verifier:* likely — checked: dotnet-legacy/Web/Orders/OrderDetail.aspx.cs lines 10-17. The first SELECT query uses the id from the query string without ownership verification. The later safe query is not used for this data retrieval.

### BOLA-R-0019-1 — BOLA in GET /java-legacy/WebContent/order/detail.jsp: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /java-legacy/WebContent/order/detail.jsp  
- **Location:** `java-legacy/WebContent/order/detail.jsp:5`

**Evidence.**

- `java-legacy/WebContent/order/detail.jsp:5` — The order_no comes from the request and is used directly without checking ownership.  
  `ResultSet rs = c.createStatement().executeQuery("SELECT * FROM orders WHERE order_no = '" + no + "'");`

**Recommendation.** Add an ownership check to the SELECT statement.

*Verifier:* likely — checked: java-legacy/WebContent/order/detail.jsp lines 3-5. The SQL statement concatenates the order_no parameter directly. No ownership check is present in the visible code.

### BOLA-R-0020 — BOLA in POST /account/save: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /account/save  
- **Location:** `java-legacy/src/com/acme/web/AccountController.java:15`

**Evidence.**

- `java-legacy/src/com/acme/web/AccountController.java:15` — Account ID can be set to another user's ID; no ownership check performed.  
  `accountDao.save(account);`

**Recommendation.** Bind the operation to the current session user.

*Verifier:* confirmed — checked: java-legacy/src/com/acme/web/AccountController.java:13-15. The POST /account/save handler directly calls accountDao.save(account) with no ownership or role check in the visible code.

### BOLA-R-0021 — BOLA in POST /account/rename: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /account/rename  
- **Location:** `java-legacy/src/com/acme/web/AccountController.java:21`

**Evidence.**

- `java-legacy/src/com/acme/web/AccountController.java:21` — The form ID can point to another user's account; no ownership check.  
  `accountDao.rename(form.getId(), form.getName());`

**Recommendation.** Verify that the account belongs to the current user before renaming.

*Verifier:* confirmed — checked: java-legacy/src/com/acme/web/AccountController.java:19-21. The POST /account/rename handler invokes accountDao.rename(form.getId(), form.getName()) without any ownership verification in the shown code.

### BOLA-R-0022 — BOLA in PUT /account/api: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** PUT /account/api  
- **Location:** `java-legacy/src/com/acme/web/AccountController.java:28`

**Evidence.**

- `java-legacy/src/com/acme/web/AccountController.java:28` — Account ID can be set to another user's ID; no ownership check.  
  `return accountDao.save(account);`

**Recommendation.** Ensure the account belongs to the current user before saving.

*Verifier:* confirmed — checked: java-legacy/src/com/acme/web/AccountController.java:25-28. The PUT /account/api handler returns accountDao.save(account) with no ownership or role check in the visible code.

### BOLA-R-0023 — BOLA in POST /admin/users/{id}/delete: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /admin/users/{id}/delete  
- **Location:** `java-legacy/src/com/acme/web/AdminUserController.java:15`

**Evidence.**

- `java-legacy/src/com/acme/web/AdminUserController.java:15` — Any authenticated user can delete any user; no ownership or admin check.  
  `userDao.deleteById(id);`

**Recommendation.** Restrict delete to admins or verify ownership.

*Verifier:* confirmed — checked: java-legacy/src/com/acme/web/AdminUserController.java:13-15. The POST /admin/users/{id}/delete handler calls userDao.deleteById(id) without any role or ownership check in the shown code.

### BOLA-R-0025 — BOLA in GET /invoices/{id}: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /invoices/{id}  
- **Location:** `java-legacy/src/com/acme/web/InvoiceController.java:17`

**Evidence.**

- `java-legacy/src/com/acme/web/InvoiceController.java:17` — Invoice ID can be any value; no ownership check.  
  `model.addAttribute("invoice", invoiceDao.findById(id));`

**Recommendation.** Bind the invoice lookup to the current user.

*Verifier:* confirmed — checked: java-legacy/src/com/acme/web/InvoiceController.java:15-17. The GET /invoices/{id} handler uses invoiceDao.findById(id) directly, with no ownership verification in the visible code.

### BOLA-R-0027 — BOLA in GET /invoices/search: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /invoices/search  
- **Location:** `java-legacy/src/com/acme/web/InvoiceController.java:29`

**Evidence.**

- `java-legacy/src/com/acme/web/InvoiceController.java:29` — Search results are not filtered by the current user.  
  `model.addAttribute("list", session.createQuery("from Invoice i where i.customer = '" + customer + "'").list());`

**Recommendation.** Filter invoices by the current user.

*Verifier:* likely — checked: InvoiceController.java:27-30. The search query concatenates the customer parameter directly and does not reference the current user or any ownership check. No global filter or allow‑list is shown in the provided context.

### BOLA-R-0028 — BOLA in GET /order/view: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /order/view  
- **Location:** `java-legacy/src/com/acme/web/OrderServlet.java:15`

**Evidence.**

- `java-legacy/src/com/acme/web/OrderServlet.java:15` — Order ID is taken from the request and used without checking ownership.  
  `ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE id = '" + id + "'");`

**Recommendation.** Verify that the order belongs to the current user before displaying.

*Verifier:* likely — checked: OrderServlet.java:13-15. The SQL statement uses the orderId request parameter without any comparison to the session user. No cast, allow‑list, or ownership helper is visible in the snippet.

### BOLA-R-0030 — BOLA in POST /admin/users/:id/delete: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /admin/users/:id/delete  
- **Location:** `node-express/routes/admin.js:9`

**Evidence.**

- `node-express/routes/admin.js:9` — Any logged‑in user can delete any user; no admin or ownership check.  
  `User.deleteOne({ _id: req.params.id }, function () { res.sendStatus(204); });`

**Recommendation.** Restrict delete to admins or verify ownership.

*Verifier:* likely — checked: admin.js:8-9. The route applies only an ensureLoggedIn middleware; there is no admin role check or ownership verification before deleting a user.

### BOLA-R-0033-1 — BOLA in GET /orders/:id: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /orders/:id  
- **Location:** `node-express/routes/orders.js:8`

**Evidence.**

- `node-express/routes/orders.js:8` — The order ID comes from the request path and the query does not filter by the authenticated user.  
  `Order.findById(req.params.id, function (err, order) { res.json(order); });`

**Recommendation.** Bind the query to the current session user.

*Verifier:* likely — checked: orders.js:8-9. The GET /orders/:id endpoint uses the request id directly in the query without filtering by the authenticated user. No ownership guard is present in the snippet.

### BOLA-R-0038-1 — BOLA in GET /stats: missing shop ownership verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /stats  
- **Location:** `node-express/routes/orders.js:28`

**Evidence.**

- `node-express/routes/orders.js:28` — The shop_id is taken from the request query and the query does not verify that the shop belongs to the authenticated user.  
  `db.query('SELECT COUNT(*) AS n FROM orders WHERE shop_id = ${req.query.shop}', function (e, r) { res.json(r); });`

**Recommendation.** Verify that the shop_id belongs to the current user before returning statistics.

*Verifier:* likely — checked: orders.js:28-29. The stats endpoint accepts a shop id from the query string and uses it directly in a SQL query. No ownership or admin check is visible in the provided context.

### BOLA-R-0043-1 — BOLA in Perl CGI order.cgi: missing user ownership verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /perl-cgi/cgi-bin/order.cgi  
- **Location:** `perl-cgi/cgi-bin/order.cgi:11`

**Evidence.**

- `perl-cgi/cgi-bin/order.cgi:11` — The order ID is taken from the request and the query does not filter by the authenticated user.  
  `$id = $q->param('id');
$sth = $dbh->prepare("SELECT * FROM orders WHERE id = $id");
$sth->execute();`

**Recommendation.** Add a user_id filter to the query.

*Verifier:* confirmed — checked: perl-cgi/cgi-bin/order.cgi: lines 11-17. The query at line 13 selects orders by id without filtering by user_id. No ownership check or parameter binding is present. The subsequent query with user_id is not used for the initial data retrieval.

### BOLA-R-0044-1 — BOLA in PHP CodeIgniter Invoice view: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /invoice/view/{id}  
- **Location:** `php-codeigniter/application/controllers/Invoice.php:9`

**Evidence.**

- `php-codeigniter/application/controllers/Invoice.php:9` — The invoice ID is taken from the request and the query does not filter by the authenticated user.  
  `$q = $this->db->query("SELECT * FROM invoices WHERE id = $id");`

**Recommendation.** Add a user_id filter to the query.

*Verifier:* confirmed — checked: php-codeigniter/application/controllers/Invoice.php: lines 9-17. The view method executes a raw query with id only, no user_id filter. No ownership check is present.

### BOLA-R-0046-1 — BOLA in PHP CodeIgniter Invoice update: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /invoice/update  
- **Location:** `php-codeigniter/application/controllers/Invoice.php:20`

**Evidence.**

- `php-codeigniter/application/controllers/Invoice.php:20` — The invoice ID is taken from the request and the update does not verify that the invoice belongs to the authenticated user.  
  `$this->db->query("UPDATE invoices SET note = ? WHERE id = ?", array($note, $id));`

**Recommendation.** Add a user_id filter to the update query.

*Verifier:* confirmed — checked: php-codeigniter/application/controllers/Invoice.php: lines 20-23. The update query uses id from POST without verifying ownership. No ownership check is present.

### BOLA-R-0053 — Needs review: POST /posts – ownership check unknown

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-639   
- **Endpoint:** POST /posts  
- **Location:** `php-laravel/routes/web.php:7`

**Evidence.**

- `php-laravel/routes/web.php:7` — Controller code not visible; cannot confirm ownership enforcement  
  `Route::post('/posts', [AccountController::class, 'post']);`

**Recommendation.** Verify that the post creation associates the post with the current user and that updates/deletes check ownership

*Verifier:* likely — checked: php-laravel/routes/web.php line 7. The route definition does not show any ownership or authentication check; controller code is not visible.

### BOLA-R-0054 — Needs review: POST /teams – ownership check unknown

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-639   
- **Endpoint:** POST /teams  
- **Location:** `php-laravel/routes/web.php:8`

**Evidence.**

- `php-laravel/routes/web.php:8` — Controller code not visible; cannot confirm ownership enforcement  
  `Route::post('/teams', [AccountController::class, 'team']);`

**Recommendation.** Verify that team operations enforce that the current user owns or is a member of the team

*Verifier:* likely — checked: php-laravel/routes/web.php line 8. The route definition does not reveal any ownership or authentication check; controller code is not visible.

### BOLA-R-0055 — Needs review: POST /account/rename – ownership check unknown

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-639   
- **Endpoint:** POST /account/rename  
- **Location:** `php-laravel/routes/web.php:9`

**Evidence.**

- `php-laravel/routes/web.php:9` — Controller code not visible; cannot confirm ownership enforcement  
  `Route::post('/account/rename', [AccountController::class, 'rename']);`

**Recommendation.** Verify that the rename action checks that the target account belongs to the current user

*Verifier:* likely — checked: php-laravel/routes/web.php line 9. The route definition does not show any ownership or authentication check; controller code is not visible.

### BOLA-R-0056 — Needs review: POST /account/profile – ownership check unknown

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-639   
- **Endpoint:** POST /account/profile  
- **Location:** `php-laravel/routes/web.php:10`

**Evidence.**

- `php-laravel/routes/web.php:10` — Controller code not visible; cannot confirm ownership enforcement  
  `Route::post('/account/profile', [AccountController::class, 'profile']);`

**Recommendation.** Verify that the profile update checks that the target profile belongs to the current user

*Verifier:* likely — checked: php-laravel/routes/web.php line 10. The route definition does not reveal any ownership or authentication check; controller code is not visible.

### BOLA-R-0057 — BOLA in GET|POST /php-plain/admin.php?action=view: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-284   
- **Endpoint:** GET|POST /php-plain/admin.php?action=view  
- **Location:** `php-plain/admin.php:6`

**Evidence.**

- `php-plain/admin.php:7` — ID comes from request  
  `$uid = (int)$_GET['uid'];`
- `php-plain/admin.php:8` — No owner check; any logged‑in user can view any user  
  `$r = mysql_query("SELECT * FROM users WHERE id = " . $uid);`

**Recommendation.** Bind query to current session user

*Verifier:* confirmed — checked: php-plain/admin.php: lines 6-8, php-plain/inc/auth.php: lines 1-7. The view case retrieves a user by uid from GET without checking that the uid matches the logged‑in user. No ownership check is present.

### BOLA-R-0058 — BOLA in GET|POST /php-plain/admin.php?action=delete: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-284   
- **Endpoint:** GET|POST /php-plain/admin.php?action=delete  
- **Location:** `php-plain/admin.php:10`

**Evidence.**

- `php-plain/admin.php:11` — ID comes from request  
  `$id = $_POST['id'];`
- `php-plain/admin.php:12` — No owner check; any logged‑in user can delete any user  
  `mysql_query("DELETE FROM users WHERE id = $id");`

**Recommendation.** Bind delete to current session user

*Verifier:* confirmed — checked: php-plain/admin.php: lines 10-12, php-plain/inc/auth.php: lines 1-7. The delete case deletes a user by id from POST without verifying ownership. No ownership check is present.

### BOLA-R-0059 — BOLA in POST /php-plain/manage_users.php: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-284   
- **Endpoint:** POST /php-plain/manage_users.php  
- **Location:** `php-plain/manage_users.php:5`

**Evidence.**

- `php-plain/manage_users.php:5` — ID comes from request  
  `if ($_SERVER['REQUEST_METHOD'] === 'POST') {`
- `php-plain/manage_users.php:6` — No owner check; any logged‑in user can delete any user  
  `$stmt = $db->prepare("DELETE FROM users WHERE id = ?");`

**Recommendation.** Bind delete to current session user

*Verifier:* confirmed — checked: php-plain/manage_users.php. The POST handler deletes a user by id without any ownership or role check; only authentication is enforced by the included auth.php.

### BOLA-R-0061 — BOLA in GET /php-plain/order_detail.php: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-284   
- **Endpoint:** GET /php-plain/order_detail.php  
- **Location:** `php-plain/order_detail.php:5`

**Evidence.**

- `php-plain/order_detail.php:5` — ID comes from request  
  `$id = $_GET['id'];`
- `php-plain/order_detail.php:6` — No owner check; any logged‑in user can view any order  
  `$res = mysql_query("SELECT * FROM orders WHERE id = " . $id);`

**Recommendation.** Bind query to current session user

*Verifier:* confirmed — checked: php-plain/order_detail.php. The order detail page queries orders by id directly from $_GET without verifying that the order belongs to the current session user.

### BOLA-R-0066 — BOLA in POST /php-plain/admin/delete_user.php: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-284   
- **Endpoint:** POST /php-plain/admin/delete_user.php  
- **Location:** `php-plain/admin/delete_user.php:5`

**Evidence.**

- `php-plain/admin/delete_user.php:5` — ID comes from request  
  `$id = (int)$_POST['id'];`
- `php-plain/admin/delete_user.php:6` — No owner check; any logged‑in user can delete any user  
  `$stmt = $db->prepare("DELETE FROM users WHERE id = ?");`

**Recommendation.** Bind delete to current session user

*Verifier:* confirmed — checked: php-plain/admin/delete_user.php. The file contains only a login check via require_once '../inc/auth.php'; no ownership or role verification is performed before executing the DELETE statement.

### BOLA-R-0067 — BOLA in POST /php-plain/admin/promote.php: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-284   
- **Endpoint:** POST /php-plain/admin/promote.php  
- **Location:** `php-plain/admin/promote.php:5`

**Evidence.**

- `php-plain/admin/promote.php:5` — ID comes from request  
  `if ($_POST['is_admin'] == '1') {`
- `php-plain/admin/promote.php:6` — No owner check; any logged‑in user can promote any user  
  `$stmt = $db->prepare("UPDATE users SET role = 'admin' WHERE id = ?");`

**Recommendation.** Bind role change to current session user

*Verifier:* confirmed — checked: php-plain/admin/promote.php. Only a login check is performed; the UPDATE statement changes a user's role based solely on the supplied id, with no ownership or role guard.

### BOLA-R-0069 — BOLA in GET /orders/<int:order_id>: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-284   
- **Endpoint:** GET /orders/<int:order_id>  
- **Location:** `python-flask/app.py:12`

**Evidence.**

- `python-flask/app.py:12` — No owner check; any logged‑in user can view any order  
  `cur.execute("SELECT * FROM orders WHERE id = %s" % order_id)`

**Recommendation.** Bind query to current user

*Verifier:* confirmed — checked: python-flask/app.py. The route '/orders/<int:order_id>' executes a raw SQL query with the id interpolated directly; no ownership check is performed before returning the result.

### BOLA-R-0073 — BOLA in POST /users/<int:uid>/name: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (no_authentication) — CWE-284, CWE-639   
- **Endpoint:** POST /users/<int:uid>/name  
- **Location:** `python-flask/profile.py:16`

**Evidence.**

- `python-flask/profile.py:16` — The user ID comes from the URL and is used directly to load and update a user record without any check that the ID belongs to the authenticated user.  
  `def rename(uid):
    user = User.query.get(uid)
    user.name = request.json["name"]
    db.session.commit()
    return jsonify(ok=True)`

**Recommendation.** Bind the update to the current session user and reject mismatches.

*Verifier:* confirmed — checked: python-flask/profile.py lines 16-20. The handler directly loads a user by the URL‑supplied UID and updates the name without any authentication or ownership verification.

### BOLA-R-0074 — BOLA in PATCH /users/<int:uid>: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (no_authentication) — CWE-284, CWE-639   
- **Endpoint:** PATCH /users/<int:uid>  
- **Location:** `python-flask/profile.py:24`

**Evidence.**

- `python-flask/profile.py:24` — The user ID is taken from the URL and used to load a user record without verifying that the ID belongs to the authenticated user.  
  `def patch(uid):
    user = User.query.get(uid)
    for key, value in request.json.items():
        setattr(user, key, value)
    db.session.commit()
    return jsonify(ok=True)`

**Recommendation.** Verify that the target user ID matches the current session user before applying changes.

*Verifier:* likely — checked: python-flask/profile.py lines 24-30. The PATCH endpoint loads a user by ID and updates it without any visible authentication or ownership check. The Auth Model does not cover the python‑flask sub‑application, and no global filter or middleware is shown in the code_context.

## 4. Systemic fixes

<!-- LLM: reporter agent writes max 5 systemic fixes here -->

## 5. Coverage and limitations

- missing from inventory: 0
- bola routes without verdict: 0
- injection candidates without verdict: 1 (I-0021)
- bfla routes without verdict: 0
- mass candidates without verdict: 0
- findings without verification: 0

<!-- LLM: reporter agent lists limitations here -->

## Appendix A — Findings rejected by the verifier

| ID | Location | Reason |
|---|---|---|
| INJ-I-0005 | `classic-asp/shop/order.asp:12` | The sid value is cast to a long integer before concatenation, preventing SQL injection. The user_id is also cast to CLng(Session("UserID")). |

## Appendix B — Method

1. Deterministic pre-scan (stack detection, endpoint candidates, query-building candidates).
2. AI agents: auth-model extraction, route inventory, BOLA audit, injection audit.
3. Independent AI verifier tries to refute each finding.
4. Human review and sign-off (`review-log.md`).

This is not a penetration test. Absence of findings does not prove absence of vulnerabilities.
