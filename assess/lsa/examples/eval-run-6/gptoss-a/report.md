# Security Audit Report — repo

> **Classification: CONFIDENTIAL.** AI-assisted static review. All findings require human review (record decisions in `review-log.md`, created from `templates/review-log.md`) before they are shared outside the team.

| Item | Value |
|---|---|
| Date | 2026-11-11 |
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
| Count | 51 | 41 | 15 | 0 | 0 |

| Category | Count |
|---|---|
| bola | 45 |
| sql_injection | 32 |
| nosql_injection | 4 |
| bfla | 12 |
| mass_assignment | 14 |

Status: unverified=0, confirmed=41, likely=66, rejected=2, needs_review=0

## Trend and time to fix

| Date | Open | New | Regressed | Fixed | Suppressed |
|---|---|---|---|---|---|
| 2026-11-11 | 107 | 107 | 0 | 0 | 0 |

No findings fixed yet.

## Outlook & Debt Forecast

> **Note:** Reliable forecasting requires at least 6 scans spanning at least 28 days. Requires at least 6 snapshots over at least 28 days (current: 1 snapshots over 0 days).

## 3. Findings

| ID | Sev | Conf | Status | Category | Endpoint | Location | Title |
|---|---|---|---|---|---|---|---|
| BFLA-R-0003-1 | critical | high | confirmed | bfla |   | `classic-asp/shop/member.asp:10` | Unrestricted member deletion in classic‑asp shop |
| BFLA-R-0007-1 | critical | high | confirmed | bfla |   | `dotnet-legacy/Web/Controllers/AdminController.cs:12` | Unrestricted user deletion in ASP.NET MVC Admin controller |
| BFLA-R-0009-1 | critical | high | confirmed | bfla |   | `dotnet-legacy/Web/Controllers/AdminController.cs:30` | Export endpoint controlled by request parameter in ASP.NET MVC |
| BFLA-R-0023-1 | critical | medium | likely | bfla |   | `java-legacy/src/com/acme/web/AdminUserController.java:13` | Unrestricted user deletion in Spring MVC Admin controller |
| BFLA-R-0030-1 | critical | medium | likely | bfla |   | `node-express/routes/admin.js:8` | Unrestricted user deletion in Express route |
| BFLA-R-0032-1 | critical | medium | likely | bfla |   | `node-express/routes/admin.js:16` | Export endpoint controlled by query param in Express |
| BFLA-R-0057-1 | critical | medium | likely | bfla |   | `php-plain/admin.php:6` | Unrestricted user view in php‑plain admin.php |
| BFLA-R-0058-1 | critical | medium | likely | bfla |   | `php-plain/admin.php:10` | Unrestricted user deletion in php‑plain admin.php |
| BFLA-R-0059-1 | critical | high | confirmed | bfla |   | `php-plain/manage_users.php:6` | Unrestricted user deletion in php‑plain manage_users.php |
| BFLA-R-0063-1 | critical | high | confirmed | bfla |   | `php-plain/profile.php:6` | Unrestricted role change in php‑plain profile.php |
| BFLA-R-0066-1 | critical | high | confirmed | bfla |   | `php-plain/admin/delete_user.php:5` | Unrestricted user deletion in php‑plain delete_user.php |
| BFLA-R-0067-1 | critical | high | confirmed | bfla |   | `php-plain/admin/promote.php:5` | User promotion controlled by request parameter in php‑plain |
| INJ-I-0001 | critical | medium | likely | sql_injection |   | `classic-asp/shop/member.asp:6` | SQL Injection in classic-asp/shop/member.asp:6 |
| INJ-I-0002 | critical | medium | likely | sql_injection |   | `classic-asp/shop/member.asp:7` | SQL Injection in classic-asp/shop/member.asp:7 |
| INJ-I-0003 | critical | medium | likely | sql_injection |   | `classic-asp/shop/member.asp:10` | SQL Injection in classic-asp/shop/member.asp:10 |
| INJ-I-0004 | critical | medium | likely | sql_injection |   | `classic-asp/shop/order.asp:6` | SQL Injection in classic-asp/shop/order.asp:6 |
| INJ-I-0006 | critical | high | confirmed | sql_injection |   | `coldfusion/app/OrderService.cfc:5` | SQL Injection in coldfusion/app/OrderService.cfc:5 |
| INJ-I-0007 | critical | high | confirmed | sql_injection |   | `coldfusion/app/order.cfm:3` | SQL Injection in coldfusion/app/order.cfm:3 |
| INJ-I-0008 | critical | medium | likely | sql_injection |   | `dotnet-legacy/Web/Controllers/InvoiceController.cs:28` | SQL Injection in dotnet-legacy/Web/Controllers/InvoiceController.cs:28 |
| INJ-I-0009 | critical | high | confirmed | sql_injection |   | `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7` | SQL Injection in dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7 |
| INJ-I-0010 | critical | high | confirmed | sql_injection |   | `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8` | SQL Injection in dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8 |
| INJ-I-0011 | critical | high | confirmed | sql_injection |   | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13` | SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13 |
| INJ-I-0012 | critical | high | confirmed | sql_injection |   | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19` | SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19 |
| INJ-I-0013 | critical | high | confirmed | sql_injection |   | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20` | SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20 |
| INJ-I-0014 | critical | high | confirmed | sql_injection |   | `java-legacy/WebContent/order/detail.jsp:5` | SQL Injection in java-legacy/WebContent/order/detail.jsp:5 |
| INJ-I-0015 | critical | medium | likely | sql_injection |   | `java-legacy/src/com/acme/mapper/OrderMapper.xml:9` | SQL Injection in java-legacy/src/com/acme/mapper/OrderMapper.xml:9 |
| INJ-I-0016 | critical | high | confirmed | sql_injection |   | `java-legacy/src/com/acme/struts/EditUserAction.java:13` | SQL Injection in java-legacy/src/com/acme/struts/EditUserAction.java:13 |
| INJ-I-0017 | critical | high | confirmed | sql_injection |   | `java-legacy/src/com/acme/web/InvoiceController.java:29` | SQL Injection in java-legacy/src/com/acme/web/InvoiceController.java:29 |
| INJ-I-0018 | critical | medium | likely | sql_injection |   | `java-legacy/src/com/acme/web/OrderServlet.java:15` | SQL Injection in java-legacy/src/com/acme/web/OrderServlet.java:15 |
| INJ-I-0019 | critical | medium | likely | sql_injection |   | `java-legacy/src/com/acme/web/OrderServlet.java:17` | SQL Injection in java-legacy/src/com/acme/web/OrderServlet.java:17 |
| INJ-I-0020 | critical | high | confirmed | sql_injection |   | `node-express/routes/orders.js:17` | SQL Injection in node-express/routes/orders.js:17 |
| INJ-I-0021 | critical | high | confirmed | sql_injection |   | `node-express/routes/orders.js:29` | SQL Injection in node-express/routes/orders.js:29 |
| INJ-I-0022 | critical | high | confirmed | nosql_injection |   | `node-express/routes/orders.js:21` | NoSQL Injection in node-express/routes/orders.js:21 |
| INJ-I-0023 | critical | high | confirmed | nosql_injection |   | `node-express/routes/orders.js:25` | NoSQL Injection in node-express/routes/orders.js:25 |
| INJ-I-0024 | critical | high | confirmed | sql_injection |   | `perl-cgi/cgi-bin/order.cgi:13` | SQL Injection in perl-cgi/cgi-bin/order.cgi:13 |
| INJ-I-0025 | critical | high | confirmed | sql_injection |   | `perl-cgi/cgi-bin/order.cgi:19` | SQL Injection in perl-cgi/cgi-bin/order.cgi:19 |
| INJ-I-0026 | critical | medium | likely | sql_injection |   | `php-codeigniter/application/controllers/Invoice.php:10` | SQL Injection in php-codeigniter/application/controllers/Invoice.php:10 |
| INJ-I-0027 | critical | high | confirmed | sql_injection |   | `php-plain/admin.php:8` | SQL Injection in php-plain/admin.php:12 |
| INJ-I-0028 | critical | high | confirmed | sql_injection |   | `php-plain/admin.php:12` | SQL Injection in php-plain/admin.php:12 |
| INJ-I-0029 | critical | high | confirmed | nosql_injection |   | `php-plain/mongo_find.php:5` | NoSQL Injection in php-plain/mongo_find.php:6 |
| INJ-I-0030 | critical | high | confirmed | nosql_injection |   | `php-plain/mongo_find.php:6` | NoSQL Injection in php-plain/mongo_find.php:6 |
| INJ-I-0031 | critical | high | confirmed | sql_injection |   | `php-plain/order_detail.php:6` | SQL Injection in php-plain/order_detail.php:6 |
| INJ-I-0032 | critical | high | confirmed | sql_injection |   | `php-plain/search.php:8` | SQL Injection in php-plain/search.php:8 |
| INJ-I-0033 | critical | high | confirmed | sql_injection |   | `php-plain/search.php:9` | SQL Injection in php-plain/search.php:9 |
| INJ-I-0034 | critical | high | confirmed | sql_injection |   | `php-plain/search.php:14` | SQL Injection in php-plain/search.php:14 |
| INJ-I-0036 | critical | high | confirmed | sql_injection |   | `python-flask/app.py:29` | SQL Injection in python-flask/app.py:29 |
| INJ-I-0037 | critical | medium | likely | sql_injection |   | `sql-procs/sp_search_orders.sql:5` | SQL Injection in sql-procs/sp_search_orders.sql:5 |
| INJ-I-0038 | critical | medium | likely | sql_injection |   | `sql-procs/sp_search_orders.sql:6` | SQL Injection in sql-procs/sp_search_orders.sql:6 |
| MASS-M-0003-1 | critical | high | confirmed | mass_assignment |   | `java-legacy/src/com/acme/web/AccountController.java:14` | Unrestricted binding of Account object in Spring MVC |
| MASS-M-0004-1 | critical | medium | likely | mass_assignment |   | `java-legacy/src/com/acme/web/AccountController.java:27` | Unrestricted binding of Account object in Spring MVC |
| MASS-M-0005-1 | critical | medium | likely | mass_assignment |   | `java-legacy/src/com/acme/web/ProfileServlet.java:12` | Unrestricted binding of Account object via BeanUtils in Java servlet |
| BOLA-R-0001 | high | medium | likely | bola | ANY /user/edit.do | `java-legacy/src/com/acme/struts/EditUserAction.java:10` | BOLA in POST /user/edit.do: missing owner verification |
| BOLA-R-0002 | high | medium | likely | bola | ANY /classic-asp/shop/member.asp?mode=edit | `classic-asp/shop/member.asp:6` | BOLA in GET /classic-asp/shop/member.asp?mode=edit: missing owner verification |
| BOLA-R-0003 | high | medium | likely | bola | ANY /classic-asp/shop/member.asp?mode=delete | `classic-asp/shop/member.asp:10` | BOLA in GET /classic-asp/shop/member.asp?mode=delete: missing owner verification |
| BOLA-R-0004 | high | medium | likely | bola | ANY /classic-asp/shop/order.asp | `classic-asp/shop/order.asp:5` | BOLA in GET /classic-asp/shop/order.asp: missing owner verification |
| BOLA-R-0005 | high | medium | likely | bola | ANY /coldfusion/app/OrderService.cfc?method=getOrder | `coldfusion/app/OrderService.cfc:4` | BOLA in GET /coldfusion/app/OrderService.cfc?method=getOrder: missing owner verification |
| BOLA-R-0006 | high | medium | likely | bola | ANY /coldfusion/app/order.cfm | `coldfusion/app/order.cfm:2` | BOLA in GET /coldfusion/app/order.cfm: missing owner verification |
| BOLA-R-0007 | high | medium | likely | bola | POST /Admin/DeleteUser | `dotnet-legacy/Web/Controllers/AdminController.cs:12` | BOLA in POST /Admin/DeleteUser: missing owner verification |
| BOLA-R-0009 | high | medium | likely | bola | POST /Admin/Export | `dotnet-legacy/Web/Controllers/AdminController.cs:32` | BOLA in GET /Admin/Export: missing owner verification |
| BOLA-R-0010 | high | medium | likely | bola | POST /Customer/Edit | `dotnet-legacy/Web/Controllers/CustomerController.cs:12` | BOLA in POST /Customer/Edit: missing owner verification |
| BOLA-R-0011 | high | medium | likely | bola | POST /Customer/EditName | `dotnet-legacy/Web/Controllers/CustomerController.cs:20` | BOLA in POST /Customer/EditName: missing owner verification |
| BOLA-R-0012 | high | medium | likely | bola | POST /Customer/Refresh | `dotnet-legacy/Web/Controllers/CustomerController.cs:27` | BOLA in POST /Customer/Refresh: missing owner verification |
| BOLA-R-0013 | high | medium | likely | bola | ANY /Invoice/Details | `dotnet-legacy/Web/Controllers/InvoiceController.cs:11` | BOLA in GET /Invoice/Details: missing owner verification |
| BOLA-R-0015 | high | medium | likely | bola | POST /Invoice/Search | `dotnet-legacy/Web/Controllers/InvoiceController.cs:26` | BOLA in POST /Invoice/Search: missing owner verification |
| BOLA-R-0016 | high | medium | likely | bola | ANY /dotnet-legacy/Web/Handlers/GetFile.ashx | `dotnet-legacy/Web/Handlers/GetFile.ashx:8` | BOLA in ANY /dotnet-legacy/Web/Handlers/GetFile.ashx: missing owner verification |
| BOLA-R-0017 | high | medium | likely | bola | ANY /dotnet-legacy/Web/Orders/EditOrder.aspx | `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7` | BOLA in POST /dotnet-legacy/Web/Orders/EditOrder.aspx: missing owner verification |
| BOLA-R-0018 | high | medium | likely | bola | ANY /dotnet-legacy/Web/Orders/OrderDetail.aspx | `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10` | BOLA in GET /dotnet-legacy/Web/Orders/OrderDetail.aspx: missing owner verification |
| BOLA-R-0019 | high | medium | likely | bola | ANY /java-legacy/WebContent/order/detail.jsp | `java-legacy/WebContent/order/detail.jsp:3` | BOLA in GET /java-legacy/WebContent/order/detail.jsp: missing owner verification |
| BOLA-R-0020 | high | medium | likely | bola | POST /account/save | `java-legacy/src/com/acme/web/AccountController.java:13` | BOLA in POST /account/save: missing owner verification |
| BOLA-R-0021 | high | medium | likely | bola | POST /account/rename | `java-legacy/src/com/acme/web/AccountController.java:19` | BOLA in POST /account/rename: missing owner verification |
| BOLA-R-0022 | high | medium | likely | bola | PUT /account/api | `java-legacy/src/com/acme/web/AccountController.java:25` | BOLA in PUT /account/api: missing owner verification |
| BOLA-R-0023 | high | medium | likely | bola | POST /admin/users/{id}/delete | `java-legacy/src/com/acme/web/AdminUserController.java:13` | BOLA in POST /admin/users/{id}/delete: missing owner verification |
| BOLA-R-0025 | high | medium | likely | bola | GET /invoices/{id} | `java-legacy/src/com/acme/web/InvoiceController.java:15` | BOLA in GET /invoices/{id}: missing owner verification |
| BOLA-R-0027 | high | medium | likely | bola | GET /invoices/search | `java-legacy/src/com/acme/web/InvoiceController.java:27` | BOLA in GET /invoices/search: missing owner verification |
| BOLA-R-0028 | high | medium | likely | bola | GET /order/view | `java-legacy/src/com/acme/web/OrderServlet.java:8` | BOLA in GET /order/view: missing owner verification |
| BOLA-R-0029 | high | medium | likely | bola | POST <see web.xml servlet-mapping> | `java-legacy/src/com/acme/web/ProfileServlet.java:9` | BOLA in POST /ProfileServlet: missing owner verification |
| BOLA-R-0030 | high | medium | likely | bola | POST /admin/users/:id/delete | `node-express/routes/admin.js:8` | BOLA in POST /admin/users/:id/delete: missing owner verification |
| BOLA-R-0033 | high | medium | likely | bola | GET /orders/:id | `node-express/routes/orders.js:8` | BOLA in GET /orders/:id: missing owner verification |
| BOLA-R-0043 | high | medium | likely | bola | ANY /perl-cgi/cgi-bin/order.cgi | `perl-cgi/cgi-bin/order.cgi:13` | BOLA in ANY /perl-cgi/cgi-bin/order.cgi: missing owner verification |
| BOLA-R-0044 | high | medium | likely | bola | ANY /invoice/view/{id} | `php-codeigniter/application/controllers/Invoice.php:10` | BOLA in ANY /invoice/view/{id}: missing owner verification |
| BOLA-R-0046 | high | medium | likely | bola | ANY /invoice/update | `php-codeigniter/application/controllers/Invoice.php:23` | BOLA in ANY /invoice/update: missing owner verification |
| BOLA-R-0057-1 | high | medium | likely | bola | GET /account/rename | `php-plain/admin.php:7` | BOLA in GET /account/rename: missing owner verification |
| BOLA-R-0057-2 | high | medium | likely | bola | POST /account/rename | `php-plain/admin.php:6` | BOLA in POST /account/rename: missing owner verification |
| BOLA-R-0058-1 | high | medium | likely | bola | POST /account/rename | `php-plain/admin.php:11` | BOLA in POST /account/rename: missing owner verification |
| BOLA-R-0059-1 | high | high | confirmed | bola | POST /php-plain/manage_users.php | `php-plain/manage_users.php:5` | BOLA in POST /php-plain/manage_users.php: missing owner verification |
| BOLA-R-0061-1 | high | high | confirmed | bola | GET /php-plain/order_detail.php | `php-plain/order_detail.php:5` | BOLA in GET /php-plain/order_detail.php: missing owner verification |
| BOLA-R-0066-1 | high | medium | likely | bola | POST /php-plain/admin/delete_user.php | `php-plain/admin/delete_user.php:5` | BOLA in POST /php-plain/admin/delete_user.php: missing owner verification |
| BOLA-R-0067-1 | high | medium | likely | bola | POST /php-plain/admin/promote.php | `php-plain/admin/promote.php:5` | BOLA in POST /php-plain/admin/promote.php: missing owner verification |
| BOLA-R-0069-1 | high | high | confirmed | bola | GET /orders/<int:order_id> | `python-flask/app.py:12` | BOLA in GET /orders/<int:order_id>: missing owner verification |
| BOLA-R-0073 | high | high | confirmed | bola | POST /users/<int:uid>/name | `python-flask/profile.py:16` | BOLA in POST /users/<int:uid>/name: missing owner verification |
| BOLA-R-0074 | high | high | confirmed | bola | PATCH /users/<int:uid> | `python-flask/profile.py:24` | BOLA in PATCH /users/<int:uid>: missing owner verification |
| MASS-M-0009-1 | high | high | confirmed | mass_assignment |   | `php-laravel/app/Http/Controllers/AccountController.php:23` | Team owner_id is writable via mass assignment |
| BOLA-R-0052-verdict | medium | medium | likely | bola | POST /register | `php-laravel/routes/web.php:6` | Missing ownership check at php-laravel/routes/web.php:6 (from auditor verdict) |
| BOLA-R-0053-verdict | medium | medium | likely | bola | POST /posts | `php-laravel/routes/web.php:7` | Missing ownership check at php-laravel/routes/web.php:7 (from auditor verdict) |
| BOLA-R-0054-verdict | medium | medium | likely | bola | POST /teams | `php-laravel/routes/web.php:8` | Missing ownership check at php-laravel/routes/web.php:8 (from auditor verdict) |
| BOLA-R-0055-verdict | medium | medium | likely | bola | POST /account/rename | `php-laravel/routes/web.php:9` | Missing ownership check at php-laravel/routes/web.php:9 (from auditor verdict) |
| BOLA-R-0056-verdict | medium | medium | likely | bola | POST /account/profile | `php-laravel/routes/web.php:10` | Missing ownership check at php-laravel/routes/web.php:10 (from auditor verdict) |
| MASS-M-0001-verdict | medium | medium | likely | mass_assignment |   | `dotnet-legacy/Web/Controllers/CustomerController.cs:12` | Mass assignment at dotnet-legacy/Web/Controllers/CustomerController.cs:12 (from auditor verdict) |
| MASS-M-0002-verdict | medium | medium | likely | mass_assignment |   | `dotnet-legacy/Web/Controllers/CustomerController.cs:30` | Mass assignment at dotnet-legacy/Web/Controllers/CustomerController.cs:30 (from auditor verdict) |
| MASS-M-0006-1 | medium | high | confirmed | mass_assignment |   | `node-express/routes/profile.js:8` | Unknown model fields in whole object binding |
| MASS-M-0007-1 | medium | high | confirmed | mass_assignment |   | `node-express/routes/profile.js:16` | Unknown model fields in whole object binding |
| MASS-M-0008-1 | medium | medium | likely | mass_assignment |   | `php-laravel/app/Http/Controllers/AccountController.php:13` | Unknown model fields in whole object binding |
| MASS-M-0010-1 | medium | medium | likely | mass_assignment |   | `php-laravel/app/Http/Controllers/AccountController.php:36` | Unknown model fields in whole object binding |
| MASS-M-0011-verdict | medium | medium | likely | mass_assignment |   | `php-plain/profile.php:6` | Mass assignment at php-plain/profile.php:6 (from auditor verdict) |
| MASS-M-0012-verdict | medium | medium | likely | mass_assignment |   | `php-plain/profile.php:10` | Mass assignment at php-plain/profile.php:10 (from auditor verdict) |
| MASS-M-0014-1 | medium | medium | likely | mass_assignment |   | `python-flask/profile.py:10` | Unknown model fields in whole object binding |
| MASS-M-0015-1 | medium | medium | likely | mass_assignment |   | `python-flask/profile.py:27` | Unknown model fields in whole object binding |

### BFLA-R-0003-1 — Unrestricted member deletion in classic‑asp shop

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `classic-asp/shop/member.asp:10`

**Impact.** Any logged‑in user can delete any member record

**Evidence.**

- `classic-asp/shop/member.asp:10` — DELETE statement executed without any role check

**Recommendation.** Add a server‑side admin role check before executing the DELETE

*Verifier:* confirmed — checked: classic-asp/shop/member.asp lines 1-11, classic-asp/shop/inc/auth.asp line 2. The code performs a DELETE without any role or ownership check. The included auth.asp only verifies that a user is logged in, not that they are an admin.

### BFLA-R-0007-1 — Unrestricted user deletion in ASP.NET MVC Admin controller

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Controllers/AdminController.cs:12`

**Impact.** Any authenticated user can delete any user account

**Evidence.**

- `dotnet-legacy/Web/Controllers/AdminController.cs:12` — db.Users.Remove executed without admin role check

**Recommendation.** Add [Authorize(Roles="Admin")] to DeleteUser action

*Verifier:* confirmed — checked: dotnet-legacy/Web/Controllers/AdminController.cs lines 6-18. DeleteUser action lacks an admin role guard; only the class-level [Authorize] ensures authentication.

### BFLA-R-0009-1 — Export endpoint controlled by request parameter in ASP.NET MVC

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bfla (role_from_request) — CWE-269, CWE-285   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Controllers/AdminController.cs:30`

**Impact.** Any user can export all user data by setting isAdmin=true

**Evidence.**

- `dotnet-legacy/Web/Controllers/AdminController.cs:32` — uses Request.QueryString["isAdmin"] to grant access

**Recommendation.** Validate admin role from session before allowing export

*Verifier:* confirmed — checked: dotnet-legacy/Web/Controllers/AdminController.cs lines 30-36. Export action grants access based solely on a request query string parameter, with no server‑side role validation.

### BFLA-R-0023-1 — Unrestricted user deletion in Spring MVC Admin controller

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/web/AdminUserController.java:13`

**Impact.** Any authenticated user can delete any user account

**Evidence.**

- `java-legacy/src/com/acme/web/AdminUserController.java:13` — delete method lacks @PreAuthorize

**Recommendation.** Add @PreAuthorize("hasRole('ADMIN')") to delete method

*Verifier:* likely — checked: java-legacy/src/com/acme/web/AdminUserController.java, java-legacy/src/com/acme/web/AdminUserController.java lines 13-15, java-legacy/src/com/acme/web/AdminUserController.java lines 19-23. No @PreAuthorize or other role check is visible on the delete method. Global security configuration is not shown.

### BFLA-R-0030-1 — Unrestricted user deletion in Express route

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `node-express/routes/admin.js:8`

**Impact.** Any logged‑in user can delete any user account

**Evidence.**

- `node-express/routes/admin.js:8` — DELETE route without admin guard

**Recommendation.** Add requireAdmin middleware before delete handler

*Verifier:* likely — checked: node-express/routes/admin.js, node-express/routes/admin.js lines 8-9, node-express/routes/admin.js lines 5-6. The delete route only uses ensureLoggedIn; no admin guard is present in the visible code.

### BFLA-R-0032-1 — Export endpoint controlled by query param in Express

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bfla (role_from_request) — CWE-269, CWE-285   
- **Endpoint:** - -  
- **Location:** `node-express/routes/admin.js:16`

**Impact.** Any user can export all user data by setting isAdmin=true

**Evidence.**

- `node-express/routes/admin.js:17` — uses req.query.isAdmin to grant access

**Recommendation.** Validate admin role from session before allowing export

*Verifier:* likely — checked: node-express/routes/admin.js, node-express/routes/admin.js lines 16-18. Export endpoint checks only a query parameter; no role validation is visible.

### BFLA-R-0057-1 — Unrestricted user view in php‑plain admin.php

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `php-plain/admin.php:6`

**Impact.** Any logged‑in user can view any user record

**Evidence.**

- `php-plain/admin.php:6` — SELECT without role check

**Recommendation.** Add server‑side admin role check before executing SELECT

*Verifier:* likely — checked: php-plain/admin.php, php-plain/admin.php lines 6-9, php-plain/inc/auth.php. Only a login check is performed; no admin role check is present in the visible code.

### BFLA-R-0058-1 — Unrestricted user deletion in php‑plain admin.php

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `php-plain/admin.php:10`

**Impact.** Any logged‑in user can delete any user record

**Evidence.**

- `php-plain/admin.php:10` — DELETE without role check

**Recommendation.** Add server‑side admin role check before executing DELETE

*Verifier:* likely — checked: php-plain/admin.php, php-plain/admin.php lines 10-12, php-plain/inc/auth.php. The delete action lacks any admin role verification in the visible code.

### BFLA-R-0059-1 — Unrestricted user deletion in php‑plain manage_users.php

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `php-plain/manage_users.php:6`

**Impact.** Any logged‑in user can delete any user record

**Evidence.**

- `php-plain/manage_users.php:6` — DELETE without server‑side role check

**Recommendation.** Add server‑side admin role check before executing DELETE

*Verifier:* confirmed — checked: php-plain/manage_users.php:1-8, php-plain/inc/auth.php:1-7. The POST handler deletes a user by id without any role or ownership guard.

### BFLA-R-0063-1 — Unrestricted role change in php‑plain profile.php

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `php-plain/profile.php:6`

**Impact.** Any logged‑in user can change their own role to admin

**Evidence.**

- `php-plain/profile.php:10` — user->role set from $_POST['role'] without check

**Recommendation.** Validate role changes against allowed values and enforce admin check

*Verifier:* confirmed — checked: php-plain/profile.php:1-11, php-plain/inc/auth.php:1-7. The script assigns any POSTed field to the user object, including role, without checking the current user's privileges.

### BFLA-R-0066-1 — Unrestricted user deletion in php‑plain delete_user.php

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bfla (missing_role_check) — CWE-285   
- **Endpoint:** - -  
- **Location:** `php-plain/admin/delete_user.php:5`

**Impact.** Any logged‑in user can delete any user record

**Evidence.**

- `php-plain/admin/delete_user.php:5` — DELETE without role check

**Recommendation.** Add server‑side admin role check before executing DELETE

*Verifier:* confirmed — checked: php-plain/admin/delete_user.php:1-8, php-plain/inc/auth.php:1-7. The file contains only a login check in auth.php and a DELETE statement that uses the supplied id. No role or ownership check is present.

### BFLA-R-0067-1 — User promotion controlled by request parameter in php‑plain

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bfla (role_from_request) — CWE-269, CWE-285   
- **Endpoint:** - -  
- **Location:** `php-plain/admin/promote.php:5`

**Impact.** Any logged‑in user can promote themselves to admin

**Evidence.**

- `php-plain/admin/promote.php:5` — role assignment from $_POST['is_admin']

**Recommendation.** Validate admin role from session before allowing promotion

*Verifier:* confirmed — checked: php-plain/admin/promote.php:1-8, php-plain/inc/auth.php:1-7. The code updates the role based solely on a POST parameter. No role verification or ownership check is performed.

### INJ-I-0001 — SQL Injection in classic-asp/shop/member.asp:6

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `classic-asp/shop/member.asp:6`

**Evidence.**

- `classic-asp/shop/member.asp:6` — Unsanitized input concatenated into query  
  `sql = "UPDATE members SET name = '" & Replace(Request.Form("name"), "'", "''") & "'"`

**Recommendation.** Use parameterized queries or prepared statements; avoid string concatenation

*Verifier:* likely — checked: classic-asp/shop/member.asp lines 6-8, classic-asp/shop/inc/auth.asp lines 1-3. No ownership or role check is visible in the code context. The authentication include only verifies that a user is logged in, not that the user owns the member record.

### INJ-I-0002 — SQL Injection in classic-asp/shop/member.asp:7

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `classic-asp/shop/member.asp:7`

**Evidence.**

- `classic-asp/shop/member.asp:7` — Unsanitized input concatenated into query  
  `sql = sql & " WHERE member_id = " & Request.Form("member_id")`

**Recommendation.** Use parameterized queries or prepared statements; avoid string concatenation

*Verifier:* likely — checked: classic-asp/shop/member.asp lines 6-8, classic-asp/shop/inc/auth.asp lines 1-3. The query concatenates the member_id from the form with no ownership or role guard shown in the context.

### INJ-I-0003 — SQL Injection in classic-asp/shop/member.asp:10

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `classic-asp/shop/member.asp:10`

**Evidence.**

- `classic-asp/shop/member.asp:10` — Unsanitized input concatenated into query  
  `conn.Execute "DELETE FROM members WHERE member_id = " & Request.QueryString("member_id")`

**Recommendation.** Use parameterized queries or prepared statements; avoid string concatenation

*Verifier:* likely — checked: classic-asp/shop/member.asp lines 9-11, classic-asp/shop/inc/auth.asp lines 1-3. The DELETE statement uses a member_id from the query string with no visible ownership check.

### INJ-I-0004 — SQL Injection in classic-asp/shop/order.asp:6

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `classic-asp/shop/order.asp:6`

**Evidence.**

- `classic-asp/shop/order.asp:6` — Unsanitized input concatenated into query  
  `Set rs = conn.Execute("SELECT * FROM orders WHERE id = " & id)`

**Recommendation.** Use parameterized queries or prepared statements; avoid string concatenation

*Verifier:* likely — checked: classic-asp/shop/order.asp lines 5-7, classic-asp/shop/inc/auth.asp lines 1-3. The SELECT query uses an id from the request without casting or an ownership guard in the visible code.

### INJ-I-0006 — SQL Injection in coldfusion/app/OrderService.cfc:5

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (template_placeholder) — CWE-89   
- **Endpoint:** - -  
- **Location:** `coldfusion/app/OrderService.cfc:5`

**Evidence.**

- `coldfusion/app/OrderService.cfc:5` — Unsanitized input interpolated into query  
  `SELECT * FROM orders WHERE id = #arguments.orderId#`

**Recommendation.** Use cfqueryparam or parameterized queries; avoid unescaped interpolation

*Verifier:* confirmed — checked: coldfusion/app/OrderService.cfc:5. The query interpolates the unsanitized argument directly into the SQL string. No ownership or role check, no parameter binding, and no integer cast is present in the visible code.

### INJ-I-0007 — SQL Injection in coldfusion/app/order.cfm:3

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (template_placeholder) — CWE-89   
- **Endpoint:** - -  
- **Location:** `coldfusion/app/order.cfm:3`

**Evidence.**

- `coldfusion/app/order.cfm:3` — Unsanitized input interpolated into query  
  `SELECT * FROM orders WHERE id = #url.id#`

**Recommendation.** Use cfqueryparam or parameterized queries; avoid unescaped interpolation

*Verifier:* confirmed — checked: coldfusion/app/order.cfm:3. The first query uses the raw URL parameter in the WHERE clause. Although a second query later uses cfqueryparam and includes a user_id check, the vulnerable query is executed and its result is output, providing an injection vector.

### INJ-I-0008 — SQL Injection in dotnet-legacy/Web/Controllers/InvoiceController.cs:28

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Controllers/InvoiceController.cs:28`

**Evidence.**

- `dotnet-legacy/Web/Controllers/InvoiceController.cs:28` — Unsanitized user input concatenated into query  
  `var list = db.Database.SqlQuery<Invoice>("SELECT * FROM Invoices WHERE Customer = '" + customer + "'").ToList();`

**Recommendation.** Use parameterized queries or escape the input before concatenation

*Verifier:* likely — checked: dotnet-legacy/Web/Controllers/InvoiceController.cs:26-28. The code concatenates the user‑supplied customer string directly into the SQL query. No parameter binding, cast, or ownership/role check is visible in the provided context.

### INJ-I-0009 — SQL Injection in dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7`

**Evidence.**

- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7` — Unsanitized input concatenated into query  
  `Dim sql As String = "UPDATE Orders SET Note = '" & txtNote.Text & "'"`

**Recommendation.** Use parameterized queries or prepared statements; avoid string concatenation

*Verifier:* confirmed — checked: dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7, dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8. Both the Note and OrderId values are concatenated into the SQL string without any parameterization or ownership check. The subsequent safe query does not mitigate the earlier vulnerable execution.

### INJ-I-0010 — SQL Injection in dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8`

**Evidence.**

- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8` — Unsanitized input concatenated into query  
  `sql &= " WHERE OrderId = " & hfOrderId.Value`

**Recommendation.** Use parameterized queries or prepared statements; avoid string concatenation

*Verifier:* confirmed — checked: dotnet-legacy/Web/Orders/EditOrder.aspx.vb:8. The OrderId is concatenated directly into the SQL string. No ownership or role validation is present in the visible code.

### INJ-I-0011 — SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13`

**Evidence.**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13` — Unsanitized input concatenated into query  
  `var cmd = new SqlCommand("SELECT * FROM Orders WHERE OrderId = " + id, conn);`

**Recommendation.** Use parameterized queries or prepared statements; avoid string concatenation

*Verifier:* confirmed — checked: dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13. The id from the query string is concatenated into the SQL command without parameterization or ownership verification. The later safe query does not prevent the execution of the vulnerable statement.

### INJ-I-0012 — SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19`

**Evidence.**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:19` — Unsanitized input concatenated into query  
  `string sql2 = string.Format("SELECT * FROM Logs WHERE Ref = '{0}'", Request["ref"]);`

**Recommendation.** Use parameterized queries or prepared statements; avoid string concatenation

*Verifier:* confirmed — checked: dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13-22. The query string is built by string.Format with user-supplied Request["ref"]. No parameter binding, no ownership or role check is visible in the code_context.

### INJ-I-0013 — SQL Injection in dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20`

**Evidence.**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:20` — Unsanitized input concatenated into query  
  `string sql3 = $"DELETE FROM Carts WHERE CartId = {Request.Form["cart"]}";`

**Recommendation.** Use parameterized queries or prepared statements; avoid string concatenation

*Verifier:* confirmed — checked: dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:13-22. The DELETE statement concatenates Request.Form["cart"] directly into the SQL. No compensating control is present in the visible code.

### INJ-I-0014 — SQL Injection in java-legacy/WebContent/order/detail.jsp:5

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `java-legacy/WebContent/order/detail.jsp:5`

**Evidence.**

- `java-legacy/WebContent/order/detail.jsp:5` — Unsanitized input concatenated into query  
  `ResultSet rs = c.createStatement().executeQuery("SELECT * FROM orders WHERE order_no = '" + no + "'");`

**Recommendation.** Use prepared statements with parameter binding; avoid string concatenation

*Verifier:* confirmed — checked: java-legacy/WebContent/order/detail.jsp:1-6. The query concatenates the request parameter "no" into the SQL string. No ownership or role check is shown.

### INJ-I-0015 — SQL Injection in java-legacy/src/com/acme/mapper/OrderMapper.xml:9

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (dynamic_identifier) — CWE-89   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/mapper/OrderMapper.xml:9`

**Evidence.**

- `java-legacy/src/com/acme/mapper/OrderMapper.xml:9` — Dynamic identifier interpolated without sanitization  
  `ORDER BY ${orderBy}`

**Recommendation.** Validate the orderBy value against an allow‑list or use a parameterized query

*Verifier:* likely — checked: java-legacy/src/com/acme/mapper/OrderMapper.xml:9. The ORDER BY clause interpolates the ${orderBy} variable without any visible allow‑list or type enforcement in the snippet.

### INJ-I-0016 — SQL Injection in java-legacy/src/com/acme/struts/EditUserAction.java:13

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/struts/EditUserAction.java:13`

**Evidence.**

- `java-legacy/src/com/acme/struts/EditUserAction.java:13` — Unsanitized input concatenated into query  
  `PreparedStatement ps = conn.prepareStatement("UPDATE users SET email = '" + email + "' WHERE id = " + userId);`

**Recommendation.** Use parameterized queries; avoid string concatenation

*Verifier:* confirmed — checked: java-legacy/src/com/acme/struts/EditUserAction.java:10-15. The UPDATE statement concatenates the email and userId parameters directly. No parameter binding or ownership check is visible.

### INJ-I-0017 — SQL Injection in java-legacy/src/com/acme/web/InvoiceController.java:29

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/web/InvoiceController.java:29`

**Evidence.**

- `java-legacy/src/com/acme/web/InvoiceController.java:29` — Unsanitized input concatenated into query  
  `model.addAttribute("list", session.createQuery("from Invoice i where i.customer = '" + customer + "'").list());`

**Recommendation.** Use parameterized queries or named parameters; avoid string concatenation

*Verifier:* confirmed — checked: java-legacy/src/com/acme/web/InvoiceController.java:27-31. The HQL query concatenates the customer request parameter. No ownership or role check is present in the code_context.

### INJ-I-0018 — SQL Injection in java-legacy/src/com/acme/web/OrderServlet.java:15

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/web/OrderServlet.java:15`

**Evidence.**

- `java-legacy/src/com/acme/web/OrderServlet.java:15` — Unsanitized request parameter concatenated into query  
  `ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE id = '" + id + "'");`
- `java-legacy/src/com/acme/web/OrderServlet.java:17` — Unsanitized request parameter used in dynamic SQL  
  `sb.append(" AND order_id = ").append(id);`

**Recommendation.** Use prepared statements or validate the id before use

*Verifier:* likely — checked: java-legacy/src/com/acme/web/OrderServlet.java:15-17. Both SQL statements build the query string by concatenating the request parameter `id` directly. No cast, parameter binding, or ownership check is shown.

### INJ-I-0019 — SQL Injection in java-legacy/src/com/acme/web/OrderServlet.java:17

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/web/OrderServlet.java:17`

**Evidence.**

- `java-legacy/src/com/acme/web/OrderServlet.java:15` — Unsanitized request parameter concatenated into query  
  `ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE id = '" + id + "'");`
- `java-legacy/src/com/acme/web/OrderServlet.java:17` — Unsanitized request parameter used in dynamic SQL  
  `sb.append(" AND order_id = ").append(id);`

**Recommendation.** Use prepared statements or validate the id before use

*Verifier:* likely — checked: java-legacy/src/com/acme/web/OrderServlet.java:15-17. Same code as INJ-I-0018; no visible mitigation.

### INJ-I-0020 — SQL Injection in node-express/routes/orders.js:17

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `node-express/routes/orders.js:17`

**Evidence.**

- `node-express/routes/orders.js:17` — Unsanitized input concatenated into query  
  `db.query("SELECT * FROM reports WHERE month = '" + req.query.month + "'", function (e, rows) { res.json(rows); });`

**Recommendation.** Use parameterized queries or query builders; avoid string concatenation

*Verifier:* confirmed — checked: node-express/routes/orders.js:17. The query concatenates user input directly into the SQL string with no sanitization, casting, or parameter binding. No ownership or role check is present on this route.

### INJ-I-0021 — SQL Injection in node-express/routes/orders.js:29

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `node-express/routes/orders.js:29`

**Evidence.**

- `node-express/routes/orders.js:29` — Unsanitized input concatenated into query  
  `db.query('SELECT COUNT(*) AS n FROM orders WHERE shop_id = ${req.query.shop}', function (e, r) { res.json(r); });`

**Recommendation.** Use parameterized queries or query builders; avoid string concatenation

*Verifier:* confirmed — checked: node-express/routes/orders.js:29. The query interpolates req.query.shop directly into the SQL string. No cast, binding, or authorization guard is visible.

### INJ-I-0022 — NoSQL Injection in node-express/routes/orders.js:21

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** nosql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `node-express/routes/orders.js:21`

**Evidence.**

- `node-express/routes/orders.js:21` — Unsanitized request body used directly as query filter  
  `db.collection('users').findOne(req.body, function (e, u) { res.json(!!u); });`

**Recommendation.** Validate and sanitize query objects; avoid passing raw request bodies to database

*Verifier:* confirmed — checked: node-express/routes/orders.js:21. The request body is passed directly to findOne without validation or sanitization. No role or ownership check is present.

### INJ-I-0023 — NoSQL Injection in node-express/routes/orders.js:25

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** nosql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `node-express/routes/orders.js:25`

**Evidence.**

- `node-express/routes/orders.js:25` — Unsanitized input concatenated into $where string  
  `db.collection('items').find({ $where: "this.name == '" + req.query.n + "'" }).toArray(function (e, r) { res.json(r); });`

**Recommendation.** Avoid $where with user input; use parameterized queries or safe query operators

*Verifier:* confirmed — checked: node-express/routes/orders.js:25. The $where string concatenates user input directly, enabling NoSQL injection. No validation or authorization guard is visible.

### INJ-I-0024 — SQL Injection in perl-cgi/cgi-bin/order.cgi:13

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `perl-cgi/cgi-bin/order.cgi:13`

**Evidence.**

- `perl-cgi/cgi-bin/order.cgi:13` — Unsanitized input concatenated into query  
  `$dbh->prepare("SELECT * FROM orders WHERE id = $id");`

**Recommendation.** Use placeholders and bind parameters; avoid string interpolation

*Verifier:* confirmed — checked: perl-cgi/cgi-bin/order.cgi:13. The prepared statement interpolates $id directly into the SQL string. No parameter binding or sanitization is used. The later safe query does not mitigate this earlier vulnerability.

### INJ-I-0025 — SQL Injection in perl-cgi/cgi-bin/order.cgi:19

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `perl-cgi/cgi-bin/order.cgi:19`

**Evidence.**

- `perl-cgi/cgi-bin/order.cgi:19` — Unsanitized input concatenated into query  
  `$dbh->do("DELETE FROM carts WHERE cart_id = " . $q->param('cart'));`

**Recommendation.** Use placeholders and bind parameters; avoid string concatenation

*Verifier:* confirmed — checked: perl-cgi/cgi-bin/order.cgi:13-19. The DELETE statement concatenates user input directly into the SQL string and no ownership or role check is present in the visible code.

### INJ-I-0026 — SQL Injection in php-codeigniter/application/controllers/Invoice.php:10

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-codeigniter/application/controllers/Invoice.php:10`

**Evidence.**

- `php-codeigniter/application/controllers/Invoice.php:10` — Unsanitized URL segment concatenated into query  
  `$q = $this->db->query("SELECT * FROM invoices WHERE id = $id");`

**Recommendation.** Use parameterized queries or escape the input before concatenation

*Verifier:* likely — checked: php-codeigniter/application/controllers/Invoice.php:10. The `view` method concatenates the `$id` variable directly into the query. No parameter binding, cast, or ownership check is present in the snippet.

### INJ-I-0027 — SQL Injection in php-plain/admin.php:12

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-plain/admin.php:8`

**Evidence.**

- `php-plain/admin.php:12` — Unsanitized input concatenated into query  
  `mysql_query("DELETE FROM users WHERE id = $id");`

**Recommendation.** Use parameterized queries or prepared statements; avoid string concatenation

*Verifier:* confirmed — checked: php-plain/admin.php:10-12, php-plain/inc/auth.php:1-7, php-plain/inc/db.php:1-4. The DELETE query uses unsanitized POST data and the included auth file only verifies login, not ownership or role.

### INJ-I-0028 — SQL Injection in php-plain/admin.php:12

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-plain/admin.php:12`

**Evidence.**

- `php-plain/admin.php:12` — Unsanitized input concatenated into query  
  `mysql_query("DELETE FROM users WHERE id = $id");`

**Recommendation.** Use parameterized queries or prepared statements; avoid string concatenation

*Verifier:* confirmed — checked: php-plain/admin.php:10-12, php-plain/inc/auth.php:1-7, php-plain/inc/db.php:1-4. Same as INJ-I-0027; no compensating control is visible.

### INJ-I-0029 — NoSQL Injection in php-plain/mongo_find.php:6

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** nosql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-plain/mongo_find.php:5`

**Evidence.**

- `php-plain/mongo_find.php:6` — Unsanitized input concatenated into $where string  
  `$docs = $coll->find(array('$where' => "this.name == '" . $_GET['n'] . "'"));`

**Recommendation.** Avoid $where with user input; use safe query operators or parameterized queries

*Verifier:* confirmed — checked: php-plain/mongo_find.php:5-6, php-plain/inc/auth.php:1-7. The $where clause concatenates user input; no ownership or role check is present in the visible code.

### INJ-I-0030 — NoSQL Injection in php-plain/mongo_find.php:6

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** nosql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-plain/mongo_find.php:6`

**Evidence.**

- `php-plain/mongo_find.php:6` — Unsanitized input concatenated into $where string  
  `$docs = $coll->find(array('$where' => "this.name == '" . $_GET['n'] . "'"));`

**Recommendation.** Avoid $where with user input; use safe query operators or parameterized queries

*Verifier:* confirmed — checked: php-plain/mongo_find.php:5-6, php-plain/inc/auth.php:1-7. Same as INJ-I-0029; no compensating control is visible.

### INJ-I-0031 — SQL Injection in php-plain/order_detail.php:6

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-plain/order_detail.php:6`

**Evidence.**

- `php-plain/order_detail.php:5` — Unsanitized GET parameter  
  `$id = $_GET['id'];`
- `php-plain/order_detail.php:6` — Unsanitized input concatenated into query  
  `$res = mysql_query("SELECT * FROM orders WHERE id = " . $id);`

**Recommendation.** Use a prepared statement with bound parameters instead of string concatenation

*Verifier:* confirmed — checked: php-plain/order_detail.php:5-6, php-plain/inc/auth.php:3-6, php-plain/inc/db.php:1-4. The GET parameter is concatenated directly into a mysql_query without any sanitization, casting, or prepared statement. No ownership or role check is present.

### INJ-I-0032 — SQL Injection in php-plain/search.php:8

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-plain/search.php:8`

**Evidence.**

- `php-plain/search.php:6` — Unsanitized GET parameter  
  `$sort = $_GET['sort'];`
- `php-plain/search.php:9` — Unsanitized input concatenated into ORDER BY clause  
  `$sql .= " ORDER BY " . $sort;`

**Recommendation.** Validate ORDER BY values against an allow‑list or use parameterized queries

*Verifier:* confirmed — checked: php-plain/search.php:6-9, php-plain/inc/auth.php:3-6, php-plain/inc/db.php:1-4. The ORDER BY clause is built from an unsanitized GET parameter with no allow‑list or integer cast. No ownership or role check is present.

### INJ-I-0033 — SQL Injection in php-plain/search.php:9

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-plain/search.php:9`

**Evidence.**

- `php-plain/search.php:6` — Unsanitized GET parameter  
  `$sort = $_GET['sort'];`
- `php-plain/search.php:9` — Unsanitized input concatenated into ORDER BY clause  
  `$sql .= " ORDER BY " . $sort;`

**Recommendation.** Validate ORDER BY values against an allow‑list or use parameterized queries

*Verifier:* confirmed — checked: php-plain/search.php:6-9, php-plain/inc/auth.php:3-6, php-plain/inc/db.php:1-4. Same as INJ-I-0032: unsanitized ORDER BY input with no guard.

### INJ-I-0034 — SQL Injection in php-plain/search.php:14

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `php-plain/search.php:14`

**Evidence.**

- `php-plain/search.php:13` — Unsanitized GET parameter interpolated into query  
  `$q = <<<SQL
SELECT * FROM products
WHERE category = '{$_GET['cat']}'
SQL;`

**Recommendation.** Use parameterized queries or escape the input before interpolation

*Verifier:* confirmed — checked: php-plain/search.php:13-15, php-plain/inc/auth.php:3-6, php-plain/inc/db.php:1-4. The heredoc interpolates a GET parameter directly into the SQL string. No escaping or parameterization is used.

### INJ-I-0036 — SQL Injection in python-flask/app.py:29

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_interpolation) — CWE-89   
- **Endpoint:** - -  
- **Location:** `python-flask/app.py:29`

**Evidence.**

- `python-flask/app.py:29` — Unsanitized f-string interpolation into query  
  `cur.execute(f"SELECT * FROM products WHERE name LIKE '%{q}%'")`

**Recommendation.** Use a parameterized query instead of f-string interpolation

*Verifier:* confirmed — checked: python-flask/app.py:24-30, python-flask/app.py:10-20. The search route uses an f‑string to build a query with user input. No parameter binding or sanitization is performed, and no ownership check is present.

### INJ-I-0037 — SQL Injection in sql-procs/sp_search_orders.sql:5

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (stored_procedure_dynamic_sql) — CWE-89   
- **Endpoint:** - -  
- **Location:** `sql-procs/sp_search_orders.sql:5`

**Evidence.**

- `sql-procs/sp_search_orders.sql:5` — Dynamic SQL built from user‑supplied parameters without sanitization  
  `SET @sql = 'SELECT * FROM Orders WHERE Customer = ''' + @Customer + ''' ORDER BY ' + @Sort`

**Recommendation.** Avoid dynamic SQL; use parameterized queries or validate the parameters

*Verifier:* likely — checked: sql-procs/sp_search_orders.sql line 5. The stored procedure builds dynamic SQL from @Customer and @Sort without any visible sanitization or allow‑list. No ownership or role check is present in the provided code.

### INJ-I-0038 — SQL Injection in sql-procs/sp_search_orders.sql:6

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** sql_injection (stored_procedure_dynamic_sql) — CWE-89   
- **Endpoint:** - -  
- **Location:** `sql-procs/sp_search_orders.sql:6`

**Evidence.**

- `sql-procs/sp_search_orders.sql:6` — Execution of unsanitized dynamic SQL  
  `EXEC(@sql)`

**Recommendation.** Avoid dynamic SQL; use parameterized queries or validate the parameters

*Verifier:* likely — checked: sql-procs/sp_search_orders.sql line 6. Execution of the unsanitized @sql string is shown, but no control is visible in the snippet.

### MASS-M-0003-1 — Unrestricted binding of Account object in Spring MVC

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/web/AccountController.java:14`

**Impact.** role, balance

**Evidence.**

- `java-legacy/src/com/acme/web/AccountController.java:27` — accountDao.save(account) with whole object binding, no allowlist

**Recommendation.** Use a DTO or explicit property copying to prevent privileged field updates

*Verifier:* confirmed — checked: java-legacy/src/com/acme/web/AccountController.java:1-30. The controller accepts a full Account model from the request and persists it directly. No role check or property allow‑list is present.

### MASS-M-0004-1 — Unrestricted binding of Account object in Spring MVC

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/web/AccountController.java:27`

**Impact.** role, balance

**Evidence.**

- `java-legacy/src/com/acme/web/AccountController.java:27` — accountDao.save(account) with whole object binding, no allowlist

**Recommendation.** Use a DTO or explicit property copying to prevent privileged field updates

*Verifier:* likely — checked: java-legacy/src/com/acme/web/AccountController.java:13-15. The controller binds the entire Account object via @ModelAttribute and persists it without any visible ownership or role check, nor an allow‑list. No global filter or configuration is shown in the provided context.

### MASS-M-0005-1 — Unrestricted binding of Account object via BeanUtils in Java servlet

- **Severity / confidence:** critical / medium  
- **Status:** likely  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `java-legacy/src/com/acme/web/ProfileServlet.java:12`

**Impact.** role, balance

**Evidence.**

- `java-legacy/src/com/acme/web/ProfileServlet.java:12` — BeanUtils.populate(account, request.getParameterMap()) binds all request parameters

**Recommendation.** Use explicit property setting or an allowlist to prevent privileged field updates

*Verifier:* likely — checked: java-legacy/src/com/acme/web/ProfileServlet.java:10-13. BeanUtils.populate() binds all request parameters to the Account object with no visible filtering or ownership enforcement in the snippet.

### BOLA-R-0001 — BOLA in POST /user/edit.do: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /user/edit.do  
- **Location:** `java-legacy/src/com/acme/struts/EditUserAction.java:10`

**Evidence.**

- `java-legacy/src/com/acme/struts/EditUserAction.java:10` — The user_id comes from the request and is used directly in the UPDATE without verifying that the target user belongs to the current session user.  
  `String userId = request.getParameter("user_id");
String email = request.getParameter("email");
Connection conn = DataSourceHolder.get().getConnection();
PreparedStatement ps = conn.prepareStatement("UPDATE users SET email = '" + email + "' WHERE id = " + userId);
ps.executeUpdate();`

**Recommendation.** Add an ownership check that ensures the user_id belongs to the current session user before performing the UPDATE.

*Verifier:* likely — checked: java-legacy/src/com/acme/struts/EditUserAction.java lines 10-14. The user_id from the request is used directly in an UPDATE statement without any ownership verification or parameter binding.

### BOLA-R-0002 — BOLA in GET /classic-asp/shop/member.asp?mode=edit: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /classic-asp/shop/member.asp?mode=edit  
- **Location:** `classic-asp/shop/member.asp:6`

**Evidence.**

- `classic-asp/shop/member.asp:6` — member_id comes from the request form and is used directly in the UPDATE without checking that the member belongs to the current session user.  
  `sql = "UPDATE members SET name = '" & Replace(Request.Form("name"), "'", "''") & "'"
sql = sql & " WHERE member_id = " & Request.Form("member_id")`

**Recommendation.** Add an ownership check that ensures the member_id belongs to the current user before performing the UPDATE.

*Verifier:* likely — checked: classic-asp/shop/member.asp:6-8, classic-asp/shop/inc/auth.asp:1-3, classic-asp/shop/inc/conn.asp:1-4. The UPDATE statement uses Request.Form("member_id") directly without any ownership check or parameter binding. No role or ownership helper is invoked in the visible code.

### BOLA-R-0003 — BOLA in GET /classic-asp/shop/member.asp?mode=delete: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /classic-asp/shop/member.asp?mode=delete  
- **Location:** `classic-asp/shop/member.asp:10`

**Evidence.**

- `classic-asp/shop/member.asp:10` — member_id comes from the query string and is used directly in the DELETE without verifying ownership.  
  `conn.Execute "DELETE FROM members WHERE member_id = " & Request.QueryString("member_id")`

**Recommendation.** Add an ownership check that ensures the member_id belongs to the current user before performing the DELETE.

*Verifier:* likely — checked: classic-asp/shop/member.asp:9-11, classic-asp/shop/inc/auth.asp:1-3, classic-asp/shop/inc/conn.asp:1-4. The DELETE statement concatenates Request.QueryString("member_id") directly. No ownership verification is present in the shown code.

### BOLA-R-0004 — BOLA in GET /classic-asp/shop/order.asp: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /classic-asp/shop/order.asp  
- **Location:** `classic-asp/shop/order.asp:5`

**Evidence.**

- `classic-asp/shop/order.asp:5` — The order id is taken from the request and the order is fetched without scoping to the current user.  
  `id = Request("id")
Set rs = conn.Execute("SELECT * FROM orders WHERE id = " & id)
Response.Write Server.HTMLEncode(rs("address"))`

**Recommendation.** Add a WHERE clause that binds the order id to the current session user before returning data.

*Verifier:* likely — checked: classic-asp/shop/order.asp:5-7, classic-asp/shop/order.asp:12-13, classic-asp/shop/inc/auth.asp:1-3, classic-asp/shop/inc/conn.asp:1-4. The first SELECT retrieves the order by id without scoping to the current user and its result is output. The later scoped query is not used for output.

### BOLA-R-0005 — BOLA in GET /coldfusion/app/OrderService.cfc?method=getOrder: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /coldfusion/app/OrderService.cfc?method=getOrder  
- **Location:** `coldfusion/app/OrderService.cfc:4`

**Evidence.**

- `coldfusion/app/OrderService.cfc:4` — The order id is taken from the request argument and the query is executed without scoping to the current user.  
  `<cfquery name="q" datasource="shop">
  SELECT * FROM orders WHERE id = #arguments.orderId#
</cfquery>`

**Recommendation.** Add a WHERE clause that binds the order id to the current session user before returning data.

*Verifier:* likely — checked: coldfusion/app/OrderService.cfc:4-6. The query interpolates #arguments.orderId# directly. No ownership check or parameter binding is visible.

### BOLA-R-0006 — BOLA in GET /coldfusion/app/order.cfm: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /coldfusion/app/order.cfm  
- **Location:** `coldfusion/app/order.cfm:2`

**Evidence.**

- `coldfusion/app/order.cfm:2` — The order id is taken from the URL and the query is executed without scoping to the current user.  
  `<cfquery name="qOrder" datasource="shop">
  SELECT * FROM orders WHERE id = #url.id#
</cfquery>`

**Recommendation.** Add a WHERE clause that binds the order id to the current session user before returning data.

*Verifier:* likely — checked: coldfusion/app/order.cfm:2-4, coldfusion/app/order.cfm:5-9. The unscoped query qOrder uses #url.id# and its result is displayed. The scoped query qMine is not used for output.

### BOLA-R-0007 — BOLA in POST /Admin/DeleteUser: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /Admin/DeleteUser  
- **Location:** `dotnet-legacy/Web/Controllers/AdminController.cs:12`

**Evidence.**

- `dotnet-legacy/Web/Controllers/AdminController.cs:12` — Any authenticated user can delete any user because there is no ownership or role check.  
  `public ActionResult DeleteUser(int id)
{
    var u = db.Users.Find(id);
    db.Users.Remove(u);
    db.SaveChanges();
    return RedirectToAction("Index");
}`

**Recommendation.** Restrict this action to administrators only or add an ownership check that ensures the target user is not the current user.

*Verifier:* likely — checked: dotnet-legacy/Web/Controllers/AdminController.cs lines 6-12. The controller is marked with [Authorize] but no role or ownership check is visible in the provided code. The absence of a role check is not confirmed, so the finding is likely.

### BOLA-R-0009 — BOLA in GET /Admin/Export: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /Admin/Export  
- **Location:** `dotnet-legacy/Web/Controllers/AdminController.cs:32`

**Evidence.**

- `dotnet-legacy/Web/Controllers/AdminController.cs:32` — The endpoint is not protected by a role check; any authenticated user can retrieve all users by setting isAdmin=true.  
  `if (Request.QueryString["isAdmin"] == "true")
{
    return Json(db.Users.ToList(), JsonRequestBehavior.AllowGet);
}`

**Recommendation.** Add an [Authorize(Roles="Admin")] attribute or remove the isAdmin query parameter and enforce role checks server‑side.

*Verifier:* likely — checked: dotnet-legacy/Web/Controllers/AdminController.cs lines 30-36. The Export action relies solely on a query‑string flag and lacks any role or ownership guard in the visible code.

### BOLA-R-0010 — BOLA in POST /Customer/Edit: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /Customer/Edit  
- **Location:** `dotnet-legacy/Web/Controllers/CustomerController.cs:12`

**Evidence.**

- `dotnet-legacy/Web/Controllers/CustomerController.cs:14` — Marks the supplied customer entity as modified without checking that the current user owns it  
  `db.Entry(customer).State = System.Data.Entity.EntityState.Modified;`

**Recommendation.** Ensure the current user is the owner of the customer before applying changes

*Verifier:* likely — checked: Reviewed CustomerController.cs lines 11-16. No ownership check, cast, or allow‑list is visible in the method body.

### BOLA-R-0011 — BOLA in POST /Customer/EditName: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /Customer/EditName  
- **Location:** `dotnet-legacy/Web/Controllers/CustomerController.cs:20`

**Evidence.**

- `dotnet-legacy/Web/Controllers/CustomerController.cs:22` — Saves the customer entity without verifying that the current user owns it  
  `db.SaveChanges();`

**Recommendation.** Add an ownership check before saving the customer entity

*Verifier:* likely — checked: Reviewed CustomerController.cs lines 20-23. The method only calls SaveChanges(); no ownership verification is shown.

### BOLA-R-0012 — BOLA in POST /Customer/Refresh: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /Customer/Refresh  
- **Location:** `dotnet-legacy/Web/Controllers/CustomerController.cs:27`

**Evidence.**

- `dotnet-legacy/Web/Controllers/CustomerController.cs:29` — Loads a customer by ID without checking that the current user owns it  
  `var customer = db.Customers.Find(id);`

**Recommendation.** Verify ownership before updating the customer record

*Verifier:* likely — checked: Reviewed CustomerController.cs lines 27-32. Customer is loaded by id and updated without any ownership check in the visible code.

### BOLA-R-0013 — BOLA in GET /Invoice/Details: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /Invoice/Details  
- **Location:** `dotnet-legacy/Web/Controllers/InvoiceController.cs:11`

**Evidence.**

- `dotnet-legacy/Web/Controllers/InvoiceController.cs:11` — The invoice is fetched by id without scoping to the current user.  
  `public ActionResult Details(int id)
{
    var inv = db.Invoices.Find(id);
    return View(inv);
}`

**Recommendation.** Add a WHERE clause that binds the invoice id to the current session user before returning data.

*Verifier:* likely — checked: dotnet-legacy/Web/Controllers/InvoiceController.cs lines 11-15. Details retrieves an invoice by id without scoping to the current user; no ownership check is shown.

### BOLA-R-0015 — BOLA in POST /Invoice/Search: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /Invoice/Search  
- **Location:** `dotnet-legacy/Web/Controllers/InvoiceController.cs:26`

**Evidence.**

- `dotnet-legacy/Web/Controllers/InvoiceController.cs:26` — The query is built from user input and returns all invoices for the given customer without scoping to the current user.  
  `public ActionResult Search(string customer)
{
    var list = db.Database.SqlQuery<Invoice>("SELECT * FROM Invoices WHERE Customer = '" + customer + "'").ToList();
    return View(list);
}`

**Recommendation.** Add a WHERE clause that binds the customer to the current session user or use parameterized queries with ownership checks.

*Verifier:* likely — checked: dotnet-legacy/Web/Controllers/InvoiceController.cs lines 26-30. The Search action builds a raw SQL query from user input and does not enforce ownership or parameter binding.

### BOLA-R-0016 — BOLA in ANY /dotnet-legacy/Web/Handlers/GetFile.ashx: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /dotnet-legacy/Web/Handlers/GetFile.ashx  
- **Location:** `dotnet-legacy/Web/Handlers/GetFile.ashx:8`

**Evidence.**

- `dotnet-legacy/Web/Handlers/GetFile.ashx:8` — Accepts a file identifier from the request without verifying that the current user owns the file  
  `string fileId = context.Request.QueryString["file_id"];`
- `dotnet-legacy/Web/Handlers/GetFile.ashx:10` — Serves the file directly after path resolution, allowing arbitrary file access  
  `context.Response.TransmitFile(path);`

**Recommendation.** Add an ownership check to ensure the current user is authorized to download the requested file

*Verifier:* likely — checked: Reviewed GetFile.ashx lines 8-10. File ID is taken directly from the query string and used to transmit a file; no ownership guard is present.

### BOLA-R-0017 — BOLA in POST /dotnet-legacy/Web/Orders/EditOrder.aspx: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /dotnet-legacy/Web/Orders/EditOrder.aspx  
- **Location:** `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7`

**Evidence.**

- `dotnet-legacy/Web/Orders/EditOrder.aspx.vb:7` — The OrderId is taken from a hidden field and used directly in the UPDATE without verifying that the order belongs to the current user.  
  `Dim sql As String = "UPDATE Orders SET Note = '" & txtNote.Text & "'"
sql &= " WHERE OrderId = " & hfOrderId.Value
Using conn As New SqlConnection(ConnStr)
    Dim cmd As New SqlCommand(sql, conn)
    conn.Open()
    cmd.ExecuteNonQuery()
End Using`

**Recommendation.** Add an ownership check that ensures the OrderId belongs to the current session user before executing the UPDATE.

*Verifier:* likely — checked: dotnet-legacy/Web/Orders/EditOrder.aspx.vb lines 7-13. The UPDATE statement uses a hidden field value directly; no ownership verification is visible.

### BOLA-R-0018 — BOLA in GET /dotnet-legacy/Web/Orders/OrderDetail.aspx: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /dotnet-legacy/Web/Orders/OrderDetail.aspx  
- **Location:** `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10`

**Evidence.**

- `dotnet-legacy/Web/Orders/OrderDetail.aspx.cs:10` — The first query fetches the order by id without scoping to the current user; the safe query is never used.  
  `string id = Request.QueryString["id"];
using (var conn = new SqlConnection(ConnStr))
{
    var cmd = new SqlCommand("SELECT * FROM Orders WHERE OrderId = " + id, conn);
    conn.Open();
    var r = cmd.ExecuteReader();
    var safe = new SqlCommand("SELECT * FROM Orders WHERE OrderId = @id AND UserId = @uid", conn);`

**Recommendation.** Replace the first query with a query that includes a WHERE clause binding OrderId to the current session user.

*Verifier:* likely — checked: dotnet-legacy/Web/Orders/OrderDetail.aspx.cs lines 10-22. No ownership or role check is visible in the provided code. The first query uses the raw id from the query string without scoping to the current user, and the safe query is never executed.

### BOLA-R-0019 — BOLA in GET /java-legacy/WebContent/order/detail.jsp: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** ANY /java-legacy/WebContent/order/detail.jsp  
- **Location:** `java-legacy/WebContent/order/detail.jsp:3`

**Evidence.**

- `java-legacy/WebContent/order/detail.jsp:3` — The order number is taken from the request and used directly in the SELECT without scoping to the current user.  
  `String no = request.getParameter("no");
Connection c = (Connection) application.getAttribute("conn");
ResultSet rs = c.createStatement().executeQuery("SELECT * FROM orders WHERE order_no = '" + no + "'");`

**Recommendation.** Add a WHERE clause that binds the order number to the current session user before returning data.

*Verifier:* likely — checked: java-legacy/WebContent/order/detail.jsp lines 1-6. The order number is concatenated directly into the SQL statement with no ownership check or parameter binding shown.

### BOLA-R-0020 — BOLA in POST /account/save: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /account/save  
- **Location:** `java-legacy/src/com/acme/web/AccountController.java:13`

**Evidence.**

- `java-legacy/src/com/acme/web/AccountController.java:13` — The account ID comes from the request body and is persisted without checking that the current user owns the account.  
  `accountDao.save(account);`

**Recommendation.** Add an ownership check that the current user owns the account before saving.

*Verifier:* likely — checked: java-legacy/src/com/acme/web/AccountController.java lines 13-15. The account is saved without checking that the current session user owns the account; no ownership or role check is visible.

### BOLA-R-0021 — BOLA in POST /account/rename: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /account/rename  
- **Location:** `java-legacy/src/com/acme/web/AccountController.java:19`

**Evidence.**

- `java-legacy/src/com/acme/web/AccountController.java:19` — The account ID is taken from the form and renamed without verifying ownership.  
  `accountDao.rename(form.getId(), form.getName());`

**Recommendation.** Verify that the current user owns the account before performing the rename.

*Verifier:* likely — checked: java-legacy/src/com/acme/web/AccountController.java lines 19-21. The rename operation uses the id from the form without verifying ownership or applying a role check.

### BOLA-R-0022 — BOLA in PUT /account/api: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** PUT /account/api  
- **Location:** `java-legacy/src/com/acme/web/AccountController.java:25`

**Evidence.**

- `java-legacy/src/com/acme/web/AccountController.java:25` — The account ID is supplied in the request body and persisted without checking that the current user owns it.  
  `return accountDao.save(account);`

**Recommendation.** Add an ownership check before saving the account.

*Verifier:* likely — checked: java-legacy/src/com/acme/web/AccountController.java lines 25-28. No ownership or role check is visible in the update method; the account is persisted directly from the request body.

### BOLA-R-0023 — BOLA in POST /admin/users/{id}/delete: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /admin/users/{id}/delete  
- **Location:** `java-legacy/src/com/acme/web/AdminUserController.java:13`

**Evidence.**

- `java-legacy/src/com/acme/web/AdminUserController.java:13` — No role or ownership check; any authenticated user can delete any user.  
  `userDao.deleteById(id);`

**Recommendation.** Require an admin role and verify that the target user is not the current user before deletion.

*Verifier:* likely — checked: java-legacy/src/com/acme/web/AdminUserController.java lines 13-15. The delete action lacks any @PreAuthorize or explicit ownership check; the only role guard appears on a different method.

### BOLA-R-0025 — BOLA in GET /invoices/{id}: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /invoices/{id}  
- **Location:** `java-legacy/src/com/acme/web/InvoiceController.java:15`

**Evidence.**

- `java-legacy/src/com/acme/web/InvoiceController.java:15` — The invoice ID is taken from the URL and the invoice is returned without checking that it belongs to the current user.  
  `model.addAttribute("invoice", invoiceDao.findById(id));`

**Recommendation.** Add an ownership check that the invoice belongs to the current user before returning it.

*Verifier:* likely — checked: java-legacy/src/com/acme/web/InvoiceController.java lines 15-18. The invoice is retrieved by ID without verifying that it belongs to the current user.

### BOLA-R-0027 — BOLA in GET /invoices/search: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /invoices/search  
- **Location:** `java-legacy/src/com/acme/web/InvoiceController.java:27`

**Evidence.**

- `java-legacy/src/com/acme/web/InvoiceController.java:27` — The customer value is supplied by the user and the query returns invoices for any customer, exposing all invoices.  
  `session.createQuery("from Invoice i where i.customer = '" + customer + "'").list();`

**Recommendation.** Restrict the query to invoices owned by the current user or validate the customer against the current user.

*Verifier:* likely — checked: java-legacy/src/com/acme/web/InvoiceController.java lines 27-30. The search query concatenates user input directly; no ownership filter or parameter binding is present.

### BOLA-R-0028 — BOLA in GET /order/view: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /order/view  
- **Location:** `java-legacy/src/com/acme/web/OrderServlet.java:8`

**Evidence.**

- `java-legacy/src/com/acme/web/OrderServlet.java:8` — The order ID comes from the request and the order is fetched without verifying that it belongs to the logged‑in user.  
  `ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE id = '" + id + "'");`

**Recommendation.** Add an ownership check that the order belongs to the current user before returning it.

*Verifier:* likely — checked: java-legacy/src/com/acme/web/OrderServlet.java lines 11-15. The order is fetched by ID from the request without any check that the logged‑in user owns it.

### BOLA-R-0029 — BOLA in POST /ProfileServlet: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST <see web.xml servlet-mapping>  
- **Location:** `java-legacy/src/com/acme/web/ProfileServlet.java:9`

**Evidence.**

- `java-legacy/src/com/acme/web/ProfileServlet.java:12` — Populates an Account object from request parameters without checking that the current user owns the account  
  `BeanUtils.populate(account, request.getParameterMap());`

**Recommendation.** Verify that the current user is authorized to modify the account before persisting changes

*Verifier:* likely — checked: Reviewed ProfileServlet.java lines 9-13. Account object is populated from request parameters without any ownership validation in the shown code.

### BOLA-R-0030 — BOLA in POST /admin/users/:id/delete: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /admin/users/:id/delete  
- **Location:** `node-express/routes/admin.js:8`

**Evidence.**

- `node-express/routes/admin.js:8` — Only a logged‑in user is required; no role or ownership check, so any authenticated user can delete any user.  
  `User.deleteOne({ _id: req.params.id }, function () { res.sendStatus(204); });`

**Recommendation.** Require an admin role and verify that the target user is not the current user before deletion.

*Verifier:* likely — checked: node-express/routes/admin.js:8-10. The route handler only checks that a user is logged in via `ensureLoggedIn`. No role check (`requireAdmin`) or ownership verification is present in the visible code. Therefore a compensating control is not observable.

### BOLA-R-0033 — BOLA in GET /orders/:id: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-284   
- **Endpoint:** GET /orders/:id  
- **Location:** `node-express/routes/orders.js:8`

**Evidence.**

- `node-express/routes/orders.js:8` — The order ID comes from the request and is used without checking that the order belongs to the authenticated user.  
  `Order.findById(req.params.id, function (err, order) { res.json(order); });`

**Recommendation.** Add an ownership check by filtering on the authenticated user’s ID or by loading the order and verifying its owner before returning it.

*Verifier:* likely — checked: node-express/routes/orders.js:8-10. The handler retrieves an order by ID without filtering on the authenticated user. No ownership check or role guard is visible in the provided snippet.

### BOLA-R-0043 — BOLA in ANY /perl-cgi/cgi-bin/order.cgi: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-284   
- **Endpoint:** ANY /perl-cgi/cgi-bin/order.cgi  
- **Location:** `perl-cgi/cgi-bin/order.cgi:13`

**Evidence.**

- `perl-cgi/cgi-bin/order.cgi:13` — The order ID is taken directly from the request and the query does not constrain the result to the authenticated user.  
  `$sth = $dbh->prepare("SELECT * FROM orders WHERE id = $id");`

**Recommendation.** Modify the query to include a user_id filter or verify the owner after fetching the record.

*Verifier:* likely — checked: perl-cgi/cgi-bin/order.cgi:13-15. The first prepared statement selects `orders` solely by `id` and is executed immediately. Although a second query later includes `user_id`, the initial query is still vulnerable. No ownership guard is present in the shown code.

### BOLA-R-0044 — BOLA in ANY /invoice/view/{id}: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-284   
- **Endpoint:** ANY /invoice/view/{id}  
- **Location:** `php-codeigniter/application/controllers/Invoice.php:10`

**Evidence.**

- `php-codeigniter/application/controllers/Invoice.php:10` — The invoice ID is taken from the request and the query does not restrict to the authenticated user’s invoices.  
  `$q = $this->db->query("SELECT * FROM invoices WHERE id = $id");`

**Recommendation.** Add a WHERE clause that includes the current user’s ID or load the invoice and compare its owner before returning it.

*Verifier:* likely — checked: php-codeigniter/application/controllers/Invoice.php:10-12. The `view` method runs a raw query against `invoices` using the supplied `id` without scoping to the current user. No ownership check is visible.

### BOLA-R-0046 — BOLA in ANY /invoice/update: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-284   
- **Endpoint:** ANY /invoice/update  
- **Location:** `php-codeigniter/application/controllers/Invoice.php:23`

**Evidence.**

- `php-codeigniter/application/controllers/Invoice.php:23` — The invoice ID is taken from the request and the update statement does not verify that the invoice belongs to the authenticated user.  
  `$this->db->query("UPDATE invoices SET note = ? WHERE id = ?", array($note, $id));`

**Recommendation.** Include the authenticated user’s ID in the WHERE clause or verify ownership before performing the update.

*Verifier:* likely — checked: php-codeigniter/application/controllers/Invoice.php:23-24. The `update` method updates an invoice by `id` without verifying that the invoice belongs to the authenticated user. No ownership guard is present in the snippet.

### BOLA-R-0057-1 — BOLA in GET /account/rename: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /account/rename  
- **Location:** `php-plain/admin.php:7`

**Evidence.**

- `php-plain/admin.php:7` — Object ID comes from the request  
  `$uid = (int)$_GET['uid'];`
- `php-plain/admin.php:8` — Query does not restrict by current user  
  `$r = mysql_query("SELECT * FROM users WHERE id = " . $uid);`

**Recommendation.** Add a WHERE clause that binds the user ID to the session user or verify ownership after fetching the record

*Verifier:* likely — checked: php-plain/admin.php lines 5-9, php-plain/inc/auth.php lines 1-7, php-plain/inc/db.php lines 1-4. The code shows a direct lookup of a user by id from the request with no ownership or role check. No global filter or other control is visible in the provided context.

### BOLA-R-0057-2 — BOLA in POST /account/rename: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /account/rename  
- **Location:** `php-plain/admin.php:6`

**Evidence.**

- `php-plain/admin.php:11` — Object ID comes from the request  
  `$id = $_POST['id'];`
- `php-plain/admin.php:12` — Delete query does not restrict by current user  
  `mysql_query("DELETE FROM users WHERE id = $id");`

**Recommendation.** Add a WHERE clause that binds the user ID to the session user or verify ownership before deletion

*Verifier:* likely — checked: php-plain/admin.php lines 10-13, php-plain/inc/auth.php lines 1-7, php-plain/inc/db.php lines 1-4. The delete action uses the id from the request without any ownership or role verification. No compensating control is shown.

### BOLA-R-0058-1 — BOLA in POST /account/rename: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /account/rename  
- **Location:** `php-plain/admin.php:11`

**Evidence.**

- `php-plain/admin.php:11` — Object ID comes from the request  
  `$id = $_POST['id'];`
- `php-plain/admin.php:12` — Delete query does not restrict by current user  
  `mysql_query("DELETE FROM users WHERE id = $id");`

**Recommendation.** Add a WHERE clause that binds the user ID to the session user or verify ownership before deletion

*Verifier:* likely — checked: php-plain/admin.php lines 10-13, php-plain/inc/auth.php lines 1-7, php-plain/inc/db.php lines 1-4. Same as BOLA-R-0057-2: no ownership or role check is present in the visible code.

### BOLA-R-0059-1 — BOLA in POST /php-plain/manage_users.php: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /php-plain/manage_users.php  
- **Location:** `php-plain/manage_users.php:5`

**Evidence.**

- `php-plain/manage_users.php:5` — Object ID comes from the request  
  `if ($_SERVER['REQUEST_METHOD'] === 'POST') {`
- `php-plain/manage_users.php:6` — Query does not restrict by current user  
  `$stmt = $db->prepare("DELETE FROM users WHERE id = ?");`

**Recommendation.** Add a WHERE clause that binds the user ID to the session user or verify ownership before deletion

*Verifier:* confirmed — checked: php-plain/manage_users.php:5-8. The POST handler deletes a user by id without any role or ownership check. The only role check is in the HTML link, not in the request handling code.

### BOLA-R-0061-1 — BOLA in GET /php-plain/order_detail.php: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /php-plain/order_detail.php  
- **Location:** `php-plain/order_detail.php:5`

**Evidence.**

- `php-plain/order_detail.php:5` — Object ID comes from the request  
  `$id = $_GET['id'];`
- `php-plain/order_detail.php:6` — Query does not restrict by current user  
  `$res = mysql_query("SELECT * FROM orders WHERE id = " . $id);`

**Recommendation.** Add a WHERE clause that binds the user ID to the session user or verify ownership after fetching the record

*Verifier:* confirmed — checked: php-plain/order_detail.php:5-6. The query selects an order by id without scoping to the current user and no ownership check is present.

### BOLA-R-0066-1 — BOLA in POST /php-plain/admin/delete_user.php: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /php-plain/admin/delete_user.php  
- **Location:** `php-plain/admin/delete_user.php:5`

**Evidence.**

- `php-plain/admin/delete_user.php:5` — Object ID comes from the request  
  `$id = (int)$_POST['id'];`
- `php-plain/admin/delete_user.php:6` — Query does not restrict by current user  
  `$stmt = $db->prepare("DELETE FROM users WHERE id = ?");`

**Recommendation.** Add a WHERE clause that binds the user ID to the session user or verify ownership before deletion

*Verifier:* likely — checked: php-plain/admin/delete_user.php lines 5-7, php-plain/inc/auth.php lines 1-7, php-plain/inc/db.php lines 1-4. The delete query uses a bound parameter but does not restrict by the current user. No ownership or role check is visible.

### BOLA-R-0067-1 — BOLA in POST /php-plain/admin/promote.php: missing owner verification

- **Severity / confidence:** high / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /php-plain/admin/promote.php  
- **Location:** `php-plain/admin/promote.php:5`

**Evidence.**

- `php-plain/admin/promote.php:5` — Object ID comes from the request  
  `if ($_POST['is_admin'] == '1') {`
- `php-plain/admin/promote.php:6` — Query does not restrict by current user  
  `$stmt = $db->prepare("UPDATE users SET role = 'admin' WHERE id = ?");`

**Recommendation.** Add a WHERE clause that binds the user ID to the session user or verify ownership before role change

*Verifier:* likely — checked: php-plain/admin/promote.php lines 5-7, php-plain/inc/auth.php lines 1-7, php-plain/inc/db.php lines 1-4. The promotion logic checks a request parameter but does not verify that the requester owns the target user or has an admin role. No compensating control is shown.

### BOLA-R-0069-1 — BOLA in GET /orders/<int:order_id>: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** GET /orders/<int:order_id>  
- **Location:** `python-flask/app.py:12`

**Evidence.**

- `python-flask/app.py:12` — Query does not restrict by current user  
  `cur.execute("SELECT * FROM orders WHERE id = %s" % order_id)`

**Recommendation.** Add a WHERE clause that binds the user ID to the current_user.id or verify ownership after fetching the record

*Verifier:* confirmed — checked: python-flask/app.py:8-13. The route '/orders/<int:order_id>' retrieves an order by id without filtering by user_id. The only ownership check is in the '/orders/mine/<int:order_id>' route.

### BOLA-R-0073 — BOLA in POST /users/<int:uid>/name: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** POST /users/<int:uid>/name  
- **Location:** `python-flask/profile.py:16`

**Evidence.**

- `python-flask/profile.py:18` — Loads the target user by ID without checking that the current user owns the record  
  `user = User.query.get(uid)`

**Recommendation.** Verify that the current user owns the user record before allowing a name change

*Verifier:* confirmed — checked: python-flask/profile.py lines 16-20. The function loads a User by uid and updates the name without any ownership check or role verification. No compensating control is present in the visible code.

### BOLA-R-0074 — BOLA in PATCH /users/<int:uid>: missing owner verification

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-284, CWE-639   
- **Endpoint:** PATCH /users/<int:uid>  
- **Location:** `python-flask/profile.py:24`

**Evidence.**

- `python-flask/profile.py:26` — Loads the target user by ID without verifying ownership  
  `user = User.query.get(uid)`

**Recommendation.** Add an ownership check before applying updates to the user record

*Verifier:* confirmed — checked: python-flask/profile.py lines 24-30. The function loads a User by uid and applies arbitrary updates without verifying that the current user owns the record. No compensating control is present in the visible code.

### MASS-M-0009-1 — Team owner_id is writable via mass assignment

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** mass_assignment (privileged_field_writable) — CWE-915   
- **Endpoint:** - -  
- **Location:** `php-laravel/app/Http/Controllers/AccountController.php:23`

**Impact.** Any authenticated user can set the owner_id of a Team, effectively taking ownership of any team.

**Evidence.**

- `php-laravel/app/Http/Controllers/AccountController.php:23` — Whole object binding: Team::create($request->all());
- `php-laravel/app/Models/Team.php:8` — fillable includes privileged field owner_id

**Recommendation.** Remove owner_id from $fillable or set it server‑side after validating ownership.

*Verifier:* confirmed — checked: php-laravel/app/Http/Controllers/AccountController.php: lines 21-24, php-laravel/app/Models/Team.php: line 8. Team::create($request->all()) uses the model’s $fillable which includes the privileged field owner_id, allowing an attacker to set ownership.

### BOLA-R-0052-verdict — Missing ownership check at php-laravel/routes/web.php:6 (from auditor verdict)

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284   
- **Endpoint:** POST /register  
- **Location:** `php-laravel/routes/web.php:6`

**Impact.** Generated from the auditor's 'needs_review' verdict; the model wrote no finding for it.

**Evidence.**

- `php-laravel/routes/web.php:6` — The auditor judged this route 'needs_review' but wrote no finding

**Recommendation.** Bind the object lookup to the current user or tenant, or check ownership before using it.

*Verifier:* likely — checked: php-laravel/routes/web.php line 6. The route definition does not show any ownership or role check. No ownership verification is visible in the provided code context.

### BOLA-R-0053-verdict — Missing ownership check at php-laravel/routes/web.php:7 (from auditor verdict)

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284   
- **Endpoint:** POST /posts  
- **Location:** `php-laravel/routes/web.php:7`

**Impact.** Generated from the auditor's 'needs_review' verdict; the model wrote no finding for it.

**Evidence.**

- `php-laravel/routes/web.php:7` — The auditor judged this route 'needs_review' but wrote no finding

**Recommendation.** Bind the object lookup to the current user or tenant, or check ownership before using it.

*Verifier:* likely — checked: php-laravel/routes/web.php line 7. The route definition does not contain any ownership or role check. No ownership verification is visible in the provided code context.

### BOLA-R-0054-verdict — Missing ownership check at php-laravel/routes/web.php:8 (from auditor verdict)

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284   
- **Endpoint:** POST /teams  
- **Location:** `php-laravel/routes/web.php:8`

**Impact.** Generated from the auditor's 'needs_review' verdict; the model wrote no finding for it.

**Evidence.**

- `php-laravel/routes/web.php:8` — The auditor judged this route 'needs_review' but wrote no finding

**Recommendation.** Bind the object lookup to the current user or tenant, or check ownership before using it.

*Verifier:* likely — checked: php-laravel/routes/web.php line 8. The route definition does not contain any ownership or role check. No ownership verification is visible in the provided code context.

### BOLA-R-0055-verdict — Missing ownership check at php-laravel/routes/web.php:9 (from auditor verdict)

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284   
- **Endpoint:** POST /account/rename  
- **Location:** `php-laravel/routes/web.php:9`

**Impact.** Generated from the auditor's 'needs_review' verdict; the model wrote no finding for it.

**Evidence.**

- `php-laravel/routes/web.php:9` — The auditor judged this route 'needs_review' but wrote no finding

**Recommendation.** Bind the object lookup to the current user or tenant, or check ownership before using it.

*Verifier:* likely — checked: php-laravel/routes/web.php:6-9. The route definition is shown, but the controller implementation is not visible in the provided context, so ownership checks cannot be confirmed or denied.

### BOLA-R-0056-verdict — Missing ownership check at php-laravel/routes/web.php:10 (from auditor verdict)

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** bola (missing_ownership_check) — CWE-284   
- **Endpoint:** POST /account/profile  
- **Location:** `php-laravel/routes/web.php:10`

**Impact.** Generated from the auditor's 'needs_review' verdict; the model wrote no finding for it.

**Evidence.**

- `php-laravel/routes/web.php:10` — The auditor judged this route 'needs_review' but wrote no finding

**Recommendation.** Bind the object lookup to the current user or tenant, or check ownership before using it.

*Verifier:* likely — checked: php-laravel/routes/web.php:6-10. Only the route definition is visible; the controller logic that might enforce ownership is not shown.

### MASS-M-0001-verdict — Mass assignment at dotnet-legacy/Web/Controllers/CustomerController.cs:12 (from auditor verdict)

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Controllers/CustomerController.cs:12`

**Impact.** Generated from the auditor's 'needs_review' verdict; the model wrote no finding for it.

**Evidence.**

- `dotnet-legacy/Web/Controllers/CustomerController.cs:12` — The auditor judged this candidate 'needs_review' but wrote no finding

**Recommendation.** Bind only an explicit allow-list of fields; never bind role, owner or balance fields.

*Verifier:* likely — checked: dotnet-legacy/Web/Controllers/CustomerController.cs:12-15. The Edit action accepts a Customer model and marks it Modified without any [Bind] include or ownership check in the snippet. The [Authorize] attribute only ensures authentication, not ownership.

### MASS-M-0002-verdict — Mass assignment at dotnet-legacy/Web/Controllers/CustomerController.cs:30 (from auditor verdict)

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `dotnet-legacy/Web/Controllers/CustomerController.cs:30`

**Impact.** Generated from the auditor's 'needs_review' verdict; the model wrote no finding for it.

**Evidence.**

- `dotnet-legacy/Web/Controllers/CustomerController.cs:30` — The auditor judged this candidate 'needs_review' but wrote no finding

**Recommendation.** Bind only an explicit allow-list of fields; never bind role, owner or balance fields.

*Verifier:* likely — checked: dotnet-legacy/Web/Controllers/CustomerController.cs: lines 26-31. The code shows a mass assignment via TryUpdateModel(customer) but no ownership or role check, integer cast, or allow‑list is visible in the provided snippet.

### MASS-M-0006-1 — Unknown model fields in whole object binding

- **Severity / confidence:** medium / high  
- **Status:** confirmed  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `node-express/routes/profile.js:8`

**Impact.** Unable to determine if privileged fields are writable.

**Evidence.**

- `node-express/routes/profile.js:8` — Location taken from the Tier 1 inventory

**Recommendation.** Review the User model definition and ensure privileged fields are not mass‑assignable.

*Verifier:* confirmed — checked: node-express/routes/profile.js: lines 7-9. User.findByIdAndUpdate(req.user._id, req.body, ...) performs a whole‑object bind with no allow‑list or ownership check.

### MASS-M-0007-1 — Unknown model fields in whole object binding

- **Severity / confidence:** medium / high  
- **Status:** confirmed  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `node-express/routes/profile.js:16`

**Impact.** Unable to determine if privileged fields are writable.

**Evidence.**

- `node-express/routes/profile.js:16` — Location taken from the Tier 1 inventory

**Recommendation.** Review the User model definition and ensure privileged fields are not mass‑assignable.

*Verifier:* confirmed — checked: node-express/routes/profile.js: lines 16-17. new User(req.body) followed by user.save() allows all fields from the request to be persisted without filtering.

### MASS-M-0008-1 — Unknown model fields in whole object binding

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `php-laravel/app/Http/Controllers/AccountController.php:13`

**Impact.** Unable to determine if privileged fields are writable due to missing field list.

**Evidence.**

- `php-laravel/app/Http/Controllers/AccountController.php:13` — Whole object binding: User::create($request->all());

**Recommendation.** Inspect the User model to confirm which fields are mass‑assignable and restrict privileged ones.

*Verifier:* likely — checked: php-laravel/app/Http/Controllers/AccountController.php: line 13. The User model definition is not shown; therefore it is unclear whether privileged fields are protected by $fillable/$guarded.

### MASS-M-0010-1 — Unknown model fields in whole object binding

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `php-laravel/app/Http/Controllers/AccountController.php:36`

**Impact.** Unable to determine if privileged fields are writable.

**Evidence.**

- `php-laravel/app/Http/Controllers/AccountController.php:23` — Whole object binding: Team::create($request->all());

**Recommendation.** Review the Team model definition and ensure privileged fields are not mass‑assignable.

*Verifier:* likely — checked: AccountController.php: lines 18-23 (team creation), AccountController.php: lines 36-37 (profile update). The controller performs whole‑object binding via $request->all() but the model’s $fillable/$guarded definition is not shown. No visible field whitelist or ownership check is present in the provided code.

### MASS-M-0011-verdict — Mass assignment at php-plain/profile.php:6 (from auditor verdict)

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `php-plain/profile.php:6`

**Impact.** Generated from the auditor's 'needs_review' verdict; the model wrote no finding for it.

**Evidence.**

- `php-plain/profile.php:6` — The auditor judged this candidate 'needs_review' but wrote no finding

**Recommendation.** Bind only an explicit allow-list of fields; never bind role, owner or balance fields.

*Verifier:* likely — checked: php-plain/profile.php:6-8. The code iterates over $_POST and assigns each field to the user object without any allow‑list or ownership check. The included auth.php only verifies login, not ownership.

### MASS-M-0012-verdict — Mass assignment at php-plain/profile.php:10 (from auditor verdict)

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** mass_assignment (privileged_field_writable) — CWE-915   
- **Endpoint:** - -  
- **Location:** `php-plain/profile.php:10`

**Impact.** Generated from the auditor's 'needs_review' verdict; the model wrote no finding for it.

**Evidence.**

- `php-plain/profile.php:10` — The auditor judged this candidate 'needs_review' but wrote no finding

**Recommendation.** Bind only an explicit allow-list of fields; never bind role, owner or balance fields.

*Verifier:* likely — checked: php-plain/profile.php:10. The assignment of $_POST['role'] to $user->role occurs without any guard or allow‑list in the visible code.

### MASS-M-0014-1 — Unknown model fields in whole object binding

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `python-flask/profile.py:10`

**Impact.** Unable to determine if privileged fields are writable.

**Evidence.**

- `python-flask/profile.py:10` — Location taken from the Tier 1 inventory

**Recommendation.** Use a DTO or explicit field mapping to prevent mass assignment of privileged fields.

*Verifier:* likely — checked: profile.py: lines 8-12 (POST route creating User with **request.json). The constructor receives all JSON fields directly; no field filtering or guard is shown in the provided code.

### MASS-M-0015-1 — Unknown model fields in whole object binding

- **Severity / confidence:** medium / medium  
- **Status:** likely  
- **Category:** mass_assignment (whole_object_binding) — CWE-915   
- **Endpoint:** - -  
- **Location:** `python-flask/profile.py:27`

**Impact.** Unable to determine if privileged fields are writable.

**Evidence.**

- `python-flask/profile.py:27` — Location taken from the Tier 1 inventory

**Recommendation.** Validate and whitelist request fields before setting attributes.

*Verifier:* likely — checked: profile.py: lines 24-29 (PATCH route with setattr loop). All JSON keys are set on the user object without any whitelist or guard. No compensating control is visible in the snippet.

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
| INJ-I-0005 | `classic-asp/shop/order.asp:12` | The query includes an ownership check by binding the user_id to the session value and casts the sid to a long, preventing injection and ensuring the user can only access their own orders. |
| MASS-M-0013-1 | `php-plain/register.php:4` | The code does not bind all POST values to a model; it explicitly inserts only email, name, and role columns. The evidence claiming whole‑object binding is incorrect. |

## Appendix B — Method

1. Deterministic pre-scan (stack detection, endpoint candidates, query-building candidates).
2. AI agents: auth-model extraction, route inventory, BOLA audit, injection audit.
3. Independent AI verifier tries to refute each finding.
4. Human review and sign-off (`review-log.md`).

This is not a penetration test. Absence of findings does not prove absence of vulnerabilities.
