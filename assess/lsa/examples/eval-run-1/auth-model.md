# Auth Model — repo
Multi-stack test repo: each top-level folder is a separate app with its own auth. No shared auth layer exists.

## 1. Stacks and data access layers
- **php-plain**: PHP 5, `mysql_*` (inc/db.php:2), PDO (inc/db.php:4), legacy MongoClient (mongo_find.php:3). MySQL + MongoDB.
- **php-codeigniter**: CodeIgniter 2/3 (core is a placeholder, system/core/CodeIgniter.php:1); CI DB `query()`/`get_where()` (Invoice.php:10,16,23).
- **java-legacy**: Servlet (web.xml:11-18), JSP scriptlet (order/detail.jsp:2-6), Struts 1 (struts-config.xml:4), Spring MVC 2.5-3.x (InvoiceController.java:8-9), JDBC, Hibernate HQL (InvoiceController.java:29), MyBatis 3 (OrderMapper.xml:3), DAO `InvoiceDao` (not in repo).
- **dotnet-legacy**: WebForms C#/VB (OrderDetail.aspx.cs, EditOrder.aspx.vb), `.ashx` (GetFile.ashx:4), MVC (InvoiceController.cs:2); ADO.NET `SqlCommand`, EF-style `ShopDb` (not in repo).
- **classic-asp**: VBScript + ADO (inc/conn.asp:2).
- **coldfusion**: `cfquery` (order.cfm:2, OrderService.cfc:4).
- **perl-cgi**: CGI.pm + CGI::Session + DBI/mysql (order.cgi:3-5,10).
- **node-express**: Express 4 router (routes/orders.js:2); `db.query` SQL + Mongo collection/model (orders.js:9,17,21).
- **python-flask**: Flask + Flask-Login, DB-API cursor (app.py:1-2,11).
- **sql-procs**: T-SQL proc with dynamic `EXEC(@sql)` (sp_search_orders.sql:5-6). No caller in repo.

## 2. Authentication (who is the user)
### php-plain
- Mechanism: PHP session; `inc/auth.php:3-7` redirects + `exit` if `$_SESSION['user_id']` empty (stop is correct).
- Enforced by: per-page `require_once 'inc/auth.php'` — present in all 5 pages (admin.php:2, mongo_find.php:2, order_detail.php:2, order_detail_safe.php:2, search.php:2).
- Current-user accessor(s): `$_SESSION['user_id']` (order_detail_safe.php:6).
### php-codeigniter
- Mechanism/enforced by: presumably `MY_Controller` constructor (Invoice.php:2,5) — **source not in repo**.
- Current-user accessor(s): `$this->session->userdata('user_id')` (Invoice.php:15).
### java-legacy
- Mechanism: `LoginFilter` (web.xml:3-6, class not in repo) mapped to `*.do` only (web.xml:9).
- Enforced by: global filter for `*.do`. `/order/view` (web.xml:17) and `*.jsp` are NOT covered. Spring `/invoices/*` coverage unknown (no DispatcherServlet in web.xml).
- Current-user accessor(s): `session.getAttribute("loginUser")` (OrderServlet.java:10, read but never checked); `Principal principal.getName()` (InvoiceController.java:22-23).
### dotnet-legacy
- Mechanism: Forms auth, global `<deny users="?"/>` (Web.config:4-5). MVC `[Authorize]` on class (InvoiceController.cs:6). Pages inherit `BasePage` (OrderDetail.aspx.cs:6, EditOrder.aspx.vb:4) — **not in repo**.
- Current-user accessor(s): `Session["UserID"]` (OrderDetail.aspx.cs:18); `CurrentUserId()` (InvoiceController.cs:19, not in repo).
### classic-asp
- Mechanism: `inc/auth.asp:2` — `If Session("UserID") = "" Then Response.Redirect` (treat as stop, medium).
- Enforced by: per-page include (member.asp:1, order.asp:1).
- Current-user accessor(s): `Session("UserID")` (order.asp:12).
### coldfusion
- Mechanism: per-page `session.userID` check + `cflocation` (order.cfm:1). No Application.cfc/.cfm in repo.
- `OrderService.cfc` `access="remote"` (OrderService.cfc:2) has **no** login check.
- Current-user accessor(s): `session.userID` (order.cfm:8).
### perl-cgi
- Mechanism: `CGI::Session->load() or die` (order.cgi:8). `load()` returns an empty session if none exists, so this is NOT a login check (medium; library behavior). `$uid` never tested (order.cgi:9).
- Current-user accessor(s): `$session->param('user_id')` (order.cgi:9).
### node-express
- Mechanism: per-route `ensureLoggedIn` checks `req.user` (orders.js:6). Who sets `req.user` (passport?) is not in repo.
- Unguarded routes: `POST /login` (orders.js:20), `GET /stats` (orders.js:28).
- Current-user accessor(s): `req.user._id` (orders.js:13).
### python-flask
- Mechanism: Flask-Login `@login_required` on every route (app.py:9,17,25). `user_loader` not in repo.
- Current-user accessor(s): `current_user.id` (app.py:20).

## 3. Authorization (what may the user access)
- Role / function-level checks: **none found in any sub-app.** php-plain `admin.php` has only the login include (admin.php:2), no admin role check. MVC `[Authorize]` has no `Roles=` (InvoiceController.cs:6). No `isUserInRole`, `@PreAuthorize`, CI role helper visible.
- Object-level (ownership / tenant) checks — inline only, no shared helper:
  - php-plain: `WHERE id = ? AND user_id = ?` bound to session (order_detail_safe.php:5-6).
  - php-codeigniter: `get_where(... 'user_id' => $uid)` from session (Invoice.php:15-16).
  - java-legacy: `invoiceDao.findByIdAndOwner(id, principal.getName())` (InvoiceController.java:23) — DAO source missing; treat as safe-by-name only (medium). MyBatis `list` filters `user_id = #{userId}` (OrderMapper.xml:8) — caller unknown.
  - dotnet-legacy: LINQ `i.Id == id && i.UserId == uid` + `HttpNotFound()` (InvoiceController.cs:20-21); `SqlCommand` with `@uid` = `Session["UserID"]` (OrderDetail.aspx.cs:16-18; built but never executed).
  - classic-asp: `AND user_id = CLng(Session("UserID"))` (order.asp:12).
  - coldfusion: `cfqueryparam` `user_id = session.userID` (order.cfm:5-9).
  - perl-cgi: `AND user_id = ?` with `$uid` (order.cgi:16-17) — but `$uid` may be undef (see §2).
  - node-express: `findOne({_id, owner: req.user._id})` (orders.js:13).
  - python-flask: `AND user_id = %s` bound to `current_user.id` (app.py:20).
- Helpers that are SAFE to treat as an ownership check:
  - None as reusable helpers. Only the inline session-bound query patterns above. `InvoiceDao.findByIdAndOwner` is a candidate but unverified (source missing).
- Helpers that LOOK like checks but are NOT (e.g. only check login):
  - `php-plain/inc/auth.php:2-7` — login only (its own comment says so).
  - `classic-asp/shop/inc/auth.asp:2` — login only.
  - `coldfusion/app/order.cfm:1` — login only.
  - `java-legacy` `LoginFilter` (web.xml:3-9) — assumed login only, source missing; `*.do` only.
  - `dotnet-legacy` `<deny users="?"/>` (Web.config:5), `[Authorize]` (InvoiceController.cs:6), `BasePage` (not in repo) — login only.
  - `node-express` `ensureLoggedIn` (orders.js:6) — login only.
  - `python-flask` `@login_required` (app.py:9,17,25) — login only.
  - `perl-cgi` `CGI::Session->load() or die` (order.cgi:8) — not even a login check.
  - `OrderServlet` reads `loginUser` (OrderServlet.java:10) but never tests it — no check.
  - `MY_Controller` (Invoice.php:2) — unknown; do not assume ownership.

## 4. Tenant / ownership data model
- Owner columns seen: `user_id` (orders: order_detail_safe.php:5, order.asp:12, order.cfm:8, order.cgi:16, app.py:20, OrderMapper.xml:8; invoices: Invoice.php:16), `UserId` (Orders: OrderDetail.aspx.cs:16; Invoices: InvoiceController.cs:20), `owner` (Mongo orders: orders.js:13), owner by username via `findByIdAndOwner(id, principal.getName())` (InvoiceController.java:23), `shop_id` (orders.js:29 — possible tenant column, not session-bound).
- Tables with no visible owner column in any query: `members` (member.asp:7,10), `users` (admin.php:8,12; EditUserAction.java:13), `items`/`notes` (OrderServlet.java:16-18), `Logs`, `Carts` (OrderDetail.aspx.cs:19-20), `carts` (order.cgi:19), `reports` (orders.js:17), `products` (search.php, app.py:29; likely public catalog).
- Tenant model: single-tenant per-user ownership assumed everywhere; `shop_id` hints multi-shop in node-express. Unknown — confirm with owner.

## 5. Exclusions and bypass paths
- dotnet-legacy: `<location path="Handlers"> <allow users="*"/>` (Web.config:7-9) → `Handlers/GetFile.ashx` is anonymous; serves files by `file_id` (GetFile.ashx:8-10, P10/P12).
- java-legacy: LoginFilter only on `*.do` (web.xml:9) → `/order/view` (web.xml:17) and `order/detail.jsp` are unfiltered.
- coldfusion: `OrderService.cfc?method=getOrder` remote, no auth (OrderService.cfc:2).
- node-express: `GET /stats` no `ensureLoggedIn` (orders.js:28); `POST /login` intentionally public (orders.js:20).
- perl-cgi: `order.cgi` effectively unauthenticated (order.cgi:8-9).
- php-plain: `admin.php` reachable by any logged-in user (admin.php:2-14).
- dotnet-legacy: `Response.Redirect("OrderList.aspx", False)` (EditOrder.aspx.vb:14) — non-stopping redirect (after the write, so low impact here).

## 6. Unknowns (checks that may live outside the code)
- java-legacy: `LoginFilter`, `InvoiceDao`, `DataSourceHolder` sources; no `ActionServlet`/`DispatcherServlet` in web.xml, so URL reachability of `/user/edit.do` and `/invoices/*` is unknown; Spring Security config absent.
- dotnet-legacy: `BasePage`, `CurrentUserId()`, `ShopDb`, `DocStore.PathFor` (may enforce ownership); `Global.asax`, `RouteConfig` absent; IIS-level auth unknown.
- php-codeigniter: `MY_Controller`, `config/routes.php`, `config/hooks.php` absent.
- node-express: app entry (`app.use` order, passport setup, router mount prefix), `../db`, `../models/order` absent.
- python-flask: `db` module, `login_manager.user_loader` absent.
- coldfusion: no Application.cfc/.cfm; server/CF Admin restrictions on remote CFC unknown.
- classic-asp / perl-cgi: IIS / Apache directory auth (`.htaccess`) not in repo.
- sql-procs: `sp_search_orders` has no caller in repo; DB permissions / row-level security unknown.

## 7. Notes for auditors
- Every sub-app has a "bad" and a "safe" variant side by side; judge each statement, not each file (e.g. order.asp:6 vs :12, order.cfm:3 vs :7-8, order.cgi:13 vs :16).
- A login guard is never an ownership check in this repo. Treat any lookup by request ID without a session-bound owner column as P1.
- Identity from request (P2): `EditUserAction.java:10` uses `user_id` param; `admin.php:7` `uid` param; `member.asp:7,10` `member_id` param.
- Hidden field ID (`hfOrderId`, EditOrder.aspx:2) is client-controlled even with ViewState MAC.
- `OrderDetail.aspx.cs:16-18` safe command is never executed; the executed one is line 13.
- CI `update()` uses bindings (Invoice.php:23) — not SQLi, but no owner filter (P1 write).
- Lower confidence to `medium` where ownership may sit in a missing helper listed in §6.
- `out_of_scope_notes` candidates: `${param.no}` reflected in JSP (detail.jsp:7); DB password read from env (no literal secret seen).
