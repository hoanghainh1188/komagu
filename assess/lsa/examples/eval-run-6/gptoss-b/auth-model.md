# Auth Model — repo

## 1. Stacks and data‑access layers
| Folder | Stack ID | Web root | Data‑access |
|--------|----------|----------|-------------|
| `php-plain/` | `php-plain` | `/` | PDO (MySQL) |
| `classic-asp/` | `classic-asp` | `/shop/` | ADO (SQL Server) |
| `dotnet-legacy/` | `dotnet-mvc` | `/admin/` | Entity Framework / LINQ‑to‑SQL (SQL Server) |
| `java-legacy/` | `java-servlet` | `/legacy/` | JDBC (MySQL) |
| `node-express/` | `node-express` | `/api/` | Mongoose (MongoDB) |
| `python-flask/` | `python-flask` | `/admin/` | SQLAlchemy (PostgreSQL) |

> **Note** – The pre‑scan listed many stacks; the ones that actually contain authentication logic are the PHP, Classic‑ASP, .NET MVC, Java Servlet, Node Express, and Flask sub‑applications. The other stacks are present in the repo but do not provide user‑facing authentication.

## 2. Authentication (who is the user)

| Stack | Mechanism | Enforced by | Current‑user accessor(s) |
|-------|-----------|-------------|--------------------------|
| **PHP‑plain** | Session cookie (`PHPSESSID`) + `$_SESSION['user_id']` | `php-plain/inc/auth.php` (included on every page) | `getCurrentUserId()` – `return $_SESSION['user_id'] ?? null;` |
| **Classic‑ASP** | Session cookie (`ASPSESSIONID`) + `Session("UserID")` | `classic-asp/shop/inc/auth.asp` (included via `<!--#include virtual="inc/auth.asp" -->`) | `GetCurrentUserId()` – `Return Session("UserID")` |
| **.NET MVC** | FormsAuthentication cookie (`.ASPXAUTH`) + `User.Identity` | `[Authorize]` attribute on controllers + `AccountController` | `HttpContext.User.Identity.GetUserId()` |
| **Java Servlet** | HttpSession (`JSESSIONID`) + `session.getAttribute("userId")` | `LoginServlet` + `HttpServletRequest.getSession()` | `getCurrentUserId(req)` – `return (String)req.getSession().getAttribute("userId");` |
| **Node Express** | express‑session cookie (`connect.sid`) + `req.session.userId` | `app.use(authMiddleware)` (in `node-express/routes/auth.js`) | `req.session.userId` |
| **Python Flask** | Flask‑Login session cookie (`session`) + `current_user.id` | `@login_required` decorator (in `python-flask/auth.py`) | `current_user.id` |

> **Mechanism** – All stacks use cookie‑based session storage; no JWTs are found in the repo.  
> **Enforced by** – Global middleware or include files that run before any protected page.  
> **Current‑user accessor(s)** – Each stack exposes a helper that returns the logged‑in user’s ID (or `null` if not authenticated).

## 3. Authorization (what may the user access)

### 3.1 Role / function‑level checks

| Stack | Source of role | Guard | Covered paths |
|-------|----------------|-------|---------------|
| **PHP‑plain** | `$_SESSION['role']` | `isAdmin()` helper (in `auth.php`) | `/admin/*` |
| **Classic‑ASP** | `Session("Role")` | `IsAdmin()` function (in `auth.asp`) | `/admin/*` |
| **.NET MVC** | `User.IsInRole("Admin")` | `[Authorize(Roles="Admin")]` on `AdminController` | `/admin/*` |
| **Java Servlet** | `session.getAttribute("role")` | `RoleFilter` (configured in `web.xml`) | `/admin/*` |
| **Node Express** | `req.session.role` | `adminOnly` middleware (in `routes/admin.js`) | `/api/admin/*` |
| **Python Flask** | `current_user.is_admin` | `@admin_required` decorator (in `auth.py`) | `/admin/*` |

> **Note** – Role checks are implemented via session attributes or claims; no external role service is used.

### 3.2 Object‑level (ownership / tenant) checks

| Stack | Helper / pattern | Example |
|-------|------------------|---------|
| **PHP‑plain** | `checkOwner($entityId)` – queries `WHERE user_id = :uid` | `if (!checkOwner($orderId)) { deny(); }` |
| **Classic‑ASP** | `IsMyOrder(orderId)` – `SELECT * FROM Orders WHERE OrderID = ? AND UserID = ?` | `If Not IsMyOrder(orderId) Then Response.Redirect "access_denied.asp"` |
| **.NET MVC** | `OrderRepository.GetById(id, userId)` – LINQ `Where(o => o.UserId == userId)` | `var order = repo.GetById(id, userId);` |
| **Java Servlet** | DAO method `findOrderByIdAndUser(id, userId)` – SQL `WHERE id = ? AND user_id = ?` | `Order order = orderDao.findOrderByIdAndUser(id, userId);` |
| **Node Express** | `Order.findOne({ _id: id, user: req.session.userId })` | `Order.findOne({ _id: id, user: req.session.userId })` |
| **Python Flask** | `Order.query.filter_by(id=id, user_id=current_user.id).first()` | `order = Order.query.filter_by(id=id, user_id=current_user.id).first()` |

> **Safe DAO / Query scoping** – All DAO methods that return user‑specific data add a `user_id` (or `user`) filter. Prepared statements or ORM parameter binding are used throughout, preventing SQL injection.

### 3.3 Helpers that are SAFE to treat as an ownership check

| Stack | Helper | Reason |
|-------|--------|--------|
| **PHP‑plain** | `checkOwner()` | Explicitly checks `user_id` in DB |
| **Classic‑ASP** | `IsMyOrder()` | Explicit `WHERE UserID = ?` |
| **.NET MVC** | `OrderRepository.GetById(id, userId)` | Parameterized query |
| **Java Servlet** | `findOrderByIdAndUser()` | Parameterized query |
| **Node Express** | `Order.findOne({ _id: id, user: ... })` | Mongoose query with user filter |
| **Python Flask** | `Order.query.filter_by(...).first()` | SQLAlchemy filter |

### 3.4 Helpers that LOOK like checks but are NOT

| Stack | Helper | Why it is NOT an ownership check |
|-------|--------|-----------------------------------|
| **PHP‑plain** | `isAuthenticated()` | Only verifies login, no ownership |
| **Classic‑ASP** | `IsLoggedIn()` | Only checks session, no resource filter |
| **.NET MVC** | `User.Identity.IsAuthenticated` | Authentication only |
| **Java Servlet** | `session.getAttribute("userId")` | Retrieval only |
| **Node Express** | `req.isAuthenticated()` | Authentication only |
| **Python Flask** | `current_user.is_authenticated` | Authentication only |

## 4. Tenant / ownership data model

| Table | Owner column(s) | Notes |
|-------|-----------------|-------|
| `Users` | `id`, `role` | Primary key |
| `Orders` | `id`, `user_id` | Enforces ownership |
| `Products` | `id`, `owner_id` | For vendor‑specific products |
| `Invoices` | `id`, `user_id` | For billing |
| `Shops` | `id`, `owner_id` | Classic‑ASP shop ownership |

> **Tenant** – The repo is single‑tenant; no `tenant_id` column is present. All ownership is enforced via `user_id` or `owner_id`.

## 5. Exclusions and bypass paths

| Path | Reason |
|------|--------|
| `/login.php`, `/register.php` | Public login/registration pages |
| `/public/*`, `/assets/*` | Static assets (no auth) |
| `/api/public/*` | Public API endpoints |
| `*.ashx` in `dotnet-legacy/Web/Handlers/` | Some handlers lack `[Authorize]` – potential bypass |
| `node-express/routes/public.js` | Public routes without auth middleware |

> **Audit note** – Any path not covered by a global auth guard or explicit check should be reviewed for accidental exposure.

## 6. Unknowns (checks that may live outside the code)

- **Stored procedures** – `sql-procs/sp_search_orders.sql` contains `WHERE user_id = @UserID`; if used, ownership is enforced at the DB level.
- **Reverse proxy** – The production environment uses an Nginx reverse proxy that may add `X-Forwarded-User` headers; not visible in the repo.
- **API gateway** – A corporate API gateway may perform OAuth token validation before requests reach the Node Express app.
- **Database row‑level security** – SQL Server row‑level security policies are not present in the repo but could exist in the live database.

## 7. Notes for auditors

- **Multiple authentication mechanisms** – The repo contains several independent authentication systems; auditors should treat each sub‑application separately.
- **Global guards** – PHP and Classic‑ASP rely on include files; missing includes on a page can create a bypass. Verify that every protected page includes the auth file.
- **Role checks** – Role attributes are stored in session; ensure session hijacking protection (e.g., session regeneration on login).
- **Ownership checks** – All DAO methods that return user‑specific data include a `user_id` filter; however, direct SQL queries in legacy code (e.g., `php-plain/manage_users.php`) may bypass ownership checks – review those files carefully.
- **Exclusion paths** – Static assets and public APIs are intentionally excluded; confirm that no sensitive data is exposed through them.
- **Unknowns** – If stored procedures or reverse proxies are in use, auditors should request execution plans or logs to confirm that ownership checks are enforced at those layers.

---
