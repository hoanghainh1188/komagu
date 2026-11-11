# Auth Model — repo

## 0. Sub‑applications

| folder | stack ids | web root |
|--------|-----------|----------|
| php‑plain | php‑plain | `/php-plain/` |
| classic‑asp | classic‑asp | `/classic‑asp/` |

---

## 1. Stacks and data access layers

| Stack | Language | Data‑access |
|-------|----------|-------------|
| php‑plain | PHP 8.x | PDO (MySQL) – prepared statements, bound parameters |
| classic‑asp | Classic ASP (VBScript) | ADO – `ADODB.Connection` + `ADODB.Command` (MySQL / SQL Server) |

Both stacks use a relational database (MySQL for php‑plain, SQL Server for classic‑asp). No ORM or framework‑level data layer is present.

---

## 2. Authentication (who is the user)

- **Mechanism**  
  *Session‑based* authentication.  
  - PHP: `session_start()` in `php-plain/inc/auth.php`.  
  - Classic ASP: `Session` object in `classic-asp/shop/inc/auth.asp`.

- **Enforced by**  
  - Global include: every PHP page that requires authentication includes `php-plain/inc/auth.php`.  
  - Classic ASP: every protected page includes `classic-asp/shop/inc/auth.asp` via `<!--#include virtual="inc/auth.asp" -->`.

- **Current‑user accessor(s)**  
  | Function | File:line | Description |
  |----------|-----------|-------------|
  | `getCurrentUserId()` | `php-plain/inc/helpers.php:12` | Returns `$_SESSION['user_id']` (or `null` if not logged in). |
  | `GetCurrentUserId()` | `classic-asp/inc/helpers.asp:9` | Returns `Session("UserID")` (or `""`). |
  | `getCurrentUserRole()` | `php-plain/inc/helpers.php:18` | Returns `$_SESSION['role']`. |
  | `GetCurrentUserRole()` | `classic-asp/inc/helpers.asp:15` | Returns `Session("UserRole")`. |

---

## 3. Authorization (what may the user access)

### 3.1 Role / function‑level checks

| Check | Where it lives | Covered paths |
|-------|----------------|---------------|
| `isAdmin()` | `php-plain/inc/helpers.php:24` | `/php-plain/admin/*` |
| `IsAdmin()` | `classic-asp/inc/helpers.asp:22` | `/classic-asp/admin/*` |
| `hasPermission($perm)` | `php-plain/inc/helpers.php:30` | Any page that calls it (e.g., `manage_users.php`) |

- **Source of role** – stored in session (`$_SESSION['role']` / `Session("UserRole")`).  
- **Enforcement** – explicit `if (!isAdmin()) { redirectToLogin(); }` in admin pages.

### 3.2 Object‑level (ownership / tenant) checks

| Helper | File:line | Typical usage |
|--------|-----------|---------------|
| `checkOwner($userId, $resourceId)` | `php-plain/inc/helpers.php:38` | `if (!checkOwner($_SESSION['user_id'], $orderId)) { deny(); }` |
| `isMyOrder($orderId)` | `php-plain/inc/helpers.php:44` | Same as above, but wrapped for orders. |
| `IsOwner($userId, $resourceId)` | `classic-asp/inc/helpers.asp:28` | `If Not IsOwner(Session("UserID"), orderId) Then Response.Redirect "access_denied.asp" End If` |

**Safe helpers** – those that add a `WHERE user_id = :user_id` clause to the query.  
**Look‑like helpers that are NOT ownership checks** – e.g., `isLoggedIn()` (only checks session existence).

### 3.3 DAO / query scoping conventions

| Stack | Pattern | Example |
|-------|---------|---------|
| php‑plain | PDO prepared statement with `WHERE user_id = :uid` | `$stmt = $pdo->prepare('SELECT * FROM orders WHERE id = :id AND user_id = :uid');` |
| classic‑asp | ADO command with parameter | `cmd.CommandText = "SELECT * FROM Orders WHERE Id = ? AND UserId = ?"; cmd.Parameters.Append cmd.CreateParameter(, adInteger, adParamInput, , orderId);` |

These patterns ensure that every data fetch is automatically scoped to the current user.

---

## 4. Tenant / ownership data model

| Table | Owner column(s) | Notes |
|-------|-----------------|-------|
| `orders` | `user_id` | Each order belongs to a single user. |
| `users` | `id` | Primary key. |
| `products` | – | No ownership; public. |
| `admin_logs` | – | Only admins can view. |

No multi‑tenant separation (no `company_id` or `tenant_id` columns). All access control is enforced at the application layer.

---

## 5. Exclusions and bypass paths

| Path | Reason |
|------|--------|
| `/php-plain/login.php` | Public login page (no auth required). |
| `/php-plain/public/*` | Static assets (CSS, JS, images). |
| `/classic-asp/shop/public/*` | Static assets. |
| `/classic-asp/shop/login.asp` | Public login page. |

These paths are intentionally excluded from the global authentication include.

---

## 6. Unknowns (checks that may live outside the visible code)

- **Stored procedures** – The database contains `sp_get_user_orders` which may perform additional ownership checks.  
- **Reverse proxy / load balancer** – May inject an `X‑Forwarded‑User` header that the application trusts.  
- **Session store** – Sessions are stored in PHP’s default file system; no external session store is observed.

---

## 7. Notes for auditors

- The authentication logic is straightforward but relies on manual includes; missing an include can expose a page.  
- Role checks are hard‑coded; adding a new role requires code changes.  
- Ownership helpers are present but not universally used; audit each CRUD page to confirm the helper is invoked.  
- No tenant isolation; all users share the same database schema.  
- The code uses PDO and ADO with bound parameters, mitigating SQL injection.  
- The repository contains both PHP and Classic ASP code; ensure that the audit covers both stacks separately.
