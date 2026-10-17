# Auth Model — php-plain
## 1. Stacks and data access layers
- **Stack**: Plain PHP 5.x (no framework; each `.php` file in the root directory is a direct web endpoint; `admin.php:5` acts as an `action` query-parameter dispatcher).
- **MySQL (legacy `mysql_*`)**: Connected in `inc/db.php:2-3` (`mysql_connect` / `mysql_select_db('shop', $link)`). Used with raw string concatenation/interpolation in `admin.php:8`, `admin.php:12`, `order_detail.php:6`, and `search.php:7-17`.
- **MySQL (PDO)**: Initialized as `$pdo` in `inc/db.php:4` (`new PDO('mysql:host=localhost;dbname=shop', ...)`). Used with positional prepared statements (`?`) in `order_detail_safe.php:5-6`.
- **MongoDB (`MongoClient`)**: Connected in `mongo_find.php:3-4` (`$m = new MongoClient(); $coll = $m->shop->members;`). Used in `mongo_find.php:5-6` (`findOne` and `find` with `$where`).

## 2. Authentication (who is the user)
- Mechanism: Native PHP session (`session_start()` in `inc/auth.php:3`) storing user identity in `$_SESSION['user_id']` (`inc/auth.php:4`). Unauthenticated requests are redirected via `header('Location: /login.php'); exit;` (`inc/auth.php:5-6`).
- Enforced by (global / per-page / per-controller): Per-page `require_once 'inc/auth.php';` at line 2 of every endpoint file (`admin.php:2`, `mongo_find.php:2`, `order_detail.php:2`, `order_detail_safe.php:2`, `search.php:2`). There is no global filter or `.htaccess` `auto_prepend_file` in the repository.
- Current-user accessor(s): `$_SESSION['user_id']` (checked in `inc/auth.php:4`, bound in `order_detail_safe.php:6`).

## 3. Authorization (what may the user access)
- Role / function-level checks: **None found in code.** Specifically, `admin.php:1-14` only includes `inc/auth.php:2` (login check) and performs no role or administrator privilege check before executing `case 'view'` (`admin.php:6-9`) or `case 'delete'` (`admin.php:10-13`).
- Object-level (ownership / tenant) checks: Enforced ad-hoc per query in SQL `WHERE` clauses where present.
  - Present in `order_detail_safe.php:5-6`: `SELECT * FROM orders WHERE id = ? AND user_id = ?` bound to `array($_GET['id'], $_SESSION['user_id'])`.
  - Absent in `order_detail.php:5-6`: `SELECT * FROM orders WHERE id = " . $id` (no `user_id` check in SQL or post-load).
  - Absent in `admin.php:6-13`: `SELECT * FROM users WHERE id = " . $uid` (`admin.php:8`) and `DELETE FROM users WHERE id = $id` (`admin.php:12`) have neither role checks nor self/ownership checks.
- Helpers that are SAFE to treat as an ownership check: **None.** There are no shared ownership helper functions or DAO methods in this repository; each endpoint must explicitly constrain queries by `$_SESSION['user_id']` (as in `order_detail_safe.php:5-6`).
- Helpers that LOOK like checks but are NOT (e.g. only check login):
  - `inc/auth.php:1-7` (`require_once 'inc/auth.php'`): Only verifies `!empty($_SESSION['user_id'])` (logged-in status). It explicitly notes on `inc/auth.php:2` (`// Login check only. Does NOT check object ownership.`) and does **not** verify object ownership or admin role.

## 4. Tenant / ownership data model
- Owner columns seen:
  - `orders.user_id` (`order_detail_safe.php:5`) — links an order row in `orders` to `$_SESSION['user_id']`.
  - `users.id` (`admin.php:8`, `admin.php:12`) — primary key of the `users` table.
- Tenant model: Single-tenant `shop` database (`inc/db.php:3-4`, `mongo_find.php:4`) with per-user ownership via `user_id`. No `company_id` or `tenant_id` columns appear in visible queries.

## 5. Exclusions and bypass paths
- Every endpoint file in the repository (`admin.php:2`, `mongo_find.php:2`, `order_detail.php:2`, `order_detail_safe.php:2`, `search.php:2`) includes `inc/auth.php` at line 2, which properly calls `exit;` after `header('Location: /login.php')` (`inc/auth.php:5-6`).
- `inc/db.php:1-5` does not include `inc/auth.php`, though direct requests to `inc/db.php` produce no output and accept no request parameters.

## 6. Unknowns (checks that may live outside the code)
- `/login.php` (referenced in `inc/auth.php:5`) is not present in the repository; how `$_SESSION['user_id']` is established is outside visible code.
- No `.htaccess`, web server config, or reverse-proxy config is present in the repository. Unless restricted externally by the web server, `/admin.php` (`admin.php:1-14`) is accessible to any logged-in user with a valid `$_SESSION['user_id']`.

## 7. Notes for auditors
- Do **not** treat `require_once 'inc/auth.php'` (`inc/auth.php:1-7`) as an authorization or ownership guard; it only enforces authentication.
- Compare `order_detail.php:5-8` (vulnerable to both BOLA and SQLi) against `order_detail_safe.php:5-8` (properly scopes `WHERE id = ? AND user_id = ?` with `$_SESSION['user_id']` via PDO prepared statement).
- In `admin.php:5-14`, any logged-in user can reach `action=view` (`admin.php:6-9`, BOLA on `users` by `$_GET['uid']`) and `action=delete` (`admin.php:10-13`, BOLA + SQLi on `DELETE FROM users WHERE id = $id` via `$_POST['id']`), unless an external web-server rule restricts `/admin.php`.
- For injection auditing: `search.php:5-16` (`addslashes` in `LIKE`, unquoted `ORDER BY $sort`, unescaped heredoc `$_GET['cat']`), `order_detail.php:6`, `admin.php:12`, and `mongo_find.php:5-6` (`$_GET` directly in `findOne` array and concatenated into `$where` JS string) all build queries with user input.
