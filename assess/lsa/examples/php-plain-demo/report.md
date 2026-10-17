# Security Audit Report — out-php-plain

> **Classification: CONFIDENTIAL.** AI-assisted static review. All findings require human review (record decisions in `review-log.md`, created from `templates/review-log.md`) before they are shared outside the team.

| Item | Value |
|---|---|
| Date | 2026-10-17 |
| Kit version | 0.1.0 |
| Scope | BOLA/IDOR; SQL/HQL/NoSQL queries built from input |
| Stacks | php |
| Endpoints inventoried | 6 (candidates: 6) |
| Endpoints audited for BOLA | 4 |
| Injection candidates reviewed | 8 |

## 1. Executive summary

- **Overall risk level is Critical.** The audit identified 10 confirmed findings (1 critical, 8 high, 1 low) and 0 `likely` findings across 4 of the 6 inventoried PHP endpoints (`admin.php`, `order_detail.php`, `search.php`, and `mongo_find.php`).
- **Critical account deletion and SQL injection (`BOLA-R-0002-1`, `INJ-I-0002-1`).** `POST /admin.php?action=delete` (`admin.php:10-12`) verifies only that a user is logged in (`inc/auth.php:4`) and interpolates `$_POST['id']` directly into `DELETE FROM users WHERE id = $id`, allowing any authenticated user to delete arbitrary user accounts or manipulate database contents.
- **High-severity customer order exposure (`BOLA-R-0004-1`, `INJ-I-0005-1`).** `GET /order_detail.php` (`order_detail.php:5-8`) concatenates `$_GET['id']` directly into `SELECT * FROM orders WHERE id = ...` without constraining `user_id` to `$_SESSION['user_id']`, allowing any logged-in user to read other customers' shipping addresses and extract database records.
- **High-severity SQL and NoSQL injection in search and member lookups (`INJ-I-0003-1`, `INJ-I-0004-1`, `INJ-I-0006-1`, `INJ-I-0007-1`, `INJ-I-0008-1`).** `GET /mongo_find.php` (`mongo_find.php:5-6`) passes raw `$_GET` values into `MongoCollection::findOne` and a `$where` JavaScript predicate on `shop.members`, while `GET /search.php` (`search.php:5-16`) builds SQL queries using `addslashes()`, unvalidated `ORDER BY` concatenation, and heredoc interpolation.
- **Systemic root cause — authentication-only include without role or ownership helpers.** Every endpoint includes `inc/auth.php:1-7`, which only checks `!empty($_SESSION['user_id'])`. No shared helper enforces administrator roles on `admin.php` or per-user ownership (`user_id = $_SESSION['user_id']`), leaving each script to implement checks ad hoc (only `order_detail_safe.php:5-6` does so).
- **Systemic root cause — legacy `mysql_*` and unvalidated MongoDB filters alongside PDO.** Even though `inc/db.php:4` initializes a PDO connection (`$pdo`), most endpoints still call legacy `mysql_query()` (`inc/db.php:2-3`) with string concatenation/interpolation or pass uncast `$_GET` parameters to `MongoClient`.

## 2. Findings overview

| Severity | critical | high | medium | low | info |
|---|---|---|---|---|---|
| Count | 1 | 8 | 0 | 1 | 0 |

| Category | Count |
|---|---|
| bola | 3 |
| sql_injection | 5 |
| nosql_injection | 2 |

Status: unverified=0, confirmed=10, likely=0, rejected=0, needs_review=0

## 3. Findings

| ID | Sev | Conf | Status | Category | Endpoint | Location | Title |
|---|---|---|---|---|---|---|---|
| BOLA-R-0002-1 | critical | high | confirmed | bola | POST /admin.php?action=delete | `admin.php:10` | Any logged-in user can delete arbitrary user accounts via admin.php?action=delete |
| BOLA-R-0004-1 | high | high | confirmed | bola | GET /order_detail.php | `order_detail.php:5` | Order shipping address readable by any logged-in user via id parameter |
| INJ-I-0002-1 | high | high | confirmed | sql_injection | POST /admin.php?action=delete | `admin.php:11` | User deletion query interpolates unvalidated POST id into DELETE statement |
| INJ-I-0003-1 | high | high | confirmed | nosql_injection | GET /mongo_find.php | `mongo_find.php:5` | MongoDB findOne filter passes raw GET parameters allowing operator injection |
| INJ-I-0004-1 | high | high | confirmed | nosql_injection | GET /mongo_find.php | `mongo_find.php:6` | MongoDB $where query concatenates unvalidated GET parameter into JavaScript expression |
| INJ-I-0005-1 | high | high | confirmed | sql_injection | GET /order_detail.php | `order_detail.php:5` | Order detail query concatenates unvalidated GET id into SELECT statement |
| INJ-I-0006-1 | high | high | confirmed | sql_injection | GET /search.php | `search.php:5` | Product search query concatenates GET keyword sanitized only with addslashes |
| INJ-I-0007-1 | high | high | confirmed | sql_injection | GET /search.php | `search.php:6` | Product search query concatenates unvalidated GET sort parameter into ORDER BY clause |
| INJ-I-0008-1 | high | high | confirmed | sql_injection | GET /search.php | `search.php:12` | Product category query interpolates unvalidated GET cat parameter in heredoc SQL |
| BOLA-R-0001-1 | low | high | confirmed | bola | GET /admin.php?action=view | `admin.php:6` | Admin user lookup accessible to any logged-in user without role or ownership check |

### BOLA-R-0002-1 — Any logged-in user can delete arbitrary user accounts via admin.php?action=delete

- **Severity / confidence:** critical / high  
- **Status:** confirmed  
- **Category:** bola (missing_role_check) — CWE-285, CWE-639 API5:2023, API1:2023  
- **Endpoint:** POST /admin.php?action=delete  
- **Location:** `admin.php:10`

**Scenario.** A normal authenticated user sends POST /admin.php?action=delete with body id=<other_user_id>, deleting another user's account.

**Impact.** Any logged-in user can delete arbitrary user accounts from the users table, causing account loss and denial of service.

**Evidence.**

- `admin.php:2` — Only checks that $_SESSION['user_id'] is non-empty; does not check administrator role or account ownership  
  `require_once 'inc/auth.php';`
- `admin.php:11` — Target user ID read directly from POST form parameter  
  `$id = $_POST['id'];`
- `admin.php:12` — Deletes arbitrary user row matching $id with no role check or session ownership constraint  
  `mysql_query("DELETE FROM users WHERE id = $id");`

**Data flow.** $_POST['id'] (admin.php:11) → $id (admin.php:11) → mysql_query("DELETE FROM users WHERE id = $id") without role or owner check (admin.php:12)

**Recommendation.** Verify that the current session belongs to an authorized administrator before allowing user deletion, and use a prepared statement bound to the validated user ID.

```
if (empty($_SESSION['is_admin'])) { http_response_code(403); exit; }
$st = $pdo->prepare('DELETE FROM users WHERE id = ?');
$st->execute(array((int)$_POST['id']));
```

*Verifier:* confirmed — checked: admin.php:1-15, inc/auth.php:1-7 (checks $_SESSION['user_id'] login only, no admin role check), inc/db.php:1-5, repository root for .htaccess or global access controls (none present). Verified that admin.php:2 only checks session login via inc/auth.php and performs no role or ownership check before deleting arbitrary user rows in admin.php:11-12.

### BOLA-R-0004-1 — Order shipping address readable by any logged-in user via id parameter

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** bola (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **Endpoint:** GET /order_detail.php  
- **Location:** `order_detail.php:5`

**Scenario.** Logged-in User A requests GET /order_detail.php?id=<order_id_of_user_B> and reads User B's order address.

**Impact.** Any authenticated user can read other customers' order records and personal shipping addresses.

**Evidence.**

- `order_detail.php:2` — Checks login status only (inc/auth.php:4); does not verify order ownership  
  `require_once 'inc/auth.php';`
- `order_detail.php:5` — Order ID taken from request query string  
  `$id = $_GET['id'];`
- `order_detail.php:6` — Queries orders by id alone without constraining user_id to $_SESSION['user_id']  
  `$res = mysql_query("SELECT * FROM orders WHERE id = " . $id);`
- `order_detail.php:8` — Outputs the fetched order's address without any post-load owner comparison  
  `echo htmlspecialchars($order['address']);`

**Data flow.** $_GET['id'] (order_detail.php:5) → $id (order_detail.php:5) → mysql_query("SELECT * FROM orders WHERE id = " . $id) (order_detail.php:6) → echo htmlspecialchars($order['address']) (order_detail.php:8)

**Recommendation.** Constrain the order lookup by the authenticated user's session ID (AND user_id = ?) using a prepared statement, as done in order_detail_safe.php.

```
$st = $pdo->prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?');
$st->execute(array($_GET['id'], $_SESSION['user_id']));
```

*Verifier:* confirmed — checked: order_detail.php:1-9, order_detail_safe.php:1-9 (confirms orders.user_id is the ownership column), inc/auth.php:1-7, post-query comparison in order_detail.php:7-8 (none present). order_detail.php:6 queries orders by $_GET['id'] alone and outputs $order['address'] at line 8 without scoping to $_SESSION['user_id'].

### INJ-I-0002-1 — User deletion query interpolates unvalidated POST id into DELETE statement

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_interpolation) — CWE-89 A03:2021  
- **Endpoint:** POST /admin.php?action=delete  
- **Location:** `admin.php:11`

**Scenario.** An authenticated user submits a crafted id parameter in the POST body to alter the WHERE clause of the DELETE statement.

**Impact.** Arbitrary deletion of user records or manipulation of database contents accessible to the application database account.

**Evidence.**

- `admin.php:11` — Source: unvalidated POST parameter id  
  `$id = $_POST['id'];`
- `admin.php:12` — Sink: unquoted string interpolation into mysql_query with no cast or binding  
  `mysql_query("DELETE FROM users WHERE id = $id");`

**Data flow.** $_POST['id'] (admin.php:11) → $id (admin.php:11) → mysql_query("DELETE FROM users WHERE id = $id") (admin.php:12)

**Recommendation.** Use PDO prepared statements with bound parameters or cast the identifier to an integer before query execution.

```
$stmt = $pdo->prepare('DELETE FROM users WHERE id = ?');
$stmt->execute(array((int)$_POST['id']));
```

*Verifier:* confirmed — checked: admin.php:10-13, inc/auth.php:1-7, inc/db.php:1-5 (connects as 'app', not root/sa). Unvalidated $_POST['id'] is directly interpolated into an unquoted numeric context in mysql_query at admin.php:12 with no cast or escaping.

### INJ-I-0003-1 — MongoDB findOne filter passes raw GET parameters allowing operator injection

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** nosql_injection (operator_injection) — CWE-943 A03:2021  
- **Endpoint:** GET /mongo_find.php  
- **Location:** `mongo_find.php:5`

**Scenario.** An authenticated user supplies array query parameters for login or pass so PHP constructs nested associative arrays interpreted as MongoDB query operators.

**Impact.** Unauthorized query filter manipulation and credential check bypass on the shop.members collection.

**Evidence.**

- `mongo_find.php:5` — Source and sink: $_GET['login'] and $_GET['pass'] passed directly into MongoCollection::findOne filter without scalar type enforcement  
  `$doc = $coll->findOne(array('login' => $_GET['login'], 'pass' => $_GET['pass']));`

**Data flow.** $_GET['login'], $_GET['pass'] (mongo_find.php:5) → $coll->findOne(...) (mongo_find.php:5)

**Recommendation.** Validate that login and pass are scalar strings or explicitly cast them to string before passing to findOne.

```
$doc = $coll->findOne(array('login' => (string)$_GET['login'], 'pass' => (string)$_GET['pass']));
```

*Verifier:* confirmed — checked: mongo_find.php:1-7, inc/auth.php:1-7. $_GET['login'] and $_GET['pass'] are passed directly into MongoCollection::findOne at mongo_find.php:5 without scalar string validation or casting, allowing array operator injection.

### INJ-I-0004-1 — MongoDB $where query concatenates unvalidated GET parameter into JavaScript expression

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** nosql_injection (js_injection) — CWE-943 A03:2021  
- **Endpoint:** GET /mongo_find.php  
- **Location:** `mongo_find.php:6`

**Scenario.** An authenticated user provides a crafted n query parameter that breaks out of the string literal inside the $where JavaScript predicate.

**Impact.** Arbitrary JavaScript predicate evaluation inside the MongoDB query context and unauthorized disclosure of shop.members documents.

**Evidence.**

- `mongo_find.php:6` — Source and sink: $_GET['n'] concatenated directly into MongoDB $where JavaScript string  
  `$docs = $coll->find(array('$where' => "this.name == '" . $_GET['n'] . "'"));`

**Data flow.** $_GET['n'] (mongo_find.php:6) → $coll->find(array('$where' => ...)) (mongo_find.php:6)

**Recommendation.** Replace the $where JavaScript evaluation with a standard field equality filter using scalar string values.

```
$docs = $coll->find(array('name' => (string)$_GET['n']));
```

*Verifier:* confirmed — checked: mongo_find.php:1-7, inc/auth.php:1-7. $_GET['n'] is concatenated directly into a MongoDB $where JavaScript expression at mongo_find.php:6 with no sanitization.

### INJ-I-0005-1 — Order detail query concatenates unvalidated GET id into SELECT statement

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89 A03:2021  
- **Endpoint:** GET /order_detail.php  
- **Location:** `order_detail.php:5`

**Scenario.** An authenticated user supplies a crafted id query parameter to modify the SQL query structure and retrieve arbitrary rows.

**Impact.** Unauthorized disclosure of order records and other tables accessible to the database user.

**Evidence.**

- `order_detail.php:5` — Source: unvalidated GET parameter id  
  `$id = $_GET['id'];`
- `order_detail.php:6` — Sink: unquoted concatenation of $id into mysql_query  
  `$res = mysql_query("SELECT * FROM orders WHERE id = " . $id);`

**Data flow.** $_GET['id'] (order_detail.php:5) → $id (order_detail.php:5) → mysql_query("SELECT * FROM orders WHERE id = " . $id) (order_detail.php:6)

**Recommendation.** Use a PDO prepared statement with bound parameters and scope the query to the authenticated user.

```
$stmt = $pdo->prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?');
$stmt->execute(array($_GET['id'], $_SESSION['user_id']));
```

*Verifier:* confirmed — checked: order_detail.php:1-9, inc/auth.php:1-7, inc/db.php:1-5. $_GET['id'] is concatenated unquoted into mysql_query at order_detail.php:6 with no integer cast or parameter binding.

### INJ-I-0006-1 — Product search query concatenates GET keyword sanitized only with addslashes

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_concatenation) — CWE-89 A03:2021  
- **Endpoint:** GET /search.php  
- **Location:** `search.php:5`

**Scenario.** An authenticated user supplies a crafted search term where addslashes fails to prevent quote breakout (such as under multibyte connection encodings) to alter the SQL query.

**Impact.** Unauthorized reading of database tables accessible to the application database account.

**Evidence.**

- `search.php:5` — Source and weak sanitizer: $_GET['q'] passed only through addslashes()  
  `$kw = addslashes($_GET['q']);`
- `search.php:8` — Concatenated into SQL LIKE clause  
  `$sql .= " AND name LIKE '%" . $kw . "%'";`
- `search.php:11` — Sink: executed via mysql_query without parameter binding  
  `$res = mysql_query($sql);`

**Data flow.** $_GET['q'] (search.php:5) → $kw (search.php:5) → $sql (search.php:8) → mysql_query($sql) (search.php:11)

**Recommendation.** Use PDO prepared statements with bound parameters instead of addslashes and string concatenation.

```
$stmt = $pdo->prepare('SELECT id, name FROM products WHERE name LIKE ?');
$stmt->execute(array('%' . $_GET['q'] . '%'));
```

*Verifier:* confirmed — checked: search.php:1-18, inc/auth.php:1-7, inc/db.php:1-5 (no mysql_set_charset call). $_GET['q'] is only passed through addslashes() at search.php:5 before concatenation into LIKE at line 8 and execution via mysql_query at line 11; addslashes is not an adequate SQLi defense per injection-patterns.md §3.

### INJ-I-0007-1 — Product search query concatenates unvalidated GET sort parameter into ORDER BY clause

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** sql_injection (dynamic_identifier) — CWE-89 A03:2021  
- **Endpoint:** GET /search.php  
- **Location:** `search.php:6`

**Scenario.** An authenticated user passes arbitrary SQL expressions in the sort query parameter to inject into the ORDER BY clause.

**Impact.** Unauthorized data extraction via boolean/time-based inference or error-based SQL injection across database tables.

**Evidence.**

- `search.php:6` — Source: unvalidated GET parameter sort  
  `$sort = $_GET['sort'];`
- `search.php:9` — Concatenated directly into ORDER BY clause without allow-list validation  
  `$sql .= " ORDER BY " . $sort;`
- `search.php:11` — Sink: executed via mysql_query  
  `$res = mysql_query($sql);`

**Data flow.** $_GET['sort'] (search.php:6) → $sort (search.php:6) → $sql (search.php:9) → mysql_query($sql) (search.php:11)

**Recommendation.** Validate the sort parameter against a strict exact-match allow-list of permitted column names and directions.

```
$allowed = array('id', 'name');
$sort = in_array($_GET['sort'], $allowed, true) ? $_GET['sort'] : 'id';
```

*Verifier:* confirmed — checked: search.php:1-18, inc/auth.php:1-7, inc/db.php:1-5. Unvalidated $_GET['sort'] is concatenated directly into the ORDER BY clause at search.php:9 and executed via mysql_query at line 11 without allow-list validation.

### INJ-I-0008-1 — Product category query interpolates unvalidated GET cat parameter in heredoc SQL

- **Severity / confidence:** high / high  
- **Status:** confirmed  
- **Category:** sql_injection (string_interpolation) — CWE-89 A03:2021  
- **Endpoint:** GET /search.php  
- **Location:** `search.php:12`

**Scenario.** An authenticated user provides a crafted cat query parameter to break out of the single-quoted string in the WHERE clause.

**Impact.** Unauthorized disclosure of data from any table accessible to the application database account.

**Evidence.**

- `search.php:14` — Source and interpolation: $_GET['cat'] interpolated directly into heredoc SQL string $q  
  `WHERE category = '{$_GET['cat']}'`
- `search.php:16` — Sink: heredoc query executed via mysql_query without binding  
  `$res2 = mysql_query($q);`

**Data flow.** $_GET['cat'] (search.php:14) → $q (search.php:12-15) → mysql_query($q) (search.php:16)

**Recommendation.** Use a PDO prepared statement with a bound parameter for the category filter.

```
$stmt = $pdo->prepare('SELECT * FROM products WHERE category = ?');
$stmt->execute(array($_GET['cat']));
```

*Verifier:* confirmed — checked: search.php:12-16, inc/auth.php:1-7, inc/db.php:1-5. $_GET['cat'] is interpolated directly into the heredoc SQL string at search.php:14 and executed via mysql_query at line 16 without escaping or parameter binding.

### BOLA-R-0001-1 — Admin user lookup accessible to any logged-in user without role or ownership check

- **Severity / confidence:** low / high  
- **Status:** confirmed  
- **Category:** bola (missing_role_check) — CWE-285, CWE-639 API5:2023, API1:2023  
- **Endpoint:** GET /admin.php?action=view  
- **Location:** `admin.php:6`

**Scenario.** A regular logged-in user sends GET /admin.php?action=view&uid=<other_user_id> and triggers a database lookup on another user's record without administrator privilege or ownership verification.

**Impact.** Unauthorized query execution against arbitrary rows in the users table by any authenticated user; however, the result resource $r is not fetched or output in admin.php, so data is not directly exposed in the HTTP response (rated low per bola-patterns.md section 6).

**Evidence.**

- `admin.php:2` — Enforces session login only (!empty($_SESSION['user_id'])); no administrator role or ownership check  
  `require_once 'inc/auth.php';`
- `admin.php:7` — Target user ID taken directly from query parameter uid  
  `$uid = (int)$_GET['uid'];`
- `admin.php:8` — Queries users table by arbitrary uid without binding to $_SESSION['user_id'] or verifying admin role (note: $r is not rendered in this file)  
  `$r = mysql_query("SELECT * FROM users WHERE id = " . $uid);`

**Data flow.** $_GET['uid'] (admin.php:7) → $uid cast to int (admin.php:7) → mysql_query("SELECT * FROM users WHERE id = " . $uid) without role or owner filter (admin.php:8)

**Recommendation.** Enforce an administrator role check from the server-side session before dispatching admin actions, or restrict the query to $_SESSION['user_id'] if intended for self-service profile lookup.

```
if (empty($_SESSION['is_admin'])) { http_response_code(403); exit; }
```

*Verifier:* confirmed — checked: admin.php:1-15, inc/auth.php:1-7 (login check only), post-query usage of $r in admin.php:8-9 (never fetched or output). No admin role or ownership check exists before querying users by $_GET['uid'] at admin.php:8; severity remains low because $r is not rendered.

## 4. Systemic fixes

1. **Migrate all legacy `mysql_*` queries to PDO prepared statements.** Remove `mysql_connect()` / `mysql_select_db()` in `inc/db.php:2-3` and replace all `mysql_query()` calls in `admin.php:8,12`, `order_detail.php:6`, and `search.php:5-16` with positional prepared statements (`$pdo->prepare(...)` and `$stmt->execute(...)`) using the `$pdo` instance already initialized in `inc/db.php:4`.
   - **Effort:** S (≤ 1 day)
   - **Closes:** `INJ-I-0002-1`, `INJ-I-0005-1`, `INJ-I-0006-1`, `INJ-I-0008-1`
2. **Add centralized role and ownership enforcement helpers.** Define `require_admin()` in `inc/auth.php` to check server-side administrator session state before running any handler in `admin.php:1-14`, and introduce a shared order data-access helper that requires `$_SESSION['user_id']` and scopes queries with `WHERE id = ? AND user_id = ?` (matching `order_detail_safe.php:5-6`).
   - **Effort:** S (≤ 1 day)
   - **Closes:** `BOLA-R-0001-1`, `BOLA-R-0002-1`, `BOLA-R-0004-1`
3. **Enforce strict allow-list validation for dynamic SQL identifiers.** Create a shared helper for `ORDER BY` clauses that validates user-supplied column names and sort directions against a hardcoded allow-list using `in_array($sort, $allowed, true)` before query construction in `search.php:6-9`.
   - **Effort:** S (≤ 1 day)
   - **Closes:** `INJ-I-0007-1`
4. **Enforce scalar string types and eliminate `$where` JavaScript in MongoDB queries.** Explicitly cast request inputs to `(string)` before passing filter arrays to `MongoCollection::findOne()`, and replace `$where` JavaScript string concatenation with standard field equality queries in `mongo_find.php:5-6`.
   - **Effort:** S (≤ 1 day)
   - **Closes:** `INJ-I-0003-1`, `INJ-I-0004-1`

## 5. Coverage and limitations

- missing from inventory: 0
- bola routes without verdict: 0
- injection candidates without verdict: 0
- findings without verification: 0

- **Missing authentication handler and external server configuration:** `/login.php` (referenced in `inc/auth.php:5`) and web server / reverse-proxy configurations (`.htaccess`, `php.ini`, virtual host rules) are not present in the repository. How `$_SESSION['user_id']` and any role attributes are populated at login, or whether external gateway rules restrict `/admin.php`, could not be verified from source code.
- **Database stored procedures and schema definitions:** Database schemas, triggers, and stored procedures for the `shop` MySQL and MongoDB databases are outside the repository and were not covered.
- **Excluded paths and file size limits:** Per `audit-config.effective.json`, paths matching `vendor/`, `node_modules/`, `bower_components/`, `packages/`, `bin/`, `obj/`, `target/`, `build/`, `dist/`, `.git/`, `test/`, `tests/`, `spec/`, `docs/`, `*.min.js`, and `*jquery*.js`, as well as files over 1024 KB, were excluded from scanning.
- **Scope and unverified/needs-review items:** Only BOLA/IDOR and SQL/HQL/NoSQL query injection were in scope; there are 0 `needs_review` items and 0 `likely` items.
- **Out-of-scope notes (`coverage.json → out_of_scope_notes`):** None recorded (`[]`).
- **Human sign-off required:** All findings and recommendations in this report are generated by an AI-assisted static audit and require human review and sign-off in `review-log.md` before remediation or external distribution.

## Appendix A — Findings rejected by the verifier

None.

## Appendix B — Method

1. Deterministic pre-scan (stack detection, endpoint candidates, query-building candidates).
2. AI agents: auth-model extraction, route inventory, BOLA audit, injection audit.
3. Independent AI verifier tries to refute each finding.
4. Human review and sign-off (`review-log.md`).

This is not a penetration test. Absence of findings does not prove absence of vulnerabilities.
