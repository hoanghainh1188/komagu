# セキュリティ監査報告書 — PHP Plain Legacy Demo

> **機密区分: 社外秘 (CONFIDENTIAL)** 本報告書はAI支援による静的コードレビュー結果です。外部共有前に必ず人間のレビュー担当者による確認・承認が必要です（判定結果は `review-log.md` に記録）。

| 項目 | 値 |
|---|---|
| 診断実施日 | 2026-10-17 |
| 監査キットバージョン | 0.1.0 |
| 監査対象スコープ | BOLA/IDOR（オブジェクトレベルの認可不備）および外部入力によるSQL/HQL/NoSQLクエリ構築 |
| 検出技術スタック | php |
| インベントリ登録エンドポイント数 | 6 (候補数: 6) |
| BOLA監査対象エンドポイント数 | 4 |
| レビュー対象インジェクション候補数 | 8 |

## 1. エグゼクティブサマリー

<!-- LLM: reporter agent writes max 8 bullets here (日本語で記載: 全体のリスクレベル、事業影響の大きい上位3件の検出事項、根本原因) -->

## 2. 検出事項の概要

| 重要度 | 緊急 (Critical) | 高 (High) | 中 (Medium) | 低 (Low) | 情報 (Info) |
|---|---|---|---|---|---|
| 件数 | 1 | 8 | 0 | 1 | 0 |

| 脆弱性分類 | 件数 |
|---|---|
| オブジェクトレベルの認可不備 (BOLA/IDOR) | 3 |
| SQLインジェクション (SQLi) | 5 |
| NoSQLインジェクション (NoSQLi) | 2 |

ステータス内訳: 未検証 (Unverified)=0, 確認済 (Confirmed)=10, likely=0, 棄却 (Rejected)=0, needs_review=0

## 3. 検出事項の詳細

| ID | 重要度 | 確信度 | ステータス | 脆弱性分類 | 対象エンドポイント | 該当箇所 | タイトル |
|---|---|---|---|---|---|---|---|
| BOLA-R-0002-1 | 緊急 (Critical) | high | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | POST /admin.php?action=delete | `admin.php:10` | Any logged-in user can delete arbitrary user accounts via admin.php?action=delete |
| BOLA-R-0004-1 | 高 (High) | high | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /order_detail.php | `order_detail.php:5` | Order shipping address readable by any logged-in user via id parameter |
| INJ-I-0002-1 | 高 (High) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | POST /admin.php?action=delete | `admin.php:11` | User deletion query interpolates unvalidated POST id into DELETE statement |
| INJ-I-0003-1 | 高 (High) | high | 確認済 (Confirmed) | NoSQLインジェクション (NoSQLi) | GET /mongo_find.php | `mongo_find.php:5` | MongoDB findOne filter passes raw GET parameters allowing operator injection |
| INJ-I-0004-1 | 高 (High) | high | 確認済 (Confirmed) | NoSQLインジェクション (NoSQLi) | GET /mongo_find.php | `mongo_find.php:6` | MongoDB $where query concatenates unvalidated GET parameter into JavaScript expression |
| INJ-I-0005-1 | 高 (High) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | GET /order_detail.php | `order_detail.php:5` | Order detail query concatenates unvalidated GET id into SELECT statement |
| INJ-I-0006-1 | 高 (High) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | GET /search.php | `search.php:5` | Product search query concatenates GET keyword sanitized only with addslashes |
| INJ-I-0007-1 | 高 (High) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | GET /search.php | `search.php:6` | Product search query concatenates unvalidated GET sort parameter into ORDER BY clause |
| INJ-I-0008-1 | 高 (High) | high | 確認済 (Confirmed) | SQLインジェクション (SQLi) | GET /search.php | `search.php:12` | Product category query interpolates unvalidated GET cat parameter in heredoc SQL |
| BOLA-R-0001-1 | 低 (Low) | high | 確認済 (Confirmed) | オブジェクトレベルの認可不備 (BOLA/IDOR) | GET /admin.php?action=view | `admin.php:6` | Admin user lookup accessible to any logged-in user without role or ownership check |

### BOLA-R-0002-1 — Any logged-in user can delete arbitrary user accounts via admin.php?action=delete

- **重要度 / 確信度:** 緊急 (Critical) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_role_check) — CWE-285, CWE-639 API5:2023, API1:2023  
- **対象エンドポイント:** POST /admin.php?action=delete  
- **該当箇所:** `admin.php:10`

**攻撃シナリオ:** A normal authenticated user sends POST /admin.php?action=delete with body id=<other_user_id>, deleting another user's account.

**影響度 (Impact):** Any logged-in user can delete arbitrary user accounts from the users table, causing account loss and denial of service.

**脆弱性の根拠コード (Evidence):**

- `admin.php:2` — Only checks that $_SESSION['user_id'] is non-empty; does not check administrator role or account ownership  
  `require_once 'inc/auth.php';`
- `admin.php:11` — Target user ID read directly from POST form parameter  
  `$id = $_POST['id'];`
- `admin.php:12` — Deletes arbitrary user row matching $id with no role check or session ownership constraint  
  `mysql_query("DELETE FROM users WHERE id = $id");`

**データフロー:** $_POST['id'] (admin.php:11) → $id (admin.php:11) → mysql_query("DELETE FROM users WHERE id = $id") without role or owner check (admin.php:12)

**推奨対策 (Recommendation):** Verify that the current session belongs to an authorized administrator before allowing user deletion, and use a prepared statement bound to the validated user ID.

```
if (empty($_SESSION['is_admin'])) { http_response_code(403); exit; }
$st = $pdo->prepare('DELETE FROM users WHERE id = ?');
$st->execute(array((int)$_POST['id']));
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: admin.php:1-15, inc/auth.php:1-7 (checks $_SESSION['user_id'] login only, no admin role check), inc/db.php:1-5, repository root for .htaccess or global access controls (none present). Verified that admin.php:2 only checks session login via inc/auth.php and performs no role or ownership check before deleting arbitrary user rows in admin.php:11-12.

### BOLA-R-0004-1 — Order shipping address readable by any logged-in user via id parameter

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_ownership_check) — CWE-639, CWE-862 API1:2023, A01:2021  
- **対象エンドポイント:** GET /order_detail.php  
- **該当箇所:** `order_detail.php:5`

**攻撃シナリオ:** Logged-in User A requests GET /order_detail.php?id=<order_id_of_user_B> and reads User B's order address.

**影響度 (Impact):** Any authenticated user can read other customers' order records and personal shipping addresses.

**脆弱性の根拠コード (Evidence):**

- `order_detail.php:2` — Checks login status only (inc/auth.php:4); does not verify order ownership  
  `require_once 'inc/auth.php';`
- `order_detail.php:5` — Order ID taken from request query string  
  `$id = $_GET['id'];`
- `order_detail.php:6` — Queries orders by id alone without constraining user_id to $_SESSION['user_id']  
  `$res = mysql_query("SELECT * FROM orders WHERE id = " . $id);`
- `order_detail.php:8` — Outputs the fetched order's address without any post-load owner comparison  
  `echo htmlspecialchars($order['address']);`

**データフロー:** $_GET['id'] (order_detail.php:5) → $id (order_detail.php:5) → mysql_query("SELECT * FROM orders WHERE id = " . $id) (order_detail.php:6) → echo htmlspecialchars($order['address']) (order_detail.php:8)

**推奨対策 (Recommendation):** Constrain the order lookup by the authenticated user's session ID (AND user_id = ?) using a prepared statement, as done in order_detail_safe.php.

```
$st = $pdo->prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?');
$st->execute(array($_GET['id'], $_SESSION['user_id']));
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: order_detail.php:1-9, order_detail_safe.php:1-9 (confirms orders.user_id is the ownership column), inc/auth.php:1-7, post-query comparison in order_detail.php:7-8 (none present). order_detail.php:6 queries orders by $_GET['id'] alone and outputs $order['address'] at line 8 without scoping to $_SESSION['user_id'].

### INJ-I-0002-1 — User deletion query interpolates unvalidated POST id into DELETE statement

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_interpolation) — CWE-89 A03:2021  
- **対象エンドポイント:** POST /admin.php?action=delete  
- **該当箇所:** `admin.php:11`

**攻撃シナリオ:** An authenticated user submits a crafted id parameter in the POST body to alter the WHERE clause of the DELETE statement.

**影響度 (Impact):** Arbitrary deletion of user records or manipulation of database contents accessible to the application database account.

**脆弱性の根拠コード (Evidence):**

- `admin.php:11` — Source: unvalidated POST parameter id  
  `$id = $_POST['id'];`
- `admin.php:12` — Sink: unquoted string interpolation into mysql_query with no cast or binding  
  `mysql_query("DELETE FROM users WHERE id = $id");`

**データフロー:** $_POST['id'] (admin.php:11) → $id (admin.php:11) → mysql_query("DELETE FROM users WHERE id = $id") (admin.php:12)

**推奨対策 (Recommendation):** Use PDO prepared statements with bound parameters or cast the identifier to an integer before query execution.

```
$stmt = $pdo->prepare('DELETE FROM users WHERE id = ?');
$stmt->execute(array((int)$_POST['id']));
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: admin.php:10-13, inc/auth.php:1-7, inc/db.php:1-5 (connects as 'app', not root/sa). Unvalidated $_POST['id'] is directly interpolated into an unquoted numeric context in mysql_query at admin.php:12 with no cast or escaping.

### INJ-I-0003-1 — MongoDB findOne filter passes raw GET parameters allowing operator injection

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** NoSQLインジェクション (NoSQLi) (operator_injection) — CWE-943 A03:2021  
- **対象エンドポイント:** GET /mongo_find.php  
- **該当箇所:** `mongo_find.php:5`

**攻撃シナリオ:** An authenticated user supplies array query parameters for login or pass so PHP constructs nested associative arrays interpreted as MongoDB query operators.

**影響度 (Impact):** Unauthorized query filter manipulation and credential check bypass on the shop.members collection.

**脆弱性の根拠コード (Evidence):**

- `mongo_find.php:5` — Source and sink: $_GET['login'] and $_GET['pass'] passed directly into MongoCollection::findOne filter without scalar type enforcement  
  `$doc = $coll->findOne(array('login' => $_GET['login'], 'pass' => $_GET['pass']));`

**データフロー:** $_GET['login'], $_GET['pass'] (mongo_find.php:5) → $coll->findOne(...) (mongo_find.php:5)

**推奨対策 (Recommendation):** Validate that login and pass are scalar strings or explicitly cast them to string before passing to findOne.

```
$doc = $coll->findOne(array('login' => (string)$_GET['login'], 'pass' => (string)$_GET['pass']));
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: mongo_find.php:1-7, inc/auth.php:1-7. $_GET['login'] and $_GET['pass'] are passed directly into MongoCollection::findOne at mongo_find.php:5 without scalar string validation or casting, allowing array operator injection.

### INJ-I-0004-1 — MongoDB $where query concatenates unvalidated GET parameter into JavaScript expression

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** NoSQLインジェクション (NoSQLi) (js_injection) — CWE-943 A03:2021  
- **対象エンドポイント:** GET /mongo_find.php  
- **該当箇所:** `mongo_find.php:6`

**攻撃シナリオ:** An authenticated user provides a crafted n query parameter that breaks out of the string literal inside the $where JavaScript predicate.

**影響度 (Impact):** Arbitrary JavaScript predicate evaluation inside the MongoDB query context and unauthorized disclosure of shop.members documents.

**脆弱性の根拠コード (Evidence):**

- `mongo_find.php:6` — Source and sink: $_GET['n'] concatenated directly into MongoDB $where JavaScript string  
  `$docs = $coll->find(array('$where' => "this.name == '" . $_GET['n'] . "'"));`

**データフロー:** $_GET['n'] (mongo_find.php:6) → $coll->find(array('$where' => ...)) (mongo_find.php:6)

**推奨対策 (Recommendation):** Replace the $where JavaScript evaluation with a standard field equality filter using scalar string values.

```
$docs = $coll->find(array('name' => (string)$_GET['n']));
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: mongo_find.php:1-7, inc/auth.php:1-7. $_GET['n'] is concatenated directly into a MongoDB $where JavaScript expression at mongo_find.php:6 with no sanitization.

### INJ-I-0005-1 — Order detail query concatenates unvalidated GET id into SELECT statement

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89 A03:2021  
- **対象エンドポイント:** GET /order_detail.php  
- **該当箇所:** `order_detail.php:5`

**攻撃シナリオ:** An authenticated user supplies a crafted id query parameter to modify the SQL query structure and retrieve arbitrary rows.

**影響度 (Impact):** Unauthorized disclosure of order records and other tables accessible to the database user.

**脆弱性の根拠コード (Evidence):**

- `order_detail.php:5` — Source: unvalidated GET parameter id  
  `$id = $_GET['id'];`
- `order_detail.php:6` — Sink: unquoted concatenation of $id into mysql_query  
  `$res = mysql_query("SELECT * FROM orders WHERE id = " . $id);`

**データフロー:** $_GET['id'] (order_detail.php:5) → $id (order_detail.php:5) → mysql_query("SELECT * FROM orders WHERE id = " . $id) (order_detail.php:6)

**推奨対策 (Recommendation):** Use a PDO prepared statement with bound parameters and scope the query to the authenticated user.

```
$stmt = $pdo->prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?');
$stmt->execute(array($_GET['id'], $_SESSION['user_id']));
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: order_detail.php:1-9, inc/auth.php:1-7, inc/db.php:1-5. $_GET['id'] is concatenated unquoted into mysql_query at order_detail.php:6 with no integer cast or parameter binding.

### INJ-I-0006-1 — Product search query concatenates GET keyword sanitized only with addslashes

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_concatenation) — CWE-89 A03:2021  
- **対象エンドポイント:** GET /search.php  
- **該当箇所:** `search.php:5`

**攻撃シナリオ:** An authenticated user supplies a crafted search term where addslashes fails to prevent quote breakout (such as under multibyte connection encodings) to alter the SQL query.

**影響度 (Impact):** Unauthorized reading of database tables accessible to the application database account.

**脆弱性の根拠コード (Evidence):**

- `search.php:5` — Source and weak sanitizer: $_GET['q'] passed only through addslashes()  
  `$kw = addslashes($_GET['q']);`
- `search.php:8` — Concatenated into SQL LIKE clause  
  `$sql .= " AND name LIKE '%" . $kw . "%'";`
- `search.php:11` — Sink: executed via mysql_query without parameter binding  
  `$res = mysql_query($sql);`

**データフロー:** $_GET['q'] (search.php:5) → $kw (search.php:5) → $sql (search.php:8) → mysql_query($sql) (search.php:11)

**推奨対策 (Recommendation):** Use PDO prepared statements with bound parameters instead of addslashes and string concatenation.

```
$stmt = $pdo->prepare('SELECT id, name FROM products WHERE name LIKE ?');
$stmt->execute(array('%' . $_GET['q'] . '%'));
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: search.php:1-18, inc/auth.php:1-7, inc/db.php:1-5 (no mysql_set_charset call). $_GET['q'] is only passed through addslashes() at search.php:5 before concatenation into LIKE at line 8 and execution via mysql_query at line 11; addslashes is not an adequate SQLi defense per injection-patterns.md §3.

### INJ-I-0007-1 — Product search query concatenates unvalidated GET sort parameter into ORDER BY clause

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (dynamic_identifier) — CWE-89 A03:2021  
- **対象エンドポイント:** GET /search.php  
- **該当箇所:** `search.php:6`

**攻撃シナリオ:** An authenticated user passes arbitrary SQL expressions in the sort query parameter to inject into the ORDER BY clause.

**影響度 (Impact):** Unauthorized data extraction via boolean/time-based inference or error-based SQL injection across database tables.

**脆弱性の根拠コード (Evidence):**

- `search.php:6` — Source: unvalidated GET parameter sort  
  `$sort = $_GET['sort'];`
- `search.php:9` — Concatenated directly into ORDER BY clause without allow-list validation  
  `$sql .= " ORDER BY " . $sort;`
- `search.php:11` — Sink: executed via mysql_query  
  `$res = mysql_query($sql);`

**データフロー:** $_GET['sort'] (search.php:6) → $sort (search.php:6) → $sql (search.php:9) → mysql_query($sql) (search.php:11)

**推奨対策 (Recommendation):** Validate the sort parameter against a strict exact-match allow-list of permitted column names and directions.

```
$allowed = array('id', 'name');
$sort = in_array($_GET['sort'], $allowed, true) ? $_GET['sort'] : 'id';
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: search.php:1-18, inc/auth.php:1-7, inc/db.php:1-5. Unvalidated $_GET['sort'] is concatenated directly into the ORDER BY clause at search.php:9 and executed via mysql_query at line 11 without allow-list validation.

### INJ-I-0008-1 — Product category query interpolates unvalidated GET cat parameter in heredoc SQL

- **重要度 / 確信度:** 高 (High) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** SQLインジェクション (SQLi) (string_interpolation) — CWE-89 A03:2021  
- **対象エンドポイント:** GET /search.php  
- **該当箇所:** `search.php:12`

**攻撃シナリオ:** An authenticated user provides a crafted cat query parameter to break out of the single-quoted string in the WHERE clause.

**影響度 (Impact):** Unauthorized disclosure of data from any table accessible to the application database account.

**脆弱性の根拠コード (Evidence):**

- `search.php:14` — Source and interpolation: $_GET['cat'] interpolated directly into heredoc SQL string $q  
  `WHERE category = '{$_GET['cat']}'`
- `search.php:16` — Sink: heredoc query executed via mysql_query without binding  
  `$res2 = mysql_query($q);`

**データフロー:** $_GET['cat'] (search.php:14) → $q (search.php:12-15) → mysql_query($q) (search.php:16)

**推奨対策 (Recommendation):** Use a PDO prepared statement with a bound parameter for the category filter.

```
$stmt = $pdo->prepare('SELECT * FROM products WHERE category = ?');
$stmt->execute(array($_GET['cat']));
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: search.php:12-16, inc/auth.php:1-7, inc/db.php:1-5. $_GET['cat'] is interpolated directly into the heredoc SQL string at search.php:14 and executed via mysql_query at line 16 without escaping or parameter binding.

### BOLA-R-0001-1 — Admin user lookup accessible to any logged-in user without role or ownership check

- **重要度 / 確信度:** 低 (Low) / high  
- **ステータス:** 確認済 (Confirmed)  
- **脆弱性分類:** オブジェクトレベルの認可不備 (BOLA/IDOR) (missing_role_check) — CWE-285, CWE-639 API5:2023, API1:2023  
- **対象エンドポイント:** GET /admin.php?action=view  
- **該当箇所:** `admin.php:6`

**攻撃シナリオ:** A regular logged-in user sends GET /admin.php?action=view&uid=<other_user_id> and triggers a database lookup on another user's record without administrator privilege or ownership verification.

**影響度 (Impact):** Unauthorized query execution against arbitrary rows in the users table by any authenticated user; however, the result resource $r is not fetched or output in admin.php, so data is not directly exposed in the HTTP response (rated low per bola-patterns.md section 6).

**脆弱性の根拠コード (Evidence):**

- `admin.php:2` — Enforces session login only (!empty($_SESSION['user_id'])); no administrator role or ownership check  
  `require_once 'inc/auth.php';`
- `admin.php:7` — Target user ID taken directly from query parameter uid  
  `$uid = (int)$_GET['uid'];`
- `admin.php:8` — Queries users table by arbitrary uid without binding to $_SESSION['user_id'] or verifying admin role (note: $r is not rendered in this file)  
  `$r = mysql_query("SELECT * FROM users WHERE id = " . $uid);`

**データフロー:** $_GET['uid'] (admin.php:7) → $uid cast to int (admin.php:7) → mysql_query("SELECT * FROM users WHERE id = " . $uid) without role or owner filter (admin.php:8)

**推奨対策 (Recommendation):** Enforce an administrator role check from the server-side session before dispatching admin actions, or restrict the query to $_SESSION['user_id'] if intended for self-service profile lookup.

```
if (empty($_SESSION['is_admin'])) { http_response_code(403); exit; }
```

*検証結果 (Verifier):* 確認済 (Confirmed) — 確認対象: admin.php:1-15, inc/auth.php:1-7 (login check only), post-query usage of $r in admin.php:8-9 (never fetched or output). No admin role or ownership check exists before querying users by $_GET['uid'] at admin.php:8; severity remains low because $r is not rendered.

## 4. 根本的恒久対策

<!-- LLM: reporter agent writes max 5 systemic fixes here (日本語で記載: 共通認可ヘルパー、パラメータバインディングDAO等のアーキテクチャ改修案と工数見積 S/M/L) -->

## 5. 調査範囲と制約事項

- missing from inventory: 0
- bola routes without verdict: 0
- injection candidates without verdict: 0
- findings without verification: 0

<!-- LLM: reporter agent lists limitations here (日本語で記載: ストアドプロシージャ、動的インクルード、設定による除外パス等) -->

## 付録A — 検証により棄却された検出事項

なし。

## 付録B — 監査手法とプロセス

1. **決定論的静的事前スキャン**: 技術スタック判定、エンドポイント候補抽出、クエリ生成箇所抽出。
2. **独立したAI監査エージェント群**: 認可モデル抽出、エンドポイント詳細精査、BOLA監査、インジェクション監査。
3. **懐疑的AI検証エージェント（Skeptic）**: 検出事項に対する反論テストを実施し、既存の防御制御による誤検知を排除。
4. **人間のエンジニアによる最終確認と承認**: `review-log.md` による判定記録とサインオフ。

**免責事項:** 本監査は侵入テスト（ペネトレーションテスト）ではありません。脆弱性が検出されなかったことは、脆弱性の非存在を証明するものではありません。
