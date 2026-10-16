# Stack Notes — PHP (plain PHP 4/5, CodeIgniter 2/3, CakePHP 1/2, old Laravel, Zend 1)

## Routing (how to find endpoints)

| Variant | Endpoint rule |
|---|---|
| Plain PHP | Every `.php` under the web root is an endpoint unless blocked (`.htaccess` `Deny`, outside docroot, `defined('IN_APP') or die`). Includes in `inc/`, `lib/`, `include/` usually are not. |
| Dispatcher pages | `switch ($_GET['mode'|'action'|'cmd'|'act'|'m'])` → one endpoint per case. Also `call_user_func($_GET['f'])` (note in out_of_scope). |
| CodeIgniter 2/3 | `application/controllers/<Name>.php`; public methods → `/<name>/<method>/<arg1>/...`. Methods starting with `_` are private. `application/config/routes.php` adds aliases. |
| CakePHP 1.x/2.x | `app/Controller/<Name>Controller.php` (2.x) or `app/controllers/<name>_controller.php` (1.x); public actions → `/<names>/<action>/<id>`. `app/Config/routes.php`. |
| Laravel 4/5 | `routes.php` / `routes/web.php` / `routes/api.php`; `Route::get|post|put|delete|any|match|resource`. Group middleware: `Route::group(['middleware' => 'auth'], ...)`. |
| Zend 1 | `application/controllers/<Name>Controller.php`, `*Action()` methods → `/<name>/<action>`. |

## Authentication idioms

- `session_start(); if (empty($_SESSION['user_id'])) { header('Location: login.php'); exit; }`
  — **check for `exit`/`die`** after `header()`.
- Common include: `require_once 'auth.php'` / `check_login()` at the top.
- `auto_prepend_file` in `php.ini` / `.htaccess` (`php_value auto_prepend_file`).
- CodeIgniter: `MY_Controller` constructor checking session; hooks
  (`application/config/hooks.php`).
- CakePHP: `AuthComponent` in `AppController::$components`;
  `$this->Auth->allow(...)` lists public actions.
- Laravel: `auth` middleware; Policies (`$this->authorize('view', $model)`).

## Ownership idioms

- Safe: `WHERE id = ? AND user_id = ?` with `$_SESSION['user_id']`;
  `$this->db->where('user_id', $this->session->userdata('id'))`;
  Laravel `Auth::user()->orders()->findOrFail($id)`;
  CakePHP `'conditions' => ['Order.id' => $id, 'Order.user_id' => $this->Auth->user('id')]`.
- Unsafe: `Order::find($id)` / `$this->Order->findById($id)` /
  `$this->db->get_where('orders', ['id' => $id])` with no later comparison.

## Input sources

`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SERVER['PATH_INFO']`,
`$_SERVER['QUERY_STRING']`, `$_FILES[...]['name']`, `file_get_contents('php://input')`,
`$HTTP_GET_VARS` (PHP 4), **`register_globals`** (PHP ≤5.3: any `$id`
may come from the request!), `extract($_GET)`, `$this->input->get/post()`
(CI), `$this->request->data` / `->params` / `->query` (Cake),
`Input::get` / `$request->input` (Laravel).

If `register_globals` is on, or `extract()`/`import_request_variables()` is
used, treat uninitialized variables as request input.

## Query sinks and gotchas

- `mysql_*` (removed in PHP 7) — no binding at all. Any variable in the query
  string needs a cast or quotes+escape.
- `"... WHERE id = $id"` — interpolation inside double quotes. Single quotes
  do not interpolate.
- `$sql .= " AND name LIKE '%" . $kw . "%'"` — multi-line building; follow
  the variable.
- `mysqli_real_escape_string` without quotes around the value → injectable.
- `addslashes` + Shift_JIS / EUC-JP / GBK client charset → multibyte bypass.
  Japanese legacy systems often use SJIS/EUC-JP.
- CodeIgniter: `$this->db->query("... $id")` unsafe;
  `$this->db->query("... ?", [$id])` safe; `->where("id = $id")` unsafe;
  `->where('id', $id)` safe; `->order_by($_GET['sort'])` unsafe (identifier).
- CakePHP: `'conditions' => "Order.id = $id"` (string) unsafe;
  `'conditions' => ['Order.id' => $id]` safe; `$this->Model->query()` raw.
- Laravel: `whereRaw("id = $id")`, `DB::raw`, `orderByRaw` unsafe with input.
- MongoDB (`MongoCollection`, `MongoDB\Collection`): `find(['user' => $_GET['u']])`
  → array operator injection.
