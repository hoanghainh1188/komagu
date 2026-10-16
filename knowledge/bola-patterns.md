# BOLA / IDOR Patterns in Legacy Code

Reference: OWASP API Security Top 10 2023 — API1 Broken Object Level
Authorization; OWASP WSTG-ATHZ-04 (Testing for IDOR); CWE-639
"Authorization Bypass Through User-Controlled Key".

## 1. Shapes of identifier input

| Shape | Legacy examples |
|---|---|
| Query string | `detail.php?id=12`, `Report.aspx?no=2020-01`, `view.asp?code=A1` |
| Form / hidden field | `<input type="hidden" name="user_id">`, ViewState-held IDs, `__doPostBack` arguments |
| Path segment | `/order/12`, Struts `/edit.do/12`, MVC `{controller}/{action}/{id}` |
| Cookie | `Request("id")` in Classic ASP also reads cookies; `$_REQUEST` includes cookies (by `request_order`) |
| JSON / XML body | AJAX handlers (`*.ashx`, `ajax.php`), SOAP `.asmx` web methods |
| File name | `download.php?file=invoice_12.pdf`, `GetFile.ashx?path=` |
| Composite | `?company=3&id=12` where `company` is also request-controlled |

## 2. Where ownership checks hide (look here before reporting)

1. **SQL WHERE clause** — `AND user_id = ?`, `AND company_id = @cid`
   bound to a session value. Most common correct form.
2. **JOIN to an ownership table** — `JOIN user_projects up ON up.project_id = p.id AND up.user_id = ?`.
3. **Post-load comparison** — load row, then
   `if ($row['user_id'] != $_SESSION['uid']) { header('Location: /'); exit; }`.
   **Check for `exit`/`return`.** Without it PHP keeps running.
4. **Shared helper** — `checkOwner($table, $id)`, `AuthUtil.canAccess(user, id)`,
   `If Not IsMyOrder(id) Then Response.End`.
5. **DAO / repository layer** — `OrderDao.findByIdForUser(id, uid)`; a base DAO
   that injects tenant filter; Hibernate filters (`@Filter`, `enableFilter`).
6. **Global filter / interceptor** — rare for object-level checks, common for
   login checks. Read it: most only check login.
7. **Database** — views per user, row-level security, stored procedure that
   takes `@UserId`. Mark as "outside visible code" if the procedure source is
   not in the repository.
8. **Framework policy** — Laravel Policies/Gates, Spring `@PreAuthorize`
   with `#id`/`returnObject`, ASP.NET `IAuthorizationService.AuthorizeAsync(user, resource, ...)`,
   Rails `current_user.orders.find(params[:id])` (scoped finder = safe).

## 3. Vulnerable patterns (report these)

- **P1 Bare lookup**: `SELECT ... WHERE id = $id` with ID from request, no owner
  column, no later comparison.
- **P2 Identity from request**: owner taken from request:
  `WHERE id = ? AND user_id = $_POST['user_id']` — attacker sets both.
- **P3 Read checked, write not**: `edit.php` checks owner on GET (display),
  but the POST branch (save) updates `WHERE id = ?` only.
- **P4 Check without stop**: redirect/alert but execution continues
  (`header()` without `exit`; `Response.Redirect(url, false)`;
  JavaScript `alert()` printed then data printed anyway).
- **P5 Parent checked, child not**: verifies `order_id` belongs to user, but
  updates `order_item` by `item_id` alone.
- **P6 Different variable**: checks `$_GET['id']`, uses `$_POST['id']` or
  `$_REQUEST['id']`.
- **P7 Tenant leak**: checks user is in role "manager" but not that the target
  belongs to the manager's company/branch.
- **P8 Mass assignment of owner**: update statement sets `user_id` /
  `company_id` from the request, moving an object to another owner.
- **P9 Bulk/export**: `export.php?ids=1,2,3` or date-range exports without
  owner filter.
- **P10 File by name**: files stored as `uploads/<id>.pdf` served by ID or
  name without owner lookup.
- **P11 Sequential "secret" keys**: `token`, `code` or encrypted IDs that are
  predictable or encrypted with a static key and not bound to the user.
- **P12 Unauthenticated data endpoint**: page excluded from the login filter
  (`<location path="Api" allow users="*">`, `/public/`), returns per-user data.

## 4. Safe patterns (do not report)

- Owner/tenant from **session/principal** bound in the same query.
- Scoped finders: `current_user.orders.find(id)`, `$user->orders()->findOrFail($id)`.
- Post-load comparison **with** stop on mismatch.
- Admin-only endpoint with enforced role check **and** the system is
  single-tenant (note it as `safe` with reason).
- Object is intentionally public (product catalog, public notices). State the
  reason; if unsure, `needs_review`.

## 5. False-positive traps

- Ownership enforced in a DAO you did not open. Open it.
- Owner filter added by a shared function that builds WHERE clauses
  (`buildWhere($conds)` adds `user_id` automatically).
- Session value copied to a local variable with a misleading name
  (`$userId = $_SESSION['login']['id']` is fine).
- Hidden field `user_id` present in the form but **ignored** by the handler,
  which uses the session instead.
- Endpoint is behind web server auth (Basic auth on `/admin` in `.htaccess` /
  IIS) and single tenant — still check tenant scoping if multi-company.
- Stored procedure enforces owner — if source is in repo (`*.sql`), read it.

## 6. Severity guide (BOLA)

| Situation | Severity |
|---|---|
| Delete other users' objects, change owner (P8), write sensitive fields (email, password, bank, price), multi-tenant leak of business data | critical |
| Read other users' personal or financial data; write other non-sensitive fields of another user's object | high |
| Read other users' non-sensitive data; write a single low-impact field (note, flag) | medium |
| Information about existence only (enumeration), low-value data | low |
| Unauthenticated (P12) | raise one level (max critical) |
| Query runs but its result is never returned or used | rate by what the query does: a write keeps its normal level; a read that is not exposed is `low` |
