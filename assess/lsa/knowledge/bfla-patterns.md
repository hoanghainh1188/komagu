# BFLA Patterns in Legacy Code

Broken function level authorization (BFLA, OWASP API5:2023, CWE-285 / CWE-269):
a **privileged function** (admin page, role change, bulk export, user deletion)
is reachable by a lower-privileged user. BOLA asks "may this user touch *this
object*?"; BFLA asks "may this user call *this function* at all?". One route can
have both.

## 1. Tier 1 hints on route candidates

`map_routes.py` adds these fields to every route candidate. They are hints for
the auditor, not findings.

| Field | Meaning |
|---|---|
| `privilege_hint` | `privileged` when the path, handler file or handler name looks administrative, or the code writes to users / roles / permissions / settings; otherwise `unknown` |
| `privilege_reasons` | why, e.g. `path:admin`, `path:export`, `write:users` |
| `role_checks` | server-side role checks found for the route (`scope: route`) or applied to the whole file (`scope: file`: class annotation, `router.use`, `before_action`) |
| `bfla_signals` | `no_role_check`, `role_from_request`, `client_side_role_check` |
| `needs_bfla_audit_hint` | any signal present; these routes are batched first |

`unknown` does not mean "not privileged": Tier 1 only sees names and SQL. A
route named `/orders/close-month` can still be an admin function.

## 2. Where role checks hide (look here before reporting)

- **Framework declarations:** `@PreAuthorize`, `@Secured`, `@RolesAllowed`
  (Java), `[Authorize(Roles=…)]` / `[Authorize(Policy=…)]` (.NET), `@admin_required`,
  `@roles_required`, `@permission_required` (Python), `authorize!`, `can?`
  (Rails/CanCanCan), `Gate::allows`, `->can()`, policies (Laravel).
- **Class or router level:** annotations above the class, `router.use(requireAdmin)`,
  `app.use('/admin', requireAdmin)`, `before_action :require_admin`, base
  controllers (`AdminBaseController`) whose constructor or filter checks the role.
- **Configuration:** Spring Security `http.authorizeRequests().antMatchers("/admin/**").hasRole(...)`,
  `<security-constraint>` with `<auth-constraint><role-name>` in `web.xml`,
  `<location path="admin"><authorization>` in `Web.config`, Apache `.htaccess`,
  reverse-proxy rules. Record these in `auth-model.md`.
- **Includes:** `include 'admin_check.php'`, `<!--#include file="inc/admin.asp"-->`,
  ColdFusion `Application.cfc` `onRequestStart` for an `/admin` folder.
- **Session role:** `$_SESSION['role'] !== 'admin'`, `Session("IsAdmin")`,
  `session.getAttribute("role")`, `req.user.role`, `current_user.admin?`.

## 3. Vulnerable patterns (report these)

| Subtype | Shape |
|---|---|
| `missing_role_check` | Admin action requires only login (`ensureLoggedIn`, `[Authorize]`, `require 'auth.php'`) and no role. |
| `missing_role_check` | Guard function exists but this route does not use it (`requireAdmin` defined, not in the route's middleware list). |
| `missing_role_check` | Some methods of an admin controller carry the role attribute and others do not. |
| `role_from_request` | Role or admin flag comes from request input: `$_POST['is_admin']`, `req.body.role`, `request.getParameter("role")`, `Request.Form["isAdmin"]`, `params[:admin]`, `form.isAdmin`, a role cookie. |
| `client_side_role_check` | The role check only hides a link, button or menu (`<?php if ($role == 'admin'): ?><a …>`); the handler itself does not check. |
| `missing_role_check` | Privileged write reachable from a user page: `UPDATE users SET role = …`, `INSERT INTO user_roles`, `DELETE FROM users`. |

## 4. Safe patterns (do not report)

- Role enforced before the handler by annotation, attribute, filter, middleware
  or configuration that covers this exact route (check path patterns and HTTP
  methods: `antMatchers(HttpMethod.GET, "/admin/**")` does not protect POST).
- Role read from a server-side source (session, token claims, database) and
  compared before any side effect, with a deny response on failure.
- Self-service functions that only act on the caller's own record (that is a
  BOLA question, not BFLA).

## 5. False-positive traps

- **Configuration protects the folder.** `web.xml`, `Web.config`, Spring
  Security config or the proxy may restrict `/admin/**`. Quote it in
  `auth-model.md` and verify the pattern really matches the route.
- **Inherited checks.** A base class constructor, `OnActionExecuting`, or a
  servlet filter mapped to the path may enforce the role.
- **Not privileged after all.** `/account/export` of the caller's own data, or
  a `settings` page for the caller's profile.
- **Role value assigned, not trusted.** An admin page that reads the *new* role
  from the form (`role = request.getParameter("role")`) after a server-side
  admin check is safe; `role_from_request` matters only when the request value
  decides access.
- **Dead code.** Admin pages not reachable from any route or mapping.

## 6. Severity guide (BFLA)

| Situation | Severity |
|---|---|
| Any authenticated user can change roles, create admins, or impersonate | critical |
| Any authenticated user can delete or bulk-export other users' data | critical |
| Anonymous access to an admin function | critical |
| Any authenticated user can change system settings, prices or workflow states | high |
| Read-only admin views (reports, user lists) open to all users | medium–high (high with personal data) |
| Role checked only in the UI, handler reachable but low impact | medium |

Adjust with `severity-and-cwe.md` (multi-tenant impact +1, compensating
control outside code −1).
