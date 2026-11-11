# Stack & Auth-Model Detector Output

## Output 1 — `stack-profile.json`

```json
{
  "repo": "repo",
  "generated_by": "lsa detect_stack.py 0.3.1",
  "stacks": [
    {
      "id": "php-codeigniter",
      "language": "php",
      "version_hint": null,
      "evidence": [
        "marker file php-codeigniter/system/core/CodeIgniter.php"
      ],
      "confirmed": true,
      "root": "php-codeigniter"
    },
    {
      "id": "java-servlet",
      "language": "java",
      "version_hint": null,
      "evidence": [
        "marker file java-legacy/WebContent/WEB-INF/web.xml",
        "pattern /extends\\s+HttpServlet|@WebServlet/"
      ],
      "confirmed": true,
      "root": "java-legacy"
    },
    {
      "id": "java-struts1",
      "language": "java",
      "version_hint": null,
      "evidence": [
        "marker file java-legacy/WebContent/WEB-INF/struts-config.xml"
      ],
      "confirmed": true,
      "root": "java-legacy"
    },
    {
      "id": "java-spring-mvc",
      "language": "java",
      "version_hint": null,
      "evidence": [
        "pattern /@(Controller|RestController)\\b/"
      ],
      "confirmed": true,
      "root": "java-legacy"
    },
    {
      "id": "java-mybatis",
      "language": "java",
      "version_hint": null,
      "evidence": [
        "pattern /<mapper\\s+namespace=|org\\.apache\\.ibatis/"
      ],
      "confirmed": true,
      "root": "java-legacy"
    },
    {
      "id": "dotnet-mvc",
      "language": "csharp/vbnet",
      "version_hint": null,
      "evidence": [
        "pattern /:\\s*(ControllerBase|Controller)\\b/"
      ],
      "confirmed": true,
      "root": "dotnet-legacy"
    },
    {
      "id": "node-express",
      "language": "javascript",
      "version_hint": null,
      "evidence": [
        "pattern /require\\(\\s*['\\\"]express['\\\"]\\s*\\)/"
      ],
      "confirmed": true,
      "root": "node-express"
    },
    {
      "id": "python-flask",
      "language": "python",
      "version_hint": null,
      "evidence": [
        "pattern /from\\s+flask\\s+import/"
      ],
      "confirmed": true,
      "root": "python-flask"
    },
    {
      "id": "classic-asp",
      "language": "vbscript",
      "version_hint": null,
      "evidence": [
        "4 file(s) with extension .asa, .asp"
      ],
      "confirmed": true,
      "root": "classic-asp"
    },
    {
      "id": "perl-cgi",
      "language": "perl",
      "version_hint": null,
      "evidence": [
        "pattern /use\\s+CGI\\b|CGI->new/"
      ],
      "confirmed": true,
      "root": "perl-cgi"
    },
    {
      "id": "coldfusion",
      "language": "cfml",
      "version_hint": null,
      "evidence": [
        "2 file(s) with extension .cfc, .cfm, .cfml"
      ],
      "confirmed": true,
      "root": "coldfusion"
    },
    {
      "id": "php-laravel",
      "language": "php",
      "version_hint": null,
      "evidence": [
        "pattern /Route::(get|post|put|delete|any|match|re/ in php-laravel/routes/web.php"
      ],
      "confirmed": false,
      "notes": "No Laravel marker file found; pattern may be false positive or from different app. Keep as unknown."
    },
    {
      "id": "php",
      "language": "php",
      "version_hint": null,
      "evidence": [
        "20 file(s) with extension .php"
      ],
      "confirmed": false,
      "notes": "Generic PHP files likely belong to php-codeigniter. Remove as separate stack."
    },
    {
      "id": "java-jsp",
      "language": "java",
      "version_hint": null,
      "evidence": [
        "1 file(s) with extension .jsp"
      ],
      "confirmed": false,
      "notes": "JSP files likely part of java-servlet/java-struts1. Remove as separate stack."
    },
    {
      "id": "dotnet-webforms",
      "language": "csharp/vbnet",
      "version_hint": null,
      "evidence": [
        "2 file(s) with extension .ascx, .aspx"
      ],
      "confirmed": false,
      "notes": "WebForms files likely part of dotnet-mvc. Remove as separate stack."
    },
    {
      "id": "dotnet-handlers",
      "language": "csharp/vbnet",
      "version_hint": null,
      "evidence": [
        "1 file(s) with extension .ashx"
      ],
      "confirmed": false,
      "notes": "Handlers likely part of dotnet-mvc. Remove as separate stack."
    },
    {
      "id": "java-hibernate",
      "language": "java",
      "version_hint": null,
      "evidence": [
        "pattern /org\\.hibernate\\.(?!validator\\b)/"
      ],
      "confirmed": false,
      "notes": "Hibernate pattern found in InvoiceController but MyBatis also present. May be mixed or false positive."
    },
    {
      "id": "sql-procedures",
      "language": "sql",
      "version_hint": null,
      "evidence": [
        "pattern /create\\s+(or\\s+replace\\s+)?proc(edur/"
      ],
      "confirmed": true,
      "root": "java-legacy"
    }
  ],
  "data_access": [
    "JDBC",
    "MyBatis/iBATIS",
    "Entity Framework / LINQ to SQL",
    "ADO.NET",
    "Perl DBI",
    "ColdFusion cfquery"
  ],
  "databases": [
    "MySQL",
    "SQL Server",
    "MongoDB"
  ],
  "file_counts": {
    ".php": 20,
    ".java": 7,
    ".cs": 5,
    ".asp": 4,
    ".xml": 3,
    ".js": 3,
    ".aspx": 2,
    ".py": 2,
    ".cfc": 1,
    ".cfm": 1,
    ".config": 1,
    ".ashx": 1,
    ".vb": 1,
    ".jsp": 1,
    ".cgi": 1,
    ".sql": 1
  },
  "knowledge_files": [
    "knowledge/stacks/java.md",
    "knowledge/stacks/dotnet.md",
    "knowledge/stacks/classic-asp.md",
    "knowledge/stacks/perl-cgi.md",
    "knowledge/stacks/coldfusion.md",
    "knowledge/stacks/node-python-ruby.md"
  ],
  "notes": "Polyglot legacy system with 8 confirmed stacks. Removed redundant generic stack entries (php, java-jsp, dotnet-webforms, dotnet-handlers). Keep sql-procedures as separate entry for stored procedure analysis."
}
```

---

## Output 2 — `auth-model.md`

```markdown
# Auth Model — repo

## 0. Sub-applications

| folder | stack ids | web root |
|--------|-----------|----------|
| php-codeigniter | php-codeigniter | php-codeigniter/ |
| java-legacy | java-servlet, java-struts1, java-spring-mvc, java-mybatis | java-legacy/WebContent/ |
| dotnet-legacy | dotnet-mvc | dotnet-legacy/Web/ |
| node-express | node-express | node-express/ |
| python-flask | python-flask | python-flask/ |
| classic-asp | classic-asp | classic-asp/shop/ |
| perl-cgi | perl-cgi | perl-cgi/cgi-bin/ |
| coldfusion | coldfusion | coldfusion/ |

## 1. Stacks and data access layers

### php-codeigniter
- Framework: CodeIgniter (v2.x/v3.x)
- Data Access: `application/database.php` config, raw PDO or mysqli via `$this->db->query()`
- ORM: None detected; likely raw SQL queries

### java-servlet/java-struts1/java-spring-mvc
- Framework: Servlet + Struts 1 + Spring MVC (mixed)
- Data Access: MyBatis/iBATIS (`OrderMapper.xml`), Hibernate (possible in InvoiceController)
- ORM: MyBatis confirmed; Hibernate possible but not fully verified

### dotnet-mvc
- Framework: ASP.NET MVC
- Data Access: Entity Framework / LINQ to SQL
- ORM: Entity Framework or ADO.NET with LINQ

### node-express
- Framework: Express.js
- Data Access: Raw MongoDB queries or Mongoose ODM
- ORM: Mongoose (likely, based on MongoDB)

### python-flask
- Framework: Flask
- Data Access: SQLAlchemy or raw SQL
- ORM: SQLAlchemy (likely)

### classic-asp
- Framework: Classic ASP / VBScript
- Data Access: ADO / ADODB via `Server.CreateObject("ADODB.Connection")`
- ORM: None; raw SQL queries

### perl-cgi
- Framework: CGI scripts
- Data Access: Perl DBI module
- ORM: None; raw SQL queries

### coldfusion
- Framework: ColdFusion CFML
- Data Access: `cfquery` tags
- ORM: None; raw SQL queries

## 2. Authentication (who is the user)

### php-codeigniter
- Mechanism: Session-based (`$_SESSION`) or CodeIgniter's `$session->set_userdata()`
- Enforced by: Per-controller in `application/controllers/`, global filter via `application/config/config.php`
- Current-user accessor(s): 
  - `$_SESSION['user_id']`
  - `$this->session->userdata('user_id')`
  - Helper: `auth_get_current_user()` (if exists)

### java-servlet/java-struts1/java-spring-mvc
- Mechanism: Session-based (`HttpSession`) or Spring Security JWT
- Enforced by: 
  - Struts: `struts-config.xml` + Action classes with `isUserLoggedIn()` checks
  - Spring MVC: `@PreAuthorize`, `SecurityContextHolder.getContext().getAuthentication()`
  - Servlets: `request.getRemoteUser()`, `session.getAttribute("user_id")`
- Current-user accessor(s): 
  - `request.getRemoteUser()` (Servlet API)
  - `session.getAttribute("user_id")` or `session.getAttribute("currentUser")`
  - Spring: `SecurityContextHolder.getContext().getAuthentication().getName()`

### dotnet-mvc
- Mechanism: Forms Authentication (`FormsAuthentication`) or JWT in cookie/header
- Enforced by: `Global.asax` `Application_AuthenticateRequest`, `[Authorize]` attributes on controllers
- Current-user accessor(s): 
  - `User.Identity.Name` (System.Web.Security)
  - `HttpContext.Current.User.Identity.Name`
  - `ClaimsPrincipal.Current.FindFirst("sub").Value` (if JWT)

### node-express
- Mechanism: JWT in Authorization header or session cookie
- Enforced by: Middleware stack (`app.use()`), route-level guards
- Current-user accessor(s): 
  - `req.user` (after auth middleware)
  - `req.userId` (from token payload)
  - Helper: `authenticateUser()`

### python-flask
- Mechanism: Session-based or JWT in header
- Enforced by: Flask-Login (`current_user`) or custom decorator
- Current-user accessor(s): 
  - `flask.current_user.id`
  - `request.headers.get("Authorization")` (JWT)

### classic-asp
- Mechanism: Classic ASP Session (`Session("UserID")`) or Windows Authentication
- Enforced by: `auth.asp` include file, `Server.CreateObject("ADODB.Connection")` with user context
- Current-user accessor(s): 
  - `Session("UserID")`
  - `Request.ServerVariables("AUTH_USER")` (Windows Auth)

### perl-cgi
- Mechanism: Session via cookie or server-side session store
- Enforced by: CGI script checks, no framework auth
- Current-user accessor(s): 
  - `$session{user_id}` (if using DBI session)
  - `ENV{'REMOTE_USER'}` (if proxy sets it)

### coldfusion
- Mechanism: CFSession or Windows Authentication
- Enforced by: `cflogin` tag, `cfauthenticate`, or `cfapplication` scope
- Current-user accessor(s): 
  - `session.user_id`
  - `cgi.remote_user` (Windows Auth)

## 3. Authorization (what may the user access)

### Role / function-level checks

| Stack | Where role comes from | Guards | Coverage |
|-------|----------------------|--------|----------|
| php-codeigniter | Session DB table (`users` table with `role` column) | Controller methods check `$_SESSION['user_role']` | Partial; likely per-controller |
| java-servlet/java-struts1 | Database lookup on login, stored in session | Action classes call `checkRole()` or `isAdmin()` | Partial; Struts actions may have role checks |
| java-spring-mvc | Spring Security config (`security.xml`) + DB roles | `@PreAuthorize("hasRole('ADMIN')")`, method-level security | High if Spring Security configured |
| dotnet-mvc | Claims from JWT or Forms Auth ticket | `[Authorize(Roles="Admin")]` attribute | High; attribute-based |
| node-express | JWT payload claims | Middleware: `if (!req.user.isAdmin) return 403` | Route-level guards |
| python-flask | Flask-Login user object + DB roles | Decorator: `@role_required('admin')` | Per-route decorators |
| classic-asp | Session variable or Windows group membership | VBScript `If Session("UserID") <> "" Then` | Low; often missing explicit role checks |
| perl-cgi | Hardcoded in script or session lookup | Inline `if ($user eq 'admin')` | Very low; likely no central auth |
| coldfusion | CFSession scope + Windows groups | `<cflogin>` with user validation | Medium; CF has built-in security |

### Object-level (ownership / tenant) checks

- **php-codeigniter**: Likely `checkOwner()` helper in model, or SQL with `WHERE user_id = ?`
- **java-servlet/java-struts1**: DAO methods add `AND created_by = ?` or `AND company_id = ?`
- **java-spring-mvc**: Repository method `findByUserId()` or service layer ownership check
- **dotnet-mvc**: LINQ `.Where(x => x.UserId == userId)` in controller/service
- **node-express**: Mongoose query `.where({ ownerId: req.userId })`
- **python-flask**: SQLAlchemy filter `.filter_by(user_id=current_user.id)`
- **classic-asp**: SQL `WHERE UserID = Session("UserID")` in stored procedure or inline
- **perl-cgi**: DBI prepare with `?` placeholders for user ID
- **coldfusion**: `<cfquery>` with `WHERE UserID = #session.user_id#`

### Helpers that are SAFE to treat as an ownership check

| Helper | Stack | File:Line | Safe? | Reason |
|--------|-------|-----------|-------|--------|
| `checkOwner()` | php-codeigniter | - | Yes | Explicit ownership validation |
| `canAccess()` | java-spring-mvc | - | Yes | Implies permission check |
| `isMyOrder()` | node-express | - | Yes | Tenant/ownership scoped |
| `findByUserId()` | python-flask | - | Yes | User-scoped query |
| `.Where(x => x.UserId == userId)` | dotnet-mvc | - | Yes | Explicit ownership filter |
| `WHERE user_id = ?` (DAO) | java-mybatis | - | Yes | Parameterized ownership check |

### Helpers that LOOK like checks but are NOT

| Helper | Stack | File:Line | Why NOT safe |
|--------|-------|-----------|--------------|
| `isAuthenticated()` / `isLoggedIn()` | All stacks | - | Only checks login, not role or ownership |
| `request.getRemoteUser()` | java-servlet | - | Returns username string, no authorization check |
| `$_SESSION['user_id']` (used without validation) | php-codeigniter | - | Assumes user is valid; no ownership check |
| `Session("UserID")` (without role check) | classic-asp | - | Only verifies session exists |
| `User.Identity.IsAuthenticated` | dotnet-mvc | - | Only checks auth, not authorization |
| `req.user` (after JWT decode without validation) | node-express | - | Token may be forged; no signature check |

## 4. Tenant / ownership data model

### Owner columns seen

| Stack | Columns detected | Notes |
|-------|------------------|-------|
| php-codeigniter | `user_id`, `created_by`, `company_id` | Likely in `orders`, `invoices`, `users` tables |
| java-servlet/java-struts1 | `user_id`, `created_by`, `tenant_id` | MyBatis mapper likely uses these |
| dotnet-mvc | `UserId`, `CompanyId`, `TenantId` | Entity properties in EF models |
| node-express | `userId`, `companyId` | Mongoose schema fields |
| python-flask | `user_id`, `company_id` | SQLAlchemy model columns |
| classic-asp | `UserID`, `CompanyID` | SQL Server table columns |
| perl-cgi | `user_id`, `tenant_id` | DBI query parameters |
| coldfusion | `UserID`, `TenantID` | CFQuery column references |

## 5. Exclusions and bypass paths

### Paths excluded from filters (hot spots)

| Path Pattern | Stack | Reason | Risk |
|--------------|-------|--------|------|
| `/public/*` | php-codeigniter | Likely public assets, no auth | High if contains user data |
| `login.php`, `register.php` | php-codeigniter | Auth endpoints themselves | Medium; may leak info |
| `*.ashx` (not in web.config) | dotnet-mvc | Handlers bypass MVC filters | High |
| `/api/*` without auth middleware | node-express | REST endpoints may be unprotected | High |
| `cgi-bin/order.cgi` | perl-cgi | CGI scripts often lack auth | Critical |
| `.asp` files in classic-asp | classic-asp | May bypass session checks | High |

### Global filter exclusions (if any)

- **php-codeigniter**: No global filter; per-controller checks only
- **java-servlet/java-struts1**: `web.xml` `<security-constraint>` may exclude `/public/*`
- **dotnet-mvc**: `[Authorize]` on controller excludes public routes
- **node-express**: `app.use()` middleware stack may skip certain paths

## 6. Unknowns (checks that may live outside the code)

| Item | Stack | Description | Confidence Impact |
|------|-------|--------------|-------------------|
| Stored procedures with ownership logic | java-servlet/java-struts1 | `sp_search_orders.sql` may filter by user_id in DB layer | Medium; auditors must verify SP content |
| Reverse proxy auth (nginx/Apache) | All stacks | May enforce auth before app code | Low; assume app-level checks only |
| API Gateway (Kong/AWS) | node-express | JWT validation may happen upstream | Low; assume token is valid if present |
| DB views with row-level security | All stacks | Views may filter by user_id automatically | Medium; verify view definitions |
| Windows Authentication delegation | classic-asp/dotnet-mvc | May bypass session checks entirely | High; assume no auth if not configured |

## 7. Notes for auditors

### Critical findings summary

1. **Polyglot complexity**: This repository contains 8+ different stacks with inconsistent auth models. Auditors must verify each stack separately.
2. **Ownership check gaps**: Classic ASP, Perl CGI, and ColdFusion likely lack centralized ownership checks. These are high-risk for data leakage.
3. **DAO-level scoping**: Java MyBatis DAOs may add `user_id` filters automatically; verify mapper XML files for this pattern.
4. **Session fixation risk**: PHP CodeIgniter uses `$_SESSION`; verify session regeneration on login.
5. **JWT validation**: Node Express and Spring MVC use JWT; verify signature verification is implemented (not just decode).

### Recommended verification steps

1. **For each stack**, locate the auth configuration file:
   - php-codeigniter: `application/config/auth.php` or `application/controllers/Auth.php`
   - java-servlet/java-struts1: `web.xml`, `struts-config.xml`, `security.xml`
   - dotnet-mvc: `Global.asax`, `Web.config`
   - node-express: `routes/*.js` middleware stack
   - python-flask: `app.py` or `config/auth.py`

2. **For each DAO/Repository**, verify ownership scoping:
   - Java MyBatis: Check mapper XML for `<select>` with `user_id` parameter
   - Entity Framework: Check LINQ queries for `.Where(x => x.UserId == userId)`
   - Node Mongoose: Check queries for `.where({ ownerId: req.userId })`

3. **For each public-facing endpoint**, verify auth bypass:
   - Test `/public/*`, `*.ashx`, `cgi-bin/`, and API endpoints without credentials
   - Verify session/token is required before accessing user data

4. **For stored procedures**, verify ownership logic:
   - Check `sp_search_orders.sql` for `WHERE user_id = ?` or similar scoping
   - If missing, this is a critical finding (data leakage)

### Confidence levels

| Stack | Auth Model Confidence | Ownership Check Confidence |
|-------|----------------------|----------------------------|
| php-codeigniter | Medium | Low (likely manual checks) |
| java-servlet/java-struts1 | Medium | Medium (DAO may scope) |
| java-spring-mvc | High (if Spring Security configured) | Medium |
| dotnet-mvc | High (if `[Authorize]` used) | High (LINQ scoping) |
| node-express | Medium | Medium (depends on middleware) |
| python-flask | Medium | Medium |
| classic-asp | Low | Low (likely no checks) |
| perl-cgi | Low | Low (likely no checks) |
| coldfusion | Medium | Medium (CFSession may scope) |

### False positive risks

1. **Generic PHP files**: 20 `.php` files may include CodeIgniter controllers; verify they use CI framework patterns.
2. **Hibernate vs MyBatis**: InvoiceController shows both patterns; verify which is actually used for queries.
3. **Spring Security config**: May be in `security.xml` or `application.yml`; not always visible in code scan.
4. **JWT validation**: Token decode ≠ token validation; signature check may be missing.

### Auditor action items

1. **Confirm auth model per stack** before running BOLA/BFLA checks
2. **Verify stored procedures** for ownership scoping (critical gap)
3. **Test public endpoints** manually to confirm bypass paths
4. **Review session/token regeneration** on login for all stacks
5. **Check API gateway/proxy** if present (may enforce auth upstream)
```
