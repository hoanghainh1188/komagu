# Stack Notes — Java (Servlet/JSP, Struts 1/2, Spring MVC 2.5–4, JAX-RS, iBATIS/MyBatis, Hibernate 3)

## Routing

| Variant | Endpoint rule |
|---|---|
| Servlet | `WEB-INF/web.xml` `<servlet>` + `<servlet-mapping><url-pattern>`; `@WebServlet("/x")` (Servlet 3). Methods `doGet`, `doPost`, `service`. Often `doPost` calls `doGet`. |
| JSP | Every `.jsp` outside `WEB-INF/` is directly reachable. JSPs with scriptlets (`<% %>`) may run queries. |
| Struts 1 | `WEB-INF/struts-config.xml` `<action path="/x" type="pkg.XAction">` → `/x.do`. `execute()`; `DispatchAction` → one endpoint per `method=` / `parameter` value. |
| Struts 2 | `struts.xml` `<package namespace="/ns"><action name="x" class="..." method="...">` → `/ns/x.action`; wildcard `name="*_*" method="{2}"`; annotations `@Action`. Action properties are set from request params (setter = input!). |
| Spring MVC | `@Controller` + `@RequestMapping` (class prefix + method), `@GetMapping`…; XML `SimpleUrlHandlerMapping`; `MultiActionController` methods. |
| JAX-RS | `@Path` on class + method, `@GET/@POST`, `@PathParam/@QueryParam`. |
| SOAP | Axis `server-config.wsdd`, JAX-WS `@WebService` — every public method is an endpoint. |

## Authentication idioms

- `web.xml` `<security-constraint>` + `<login-config>` (container auth;
  `request.getRemoteUser()`, `isUserInRole`).
- `javax.servlet.Filter` checking `session.getAttribute("loginUser")` —
  read `<filter-mapping>` url-patterns; gaps (e.g. `*.do` mapped, `*.jsp`
  not) are bypass paths.
- Struts 2 interceptor stack (`<interceptor-ref name="loginCheck">`),
  Struts 1 base `Action` class, Spring `HandlerInterceptor`,
  Spring Security `<intercept-url pattern=... access=...>`.

## Ownership idioms

- Safe: DAO `findByIdAndUserId(id, loginUser.getId())`; SQL with
  `AND user_id = ?` bound to session user; Spring Security
  `@PreAuthorize("@perm.canRead(#id, principal)")` (read the bean).
- Unsafe: `dao.findById(Long.parseLong(request.getParameter("id")))` then
  forward to JSP with no comparison. Struts 2 action with `setId()` and
  `getOrder()` loading by `id` only.

## Input sources

`request.getParameter*`, `getParameterValues`, `getParameterMap`,
`getQueryString`, `getPathInfo`, `getRequestURI`, `getHeader`, `getCookies`,
`getInputStream/getReader`; Struts 1 `ActionForm` getters; Struts 2 action
setters / `ModelDriven`; Spring `@RequestParam`, `@PathVariable`,
`@ModelAttribute`, `@RequestBody`; JSP `${param.x}`.

## Query sinks and gotchas

- `stmt.executeQuery("SELECT ... WHERE id=" + id)` — classic.
- `conn.prepareStatement("... WHERE name='" + name + "'")` — **prepared but
  concatenated**: still injectable.
- `StringBuffer/StringBuilder sql; sql.append(" AND x='").append(v).append("'")`.
- `String.format("... %s", v)`.
- **iBATIS 2** (`sqlMap` XML): `#prop#` safe, **`$prop$` unsafe**.
- **MyBatis 3** (`<mapper>` XML / `@Select`): `#{prop}` safe,
  **`${prop}` unsafe** (often used for `ORDER BY ${sort}` and `IN (${ids})`).
- Hibernate: `session.createQuery("from Order where id=" + id)` (HQL, CWE-564),
  `createSQLQuery(...)`; `Restrictions.sqlRestriction(str)`.
- JdbcTemplate: `jdbcTemplate.queryForList("..." + v)` unsafe;
  `queryForList("... ?", v)` safe.
- Mongo Java driver: `new BasicDBObject("$where", "..." + v)`;
  `BasicDBObject.parse(request.getParameter("q"))`.
