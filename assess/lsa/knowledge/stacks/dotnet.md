# Stack Notes — .NET Framework (ASP.NET WebForms, MVC 2–5, Web API 1/2, ASMX, WCF, C# and VB.NET)

## Routing

| Variant | Endpoint rule |
|---|---|
| WebForms | Every `.aspx` is an endpoint. Logic in code-behind `.aspx.cs` / `.aspx.vb` (`Page_Load`, button `_Click` handlers = POST endpoints via postback). `RouteTable.Routes.MapPageRoute` in `Global.asax` adds friendly URLs. |
| Handlers | `.ashx` (`IHttpHandler.ProcessRequest`) — common for AJAX/download. Often forgotten in auth config. |
| ASMX / WCF | `.asmx` `[WebMethod]` public methods; `.svc` + `[OperationContract]`. Each method = endpoint. |
| MVC | `Controllers/<Name>Controller.cs`; public methods returning `ActionResult`/`JsonResult`/`FileResult` → `/{controller}/{action}/{id}` (see `RouteConfig.cs` / `Global.asax`). `[HttpPost]`, `[Route]` (MVC 5 attribute routing), Areas. VB: `Public Function Edit(id As Integer) As ActionResult`. |
| Web API | `ApiController`; verbs by method name prefix (`GetOrder`, `PostOrder`) or `[HttpGet]`; `WebApiConfig` `api/{controller}/{id}`. |

## Authentication idioms

- `web.config` `<authentication mode="Forms">` + `<authorization><deny users="?"/>`;
  `<location path="...">` overrides — **a `<location>` with `allow users="*"`
  is a bypass path.** Note: `<authorization>` in IIS classic mode may not
  cover non-ASP.NET files.
- `Global.asax` `Application_AuthenticateRequest` / `Application_BeginRequest`.
- Base page class (`BasePage : Page`) checking `Session["UserID"]` in
  `OnInit` / `OnLoad`. Pages not inheriting it are unprotected.
- MVC `[Authorize]` (login only, unless `Roles=`/`Policy=`), global
  `filters.Add(new AuthorizeAttribute())` in `FilterConfig`,
  `[AllowAnonymous]` exceptions.

## Ownership idioms

- Safe: `WHERE Id = @Id AND UserId = @UserId` with
  `cmd.Parameters.AddWithValue("@UserId", Session["UserID"])`;
  `db.Orders.Where(o => o.Id == id && o.UserId == currentUserId)`;
  post-load `if (order.UserId != CurrentUser.Id) return HttpNotFound();`.
- Unsafe: `db.Orders.Find(id)`; `Request.QueryString["id"]` → SQL by id only.
- `Response.Redirect(url)` ends the request (throws ThreadAbort) **but
  `Response.Redirect(url, false)` does not** — code continues.
- `Server.Transfer` continues on the target page only.
- ViewState / hidden field IDs are client-controlled (ViewState MAC prevents
  tampering ViewState, **not** hidden fields or `Request.Form`).

## Input sources

`Request.QueryString`, `Request.Form`, `Request.Params`, `Request["x"]`
(QueryString + Form + Cookies + ServerVariables), `Request.Cookies`,
`Request.Headers`, `Request.PathInfo`, `RouteData.Values`, control values
(`txtId.Text`, `ddl.SelectedValue`, `HiddenField.Value`), `GridView`
`DataKeys` (server-side, safer) vs `CommandArgument` (client-modifiable),
MVC action parameters and model binding, `[FromBody]`.

## Query sinks and gotchas

- C#: `new SqlCommand("SELECT ... WHERE id=" + id, conn)`;
  `cmd.CommandText = "..." + txt.Text`; `string.Format("... '{0}'", v)`;
  `$"... {v}"` (C# 6+).
- VB.NET: `"SELECT ... WHERE id=" & id` and `sql &= " AND ..."`.
- `SqlDataAdapter(sql, conn)`, `SqlHelper.ExecuteDataset(conn, CommandType.Text, sql)`
  (Microsoft Data Access Application Block), Enterprise Library
  `db.GetSqlStringCommand(sql)`.
- `SqlDataSource` in `.aspx` with `SelectCommand="... WHERE id=' + ..."` or
  `FilterExpression` — check markup too.
- EF6: `db.Database.SqlQuery<T>("..." + v)`, `ExecuteSqlCommand("..." + v)`.
- LINQ to SQL: `ExecuteQuery("..." + v)` unsafe; `ExecuteQuery("... {0}", v)`
  is parameterized (safe).
- `Replace("'", "''")` helpers — see injection-patterns §3.
- Typed parameters: action `int id` / `Integer.Parse` → numeric, cannot inject.
