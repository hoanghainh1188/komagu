# Stack Notes — Classic ASP (VBScript / JScript, ADO)

## Routing

- Every `.asp` file is an endpoint. `<!--#include file="..."-->` /
  `virtual="..."` pulls in shared code (often `conn.asp`, `auth.asp`,
  `common.asp`). Include files with `.inc` extension may be **downloadable
  as source** if IIS does not map `.inc` — note in out_of_scope.
- Dispatchers: `Select Case Request("mode")` → one endpoint per case.

## Authentication idioms

- `If Session("UserID") = "" Then Response.Redirect "login.asp"` —
  in Classic ASP `Response.Redirect` normally ends script processing.
  Treat it as a stop, but if the decision depends on it for a critical
  finding, say so and use confidence `medium`.
  `Response.Write "<script>location.href=...</script>"` does **not** stop.
- Shared include `auth.asp` at the top. Pages without the include are
  unprotected — compare the include list across files.
- IIS directory security (Windows auth / Basic) — outside code, add to
  Unknowns.

## Ownership idioms

- Safe: `"... WHERE id=" & CLng(Request("id")) & " AND user_id=" & CLng(Session("UserID"))`
  (numeric cast + session binding) or ADO `Command` with parameters.
- Unsafe: `"SELECT * FROM orders WHERE id=" & Request("id")`.

## Input sources

`Request("x")` — reads **QueryString, Form, Cookies, ClientCertificate,
ServerVariables** in that order; `Request.QueryString`, `Request.Form`,
`Request.Cookies`, `Request.ServerVariables("HTTP_...")`,
`Request.BinaryRead`, upload components (`Persits.Upload` `.Form`).

## Query sinks and gotchas

- `conn.Execute(sql)`, `Set rs = conn.Execute(sql)`, `rs.Open sql, conn, 1, 3`,
  `cmd.CommandText = sql` then `cmd.Execute` (safe only if
  `cmd.Parameters.Append cmd.CreateParameter(...)` is used and the SQL has `?`).
- Building: `sql = "SELECT ..." & x`, `sql = sql & " AND ..." & y`.
- Sanitizers often seen: `Replace(x, "'", "''")` (string context only),
  `IsNumeric` + `CLng/CInt` (numeric, OK if non-numeric input stops the
  page — check `On Error Resume Next`! With it, a failed `CLng` leaves the
  variable empty or unchanged and execution continues).
- JScript ASP: `"..." + Request("id")`.
