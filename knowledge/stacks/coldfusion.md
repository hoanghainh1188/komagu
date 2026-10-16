# Stack Notes — ColdFusion (CFML: .cfm / .cfc)

## Routing

- Every `.cfm` is an endpoint. `.cfc` components with
  `access="remote"` functions are callable as
  `/path/Comp.cfc?method=fn&arg=...` (and via SOAP/JSON) — easy to miss.
- `Application.cfc` / `Application.cfm` runs before every request
  (`onRequestStart`) — usual place for login checks.
- Frameworks: Fusebox (`index.cfm?fuseaction=circuit.action` → one endpoint
  per fuseaction), FW/1, ColdBox (`index.cfm?event=handler.action`).

## Authentication idioms

- `<cflogin>`, `getAuthUser()`, `isUserInRole()`; `session.userID` checks in
  `onRequestStart`. Check for exclusions (`if listFindNoCase("login.cfm,...", ...)`).

## Input sources

`url.x`, `form.x`, `cookie.x`, `cgi.*`, `arguments.x` (in remote CFC
methods = request input), `attributes.x` (Fusebox merges url+form),
`rc.x` (FW/1 / ColdBox request context).

## Query sinks and gotchas

- `<cfquery>SELECT ... WHERE id = #url.id#</cfquery>` — unsafe
  (CF auto-escapes single quotes **only** inside quoted string context;
  numeric context and values passed through functions like
  `preserveSingleQuotes()` are injectable).
- Safe: `<cfqueryparam value="#url.id#" cfsqltype="cf_sql_integer">`.
- `queryExecute("SELECT ... " & url.id)` unsafe; with params struct safe.
- `ORDER BY #url.sort#` — identifier, needs allow-list.
- `preserveSingleQuotes(sql)` — strong sign of hand-built SQL; review always.
