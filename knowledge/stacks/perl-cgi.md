# Stack Notes — Perl CGI (CGI.pm, DBI)

## Routing

- Every `.cgi` / `.pl` in `cgi-bin/` (or a dir with `ExecCGI` / `AddHandler cgi-script`)
  is an endpoint. Dispatchers: `if ($q->param('mode') eq 'edit')`,
  hash of subs `%dispatch = (edit => \&edit)`.
- `CGI::Application` / `CGI::Application::Dispatch`: `run_modes` map;
  `mode_param`.

## Authentication idioms

- Cookie/session via `CGI::Session`: `$session->param('user_id')`.
- Web server Basic auth (`.htaccess` `AuthType Basic`) → `$ENV{REMOTE_USER}`
  (server-side, trustworthy).
- Hand-made cookie: `$q->cookie('uid')` used **as identity** — that is
  client-controlled (P2 in bola-patterns).

## Input sources

`$q->param('x')`, `param('x')`, `$cgi->Vars`, `$q->url_param`,
`$q->cookie`, `$ENV{QUERY_STRING}`, `$ENV{PATH_INFO}`, `$ENV{HTTP_*}`,
`<STDIN>` (POST body), `ReadParse()` → `%in` (cgi-lib.pl).

**Context trap:** `param()` in list context returns multiple values —
`{ id => param('id') }` can inject extra hash keys (CVE class seen in
Bugzilla). Note when used to build query hashes.

## Query sinks and gotchas

- DBI: `$dbh->do("DELETE FROM t WHERE id=$id")`,
  `$dbh->prepare("SELECT ... WHERE name='$name'")` (interpolated, then
  `execute()` with no binds) — unsafe.
- Safe: `$dbh->prepare('... WHERE id = ?'); $sth->execute($id)`.
- `$dbh->quote($v)` — safe for string values when used correctly; not for
  identifiers.
- Taint mode (`#!/usr/bin/perl -T`) does not stop SQL injection; untainting
  with a loose regex (`/(.*)/`) is common.
