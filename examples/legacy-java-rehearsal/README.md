# Legacy Java rehearsal app

**Deliberately vulnerable. Run it only on localhost and never deploy it.** It exists to rehearse [`docs/pilot-execution-runbook.md`](../../docs/pilot-execution-runbook.md) on a running application. All code is project-owned, and every password and "secret" in it is fake.

It is a Struts 1.3 / JSP app compiled for Java 8 and served by Tomcat 9, with an in-memory H2 database.

| Route | Purpose |
|---|---|
| `POST /login.do` | `JSESSIONID` login. Accounts `rehearsal-a` (owner) and `rehearsal-b` (attacker); passwords are in `src/main/resources/seed.sql` |
| `/home.do` | Session check page, contains `Signed in as` |
| `/order/detail.do?id=` | BOLA, read |
| `/order/edit.do?id=` | BOLA, read; issues a Struts token |
| `POST /order/update.do` | BOLA, write; needs `org.apache.struts.taglib.html.TOKEN` |
| `/invoice/view.do?invoiceId=` | BOLA, read; id parameter is not called `id` |
| `/order/search.do?q=` | SQL injection through JDBC concatenation |
| `/order/list.do?sort=` | SQL injection through MyBatis `${sort}` |
| `/admin/report.do` | Role check that denies with a `200` Windows-31J error page |

Without a session, every action answers `302` to `/login.do`. Object ids for the owner are `101` (order and invoice), and for the attacker `201`.

```bash
docker compose up -d --build   # http://127.0.0.1:18080
docker compose down
```

`fixes/apply-fixes.sh DIR` applies the runbook W10-3 fixes to a copy of the app: `OwnershipEnforcer` on the four BOLA routes, `PreparedStatement` for the search and `safeOrderBy` for the sort. After the fixes the routes deny in three ways: `404` (detail, edit), a `200` error page (invoice) and `302` to `/login.do` (update).

`META-INF/context.xml`, `db-prod.properties` and `src/test/resources/test-data/` are planted so that the W9-2 exclude list has something to remove. `Db.java` names a planted host for the `komagu leak-check` canary.
