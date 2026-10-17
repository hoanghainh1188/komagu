# Query Injection Patterns in Legacy Code (SQL / HQL / NoSQL)

References: OWASP SQL Injection Prevention Cheat Sheet; OWASP Query
Parameterization Cheat Sheet; CWE-89, CWE-564, CWE-943.

## 1. Building patterns (how the dynamic string is made)

| Pattern | Examples |
|---|---|
| Concatenation | PHP `.`/`.=`, Java/C#/JS `+`/`+=`, VB/ASP `&`/`&=`, Perl `.`, Python `+` |
| Interpolation | PHP `"... $id"` / `"{$row['id']}"`, Perl `"... $id"`, Ruby `"#{id}"`, JS template `` `${id}` `` (including multiline template literals), C# `$"... {id}"`, Python f-string (`f"..."` and multiline `f"""..."""`) |
| Formatting | `String.format`, `string.Format`, `sprintf`, Python `%` / `.format`, `MessageFormat` |
| Template placeholder | MyBatis `${param}` (even when mixed with `#{safeParam}`), iBATIS `$param$`, ColdFusion `#var#` / `#url.id#` / `#arguments.id#` inside `<cfquery>` without `<cfqueryparam>` |
| Builder misuse | `whereRaw`, `DB::raw`, `orderByRaw`, Hibernate `createQuery("..." + x)`, `createSQLQuery`, Criteria `Restrictions.sqlRestriction(x)`, CodeIgniter `$this->db->where("id = $id")` / `query("..." . $x)` |
| Dynamic identifiers | `ORDER BY $sort`, `ORDER BY ${orderBy}`, `GROUP BY $col`, `SELECT $cols`, table names from input — parameter binding cannot bind identifiers; an explicit allow-list is required |
| Stored procedure dynamic SQL | `EXEC('SELECT ... ' + @p)`, `sp_executesql` with concatenated string, Oracle `EXECUTE IMMEDIATE '...' || p` |

### 1.1 High-risk multi-stack interpolation nuances

- **MyBatis / iBATIS XML (`${...}` vs. `#{...}`)**: `#{param}` compiles to a `?`
  PreparedStatement placeholder (safe). `${param}` (and iBATIS `$param$`) performs
  raw string substitution before statement preparation. A query that uses `#{id}`
  in `WHERE` but `${orderBy}` in `ORDER BY` is **vulnerable** (`template_placeholder`
  / `dynamic_identifier`) unless the mapper XML wraps it in a static `<choose><when>`
  allow-list or the Java caller strictly validates against an enum/Set of column names.
- **Multi-line & split construction**: In C# (`string.Format`, `$"..."`), Python
  (`f"""..."""`), and Node.js (`` `SELECT ... ${expr}` ``), a query string is often
  assigned to a local variable (`sql2`, `sql3`) and executed several lines later
  (`new SqlCommand(sql2, conn).ExecuteReader()`, `cursor.execute(sql)`). Trace every
  built SQL variable to its execution sink and include both the construction line
  and the sink line in the finding evidence.
- **ColdFusion `<cfquery>`**: ColdFusion auto-escapes single quotes inside
  `#...#` only in string literals, which fails completely for unquoted numeric
  expressions (`WHERE id = #url.id#`), `ORDER BY #url.sort#`, or when
  `preserveSingleQuotes()` is used. Any request-derived `#...#` inside `<cfquery>`
  not wrapped in `<cfqueryparam>` must be flagged as `template_placeholder`.

## 2. Sinks by stack

- **PHP**: `mysql_query`, `mysqli_query`, `mysqli::query`, `pg_query`,
  `odbc_exec`, `sqlsrv_query`, `oci_parse`, `PDO::query`, `PDO::exec`,
  `$db->query/->Execute/->GetAll/->GetRow` (ADOdb, PEAR DB), CodeIgniter
  `$this->db->query`, CakePHP `$this->Model->query`, Laravel `DB::select/
  statement/unprepared`.
- **Java**: `Statement.execute*`, `Connection.prepareStatement(sql)` **when
  `sql` is concatenated** (prepared but not parameterized!),
  `JdbcTemplate.query*/update(sql)` with concatenated `sql`,
  Hibernate `session.createQuery/createSQLQuery`, JPA `createQuery/
  createNativeQuery`, MyBatis/iBATIS mapper XML.
- **.NET**: `SqlCommand`/`OleDbCommand`/`OdbcCommand`/`OracleCommand`
  (`CommandText`, constructor), `SqlDataAdapter(sql, conn)`,
  `SqlDataSource SelectCommand`, `ExecuteReader/NonQuery/Scalar`,
  Enterprise Library `db.ExecuteDataSet(CommandType.Text, sql)`,
  EF `SqlQuery`/`ExecuteSqlCommand`/`FromSqlRaw` with concatenation.
- **Classic ASP**: `conn.Execute`, `rs.Open sql, conn`, `cmd.CommandText`.
- **Perl**: `$dbh->do`, `$dbh->prepare` (with interpolated SQL),
  `selectall_arrayref`, `selectrow_*`.
- **ColdFusion**: `<cfquery>` body, `queryExecute("..." & x)`.
- **Node**: `connection.query`, `pool.query`, `sequelize.query`,
  `knex.raw`, `db.collection(...).find/aggregate/$where`.
- **Python**: `cursor.execute`, `executemany`, `engine.execute`,
  `Model.objects.raw`, `extra(where=...)`.
- **Ruby**: `find_by_sql`, `where("...#{}")`, `order(params[:sort])`,
  `connection.execute`.
- **NoSQL**: MongoDB `$where`, `mapReduce`, `$function`, `$accumulator`;
  filters taken directly from request objects; CouchDB/Elastic query strings
  built by concatenation (Elastic `query_string` with raw input).

## 3. Sanitizers that are / are not enough

| Defence | Enough? | Notes |
|---|---|---|
| Bound parameters (`?`, `:name`, `@p`, `#{}` in MyBatis, `cfqueryparam`) | Yes | Only if **every** dynamic value is bound. |
| Integer cast (`(int)`, `intval`, `Integer.parseInt`, `CLng` after `IsNumeric`, `int.Parse`) | Yes for numeric context | Check failure handling; `IsNumeric` in VBScript accepts `1e5`, `&H10` — still numeric, low risk. |
| Allow-list for identifiers / sort / direction | Yes | Must be exact match (`switch`/`case`, `in_array(..., true)`, `Set.contains`, Enum parse, or MyBatis `<choose><when>` with static SQL), not substring "contains". |
| `mysql_real_escape_string` / `mysqli_real_escape_string` | Only inside quotes | Unquoted numeric context (`WHERE id = $id`) stays injectable. Charset issues with GBK/SJIS if `SET NAMES` used instead of `set_charset`. |
| `addslashes` | No (weak) | Multibyte bypass with SJIS/GBK — relevant for Japanese legacy systems. |
| `Replace(x, "'", "''")` (ASP/VB/C#) | Only inside quotes, and only for string context | Numeric context injectable. |
| `htmlspecialchars`, `strip_tags`, `Server.HTMLEncode` | No | Wrong context. |
| Regex "no quotes" / blacklist (`select`, `union`) | No | Treat as unsanitized; mention in notes. |
| `magic_quotes_gpc` | No | Removed in PHP 5.4; never rely on it. |
| ORM entity methods (`find($id)`, `Where(x => x.Id == id)`) | Yes | Not raw. |

## 4. NoSQL specifics

- **Operator injection**: PHP turns `?user[$ne]=x` into an array;
  `$coll->find(['user' => $_GET['user']])` then matches everything.
  Node: `find({user: req.body.user})` with JSON body `{"user": {"$ne": null}}`.
  Fix: cast to string / validate type, or reject objects.
- **JavaScript execution**: `$where: "this.owner == '" + x + "'"`. Use the §5 table, minimum `high`.
- **Aggregation**: `$lookup`/`$match` stages built from request JSON.
- **Regex**: `{$regex: input}` → data enumeration / ReDoS. Medium.

## 5. Severity guide (injection)

| Situation | Severity |
|---|---|
| Reachable without login, tainted, no sanitizer | critical |
| Reachable after login (any user), tainted, no sanitizer | high (critical only if the repo shows the DB account is admin / `sa` / `root`) |
| Reachable only by admin role, or second-order | medium |
| Dynamic identifier (`ORDER BY ${sort}`) with no allow-list | high (if reachable by normal user) or medium (if constrained context) |
| Dynamic identifier with partial validation; regex/ReDoS | medium / low |
| Query is executed, but the code path is not reachable from HTTP today (dead page, internal batch) | low |

A string that is built but **never sent to any sink** is not a finding: verdict `not_a_query`, reason "built but never executed".

## 6. False-positive traps

- String concatenation of **constants only** (`"SELECT * FROM " . TABLE_NAME`).
- Value cast to int earlier, in another function. Trace the caller.
- Dynamic `ORDER BY` or column name strictly mapped through a hardcoded
  `switch`/`case`, `in_array($sort, ['id', 'date'], true)`, Enum, or static
  MyBatis `<choose><when>` block.
- Prepared statement where only placeholders are concatenated
  (`"IN (" + String.join(",", Collections.nCopies(n, "?")) + ")"`) — safe if
  values are bound afterwards.
- Log or error messages that contain SQL keywords.
- MyBatis `#{}` (safe) vs `${}` (unsafe) — do not confuse.
- Session-only values (`$_SESSION['uid']` set by the server at login) — not
  attacker-controlled, but note if the session value itself came from an
  unvalidated request earlier.
- Code that builds SQL for a **different** DB used only offline (report
  generation scripts not reachable from HTTP) — low, not critical.
