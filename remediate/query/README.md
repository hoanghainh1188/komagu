# Komainu Safe Query Helpers & Linters (D3)

The **Komainu Safe Query Helpers & Linters** component implements **Layer 5: Scoped Database Access & Safe Query Construction** in the 5-layer STRIDE defense model of Boilerplate 1.

It combines **runtime defensive helpers** (allow-lists for dynamic sorting and column names) with **compile-time / build-time static linters** (Roslyn Analyzer for C# and detekt rule for Kotlin) to eliminate SQL/JPQL injection (**CWE-89**) by design.

---

## 1. Runtime Safe Query Helpers

### Dynamic Sort & Column Name Allow-Listing

Dynamic `ORDER BY` clauses cannot be parameterized using standard database query bindings. To prevent SQL injection through sort parameters, applications must validate requested column names against an explicit allow-list.

#### .NET 8 (C#)
```csharp
using Komainu.Security.Query;

// Define allowed sort columns
var allowList = new SafeSortAllowList(new[] { "id", "created_at", "total_amount", "status" });

// Validates column and builds safe clause: "created_at DESC"
// Throws SecurityException if malicious characters (e.g. "id; DROP TABLE--") or unapproved columns are passed
string safeOrderBy = allowList.BuildSortClause(userInputColumn, SortDirection.Descending);
```

#### Spring Boot 3 (Kotlin)
```kotlin
import io.komagu.security.query.SafeSortAllowList

val allowList = SafeSortAllowList(listOf("id", "created_at", "total_amount", "status"))

// Throws SecurityException if column contains special characters or is not whitelisted
val safeClause = allowList.buildSortClause(userInputColumn, "DESC")
```

---

## 2. Static Analysis Linters (Shift-Left Security)

### Roslyn Diagnostic Analyzer (.NET / C#)

The `Komainu.Security.Query.Analyzers` package inspects syntax trees during build time and inside the IDE to flag any string concatenation or string interpolation passed into raw SQL query methods:

- **Diagnostic ID:** `KOMAINU001`
- **Severity:** `Warning` / `Error`
- **Target APIs:** `FromSqlRaw`, `ExecuteSqlRaw`, `ExecuteSqlRawAsync`, `SqlQueryRaw`, `Query`, `Execute`.

#### Flagged Unsafe Code (Compile Warning):
```csharp
// Unsafe: String concatenation
dbContext.Orders.FromSqlRaw("SELECT * FROM orders WHERE id = " + orderId);

// Unsafe: String interpolation
dbContext.Orders.FromSqlRaw($"SELECT * FROM orders WHERE id = {orderId}");
```

#### Approved Safe Code:
```csharp
// Safe: Parameterized query
dbContext.Orders.FromSqlRaw("SELECT * FROM orders WHERE id = @id", new SqlParameter("@id", orderId));

// Safe: EF Core FormattableString interpolation (automatically parameterized)
dbContext.Orders.FromSqlInterpolated($"SELECT * FROM orders WHERE id = {orderId}");
```

---

### detekt Custom Rule (Kotlin / Spring)

The `komagu-security-query` module provides the custom detekt rule `StringBuiltSqlQueryRule`:

- **Rule ID:** `StringBuiltSqlQuery`
- **RuleSet:** `komainu-security`
- **Severity:** `Security` / `Debt.FIVE_MINS`
- **Target APIs:** `em.createQuery`, `em.createNativeQuery`, `jdbcTemplate.query`, `jdbcClient.sql`.

#### Flagged Unsafe Code:
```kotlin
// Unsafe: String concatenation
em.createQuery("SELECT o FROM Order o WHERE o.id = " + orderId)

// Unsafe: String template interpolation
em.createNativeQuery("SELECT * FROM orders WHERE id = $orderId")
```

#### Approved Safe Code:
```kotlin
// Safe: Parameterized query with bound variable
em.createQuery("SELECT o FROM Order o WHERE o.id = :orderId")
    .setParameter("orderId", orderId)
```

---

## 3. Automated Verification

Run both test suites:

- **.NET 8 Tests (18 tests):**
  ```bash
  dotnet test remediate/query/dotnet/Komainu.Security.Query.slnx
  ```
- **Spring Boot 3 Tests (8 tests):**
  ```bash
  gradle -p remediate/query/spring test
  ```
