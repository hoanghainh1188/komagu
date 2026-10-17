# Komainu Legacy Remediation Shims (`remediate/legacy_shims/`)

For legacy enterprise systems that cannot immediately migrate to **.NET 8** or **Kotlin / Spring Boot 3** (covered by `remediate/authz`, `remediate/identity`, and `remediate/query`), this directory provides **zero-dependency, drop-in remediation shims** for legacy stacks supported by the LSA kit.

---

## Core Security Invariants

Every legacy shim enforces the same four architectural invariants as Boilerplate 1:

1. **Identity from Server-Side Session Only:** Never trust `user_id` or `company_id` from query strings, POST bodies, or hidden form fields. Always read the authenticated principal from the server-side session (`$_SESSION`, `HttpSession`, `Session("UserID")`).
2. **Two-Way Ownership Binding:** Verify that the requested resource ID (`order_id`, `member_id`, `cart_id`) explicitly belongs to the authenticated session user (`WHERE id = ? AND user_id = ?`).
3. **Deny-by-Default with Immediate Stop (HTTP 404):** When ownership verification fails, immediately return `404 Not Found` (preventing ID enumeration) and terminate execution (`exit`, `return`, `Response.End`, `<cfabort>`) to prevent the **P4 Check-Without-Stop** vulnerability.
4. **Parameterized Queries & Strict Identifier Allow-Lists:** Bind all data values via prepared statements (`PDO`, `PreparedStatement`, `ADODB.Command`, `<cfqueryparam>`) and validate dynamic `ORDER BY` / table / column identifiers against an exact-match allow-list.

---

## Available Stack Shims

| Stack | File | Fixes |
|---|---|---|
| **PHP (5.6 – 8.x)** | [`php/komainu_authz_shim.php`](php/komainu_authz_shim.php) | BOLA (`missing_ownership_check`, `check_result_ignored`) & SQLi (`string_concatenation`, `dynamic_identifier`) |
| **Java (Servlet / Struts 1 / JSP / MyBatis)** | [`java/OwnershipEnforcer.java`](java/OwnershipEnforcer.java)<br/>[`java/mybatis-safe-sort-example.xml`](java/mybatis-safe-sort-example.xml) | BOLA in Servlets/Struts Actions & MyBatis `${orderBy}` XML injection |
| **ColdFusion (CFML)** | [`coldfusion/KomainuSecurityShim.cfc`](coldfusion/KomainuSecurityShim.cfc) | Unauthenticated `access="remote"` CFC exposure, missing `<cfqueryparam>`, and BOLA |
| **Classic ASP (VBScript)** | [`classic_asp/check_owner.asp`](classic_asp/check_owner.asp) | BOLA on `member_id` / `cart_id` mutations (`Login != Authorization`) and unparameterized `conn.Execute` |

---

## Running Verification Tests

```bash
python3 remediate/legacy_shims/tests/test_legacy_shims.py
```
