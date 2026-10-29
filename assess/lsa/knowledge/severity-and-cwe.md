# Severity, Confidence and Classification

## Severity levels

`critical` > `high` > `medium` > `low` > `info`

Use the category tables in `bola-patterns.md` §6 and
`injection-patterns.md` §5. Then adjust:

- **+1 level** (max critical): no authentication needed; affects all tenants;
  exposes credentials or payment data.
- **−1 level** (min low): reachable only by an enforced admin role in a
  single-tenant system; strong compensating control outside code that you can
  cite (and it is in `auth-model.md`).
- Never lower severity because "IDs are hard to guess".

## Confidence

See `_shared-rules.md` §4. Severity and confidence are independent: a
`critical` finding can be `low` confidence. Reviewers sort by both.

## Classification map

| category | subtype examples | CWE | OWASP |
|---|---|---|---|
| `bola` | missing_ownership_check, parent_checked_child_not, check_result_ignored | CWE-639, CWE-862 | API1:2023, A01:2021 |
| `bola` | id_from_request_used_as_identity | CWE-639, CWE-566 | API1:2023 |
| `bola` | no_authentication | CWE-306, CWE-639 | API1:2023, API2:2023 |
| `bola` | ownership_check_bypassable | CWE-639, CWE-863 | API1:2023 |
| `bola` | missing_role_check (legacy; new findings use `bfla`) | CWE-285 | API5:2023 |
| `bfla` | missing_role_check (privileged function open to lower roles) | CWE-285 | API5:2023, A01:2021 |
| `bfla` | role_from_request (role or admin flag read from request input) | CWE-269, CWE-285 | API5:2023 |
| `bfla` | client_side_role_check (check only hides a menu, link or button) | CWE-602, CWE-285 | API5:2023 |
| `mass_assignment` | whole_object_binding (request body bound to a model without an allow-list) | CWE-915 | API3:2023, A01:2021 |
| `mass_assignment` | privileged_field_writable (role, owner, tenant, price or status writable by the caller) | CWE-915, CWE-269 | API3:2023 |
| `sql_injection` | string_concatenation, string_interpolation, format_string, template_placeholder, dynamic_identifier, second_order, stored_procedure_dynamic_sql | CWE-89 | A03:2021 |
| `sql_injection` | (HQL/JPQL) | CWE-564, CWE-89 | A03:2021 |
| `nosql_injection` | operator_injection, js_injection | CWE-943 | A03:2021 |

Finding id prefixes: `BOLA-`, `INJ-`, `BFLA-`, `MASS-`.

## Fingerprint

`fingerprint` is optional. When present it has the form `kfp1:<64 lowercase hex>`
and must not depend on line numbers, so the same issue keeps the same value
across scans. Exporters copy it to SARIF `partialFingerprints["komainu/v1"]`.

## SARIF level mapping

| severity | SARIF `level` | `security-severity` |
|---|---|---|
| critical | error | 9.5 |
| high | error | 8.0 |
| medium | warning | 5.5 |
| low | note | 3.0 |
| info | note | 1.0 |
