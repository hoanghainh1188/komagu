# Migrating to Komagu 2.0

Komagu 1.x kept some identifiers under the old name "Komainu", because systems outside this repository match on them ([ADR-0007](adr/0007-rename-to-komagu.md)). 2.0 renames all of them at once and removes the 1.x compatibility shims (#312). Use this guide to update suppressions, alerts, tokens and deployed infrastructure before you upgrade.

## Old → new

| Identifier | 1.x | 2.0 | Transition |
|---|---|---|---|
| SARIF rule IDs (`komagu scan`, DevSecOps pipeline, remediator) | `KOMAINU-BOLA-CWE639`, `KOMAINU-INJ-CWE89`, `KOMAINU-SCA-*`, `KOMAINU-SECRET-001`, `KOMAINU-CONTAINER-001` | `KOMAGU-*` (same suffixes) | Hard rename in output. `komagu test --from-scan` / `--export-poc` still read `KOMAINU-*` from a 1.x SARIF file |
| Roslyn analyzer ID | `KOMAINU001` | `KOMAGU001` | Hard rename |
| detekt rule set | `komainu-security` | `komagu-security` | Hard rename |
| SARIF fingerprint key | `partialFingerprints["komainu/v1"]` | `partialFingerprints["komagu/v1"]` | Dual-read: `--baseline` still reads `komainu/v1` from a 1.x SARIF file during 2.x |
| Adapter `contract.json` generator | `komainu-lsa` | `komagu-lsa` | Dual-read: the generic adapter still rebuilds a 1.x contract |
| `AGENTS.md` managed block markers | `<!-- komainu-lsa:begin … -->` / `<!-- komainu-lsa:end -->` | `<!-- komagu-lsa:begin … -->` / `<!-- komagu-lsa:end -->` | Dual-read: the Codex adapter replaces a 1.x block in place |
| Audit event name (authz .NET, Spring, Python, Node.js, Go) | `Komainu.Authorization.Denied` | `Komagu.Authorization.Denied` | Hard rename |
| Python audit logger | `komainu.security.audit` | `komagu.security.audit` | Hard rename |
| Coraza / ModSecurity rule tags | `komainu-sqli`, `komainu-xss`, `komainu-path-traversal`, `komainu-virtual-patch`, `komainu-bola` | `komagu-*` | Hard rename |
| ColdFusion exception types | `Komainu.InvalidId`, `Komainu.DisallowedIdentifier`, `Komainu.InvalidIdentifier`, `Komainu.AccessDenied` | `Komagu.*` | Hard rename |
| Default token audience (identity .NET, Spring, Python; Keycloak test realm) | `komainu-api` | `komagu-api` | Hard rename; the audience stays configurable |
| PostgreSQL application role | `komainu_app` | `komagu_app` | Hard rename |
| Terraform `project_name` default | `komainu` | `komagu` | Hard rename; pin the old value to keep resources (see below) |
| BOLA patcher already-fixed marker | `[KOMAINU-FIX]` | none | Still read. Nothing has written it since #216, so files patched before then are still skipped |

Why most of these are hard renames: Komagu emits them, and your systems match on them. Only you can update those matchers, and keeping two names alive in emitted output would double every alert and suppression. Dual-read is kept only where Komagu reads its own earlier output back.

## Removed compatibility shims

| Removed | Use instead |
|---|---|
| npm bins `komainu`, `komainu-guard` (`bin/komainu-legacy.js`) and `bin/komainu` | `komagu` (`npx @hoanghainh/komagu`, `bin/komagu`) |
| `KOMAINU_*` environment variables (CLI and the remediate Python modules) | `KOMAGU_*`. Old names are now ignored without a warning, so check deployments: `env \| grep ^KOMAINU_` |
| `komainu.security.*` Spring properties and `KOMAINU_SECURITY_*` env vars (`LegacyKomainuPropertiesPostProcessor`) | `komagu.security.*` / `KOMAGU_SECURITY_*` |
| `TARGET/.komainu/suppressions.json` fallback in `komagu scan` | `TARGET/.komagu/suppressions.json` |
| `komainu-out/`, `.komainu-devsecops/` lookup in `komagu fix` | `komagu-out/`, `.komagu-devsecops/`, or `--findings PATH` |
| `komainu-guard` import detection in the BOLA patcher | Files that import from `@hoanghainh/komagu` are detected; update old imports first |

## Steps

### 1. Suppressions and baselines

- Replace `KOMAINU-` with `KOMAGU-` in SARIF-based suppressions, policy files and dashboards.
- .NET: replace `KOMAINU001` in `#pragma warning disable`, `[SuppressMessage]` and `.editorconfig` (`dotnet_diagnostic.KOMAINU001.severity` → `dotnet_diagnostic.KOMAGU001.severity`).
- Kotlin: replace `komainu-security` in `detekt.yml` and in `@Suppress("komainu-security:…")`.
- `.komagu/suppressions.json` entries match on the `kfp1:` fingerprint value, which does not change. Only move a `.komainu/suppressions.json` file to `.komagu/`.
- An existing `--baseline` (`baseline.json` or a 1.x SARIF file) keeps working during 2.x. Regenerate it with `--update-baseline` once, so it is still read after the `komainu/v1` fallback is removed.

### 2. GitHub code scanning

Code scanning identifies alerts by rule ID and fingerprint, so after the first 2.0 upload the old `KOMAINU-*` alerts close as fixed and the same issues reopen as new `KOMAGU-*` alerts. Before you upload:

1. Export or note the dismissed alerts and their reasons: `gh api repos/OWNER/REPO/code-scanning/alerts?state=dismissed`.
2. Upload the 2.0 SARIF, then dismiss the matching `KOMAGU-*` alerts again with the same reason.

### 3. SIEM and WAF alerts

Update every query that matches the old names. Run the old and new terms side by side until no 1.x deployment is left:

```text
# Before
event.name:"Komainu.Authorization.Denied" OR log.logger:"komainu.security.audit"
# During the rollout
event.name:("Komainu.Authorization.Denied" OR "Komagu.Authorization.Denied")
# Coraza / ModSecurity audit log
tag:komainu-*  →  tag:komagu-*
```

### 4. Tokens (audience)

If you used the default audience, issued tokens carry `aud: komainu-api` and the 2.0 validators reject them with 401. Either:

- keep the old value explicitly: `KomaguOidcOptions.Audience = "komainu-api"` (.NET), `komagu.security.oidc.audience=komainu-api` (Spring), `audience="komainu-api"` (Python); or
- add a `komagu-api` client or audience mapper in the identity provider, issue tokens for both audiences, deploy 2.0, then remove `komainu-api` once old tokens have expired.

### 5. PostgreSQL role

`rls_isolation.sql` and `schema_per_tenant.sql` now grant to `komagu_app`. On an existing database, rename the role before you re-run the scripts. Grants, RLS policies and default privileges follow the role:

```sql
ALTER ROLE komainu_app RENAME TO komagu_app;
-- Renaming clears an MD5 password; set it again from your vault:
ALTER ROLE komagu_app WITH LOGIN PASSWORD '...';
```

Then update the application's connection user (`DATABASE_URL`, connection-string secrets).

### 6. Terraform

`project_name` is part of the resource names (VPCs, security groups, ECS clusters, S3 buckets). If the default changes, Terraform replaces those resources. A `moved` block cannot help, because the resource addresses stay the same and only attribute values change. To keep existing infrastructure, pin the old value:

```hcl
# terraform.tfvars
project_name = "komainu"
```

Use the new default only for new environments, or when you plan a recreation (for example a DR rebuild). Then compare `terraform plan` output before you apply. The DR runbook now uses `komagu-production-standby-dr-cluster` and `osaka-dr-alb.komagu.internal`; adjust it if you pinned the old name.

### 7. ColdFusion

Update `cfcatch` blocks that match on type:

```cfml
<cfcatch type="Komainu.AccessDenied">  →  <cfcatch type="Komagu.AccessDenied">
```

### 8. Environment variables and Spring properties

Rename every `KOMAINU_*` variable to `KOMAGU_*` and every `komainu.security.*` property to `komagu.security.*`. In 2.0 the old names are ignored, so a missing rename falls back to the default value. For secrets such as `KOMAGU_AUDIT_HMAC_KEY` and `KOMAGU_JWT_SECRET`, this means startup fails or a generated value is used.
