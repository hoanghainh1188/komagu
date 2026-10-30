# ADR-0007: Rename the product from Komainu to Komagu

Date: 2026-10-30 · Status: accepted; applied in #291–#295, #301 · Owner: Harry · Supersedes the name in [ADR-0001](0001-name-and-repository-structure.md)

## Context

"Komainu" collides with existing names in the security space:

- **Komainu** (komainu.com), a regulated digital-asset custody and security company backed by
  Nomura, Ledger and CoinShares. Our `Komainu.Security.*` namespaces made confusion likely.
- **npm `komainu`**, an unrelated Express security middleware by another maintainer. Our
  `komainu` CLI binary shared its name.

`komagu` was free on npm, PyPI, NuGet and crates.io at the time of the decision. This is a
name-collision check, not legal advice; a formal trademark search is still recommended before
a public launch. The lifecycle structure from ADR-0001 is unchanged.

## Decision

| Item | Before | After |
|---|---|---|
| Product / repository | Komainu, `hoanghainh1188/komainu` | Komagu, `hoanghainh1188/komagu` |
| npm package / CLI | `komainu-guard` / `komainu`, `komainu-guard` | `@hoanghainh/komagu` / `komagu` |
| .NET | `Komainu.Security.*` | `Komagu.Security.*` |
| Java / Kotlin | `io.komainu`, `komainu.security.oidc.*` | `io.komagu`, `komagu.security.oidc.*` |
| Python | `komainu_authz`, `komainu_identity` | `komagu_authz`, `komagu_identity` |
| Env vars | `KOMAINU_*` | `KOMAGU_*` |
| Docker image | `ghcr.io/hoanghainh1188/komainu` | `ghcr.io/hoanghainh1188/komagu` |

### Compatibility until the next major release

- The `komainu` and `komainu-guard` binaries still run and print a deprecation notice.
- `KOMAINU_*` env vars, `komainu.security.*` Spring properties and `.komainu/suppressions.json`
  are still read, with a warning. `KOMAGU_*` values win when both are set.
- `komagu fix` still finds results in the old `komainu-out/` and `.komainu-devsecops/` folders.

### Identifiers kept as they are

These are matched by systems outside this repository. Changing them would silently break
suppressions, alerts, tokens or deployed infrastructure, so they keep the old name:

| Identifier | Matched by |
|---|---|
| Rule IDs `KOMAINU-*`, Roslyn analyzer `KOMAINU001`, detekt rule set `komainu-security` | Suppressions, baselines, `.editorconfig`, `@Suppress` |
| SARIF fingerprint key `komainu/v1` | GitHub code-scanning alert history |
| `komainu-lsa` generator value and `AGENTS.md` markers | Re-running the adapter builder on a client workspace |
| Audit event `Komainu.Authorization.Denied`, logger `komainu.security.audit`, Coraza tags `komainu-*` | SIEM and WAF log alerts |
| ColdFusion exception types `Komainu.*` | `cfcatch` blocks in client code |
| Default token audience `komainu-api` | Tokens already issued |
| PostgreSQL role `komainu_app`, Terraform `project` default `komainu` | Deployed databases and cloud resources |
| `[KOMAINU-FIX]` marker | The patcher's own already-fixed check |

## Consequences

- Consumers of the .NET, Kotlin, Python, Go, Node.js and legacy-shim modules must update
  imports and package coordinates. None of these were published to a package registry.
- The kept identifiers are listed in one place, so a later major release can rename them
  together with a migration note.
- `CHANGELOG.md` history and `delivery/pilot/` records keep the old name and URLs; GitHub
  redirects the old repository URL.
