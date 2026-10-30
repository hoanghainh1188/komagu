# Security scanning in CI

The `Security Scan` workflow (`.github/workflows/security-scan.yml`) runs static
analysis and dependency/CVE scanners and publishes the results to **GitHub code
scanning** (repository → *Security* → *Code scanning*).

## Phase 1: report-only (current)

- Findings **never fail** a build. A scanner that crashes still fails its job,
  so a broken scanner stays visible.
- The workflow runs on pull requests that touch scannable files, on every push to
  `main`, every Monday at 02:17 UTC, and on demand (`workflow_dispatch`).
- SARIF upload is skipped for fork and Dependabot pull requests, because their
  token is read-only. Those PRs still run the scanners.

## Tools and code scanning categories

| Job | Tool | Category | Scope |
|---|---|---|---|
| `python` | Bandit 1.9.4 (medium and above) | `bandit` | All Python, minus exclusions |
| `python` | pip-audit 2.10.1 | job summary only | Every `requirements*.txt` |
| `go` | golangci-lint 2.15.0 (gosec, errcheck, staticcheck, ...) | `golangci-lint` | `remediate/authz/golang` |
| `go` | govulncheck 1.9.0 | `govulncheck` | `remediate/authz/golang` |
| `dotnet` | Roslyn analyzers (`latest-recommended`, security = all) | `roslyn` | `remediate/*/dotnet/src`, member-portal backend |
| `dotnet` | `dotnet list package --vulnerable` | job summary only | Same projects |
| `kotlin` | Detekt 1.23.8 CLI + Komagu `StringBuiltSqlQuery` rule | `detekt` | `remediate/*/spring`, member-portal Spring backend |
| `codeql` | CodeQL `security-extended` | `/language:<lang>` | python, go, csharp, javascript-typescript, actions |
| `trivy` | Trivy 0.76.0 `fs` (vuln, secret, misconfig) | `trivy-fs` | Repository, minus exclusions |
| `trivy` | Trivy 0.76.0 `image` | `trivy-image` | Root `Dockerfile` (not on PRs) |

Notes:

- **Kotlin is not analysed by CodeQL**, because the modules use Kotlin 2.4 and
  CodeQL cannot extract that version yet. Detekt covers Kotlin until it can.
- **Detekt runs as a CLI**, not as a Gradle plugin, because the Detekt 1.x Gradle
  plugin does not support Kotlin 2.4. The Komagu rule set has to be enabled
  explicitly in `config/detekt/detekt.yml`; third-party rule sets are inactive
  by default.
- **The Go scanners use the latest stable Go toolchain.** Stdlib CVEs of
  end-of-life Go releases would otherwise hide real findings.

## Excluded paths

Intentionally vulnerable code is excluded from scanning:

- `assess/lsa/tests/fixtures/`: LSA detector fixtures
- `assess/lsa/examples/`, `delivery/pilot/`: sample audit outputs
- `examples/member-portal/backend-dotnet/Controllers/LegacyTestController.cs`:
  opt-in planted BOLA endpoints of the D6 demo (CodeQL only)

The exclusion lists are kept in `.bandit.yml`, `.github/codeql/codeql-config.yml`
and the Trivy `--skip-dirs` flags in the workflow.

## Handling a finding

1. Fix it, if it is real.
2. If it is a false positive or an accepted risk, suppress it as close to the
   code as possible and give a reason:
   - Python: `# nosec B310  # URL is a fixed http://localhost test endpoint`
   - Go: `//nolint:gosec // reason`
   - C#: `[SuppressMessage("Security", "CAxxxx", Justification = "...")]`
   - Kotlin: `@Suppress("StringBuiltSqlQuery") // reason`
   - Trivy misconfig: an entry in `.trivyignore` with a comment
3. Alternatively, dismiss the alert in the Security tab and select a reason.

## Phase 2: gating (planned)

1. Triage the phase 1 baseline until no High/Critical alerts remain open.
2. Enable the branch protection rule *Require code scanning results* for `main`,
   with the threshold set to *High or higher* for security alerts.
3. Consider removing the `--exit-zero`-style flags for tools that do not
   report to code scanning (pip-audit, NuGet audit).
