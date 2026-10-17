# Komainu OpenID Connect (OIDC) Authentication Integration (D2)

The **Komainu OIDC Authentication Integration** implements **Layer 3: Authentication** in the 5-layer STRIDE defense model of Boilerplate 1.

It provides standardized, production-grade JWT access token validation conforming strictly to **RFC 9700** and the **OAuth 2.1 draft** (Authorization Code Flow with PKCE only) across both **.NET 8** and **Spring Boot 3**.

---

## 1. Security Invariants & Acceptance Criteria

Every incoming request bearing an access token is validated against 5 mandatory security rules:

| Security Rule | Description | Denial Outcome |
|---|---|---|
| **Missing Token** | No `Authorization: Bearer <token>` header supplied. | **HTTP 401 Unauthorized** |
| **Token Expiry** | Current timestamp > `exp` claim (`ClockSkew` enforced to 0s or strict delta). | **HTTP 401 Unauthorized** |
| **Issuer Validation** | Token `iss` claim does not match configured trusted IdP authority. | **HTTP 401 Unauthorized** |
| **Audience Validation** | Token `aud` claim does not include the target resource server ID (`komainu-api`). | **HTTP 401 Unauthorized** |
| **Cryptographic Signature** | Token signed by untrusted key or payload tampered with. | **HTTP 401 Unauthorized** |

---

## 2. Local Keycloak Test Environment (`test-env/`)

A pre-configured Keycloak 24+ environment is included in `remediate/identity/test-env/`:

### Starting the Keycloak Dev Container

```bash
cd remediate/identity/test-env
docker compose up -d
```

Keycloak starts at `http://localhost:8080` with the `komainu` realm pre-loaded:
- **Admin Console:** `http://localhost:8080/admin` (Username: `admin`, Password: `admin`)
- **Realm Discovery URL:** `http://localhost:8080/realms/komainu/.well-known/openid-configuration`
- **Clients:**
  - `komainu-portal`: Public SPA client (Standard Flow + PKCE enforced)
  - `komainu-api`: Resource server bearer-only client (`aud`: `komainu-api`)
- **Test Personas:**
  - `alice` (Password: `password123`, Tenant: `tenant-alpha`, Role: `Member`)
  - `bob` (Password: `password123`, Tenant: `tenant-alpha`, Role: `Member`)
  - `charlie` (Password: `password123`, Tenant: `tenant-beta`, Role: `Member`)

---

## 3. .NET 8 (C#) Usage

### Installation & Configuration

In `Program.cs`:

```csharp
using Komainu.Security.Identity;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddKomainuJwtAuthentication(options =>
{
    options.Issuer = builder.Configuration["Authentication:Issuer"] ?? "https://auth.komainu.test/realms/komainu";
    options.Audience = "komainu-api";
    options.RequireHttpsMetadata = builder.Environment.IsProduction();
    options.ClockSkew = TimeSpan.Zero;
});

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
```

---

## 4. Spring Boot 3 (Kotlin) Usage

### Configuration (`application.yml`)

```yaml
komainu:
  security:
    oidc:
      issuer: "https://auth.komainu.test/realms/komainu"
      audience: "komainu-api"
      jwk-set-uri: "https://auth.komainu.test/realms/komainu/protocol/openid-connect/certs"
      clock-skew-seconds: 0
```

The auto-configuration registers:
1. `KomainuAudienceValidator`: Enforces `aud == komainu-api`.
2. `KomainuJwtAuthenticationConverter`: Maps `sub` to principal and `tenant_id` claim to authentication details.
3. Stateless `SecurityFilterChain` permitting public endpoints and enforcing authentication on all other APIs.

---

## 5. Automated Verification

Both test suites verify all 6 acceptance criteria scenarios:

```bash
# .NET 8 (6 tests)
dotnet test remediate/identity/dotnet/Komainu.Security.Identity.slnx

# Spring Boot 3 (6 tests)
gradle -p remediate/identity/spring test
```
