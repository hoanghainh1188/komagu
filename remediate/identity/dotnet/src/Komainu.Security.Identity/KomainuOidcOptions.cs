namespace Komainu.Security.Identity;

using Microsoft.IdentityModel.Tokens;

/// <summary>
/// Configuration options for Komainu OpenID Connect / JWT bearer token validation.
/// </summary>
public sealed class KomainuOidcOptions
{
    /// <summary>
    /// Expected token issuer URL (e.g. "https://keycloak.example.com/realms/komainu").
    /// </summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// Expected resource server audience identifier (e.g. "komainu-api").
    /// </summary>
    public string Audience { get; set; } = "komainu-api";

    /// <summary>
    /// OIDC well-known configuration endpoint URI.
    /// If null, default discovery URI is inferred from Issuer.
    /// </summary>
    public string? MetadataAddress { get; set; }

    /// <summary>
    /// Whether HTTPS is required for OIDC metadata discovery.
    /// Default is true. Can be set to false in local development / test environments.
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>
    /// Allowed clock drift during token expiration evaluation.
    /// Default is 0 seconds (strict lifetime enforcement).
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.Zero;

    /// <summary>
    /// Optional explicit signing keys (primarily used in local test harnesses).
    /// </summary>
    public IEnumerable<SecurityKey>? IssuerSigningKeys { get; set; }

    /// <summary>
    /// Claim type used to map user subject identifier. Default is "sub".
    /// </summary>
    public string UserClaimType { get; set; } = "sub";

    /// <summary>
    /// Claim type used to map organization tenant identifier. Default is "tenant_id".
    /// </summary>
    public string TenantClaimType { get; set; } = "tenant_id";
}
