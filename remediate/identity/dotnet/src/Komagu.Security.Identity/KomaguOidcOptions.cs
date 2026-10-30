namespace Komagu.Security.Identity;

using Microsoft.IdentityModel.Tokens;

/// <summary>
/// Configuration options for Komagu OpenID Connect / JWT bearer token validation.
/// </summary>
public sealed class KomaguOidcOptions
{
    /// <summary>
    /// Expected token issuer URL (e.g. "https://keycloak.example.com/realms/komagu").
    /// </summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// Expected resource server audience identifier (e.g. "komagu-api").
    /// The pre-rename default is kept so issued tokens stay valid (#290).
    /// </summary>
    public string Audience { get; set; } = "komagu-api";

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
