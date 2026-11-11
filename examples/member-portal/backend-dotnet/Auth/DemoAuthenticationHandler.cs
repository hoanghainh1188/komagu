namespace MemberPortal.Backend.Auth;

using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

/// <summary>
/// Flexible authentication handler supporting mock tokens for personas as well as JWT claims.
/// </summary>
public class DemoAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public DemoAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var authHeaderValues))
        {
            // Anonymous fallback
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var header = authHeaderValues.ToString();
        var token = header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? header.Substring(7).Trim()
            : header.Trim();

        var claims = token switch
        {
            "token-user-a" => new[]
            {
                new Claim(ClaimTypes.NameIdentifier, "user-a"),
                new Claim("sub", "user-a"),
                new Claim("tenant_id", "tenant-alpha"),
                new Claim("name", "Alice"),
                new Claim(ClaimTypes.Role, "member")
            },
            "token-user-b" => new[]
            {
                new Claim(ClaimTypes.NameIdentifier, "user-b"),
                new Claim("sub", "user-b"),
                new Claim("tenant_id", "tenant-alpha"),
                new Claim("name", "Bob"),
                new Claim(ClaimTypes.Role, "member")
            },
            "token-user-c" => new[]
            {
                new Claim(ClaimTypes.NameIdentifier, "user-c"),
                new Claim("sub", "user-c"),
                new Claim("tenant_id", "tenant-beta"),
                new Claim("name", "Charlie"),
                new Claim(ClaimTypes.Role, "member")
            },
            _ => new[]
            {
                new Claim(ClaimTypes.NameIdentifier, token),
                new Claim("sub", token),
                new Claim("tenant_id", "tenant-alpha"),
                new Claim(ClaimTypes.Role, "member")
            }
        };

        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
