namespace Komainu.Security.Identity.Tests;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

public sealed class TestTokenGenerator : IDisposable
{
    private readonly RSA _rsa;
    public RsaSecurityKey SigningKey { get; }

    public TestTokenGenerator()
    {
        _rsa = RSA.Create(2048);
        SigningKey = new RsaSecurityKey(_rsa) { KeyId = "komainu-test-key-1" };
    }

    public string GenerateToken(
        string issuer = "https://auth.komainu.test/realms/komainu",
        string audience = "komainu-api",
        string userId = "user-alice",
        string tenantId = "tenant-alpha",
        DateTime? expires = null,
        SecurityKey? customSigningKey = null)
    {
        var keyToUse = customSigningKey ?? SigningKey;
        var credentials = new SigningCredentials(keyToUse, SecurityAlgorithms.RsaSha256);

        var claims = new List<Claim>
        {
            new("sub", userId),
            new("tenant_id", tenantId),
            new("role", "Member")
        };

        var now = DateTime.UtcNow;
        var exp = expires ?? now.AddHours(1);
        var notBefore = exp.AddHours(-1);
        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: notBefore,
            expires: exp,
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public void Dispose()
    {
        _rsa.Dispose();
    }
}
