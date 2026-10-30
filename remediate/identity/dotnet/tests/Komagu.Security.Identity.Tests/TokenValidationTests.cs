namespace Komagu.Security.Identity.Tests;

using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

public class TokenValidationTests : IDisposable
{
    private const string ExpectedIssuer = "https://auth.komagu.test/realms/komagu";
    private const string ExpectedAudience = "komainu-api";

    private readonly TestTokenGenerator _tokenGenerator;
    private readonly TestServer _server;
    private readonly HttpClient _client;

    public TokenValidationTests()
    {
        _tokenGenerator = new TestTokenGenerator();

        var builder = new WebHostBuilder()
            .ConfigureServices(services =>
            {
                services.AddRouting();
                services.AddAuthorization();

                services.AddKomaguJwtAuthentication(options =>
                {
                    options.Issuer = ExpectedIssuer;
                    options.Audience = ExpectedAudience;
                    options.RequireHttpsMetadata = false;
                    options.ClockSkew = TimeSpan.Zero;
                    options.IssuerSigningKeys = new[] { _tokenGenerator.SigningKey };
                });
            })
            .Configure(app =>
            {
                app.UseRouting();
                app.UseAuthentication();
                app.UseAuthorization();

                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet("/api/test/secure", async context =>
                    {
                        var user = context.User;
                        var sub = user.FindFirst("sub")?.Value;
                        var tenant = user.FindFirst("tenant_id")?.Value;

                        await context.Response.WriteAsJsonAsync(new
                        {
                            status = "authenticated",
                            userId = sub,
                            tenantId = tenant
                        });
                    }).RequireAuthorization();
                });
            });

        _server = new TestServer(builder);
        _client = _server.CreateClient();
    }

    [Fact]
    public async Task Request_WithValidToken_Returns200OkAndIdentifiesUser()
    {
        // Arrange
        var token = _tokenGenerator.GenerateToken(
            issuer: ExpectedIssuer,
            audience: ExpectedAudience,
            userId: "user-alice",
            tenantId: "tenant-alpha");

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/test/secure");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Act
        var response = await _client.SendAsync(request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Request_WithMissingToken_Returns401Unauthorized()
    {
        // Arrange: No Authorization header provided
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/test/secure");

        // Act
        var response = await _client.SendAsync(request);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Request_WithExpiredToken_Returns401Unauthorized()
    {
        // Arrange: Token expired 10 minutes ago
        var expiredToken = _tokenGenerator.GenerateToken(
            issuer: ExpectedIssuer,
            audience: ExpectedAudience,
            expires: DateTime.UtcNow.AddMinutes(-10));

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/test/secure");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", expiredToken);

        // Act
        var response = await _client.SendAsync(request);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Request_WithWrongIssuer_Returns401Unauthorized()
    {
        // Arrange: Token signed by legitimate key but claims an untrusted issuer
        var wrongIssuerToken = _tokenGenerator.GenerateToken(
            issuer: "https://evil-idp.attacker.test/realms/evil",
            audience: ExpectedAudience);

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/test/secure");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", wrongIssuerToken);

        // Act
        var response = await _client.SendAsync(request);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Request_WithWrongAudience_Returns401Unauthorized()
    {
        // Arrange: Token issued for another client/audience
        var wrongAudienceToken = _tokenGenerator.GenerateToken(
            issuer: ExpectedIssuer,
            audience: "some-other-service-api");

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/test/secure");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", wrongAudienceToken);

        // Act
        var response = await _client.SendAsync(request);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Request_WithBadSignature_Returns401Unauthorized()
    {
        // Arrange: Token signed by an attacker's rogue key pair
        using var rogueRsa = RSA.Create(2048);
        var rogueKey = new RsaSecurityKey(rogueRsa);

        var forgedToken = _tokenGenerator.GenerateToken(
            issuer: ExpectedIssuer,
            audience: ExpectedAudience,
            customSigningKey: rogueKey);

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/test/secure");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", forgedToken);

        // Act
        var response = await _client.SendAsync(request);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    public void Dispose()
    {
        _client.Dispose();
        _server.Dispose();
        _tokenGenerator.Dispose();
    }
}
