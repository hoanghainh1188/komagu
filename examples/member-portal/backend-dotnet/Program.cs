using System.Security.Claims;
using System.Text.Encodings.Web;
using MemberPortal.Backend.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Komagu.Security.Authorization;

var builder = WebApplication.CreateBuilder(args);

// Add Database Context with SQLite
builder.Services.AddDbContext<PortalDbContext>(options =>
{
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") 
        ?? "Data Source=member_portal.db";
    options.UseSqlite(connectionString);
});

// Register Komagu D1 Authorization Service
builder.Services.AddScoped<ISecurityAuditSink, LoggingSecurityAuditSink>();
builder.Services.AddScoped<IKomaguAuthorizationService, DefaultKomaguAuthorizationService>();

// Configure Authentication (Demo Mock + OIDC claims mapping)
builder.Services.AddAuthentication("DemoAuth")
    .AddScheme<AuthenticationSchemeOptions, DemoAuthenticationHandler>("DemoAuth", _ => { });

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

// Ensure SQLite database and seed records are created
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<PortalDbContext>();
    db.Database.EnsureCreated();
}

app.UseCors("AllowAll");
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

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
