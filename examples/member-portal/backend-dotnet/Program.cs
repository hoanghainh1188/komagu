using MemberPortal.Backend.Auth;
using MemberPortal.Backend.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
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
