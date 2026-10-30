namespace Komagu.Security.Identity;

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

/// <summary>
/// Service collection extension methods for configuring Komagu OIDC / JWT authentication.
/// </summary>
public static class OidcServiceCollectionExtensions
{
    /// <summary>
    /// Configures strict JWT Bearer token authentication conforming to RFC 9700 and Boilerplate 1 standards.
    /// </summary>
    public static AuthenticationBuilder AddKomaguJwtAuthentication(
        this IServiceCollection services,
        Action<KomaguOidcOptions> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        var options = new KomaguOidcOptions();
        configureOptions(options);

        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            throw new ArgumentException("KomaguOidcOptions.Issuer is required.", nameof(configureOptions));
        }

        return services.AddAuthentication(authOptions =>
        {
            authOptions.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            authOptions.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(jwtOptions =>
        {
            jwtOptions.Authority = options.Issuer;
            jwtOptions.Audience = options.Audience;
            jwtOptions.RequireHttpsMetadata = options.RequireHttpsMetadata;

            if (!string.IsNullOrWhiteSpace(options.MetadataAddress))
            {
                jwtOptions.MetadataAddress = options.MetadataAddress;
            }

            var tokenValidationParams = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = options.Issuer,

                ValidateAudience = true,
                ValidAudience = options.Audience,

                ValidateLifetime = true,
                ClockSkew = options.ClockSkew,

                ValidateIssuerSigningKey = true,
                RequireSignedTokens = true,

                NameClaimType = options.UserClaimType,
                RoleClaimType = ClaimTypes.Role
            };

            if (options.IssuerSigningKeys != null)
            {
                tokenValidationParams.IssuerSigningKeys = options.IssuerSigningKeys;
            }

            jwtOptions.TokenValidationParameters = tokenValidationParams;

            jwtOptions.Events = new JwtBearerEvents
            {
                OnAuthenticationFailed = context =>
                {
                    var logger = context.HttpContext.RequestServices.GetService<ILoggerFactory>()
                        ?.CreateLogger("Komagu.Security.Identity.Authentication");

                    logger?.LogWarning(
                        context.Exception,
                        "[AUTH FAILURE] Token validation failed: {Message} | RemoteIP: {RemoteIp}",
                        context.Exception.Message,
                        context.HttpContext.Connection.RemoteIpAddress);

                    return Task.CompletedTask;
                },
                OnChallenge = context =>
                {
                    // Ensure 401 Unauthorized is returned without disclosing internal state
                    context.HandleResponse();
                    context.Response.StatusCode = 401;
                    context.Response.ContentType = "application/json";

                    var errorJson = System.Text.Json.JsonSerializer.Serialize(new
                    {
                        error = "unauthorized",
                        error_description = "A valid OpenID Connect bearer token is required."
                    });

                    return context.Response.WriteAsync(errorJson);
                }
            };
        });
    }
}
