namespace Komagu.Security.AspNetCore;

using Komagu.Security.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

/// <summary>
/// Extension methods for registering Komagu authorization services in ASP.NET Core dependency injection.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds Komagu object-level authorization services to the specified service collection.
    /// </summary>
    public static IServiceCollection AddKomaguAuthorization(this IServiceCollection services)
    {
        services.TryAddSingleton<ISecurityAuditSink, LoggingSecurityAuditSink>();
        services.TryAddScoped<IKomaguAuthorizationService, DefaultKomaguAuthorizationService>();
        services.AddOptions<KomaguRoleOptions>();
        return services;
    }

    /// <summary>
    /// Adds Komagu object-level authorization services with a custom security audit sink.
    /// </summary>
    public static IServiceCollection AddKomaguAuthorization<TAuditSink>(this IServiceCollection services)
        where TAuditSink : class, ISecurityAuditSink
    {
        services.AddSingleton<ISecurityAuditSink, TAuditSink>();
        services.TryAddScoped<IKomaguAuthorizationService, DefaultKomaguAuthorizationService>();
        services.AddOptions<KomaguRoleOptions>();
        return services;
    }

    /// <summary>
    /// Configures the <see cref="RequireRoleAttribute"/> guard (role claim type, 403 vs 404 on denial).
    /// Call after <c>AddKomaguAuthorization</c>.
    /// </summary>
    public static IServiceCollection ConfigureKomaguRoles(
        this IServiceCollection services,
        Action<KomaguRoleOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);
        services.AddOptions<KomaguRoleOptions>().Configure(configure);
        return services;
    }
}
