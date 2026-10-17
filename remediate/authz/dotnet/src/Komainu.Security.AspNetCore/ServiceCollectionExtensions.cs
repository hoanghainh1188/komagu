namespace Komainu.Security.AspNetCore;

using Komainu.Security.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

/// <summary>
/// Extension methods for registering Komainu authorization services in ASP.NET Core dependency injection.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds Komainu object-level authorization services to the specified service collection.
    /// </summary>
    public static IServiceCollection AddKomainuAuthorization(this IServiceCollection services)
    {
        services.TryAddSingleton<ISecurityAuditSink, LoggingSecurityAuditSink>();
        services.TryAddScoped<IKomainuAuthorizationService, DefaultKomainuAuthorizationService>();
        return services;
    }

    /// <summary>
    /// Adds Komainu object-level authorization services with a custom security audit sink.
    /// </summary>
    public static IServiceCollection AddKomainuAuthorization<TAuditSink>(this IServiceCollection services)
        where TAuditSink : class, ISecurityAuditSink
    {
        services.AddSingleton<ISecurityAuditSink, TAuditSink>();
        services.TryAddScoped<IKomainuAuthorizationService, DefaultKomainuAuthorizationService>();
        return services;
    }
}
