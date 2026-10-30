namespace Komagu.Security.EntityFrameworkCore;

using System.Linq;
using Komagu.Security.Authorization;

/// <summary>
/// EF Core LINQ query extension methods enforcing tenant and user isolation boundaries at query compilation.
/// </summary>
public static class ScopedQueryExtensions
{
    /// <summary>
    /// Appends tenant and user ownership predicate to the query pipeline.
    /// Only records matching both currentTenantId and currentUserId will be retrieved.
    /// </summary>
    public static IQueryable<T> WithUserScope<T, TKey>(
        this IQueryable<T> query,
        string currentUserId,
        string currentTenantId) where T : class, IOwnedResource<TKey>
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentException.ThrowIfNullOrWhiteSpace(currentUserId);
        ArgumentException.ThrowIfNullOrWhiteSpace(currentTenantId);

        return query.Where(entity => entity.TenantId == currentTenantId && entity.OwnerUserId == currentUserId);
    }

    /// <summary>
    /// Appends tenant and user ownership predicate to the query pipeline for non-generic IOwnedResource.
    /// </summary>
    public static IQueryable<T> WithUserScope<T>(
        this IQueryable<T> query,
        string currentUserId,
        string currentTenantId) where T : class, IOwnedResource
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentException.ThrowIfNullOrWhiteSpace(currentUserId);
        ArgumentException.ThrowIfNullOrWhiteSpace(currentTenantId);

        return query.Where(entity => entity.TenantId == currentTenantId && entity.OwnerUserId == currentUserId);
    }

    /// <summary>
    /// Appends tenant-level isolation predicate to the query pipeline (e.g. for tenant-wide administrative queries).
    /// </summary>
    public static IQueryable<T> WithTenantScope<T>(
        this IQueryable<T> query,
        string currentTenantId) where T : class, IOwnedResource
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentException.ThrowIfNullOrWhiteSpace(currentTenantId);

        return query.Where(entity => entity.TenantId == currentTenantId);
    }
}
