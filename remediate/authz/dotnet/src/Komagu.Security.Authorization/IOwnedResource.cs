namespace Komagu.Security.Authorization;

/// <summary>
/// Defines ownership properties required to perform tenant- and user-level authorization.
/// </summary>
/// <typeparam name="TKey">Type of the resource unique identifier.</typeparam>
public interface IOwnedResource<out TKey>
{
    /// <summary>
    /// Unique identifier of the resource.
    /// </summary>
    TKey Id { get; }

    /// <summary>
    /// Subject identifier of the owning user extracted from verified token claims.
    /// </summary>
    string OwnerUserId { get; }

    /// <summary>
    /// Tenant or organization identifier extracted from verified token claims.
    /// </summary>
    string TenantId { get; }
}

/// <summary>
/// Non-generic marker interface for reflection and weakly typed authorization filters.
/// </summary>
public interface IOwnedResource
{
    /// <summary>
    /// Subject identifier of the owning user.
    /// </summary>
    string OwnerUserId { get; }

    /// <summary>
    /// Tenant or organization identifier.
    /// </summary>
    string TenantId { get; }
}
