namespace Komagu.Security.AspNetCore;

/// <summary>
/// Optional resolver interface used by declarative filters to load resources by ID from persistent storage.
/// </summary>
public interface IKomaguResourceResolver
{
    /// <summary>
    /// Resolves a resource entity by its type and string identifier.
    /// </summary>
    ValueTask<object?> ResolveAsync(Type resourceType, string resourceId, CancellationToken cancellationToken = default);
}
