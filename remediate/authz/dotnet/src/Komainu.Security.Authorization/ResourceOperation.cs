namespace Komainu.Security.Authorization;

/// <summary>
/// Supported operations for object-level authorization checks.
/// </summary>
public enum ResourceOperation
{
    /// <summary>
    /// Read or view operation.
    /// </summary>
    Read,

    /// <summary>
    /// Create or insert operation.
    /// </summary>
    Create,

    /// <summary>
    /// Update or mutate operation.
    /// </summary>
    Update,

    /// <summary>
    /// Delete or purge operation.
    /// </summary>
    Delete
}
