namespace Komainu.Security.Authorization;

/// <summary>
/// Encapsulates the evaluation outcome of an object-level authorization check.
/// </summary>
public record AuthorizationResult(bool Succeeded, string? FailureReason = null)
{
    /// <summary>
    /// Factory method for successful authorization decision.
    /// </summary>
    public static AuthorizationResult Success() => new(true);

    /// <summary>
    /// Factory method for denied authorization decision with failure rationale.
    /// </summary>
    public static AuthorizationResult Denied(string reason) => new(false, reason);
}
