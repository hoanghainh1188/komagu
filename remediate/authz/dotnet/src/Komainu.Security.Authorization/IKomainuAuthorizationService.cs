namespace Komainu.Security.Authorization;

using System.Security.Claims;

/// <summary>
/// Primary imperative authorization service for evaluating object-level permissions (BOLA defense).
/// </summary>
public interface IKomainuAuthorizationService
{
    /// <summary>
    /// Evaluates if the current authenticated user owns and can access the given resource.
    /// Emits a structured security audit event on denial.
    /// </summary>
    ValueTask<AuthorizationResult> AuthorizeAsync<T>(
        ClaimsPrincipal user,
        T resource,
        ResourceOperation operation,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Extracts the verified subject user ID from token claims.
    /// Throws UnauthorizedAccessException if missing or invalid.
    /// </summary>
    string GetCurrentUserId(ClaimsPrincipal user);

    /// <summary>
    /// Extracts the verified tenant ID from token claims.
    /// Throws UnauthorizedAccessException if missing or invalid.
    /// </summary>
    string GetCurrentTenantId(ClaimsPrincipal user);
}
