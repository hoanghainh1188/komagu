namespace Komagu.Security.AspNetCore;

/// <summary>
/// HTTP response returned by <see cref="RoleAuthorizationFilter"/> when an authenticated caller lacks every required role.
/// </summary>
public enum RoleDenyResponse
{
    /// <summary>
    /// HTTP 403 Forbidden (default).
    /// </summary>
    Forbidden,

    /// <summary>
    /// HTTP 404 Not Found, hiding the existence of the privileged endpoint.
    /// </summary>
    NotFound
}
