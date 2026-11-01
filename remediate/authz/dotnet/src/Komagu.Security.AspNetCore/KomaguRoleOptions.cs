namespace Komagu.Security.AspNetCore;

using System.Security.Claims;

/// <summary>
/// Options for <see cref="RequireRoleAttribute"/> / <see cref="RoleAuthorizationFilter"/>.
/// </summary>
public sealed class KomaguRoleOptions
{
    /// <summary>
    /// Claim type read from the authenticated <see cref="ClaimsPrincipal"/> to obtain the caller's roles.
    /// Defaults to <see cref="ClaimTypes.Role"/>; set to <c>"role"</c> or <c>"roles"</c> for raw JWT claims.
    /// </summary>
    public string RoleClaimType { get; set; } = ClaimTypes.Role;

    /// <summary>
    /// Response returned when an authenticated caller lacks every required role. Defaults to 403 Forbidden.
    /// </summary>
    public RoleDenyResponse DenyWith { get; set; } = RoleDenyResponse.Forbidden;
}
