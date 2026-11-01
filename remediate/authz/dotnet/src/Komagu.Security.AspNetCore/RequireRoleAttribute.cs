namespace Komagu.Security.AspNetCore;

using Microsoft.AspNetCore.Mvc;

/// <summary>
/// Declarative function-level authorization (BFLA defense): the authenticated caller must hold at least one of the
/// given roles. Roles are read only from verified <c>HttpContext.User</c> claims, never from the request.
/// Returns 401 when unauthenticated and 403 (or 404, see <see cref="KomaguRoleOptions.DenyWith"/>) when denied.
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = true, Inherited = true)]
public sealed class RequireRoleAttribute : TypeFilterAttribute
{
    public RequireRoleAttribute(params string[] roles)
        : base(typeof(RoleAuthorizationFilter))
    {
        if (roles == null || roles.Length == 0)
        {
            throw new ArgumentException("At least one required role must be specified.", nameof(roles));
        }

        if (roles.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("Required roles must not be null, empty or whitespace.", nameof(roles));
        }

        Roles = roles.ToArray();
        Arguments = new object[] { Roles.ToArray() };
    }

    /// <summary>
    /// Roles accepted by this guard; holding any one of them (exact, ordinal match) grants access.
    /// </summary>
    public IReadOnlyList<string> Roles { get; }
}
