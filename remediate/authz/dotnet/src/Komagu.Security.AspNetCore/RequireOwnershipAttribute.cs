namespace Komagu.Security.AspNetCore;

using Komagu.Security.Authorization;
using Microsoft.AspNetCore.Mvc;

/// <summary>
/// Declarative attribute to enforce object ownership at the controller action boundary.
/// Automatically returns HTTP 404 Not Found on ownership or tenant mismatch to eliminate ID enumeration.
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false, Inherited = true)]
public sealed class RequireOwnershipAttribute : TypeFilterAttribute
{
    public RequireOwnershipAttribute(
        Type resourceType,
        string idRouteParameter = "id",
        ResourceOperation operation = ResourceOperation.Read)
        : base(typeof(OwnershipAuthorizationFilter))
    {
        Arguments = new object[] { resourceType, idRouteParameter, operation };
    }
}
