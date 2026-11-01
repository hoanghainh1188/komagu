namespace Komagu.Security.AspNetCore;

using System.Diagnostics;
using Komagu.Security.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;

/// <summary>
/// Authorization filter enforcing that the authenticated caller holds at least one required role.
/// Runs before model binding, so request-supplied values (route, query, form, body, headers) can never grant a role.
/// </summary>
public sealed class RoleAuthorizationFilter : IAsyncAuthorizationFilter
{
    /// <summary>
    /// Audit event name emitted on a role denial.
    /// </summary>
    public const string RoleDeniedEventName = "Komagu.Authorization.RoleDenied";

    private readonly string[] _requiredRoles;
    private readonly ISecurityAuditSink _auditSink;
    private readonly IKomaguAuthorizationService _authorizationService;
    private readonly KomaguRoleOptions _options;

    public RoleAuthorizationFilter(
        string[] requiredRoles,
        ISecurityAuditSink auditSink,
        IKomaguAuthorizationService authorizationService,
        IOptions<KomaguRoleOptions> options)
    {
        ArgumentNullException.ThrowIfNull(requiredRoles);
        if (requiredRoles.Length == 0 || requiredRoles.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("At least one non-empty required role must be specified.", nameof(requiredRoles));
        }

        _requiredRoles = requiredRoles.ToArray();
        _auditSink = auditSink ?? throw new ArgumentNullException(nameof(auditSink));
        _authorizationService = authorizationService ?? throw new ArgumentNullException(nameof(authorizationService));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
    }

    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var user = context.HttpContext.User;

        // Invariant: Unauthenticated callers get 401 before any role evaluation
        if (user?.Identity?.IsAuthenticated != true)
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        // Roles come only from the verified principal; exact, ordinal match against any required role
        var roleClaimType = string.IsNullOrWhiteSpace(_options.RoleClaimType)
            ? System.Security.Claims.ClaimTypes.Role
            : _options.RoleClaimType;

        var hasRole = user.FindAll(roleClaimType)
            .Any(c => _requiredRoles.Contains(c.Value, StringComparer.Ordinal));

        if (hasRole)
        {
            return;
        }

        context.Result = _options.DenyWith == RoleDenyResponse.NotFound
            ? new NotFoundResult()
            : new StatusCodeResult(StatusCodes.Status403Forbidden);

        await EmitDenialAsync(context).ConfigureAwait(false);
    }

    private async ValueTask EmitDenialAsync(AuthorizationFilterContext context)
    {
        var httpContext = context.HttpContext;
        try
        {
            var auditEvent = new SecurityAuditEvent
            {
                Timestamp = DateTimeOffset.UtcNow,
                EventName = RoleDeniedEventName,
                TraceId = Activity.Current?.Id ?? httpContext.TraceIdentifier,
                ActorUserId = TryRead(() => _authorizationService.GetCurrentUserId(httpContext.User)),
                ActorTenantId = TryRead(() => _authorizationService.GetCurrentTenantId(httpContext.User)),
                ResourceType = "Endpoint",
                ResourceId = context.ActionDescriptor?.DisplayName ?? httpContext.Request.Path.Value,
                ClientIp = httpContext.Connection.RemoteIpAddress?.ToString(),
                Reason = $"Missing required role: caller holds none of [{string.Join(", ", _requiredRoles)}]"
            };

            await _auditSink.EmitAsync(auditEvent, httpContext.RequestAborted).ConfigureAwait(false);
        }
        catch
        {
            // Auditing failures must not mask or alter the denial outcome
        }
    }

    private static string? TryRead(Func<string> read)
    {
        try
        {
            return read();
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }
}
