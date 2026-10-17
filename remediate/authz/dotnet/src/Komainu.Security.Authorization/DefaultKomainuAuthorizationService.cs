namespace Komainu.Security.Authorization;

using System.Security.Claims;

/// <summary>
/// Default implementation of IKomainuAuthorizationService enforcing tenant and user boundaries.
/// </summary>
public sealed class DefaultKomainuAuthorizationService : IKomainuAuthorizationService
{
    private readonly ISecurityAuditSink _auditSink;

    private static readonly string[] UserIdClaimTypes =
    [
        ClaimTypes.NameIdentifier,
        "sub",
        "uid",
        "userId",
        "user_id"
    ];

    private static readonly string[] TenantIdClaimTypes =
    [
        "tenant_id",
        "tid",
        "tenant",
        "org_id",
        "organization_id"
    ];

    public DefaultKomainuAuthorizationService(ISecurityAuditSink auditSink)
    {
        _auditSink = auditSink ?? throw new ArgumentNullException(nameof(auditSink));
    }

    public async ValueTask<AuthorizationResult> AuthorizeAsync<T>(
        ClaimsPrincipal user,
        T resource,
        ResourceOperation operation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        if (user.Identity?.IsAuthenticated != true)
        {
            var unauthReason = "User is unauthenticated";
            await EmitAuditOnDenialAsync(
                user,
                resource,
                operation,
                unauthReason,
                cancellationToken).ConfigureAwait(false);

            return AuthorizationResult.Denied(unauthReason);
        }

        string currentUserId;
        string currentTenantId;

        try
        {
            currentUserId = GetCurrentUserId(user);
            currentTenantId = GetCurrentTenantId(user);
        }
        catch (UnauthorizedAccessException ex)
        {
            await EmitAuditOnDenialAsync(
                user,
                resource,
                operation,
                ex.Message,
                cancellationToken).ConfigureAwait(false);

            return AuthorizationResult.Denied(ex.Message);
        }

        if (resource == null)
        {
            // Resource null is treated as not found
            return AuthorizationResult.Denied("Resource is null");
        }

        // Determine owner and tenant of the target resource
        string? resourceOwnerUserId = null;
        string? resourceTenantId = null;
        string? resourceIdString = null;

        if (resource is IOwnedResource nonGenericResource)
        {
            resourceOwnerUserId = nonGenericResource.OwnerUserId;
            resourceTenantId = nonGenericResource.TenantId;
        }

        // Handle generic IOwnedResource<TKey>
        var ownedResourceGenericType = typeof(T)
            .GetInterfaces()
            .FirstOrDefault(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IOwnedResource<>));

        if (ownedResourceGenericType != null)
        {
            var idProp = ownedResourceGenericType.GetProperty(nameof(IOwnedResource<object>.Id));
            var ownerProp = ownedResourceGenericType.GetProperty(nameof(IOwnedResource<object>.OwnerUserId));
            var tenantProp = ownedResourceGenericType.GetProperty(nameof(IOwnedResource<object>.TenantId));

            resourceIdString = idProp?.GetValue(resource)?.ToString();
            resourceOwnerUserId = ownerProp?.GetValue(resource) as string ?? resourceOwnerUserId;
            resourceTenantId = tenantProp?.GetValue(resource) as string ?? resourceTenantId;
        }

        if (resourceOwnerUserId == null || resourceTenantId == null)
        {
            // Reflection fallback for properties named OwnerUserId and TenantId
            var type = resource.GetType();
            var ownerProp = type.GetProperty("OwnerUserId");
            var tenantProp = type.GetProperty("TenantId");
            var idProp = type.GetProperty("Id");

            resourceOwnerUserId = ownerProp?.GetValue(resource)?.ToString();
            resourceTenantId = tenantProp?.GetValue(resource)?.ToString();
            resourceIdString ??= idProp?.GetValue(resource)?.ToString();
        }

        if (string.IsNullOrEmpty(resourceOwnerUserId) || string.IsNullOrEmpty(resourceTenantId))
        {
            var msg = $"Resource of type {typeof(T).Name} does not expose OwnerUserId and TenantId";
            await EmitAuditOnDenialAsync(user, resource, operation, msg, cancellationToken).ConfigureAwait(false);
            return AuthorizationResult.Denied(msg);
        }

        // 1. Tenant boundary validation
        if (!string.Equals(currentTenantId, resourceTenantId, StringComparison.Ordinal))
        {
            var reason = $"Tenant boundary violation: current tenant '{currentTenantId}' != resource tenant '{resourceTenantId}'";
            await EmitAuditOnDenialAsync(
                user,
                resource,
                operation,
                reason,
                cancellationToken,
                resourceIdString,
                currentUserId,
                currentTenantId).ConfigureAwait(false);

            return AuthorizationResult.Denied(reason);
        }

        // 2. User ownership validation
        if (!string.Equals(currentUserId, resourceOwnerUserId, StringComparison.Ordinal))
        {
            var reason = $"User ownership violation: current user '{currentUserId}' != resource owner '{resourceOwnerUserId}'";
            await EmitAuditOnDenialAsync(
                user,
                resource,
                operation,
                reason,
                cancellationToken,
                resourceIdString,
                currentUserId,
                currentTenantId).ConfigureAwait(false);

            return AuthorizationResult.Denied(reason);
        }

        return AuthorizationResult.Success();
    }

    public string GetCurrentUserId(ClaimsPrincipal user)
    {
        ArgumentNullException.ThrowIfNull(user);

        foreach (var claimType in UserIdClaimTypes)
        {
            var val = user.FindFirst(claimType)?.Value;
            if (!string.IsNullOrWhiteSpace(val))
            {
                return val;
            }
        }

        throw new UnauthorizedAccessException("Verified user subject identifier claim is missing from security context");
    }

    public string GetCurrentTenantId(ClaimsPrincipal user)
    {
        ArgumentNullException.ThrowIfNull(user);

        foreach (var claimType in TenantIdClaimTypes)
        {
            var val = user.FindFirst(claimType)?.Value;
            if (!string.IsNullOrWhiteSpace(val))
            {
                return val;
            }
        }

        throw new UnauthorizedAccessException("Verified tenant identifier claim is missing from security context");
    }

    private async ValueTask EmitAuditOnDenialAsync<T>(
        ClaimsPrincipal user,
        T? resource,
        ResourceOperation operation,
        string reason,
        CancellationToken cancellationToken,
        string? resourceId = null,
        string? actorUserId = null,
        string? actorTenantId = null)
    {
        try
        {
            actorUserId ??= ExtractOptionalClaim(user, UserIdClaimTypes);
            actorTenantId ??= ExtractOptionalClaim(user, TenantIdClaimTypes);

            var auditEvent = new SecurityAuditEvent
            {
                Timestamp = DateTimeOffset.UtcNow,
                EventName = "Komainu.Authorization.Denied",
                ActorUserId = actorUserId,
                ActorTenantId = actorTenantId,
                ResourceType = typeof(T).Name,
                ResourceId = resourceId,
                Operation = operation,
                Reason = reason
            };

            await _auditSink.EmitAsync(auditEvent, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // Auditing failures must not mask or alter the denial outcome
        }
    }

    private static string? ExtractOptionalClaim(ClaimsPrincipal? user, string[] candidateClaimTypes)
    {
        if (user == null) return null;
        foreach (var claimType in candidateClaimTypes)
        {
            var val = user.FindFirst(claimType)?.Value;
            if (!string.IsNullOrWhiteSpace(val)) return val;
        }
        return null;
    }
}
