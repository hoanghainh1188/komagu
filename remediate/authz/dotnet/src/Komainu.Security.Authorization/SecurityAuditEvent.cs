namespace Komainu.Security.Authorization;

/// <summary>
/// Structured security event emitted when an object-level authorization attempt is evaluated or denied.
/// </summary>
public record SecurityAuditEvent
{
    /// <summary>
    /// UTC timestamp of the audit event.
    /// </summary>
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// Event name or category.
    /// </summary>
    public string EventName { get; init; } = "Komainu.Authorization.Denied";

    /// <summary>
    /// Distributed tracing identifier (W3C traceparent or correlation ID).
    /// </summary>
    public string? TraceId { get; init; }

    /// <summary>
    /// Caller user identifier extracted from verified token claims.
    /// </summary>
    public string? ActorUserId { get; init; }

    /// <summary>
    /// Caller tenant identifier extracted from verified token claims.
    /// </summary>
    public string? ActorTenantId { get; init; }

    /// <summary>
    /// Target resource entity type name.
    /// </summary>
    public string ResourceType { get; init; } = string.Empty;

    /// <summary>
    /// Target resource identifier as string.
    /// </summary>
    public string? ResourceId { get; init; }

    /// <summary>
    /// Attempted operation on the resource.
    /// </summary>
    public ResourceOperation Operation { get; init; }

    /// <summary>
    /// Client remote IP address if available.
    /// </summary>
    public string? ClientIp { get; init; }

    /// <summary>
    /// Evaluation outcome description or reason for denial.
    /// </summary>
    public string Reason { get; init; } = string.Empty;
}
