namespace Komagu.Security.Authorization;

using Microsoft.Extensions.Logging;

/// <summary>
/// Default security audit sink implementation logging structured events via ILogger.
/// </summary>
public sealed partial class LoggingSecurityAuditSink : ISecurityAuditSink
{
    private readonly ILogger<LoggingSecurityAuditSink> _logger;

    public LoggingSecurityAuditSink(ILogger<LoggingSecurityAuditSink> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public ValueTask EmitAsync(SecurityAuditEvent auditEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);

        LogAuditEvent(
            _logger,
            auditEvent.EventName,
            auditEvent.TraceId ?? "none",
            auditEvent.ActorUserId ?? "anonymous",
            auditEvent.ActorTenantId ?? "none",
            auditEvent.ResourceType,
            auditEvent.ResourceId ?? "unknown",
            auditEvent.Operation,
            auditEvent.ClientIp ?? "unknown",
            auditEvent.Reason);

        return ValueTask.CompletedTask;
    }

    [LoggerMessage(
        EventId = 1,
        Level = LogLevel.Warning,
        Message = "[SECURITY AUDIT] {EventName} | TraceId: {TraceId} | Actor: {ActorUserId} | Tenant: {ActorTenantId} | Target: {ResourceType}/{ResourceId} | Op: {Operation} | IP: {ClientIp} | Reason: {Reason}")]
    private static partial void LogAuditEvent(
        ILogger logger,
        string eventName,
        string traceId,
        string actorUserId,
        string actorTenantId,
        string resourceType,
        string resourceId,
        ResourceOperation operation,
        string clientIp,
        string reason);
}
