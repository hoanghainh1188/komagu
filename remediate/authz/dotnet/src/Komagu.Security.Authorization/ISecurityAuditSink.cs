namespace Komagu.Security.Authorization;

/// <summary>
/// Sink interface for receiving and publishing structured security audit events to SIEM or log aggregators.
/// </summary>
public interface ISecurityAuditSink
{
    /// <summary>
    /// Emits a structured security audit event asynchronously.
    /// </summary>
    ValueTask EmitAsync(SecurityAuditEvent auditEvent, CancellationToken cancellationToken = default);
}
