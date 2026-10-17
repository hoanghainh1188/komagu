package io.komainu.security.authorization

import org.slf4j.LoggerFactory

/**
 * Default audit sink logging structured security events through SLF4J at WARN level.
 */
class LoggingSecurityAuditSink : SecurityAuditSink {
    private val logger = LoggerFactory.getLogger(LoggingSecurityAuditSink::class.java)

    override fun emit(event: SecurityAuditEvent) {
        logger.warn(
            "[SECURITY AUDIT] {} | TraceId: {} | Actor: {} | Tenant: {} | Target: {}/{} | Op: {} | IP: {} | Reason: {}",
            event.eventName,
            event.traceId ?: "none",
            event.actorUserId ?: "anonymous",
            event.actorTenantId ?: "none",
            event.resourceType,
            event.resourceId ?: "unknown",
            event.operation,
            event.clientIp ?: "unknown",
            event.reason
        )
    }
}
