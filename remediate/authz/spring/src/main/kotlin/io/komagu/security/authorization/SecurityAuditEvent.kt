package io.komagu.security.authorization

import java.time.Instant

/**
 * Structured security event emitted when an authorization attempt is evaluated or denied.
 */
data class SecurityAuditEvent(
    val timestamp: Instant = Instant.now(),
    // Kept as "Komainu.*" after the rename so existing SIEM rules still match (#290).
    val eventName: String = "Komainu.Authorization.Denied",
    val traceId: String? = null,
    val actorUserId: String? = null,
    val actorTenantId: String? = null,
    val resourceType: String = "",
    val resourceId: String? = null,
    val operation: ResourceOperation = ResourceOperation.READ,
    val clientIp: String? = null,
    val reason: String = ""
)

/**
 * Sink interface for processing security audit events.
 */
fun interface SecurityAuditSink {
    fun emit(event: SecurityAuditEvent)
}
