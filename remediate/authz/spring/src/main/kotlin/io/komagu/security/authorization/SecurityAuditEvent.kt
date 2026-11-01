package io.komagu.security.authorization

import java.time.Instant

/**
 * Structured security event emitted when an authorization attempt is evaluated or denied.
 */
data class SecurityAuditEvent(
    val timestamp: Instant = Instant.now(),
    val eventName: String = DENIED,
    val traceId: String? = null,
    val actorUserId: String? = null,
    val actorTenantId: String? = null,
    val resourceType: String = "",
    val resourceId: String? = null,
    val operation: ResourceOperation = ResourceOperation.READ,
    val clientIp: String? = null,
    val reason: String = ""
) {
    companion object {
        /** Object-level (ownership / tenant) denial. */
        const val DENIED = "Komagu.Authorization.Denied"

        /** Function-level denial: the caller lacks every role required by @RequireRole. */
        const val ROLE_DENIED = "Komagu.Authorization.RoleDenied"
    }
}

/**
 * Sink interface for processing security audit events.
 */
fun interface SecurityAuditSink {
    fun emit(event: SecurityAuditEvent)
}
