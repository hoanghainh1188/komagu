package io.komagu.security.authorization

import io.komagu.security.spring.ResourceNotFoundException
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.jwt.Jwt
import java.time.Instant

/**
 * Default implementation of KomaguSecurityManager.
 */
class DefaultKomaguSecurityManager(
    private val auditSink: SecurityAuditSink = LoggingSecurityAuditSink()
) : KomaguSecurityManager {

    companion object {
        private val USER_ID_CLAIMS = listOf("sub", "uid", "userId", "user_id", "id")
        private val TENANT_ID_CLAIMS = listOf("tenant_id", "tid", "tenant", "org_id", "organization_id")
    }

    override fun <T> requireOwnership(
        resource: T?,
        operation: ResourceOperation,
        ownerUserIdExtractor: ((T) -> String)?,
        tenantIdExtractor: ((T) -> String)?
    ) {
        val decision = checkOwnership(resource, operation, ownerUserIdExtractor, tenantIdExtractor)
        if (!decision.granted) {
            // Invariant: Deny by default with HTTP 404 Not Found
            throw ResourceNotFoundException(decision.failureReason ?: "Resource not found")
        }
    }

    override fun <T> checkOwnership(
        resource: T?,
        operation: ResourceOperation,
        ownerUserIdExtractor: ((T) -> String)?,
        tenantIdExtractor: ((T) -> String)?
    ): AuthorizationDecision {
        val authentication = SecurityContextHolder.getContext().authentication

        if (authentication == null || !authentication.isAuthenticated || authentication is AnonymousAuthenticationToken) {
            val reason = "Caller is unauthenticated"
            emitDenialAudit(authentication, resource, operation, reason)
            return AuthorizationDecision.denied(reason)
        }

        val currentUserId = try {
            getCurrentUserId(authentication)
        } catch (ex: Exception) {
            emitDenialAudit(authentication, resource, operation, ex.message ?: "Invalid user identity")
            return AuthorizationDecision.denied(ex.message ?: "Invalid user identity")
        }

        val currentTenantId = try {
            getCurrentTenantId(authentication)
        } catch (ex: Exception) {
            emitDenialAudit(authentication, resource, operation, ex.message ?: "Invalid tenant identity")
            return AuthorizationDecision.denied(ex.message ?: "Invalid tenant identity")
        }

        if (resource == null) {
            return AuthorizationDecision.denied("Resource is null")
        }

        // Extract ownerUserId and tenantId from resource
        var resourceOwnerUserId: String? = null
        var resourceTenantId: String? = null
        var resourceId: String? = null

        if (resource is OwnedResource<*>) {
            resourceOwnerUserId = resource.ownerUserId
            resourceTenantId = resource.tenantId
            resourceId = resource.id?.toString()
        }

        if (ownerUserIdExtractor != null) {
            resourceOwnerUserId = ownerUserIdExtractor(resource)
        }
        if (tenantIdExtractor != null) {
            resourceTenantId = tenantIdExtractor(resource)
        }

        // Reflection fallback if not implementing OwnedResource directly
        if (resourceOwnerUserId == null || resourceTenantId == null) {
            try {
                val clazz = resource::class.java
                val ownerField = clazz.methods.firstOrNull { it.name == "getOwnerUserId" || it.name == "ownerUserId" }
                val tenantField = clazz.methods.firstOrNull { it.name == "getTenantId" || it.name == "tenantId" }
                val idField = clazz.methods.firstOrNull { it.name == "getId" || it.name == "id" }

                resourceOwnerUserId = resourceOwnerUserId ?: ownerField?.invoke(resource)?.toString()
                resourceTenantId = resourceTenantId ?: tenantField?.invoke(resource)?.toString()
                resourceId = resourceId ?: idField?.invoke(resource)?.toString()
            } catch (_: Exception) {
            }
        }

        val trimmedOwner = resourceOwnerUserId?.trim()
        val trimmedTenant = resourceTenantId?.trim()

        if (trimmedOwner.isNullOrEmpty() || trimmedTenant.isNullOrEmpty()) {
            val reason = "Target resource does not expose ownerUserId and tenantId"
            emitDenialAudit(authentication, resource, operation, reason, resourceId)
            return AuthorizationDecision.denied(reason)
        }

        // 1. Tenant boundary check
        if (trimmedTenant != currentTenantId) {
            val reason = "Tenant boundary violation: current tenant '$currentTenantId' != resource tenant '$trimmedTenant'"
            emitDenialAudit(authentication, resource, operation, reason, resourceId)
            return AuthorizationDecision.denied(reason)
        }

        // 2. User ownership check
        if (trimmedOwner != currentUserId) {
            val reason = "User ownership violation: current user '$currentUserId' != resource owner '$trimmedOwner'"
            emitDenialAudit(authentication, resource, operation, reason, resourceId)
            return AuthorizationDecision.denied(reason)
        }

        return AuthorizationDecision.granted()
    }

    override fun getCurrentUserId(authentication: Authentication?): String {
        val auth = authentication ?: SecurityContextHolder.getContext().authentication
        ?: throw IllegalStateException("No authentication present in security context")

        when (val principal = auth.principal) {
            is Jwt -> {
                for (claim in USER_ID_CLAIMS) {
                    val value = principal.getClaimAsString(claim)?.trim()
                    if (!value.isNullOrBlank()) return value
                }
            }
        }

        val name = auth.name?.trim()
        if (!name.isNullOrBlank() && auth !is AnonymousAuthenticationToken) {
            return name
        }

        throw IllegalStateException("Verified user identity claim missing in token context")
    }

    override fun getCurrentTenantId(authentication: Authentication?): String {
        val auth = authentication ?: SecurityContextHolder.getContext().authentication
        ?: throw IllegalStateException("No authentication present in security context")

        when (val principal = auth.principal) {
            is Jwt -> {
                for (claim in TENANT_ID_CLAIMS) {
                    val value = principal.getClaimAsString(claim)?.trim()
                    if (!value.isNullOrBlank()) return value
                }
            }
        }

        // Fallback for custom authentication details
        val details = auth.details
        if (details is Map<*, *>) {
            for (claim in TENANT_ID_CLAIMS) {
                val value = details[claim]?.toString()?.trim()
                if (!value.isNullOrBlank()) return value
            }
        }

        throw IllegalStateException("Verified tenant identity claim missing in token context")
    }

    private fun <T> emitDenialAudit(
        auth: Authentication?,
        resource: T?,
        operation: ResourceOperation,
        reason: String,
        resourceId: String? = null
    ) {
        try {
            val actorUserId = try { auth?.let { getCurrentUserId(it) } } catch (_: Exception) { null }
            val actorTenantId = try { auth?.let { getCurrentTenantId(it) } } catch (_: Exception) { null }

            val auditEvent = SecurityAuditEvent(
                timestamp = Instant.now(),
                eventName = "Komagu.Authorization.Denied",
                actorUserId = actorUserId,
                actorTenantId = actorTenantId,
                resourceType = resource?.let { it::class.java.simpleName } ?: "Unknown",
                resourceId = resourceId,
                operation = operation,
                reason = reason
            )
            auditSink.emit(auditEvent)
        } catch (_: Exception) {
            // Auditing failures must never alter the denial outcome
        }
    }
}
