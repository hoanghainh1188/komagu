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
        val denial = findDenial(authentication, resource, ownerUserIdExtractor, tenantIdExtractor)
            ?: return AuthorizationDecision.granted()
        if (denial.audited) {
            emitDenialAudit(authentication, resource, operation, denial.reason, denial.resourceId)
        }
        return AuthorizationDecision.denied(denial.reason)
    }

    /** Why the caller may not act on [resource], or null when it may. Checks run in order; the first failure wins. */
    private fun <T> findDenial(
        authentication: Authentication?,
        resource: T?,
        ownerUserIdExtractor: ((T) -> String)?,
        tenantIdExtractor: ((T) -> String)?
    ): Denial? {
        val caller = authentication?.takeIf { it.isAuthenticated && it !is AnonymousAuthenticationToken }
        val userId = caller?.let { runCatching { getCurrentUserId(it) } }
        val tenantId = caller?.let { runCatching { getCurrentTenantId(it) } }
        return when {
            userId == null || tenantId == null -> Denial("Caller is unauthenticated")
            userId.isFailure -> Denial(userId.exceptionOrNull()?.message ?: "Invalid user identity")
            tenantId.isFailure -> Denial(tenantId.exceptionOrNull()?.message ?: "Invalid tenant identity")
            resource == null -> Denial("Resource is null", audited = false)
            else -> ownershipDenial(
                resourceIdentity(resource, ownerUserIdExtractor, tenantIdExtractor),
                userId.getOrThrow(),
                tenantId.getOrThrow()
            )
        }
    }

    private fun ownershipDenial(identity: ResourceIdentity, currentUserId: String, currentTenantId: String): Denial? {
        val owner = identity.ownerUserId?.trim()
        val tenant = identity.tenantId?.trim()
        val reason = when {
            owner.isNullOrEmpty() || tenant.isNullOrEmpty() ->
                "Target resource does not expose ownerUserId and tenantId"
            // 1. Tenant boundary check
            tenant != currentTenantId ->
                "Tenant boundary violation: current tenant '$currentTenantId' != resource tenant '$tenant'"
            // 2. User ownership check
            owner != currentUserId ->
                "User ownership violation: current user '$currentUserId' != resource owner '$owner'"
            else -> null
        }
        return reason?.let { Denial(it, resourceId = identity.id) }
    }

    /** Owner, tenant and id from [OwnedResource], the extractors, then getters as a fallback. */
    private fun <T> resourceIdentity(
        resource: T & Any,
        ownerUserIdExtractor: ((T) -> String)?,
        tenantIdExtractor: ((T) -> String)?
    ): ResourceIdentity {
        val owned = resource as? OwnedResource<*>
        val identity = ResourceIdentity(
            ownerUserId = ownerUserIdExtractor?.invoke(resource) ?: owned?.ownerUserId,
            tenantId = tenantIdExtractor?.invoke(resource) ?: owned?.tenantId,
            id = owned?.id?.toString()
        )
        if (identity.ownerUserId != null && identity.tenantId != null) {
            return identity
        }
        // Reflection fallback if not implementing OwnedResource directly
        fun read(vararg names: String): String? = try {
            resource::class.java.methods.firstOrNull { it.name in names }?.invoke(resource)?.toString()
        } catch (_: Exception) {
            null
        }
        return ResourceIdentity(
            ownerUserId = identity.ownerUserId ?: read("getOwnerUserId", "ownerUserId"),
            tenantId = identity.tenantId ?: read("getTenantId", "tenantId"),
            id = identity.id ?: read("getId", "id")
        )
    }

    override fun getCurrentUserId(authentication: Authentication?): String {
        val auth = authentication ?: SecurityContextHolder.getContext().authentication
        ?: error("No authentication present in security context")

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

        error("Verified user identity claim missing in token context")
    }

    override fun getCurrentTenantId(authentication: Authentication?): String {
        val auth = authentication ?: SecurityContextHolder.getContext().authentication
        ?: error("No authentication present in security context")

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

        error("Verified tenant identity claim missing in token context")
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

    private class Denial(val reason: String, val resourceId: String? = null, val audited: Boolean = true)

    private class ResourceIdentity(val ownerUserId: String?, val tenantId: String?, val id: String?)
}
