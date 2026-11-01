package io.komagu.security.spring

import io.komagu.security.authorization.KomaguSecurityManager
import io.komagu.security.authorization.SecurityAuditEvent
import io.komagu.security.authorization.SecurityAuditSink
import org.aspectj.lang.ProceedingJoinPoint
import org.aspectj.lang.annotation.Around
import org.aspectj.lang.annotation.Aspect
import org.aspectj.lang.reflect.MethodSignature
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import java.time.Instant

/**
 * Spring AOP Aspect enforcing [RequireRole] on annotated methods and classes (BFLA defense).
 *
 * Roles come only from the granted authorities of the authentication in `SecurityContextHolder`;
 * request parameters, bodies and headers are never consulted. See [RequireRole] for the matching rule.
 *
 * NOTE ON PROXY BYPASS (Self-Invocation):
 * Direct calls within the same class bypass the Spring proxy and will NOT trigger this aspect.
 */
@Aspect
class RoleAspect(
    private val securityManager: KomaguSecurityManager,
    private val auditSink: SecurityAuditSink,
    private val hideDeniedAsNotFound: Boolean = false
) {

    companion object {
        const val ROLE_PREFIX = "ROLE_"

        /** Strips one leading `ROLE_` prefix; the remaining name is compared case-sensitively. */
        fun normalizeRole(role: String): String = role.trim().removePrefix(ROLE_PREFIX)
    }

    @Around("@annotation(io.komagu.security.spring.RequireRole) || @within(io.komagu.security.spring.RequireRole)")
    fun enforceRole(joinPoint: ProceedingJoinPoint): Any? {
        val method = (joinPoint.signature as? MethodSignature)?.method
        val annotation = method?.getAnnotation(RequireRole::class.java)
            ?: method?.declaringClass?.getAnnotation(RequireRole::class.java)
            ?: joinPoint.target?.javaClass?.getAnnotation(RequireRole::class.java)
            ?: return joinPoint.proceed()

        val target = method?.let { "${it.declaringClass.simpleName}.${it.name}" } ?: "method"
        requireAnyRole(annotation.value.toList(), annotation.hideAsNotFound, target)
        return joinPoint.proceed()
    }

    /**
     * Programmatic check: returns normally when the current principal holds at least one of [roles].
     * Throws [AuthenticationRequiredException] (401), [RoleDeniedException] (403) or, when
     * [hideAsNotFound] (or the configured default) is set, [ResourceNotFoundException] (404).
     */
    fun requireAnyRole(roles: Collection<String>, hideAsNotFound: Boolean = false, target: String = "method") {
        val required = roles.map { normalizeRole(it) }
        check(required.isNotEmpty() && required.none { it.isEmpty() }) {
            "@RequireRole on '$target' must list at least one non-blank role"
        }

        val authentication = SecurityContextHolder.getContext().authentication
        if (authentication == null || !authentication.isAuthenticated ||
            authentication is AnonymousAuthenticationToken
        ) {
            throw AuthenticationRequiredException()
        }

        val granted = authentication.authorities.orEmpty()
            .mapNotNull { it.authority }
            .map { normalizeRole(it) }
            .toSet()
        if (required.any { it in granted }) return

        val reason = "Caller lacks required role(s) [${required.joinToString(", ")}] for '$target'"
        emitRoleDeniedAudit(authentication, target, reason)
        throw if (hideAsNotFound || hideDeniedAsNotFound) ResourceNotFoundException() else RoleDeniedException()
    }

    private fun emitRoleDeniedAudit(authentication: Authentication, target: String, reason: String) {
        try {
            auditSink.emit(
                SecurityAuditEvent(
                    timestamp = Instant.now(),
                    eventName = SecurityAuditEvent.ROLE_DENIED,
                    actorUserId = runCatching { securityManager.getCurrentUserId(authentication) }.getOrNull(),
                    actorTenantId = runCatching { securityManager.getCurrentTenantId(authentication) }.getOrNull(),
                    resourceType = "Endpoint",
                    resourceId = target,
                    reason = reason
                )
            )
        } catch (_: Exception) {
            // Auditing failures must never alter the denial outcome
        }
    }
}
