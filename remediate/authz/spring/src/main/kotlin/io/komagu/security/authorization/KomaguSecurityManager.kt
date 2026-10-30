package io.komagu.security.authorization

import io.komagu.security.spring.ResourceNotFoundException
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.jwt.Jwt

/**
 * Primary security manager for JVM / Spring applications enforcing object-level authorization (BOLA defense).
 */
interface KomaguSecurityManager {
    /**
     * Imperative assertion: verifies ownership and tenant boundary.
     * Throws ResourceNotFoundException (mapped to HTTP 404 Not Found) on failure or mismatch.
     */
    fun <T> requireOwnership(
        resource: T?,
        operation: ResourceOperation = ResourceOperation.READ,
        ownerUserIdExtractor: ((T) -> String)? = null,
        tenantIdExtractor: ((T) -> String)? = null
    )

    /**
     * Evaluates authorization without throwing an exception.
     */
    fun <T> checkOwnership(
        resource: T?,
        operation: ResourceOperation = ResourceOperation.READ,
        ownerUserIdExtractor: ((T) -> String)? = null,
        tenantIdExtractor: ((T) -> String)? = null
    ): AuthorizationDecision

    /**
     * Extracts verified subject user ID from security context token claims.
     */
    fun getCurrentUserId(authentication: Authentication? = null): String

    /**
     * Extracts verified tenant ID from security context token claims.
     */
    fun getCurrentTenantId(authentication: Authentication? = null): String
}
