package io.komainu.security.authorization

/**
 * Contract implemented by domain entities and DTOs that require object-level ownership checks.
 */
interface OwnedResource<TKey> {
    /**
     * Unique identifier of the resource.
     */
    val id: TKey

    /**
     * Subject identifier of the owning user extracted from verified token claims.
     */
    val ownerUserId: String

    /**
     * Tenant identifier extracted from verified token claims.
     */
    val tenantId: String
}
