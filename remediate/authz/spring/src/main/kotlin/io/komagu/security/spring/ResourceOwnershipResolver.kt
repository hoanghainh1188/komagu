package io.komagu.security.spring

/**
 * Resolves an entity instance from its identifier for pre-invocation ownership verification.
 */
interface ResourceOwnershipResolver<T> {
    /**
     * Determines whether this resolver can handle the specified entity class.
     */
    fun supports(entityClass: Class<*>): Boolean

    /**
     * Resolves the entity by its identifier.
     * Returns null if the entity does not exist.
     */
    fun resolve(id: Any): T?
}
