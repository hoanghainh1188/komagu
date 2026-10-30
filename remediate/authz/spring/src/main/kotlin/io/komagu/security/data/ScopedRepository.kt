package io.komagu.security.data

import org.springframework.data.repository.NoRepositoryBean
import org.springframework.data.repository.Repository
import java.util.Optional

/**
 * Scoped repository interface guaranteeing tenant and user boundary matching in queries.
 */
@NoRepositoryBean
interface ScopedRepository<T, ID> : Repository<T, ID> {
    /**
     * Safe query retrieving resource strictly scoped to both tenantId and ownerUserId.
     */
    fun findByIdAndTenantIdAndOwnerUserId(id: ID, tenantId: String, ownerUserId: String): Optional<T>

    /**
     * Safe query retrieving all resources belonging strictly to the specified tenant and owner.
     */
    fun findAllByTenantIdAndOwnerUserId(tenantId: String, ownerUserId: String): List<T>
}
