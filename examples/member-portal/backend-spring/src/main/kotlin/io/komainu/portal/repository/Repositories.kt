package io.komainu.portal.repository

import io.komainu.portal.model.DocumentEntity
import io.komainu.portal.model.OrderEntity
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import java.util.Optional

@Repository
interface OrderRepository : JpaRepository<OrderEntity, String> {
    fun findByTenantIdAndOwnerUserId(tenantId: String, ownerUserId: String): List<OrderEntity>
    fun findByIdAndTenantIdAndOwnerUserId(id: String, tenantId: String, ownerUserId: String): Optional<OrderEntity>
}

@Repository
interface DocumentRepository : JpaRepository<DocumentEntity, String> {
    fun findByTenantIdAndOwnerUserId(tenantId: String, ownerUserId: String): List<DocumentEntity>
    fun findByIdAndTenantIdAndOwnerUserId(id: String, tenantId: String, ownerUserId: String): Optional<DocumentEntity>
}
