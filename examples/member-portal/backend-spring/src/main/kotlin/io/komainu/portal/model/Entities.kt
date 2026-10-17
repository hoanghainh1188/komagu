package io.komainu.portal.model

import io.komainu.security.authorization.OwnedResource
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.math.BigDecimal
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "portal_orders")
class OrderEntity(
    @Id
    override val id: String = UUID.randomUUID().toString().replace("-", ""),
    override val tenantId: String = "",
    override val ownerUserId: String = "",
    var totalAmount: BigDecimal = BigDecimal.ZERO,
    var status: String = "pending",
    var description: String = "",
    var createdAt: Instant = Instant.now()
) : OwnedResource<String>

@Entity
@Table(name = "portal_documents")
class DocumentEntity(
    @Id
    override val id: String = UUID.randomUUID().toString().replace("-", ""),
    override val tenantId: String = "",
    override val ownerUserId: String = "",
    var title: String = "",
    var content: String = "",
    var isConfidential: Boolean = true,
    var createdAt: Instant = Instant.now()
) : OwnedResource<String>

data class PersonaDto(
    val userId: String,
    val displayName: String,
    val tenantId: String,
    val tenantName: String,
    val role: String,
    val mockToken: String
)

data class CreateOrderRequest(
    val totalAmount: BigDecimal,
    val description: String
)

data class UpdateOrderRequest(
    val description: String?,
    val status: String?
)
