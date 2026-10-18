package io.komainu.portal.controller

import io.komainu.portal.model.CreateOrderRequest
import io.komainu.portal.model.DocumentEntity
import io.komainu.portal.model.OrderEntity
import io.komainu.portal.model.PersonaDto
import io.komainu.portal.model.UpdateOrderRequest
import io.komainu.portal.repository.DocumentRepository
import io.komainu.portal.repository.OrderRepository
import io.komainu.security.authorization.KomainuSecurityManager
import io.komainu.security.authorization.ResourceOperation
import io.komainu.security.query.SafeSortAllowList
import io.komainu.security.spring.ResourceNotFoundException
import jakarta.persistence.EntityManager
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.time.Instant

@RestController
@RequestMapping("/api/v1/auth")
class AuthController {
    private val personas = listOf(
        PersonaDto(
            userId = "user-a",
            displayName = "Alice (User A)",
            tenantId = "tenant-alpha",
            tenantName = "Alpha Corporation",
            role = "member",
            mockToken = "token-user-a"
        ),
        PersonaDto(
            userId = "user-b",
            displayName = "Bob (User B - Attacker/Peer)",
            tenantId = "tenant-alpha",
            tenantName = "Alpha Corporation",
            role = "member",
            mockToken = "token-user-b"
        ),
        PersonaDto(
            userId = "user-c",
            displayName = "Charlie (User C - Cross-Tenant)",
            tenantId = "tenant-beta",
            tenantName = "Beta Holdings",
            role = "member",
            mockToken = "token-user-c"
        )
    )

    @GetMapping("/personas")
    fun getPersonas(): List<PersonaDto> = personas
}

@RestController
@RequestMapping("/api/v1/orders")
class OrderController(
    private val orderRepository: OrderRepository,
    private val securityManager: KomainuSecurityManager
) {
    private val sortAllowList = SafeSortAllowList(listOf("createdAt", "totalAmount", "status", "id"))

    @GetMapping
    fun listOrders(
        @RequestParam(required = false) sort: String?,
        @RequestParam(defaultValue = "desc") dir: String
    ): List<OrderEntity> {
        val userId = securityManager.getCurrentUserId()
        val tenantId = securityManager.getCurrentTenantId()

        val orders = orderRepository.findByTenantIdAndOwnerUserId(tenantId, userId)

        return if (!sort.isNullOrBlank()) {
            val validCol = sortAllowList.validateColumnName(sort)
            val isAsc = dir.equals("asc", ignoreCase = true)
            when (validCol.lowercase()) {
                "totalamount" -> if (isAsc) orders.sortedBy { it.totalAmount } else orders.sortedByDescending { it.totalAmount }
                "status" -> if (isAsc) orders.sortedBy { it.status } else orders.sortedByDescending { it.status }
                else -> if (isAsc) orders.sortedBy { it.createdAt } else orders.sortedByDescending { it.createdAt }
            }
        } else {
            orders.sortedByDescending { it.createdAt }
        }
    }

    @GetMapping("/{id}")
    fun getOrder(@PathVariable id: String): OrderEntity {
        val order = orderRepository.findById(id).orElse(null)
        // Enforce Komainu D1 ownership check -> throws ResourceNotFoundException (404) on breach
        securityManager.requireOwnership(order, ResourceOperation.READ)
        return order!!
    }

    @PostMapping
    fun createOrder(@RequestBody request: CreateOrderRequest): ResponseEntity<OrderEntity> {
        val userId = securityManager.getCurrentUserId()
        val tenantId = securityManager.getCurrentTenantId()

        val order = OrderEntity(
            tenantId = tenantId,
            ownerUserId = userId,
            totalAmount = request.totalAmount,
            description = request.description,
            status = "pending",
            createdAt = Instant.now()
        )
        val saved = orderRepository.save(order)
        return ResponseEntity.status(HttpStatus.CREATED).body(saved)
    }

    @PutMapping("/{id}")
    fun updateOrder(
        @PathVariable id: String,
        @RequestBody request: UpdateOrderRequest
    ): OrderEntity {
        val order = orderRepository.findById(id).orElse(null)
        securityManager.requireOwnership(order, ResourceOperation.UPDATE)

        request.description?.let { order!!.description = it }
        request.status?.let { order!!.status = it }

        return orderRepository.save(order!!)
    }

    @DeleteMapping("/{id}")
    fun deleteOrder(@PathVariable id: String): ResponseEntity<Void> {
        val order = orderRepository.findById(id).orElse(null)
        securityManager.requireOwnership(order, ResourceOperation.DELETE)

        orderRepository.delete(order!!)
        return ResponseEntity.noContent().build()
    }
}

@RestController
@RequestMapping("/api/v1/documents")
class DocumentController(
    private val documentRepository: DocumentRepository,
    private val securityManager: KomainuSecurityManager
) {
    @GetMapping
    fun listDocuments(): List<DocumentEntity> {
        val userId = securityManager.getCurrentUserId()
        val tenantId = securityManager.getCurrentTenantId()
        return documentRepository.findByTenantIdAndOwnerUserId(tenantId, userId)
    }

    @GetMapping("/{id}")
    fun getDocument(@PathVariable id: String): DocumentEntity {
        val doc = documentRepository.findById(id).orElse(null)
        securityManager.requireOwnership(doc, ResourceOperation.READ)
        return doc!!
    }
}

@RestController
@RequestMapping("/api/v1/test")
class LegacyTestController(
    private val orderRepository: OrderRepository,
    private val entityManager: EntityManager,
    private val securityManager: KomainuSecurityManager,
    @Value("\${enable.security.test.vulnerabilities:false}")
    private val vulnerabilitiesEnabled: Boolean
) {
    @GetMapping("/legacy-orders/{id}")
    fun getLegacyOrder(@PathVariable id: String): ResponseEntity<Any> {
        if (vulnerabilitiesEnabled) {
            // PLANT-BOLA: Return order directly without verifying ownership
            val order = orderRepository.findById(id).orElse(null)
                ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body(mapOf("error" to "Not found"))
            return ResponseEntity.ok(order)
        }

        // REMEDIATED (D1): Enforce ownership check with 404 deny-by-default
        val order = orderRepository.findById(id).orElse(null)
            ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body(mapOf("error" to "Not found"))
        securityManager.requireOwnership(order, ResourceOperation.READ)
        return ResponseEntity.ok(order)
    }

    @PutMapping("/legacy-orders/{id}")
    fun updateLegacyOrder(
        @PathVariable id: String,
        @RequestBody request: UpdateOrderRequest
    ): ResponseEntity<Any> {
        if (vulnerabilitiesEnabled) {
            // PLANT-BOLA: Direct update without ownership check
            val order = orderRepository.findById(id).orElse(null)
                ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body(mapOf("error" to "Not found"))

            request.description?.let { order.description = it }
            request.status?.let { order.status = it }
            val updated = orderRepository.save(order)
            return ResponseEntity.ok(updated)
        }

        // REMEDIATED (D1): Enforce ownership check on update
        val order = orderRepository.findById(id).orElse(null)
            ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body(mapOf("error" to "Not found"))
        securityManager.requireOwnership(order, ResourceOperation.UPDATE)

        request.description?.let { order.description = it }
        request.status?.let { order.status = it }
        val updated = orderRepository.save(order)
        return ResponseEntity.ok(updated)
    }

    @DeleteMapping("/legacy-orders/{id}")
    fun deleteLegacyOrder(@PathVariable id: String): ResponseEntity<Any> {
        if (vulnerabilitiesEnabled) {
            // PLANT-BOLA: Direct deletion without ownership check
            val order = orderRepository.findById(id).orElse(null)
                ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body(mapOf("error" to "Not found"))

            orderRepository.delete(order)
            return ResponseEntity.noContent().build()
        }

        // REMEDIATED (D1): Enforce ownership check on delete
        val order = orderRepository.findById(id).orElse(null)
            ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body(mapOf("error" to "Not found"))
        securityManager.requireOwnership(order, ResourceOperation.DELETE)

        orderRepository.delete(order)
        return ResponseEntity.noContent().build()
    }

    @GetMapping("/legacy-search")
    fun searchLegacy(@RequestParam query: String): ResponseEntity<Any> {
        if (vulnerabilitiesEnabled) {
            // PLANT-SQLI: String concatenation in native SQL query
            val sql = "SELECT * FROM portal_orders WHERE description LIKE '%$query%'"
            val queryResult = entityManager.createNativeQuery(sql, OrderEntity::class.java).resultList
            return ResponseEntity.ok(queryResult)
        }

        // REMEDIATED (D3): Parameterized query preventing SQL injection
        val queryResult = entityManager.createQuery(
            "SELECT o FROM OrderEntity o WHERE o.description LIKE :query",
            OrderEntity::class.java
        ).setParameter("query", "%$query%").resultList

        return ResponseEntity.ok(queryResult)
    }
}
