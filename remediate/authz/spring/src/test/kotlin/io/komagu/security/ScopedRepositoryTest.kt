package io.komagu.security

import io.komagu.security.authorization.OwnedResource
import io.komagu.security.data.ScopedRepository
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ScopedRepositoryTest {

    data class Order(
        override val id: UUID,
        override val ownerUserId: String,
        override val tenantId: String,
        val totalAmount: Double
    ) : OwnedResource<UUID>

    interface OrderRepository : ScopedRepository<Order, UUID>

    @Test
    fun `scoped repository queries strictly with tenantId and ownerUserId`() {
        val repo = mockk<OrderRepository>()
        val orderId = UUID.randomUUID()
        val expectedOrder = Order(orderId, "user-1", "tenant-1", 99.9)

        every {
            repo.findByIdAndTenantIdAndOwnerUserId(orderId, "tenant-1", "user-1")
        } returns Optional.of(expectedOrder)

        val result = repo.findByIdAndTenantIdAndOwnerUserId(orderId, "tenant-1", "user-1")

        assertTrue(result.isPresent)
        assertEquals("user-1", result.get().ownerUserId)
        assertEquals("tenant-1", result.get().tenantId)
        verify(exactly = 1) { repo.findByIdAndTenantIdAndOwnerUserId(orderId, "tenant-1", "user-1") }
    }
}
