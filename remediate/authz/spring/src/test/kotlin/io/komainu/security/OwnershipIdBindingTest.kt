package io.komainu.security

import io.komainu.security.authorization.DefaultKomainuSecurityManager
import io.komainu.security.authorization.OwnedResource
import io.komainu.security.authorization.ResourceOperation
import io.komainu.security.spring.OwnershipAspect
import io.komainu.security.spring.RequireOwnership
import io.komainu.security.spring.ResourceNotFoundException
import io.komainu.security.spring.ResourceOwnershipResolver
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.aop.aspectj.annotation.AspectJProxyFactory
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.jwt.Jwt
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/**
 * Regression tests for #221 through a real AOP proxy and the real security manager:
 * the id must be resolved server-side and a client-supplied object must never stand in for it.
 */
class OwnershipIdBindingTest {

    data class Order(
        override val id: String,
        override val ownerUserId: String,
        override val tenantId: String,
        val note: String = ""
    ) : OwnedResource<String>

    private val attackerOrder = Order("attacker-order", "attacker", "tenant-1")
    private val victimOrder = Order("victim-order", "victim", "tenant-1")

    private val resolver = object : ResourceOwnershipResolver<Order> {
        override fun supports(entityClass: Class<*>) = Order::class.java.isAssignableFrom(entityClass)
        override fun resolve(id: Any): Order? = listOf(attackerOrder, victimOrder).find { it.id == id.toString() }
    }

    open class OrderController {
        var handlerRan = false

        @RequireOwnership(entityClass = Order::class, idParam = "id", operation = ResourceOperation.UPDATE)
        open fun updateWithMismatchedIdName(orderId: String, body: Order): String { handlerRan = true; return "updated" }

        @RequireOwnership(entityClass = Order::class, idParam = "id", operation = ResourceOperation.DELETE)
        open fun deleteWithMismatchedIdName(orderId: String, body: Order): String { handlerRan = true; return "deleted" }

        @RequireOwnership(entityClass = Order::class, idParam = "id", operation = ResourceOperation.DELETE)
        open fun deleteSingleWithMismatchedId(orderId: String): String { handlerRan = true; return "deleted" }

        @RequireOwnership(entityClass = Order::class, idParam = "id", operation = ResourceOperation.UPDATE)
        open fun update(id: String, body: Order): String { handlerRan = true; return "updated" }

        @RequireOwnership(entityClass = Order::class, operation = ResourceOperation.CREATE)
        open fun createBoth(first: Order, second: Order): String { handlerRan = true; return "created" }
    }

    @RequireOwnership(entityClass = Order::class, idParam = "id", operation = ResourceOperation.UPDATE)
    open class ClassLevelController {
        var handlerRan = false
        open fun update(orderId: String, body: Order): String { handlerRan = true; return "updated" }
    }

    private fun <T : Any> proxy(target: T): T {
        val factory = AspectJProxyFactory(target)
        factory.isProxyTargetClass = true
        factory.addAspect(OwnershipAspect(DefaultKomainuSecurityManager(), listOf(resolver)))
        return factory.getProxy()
    }

    @BeforeEach
    fun authenticateAttacker() {
        val jwt = mockk<Jwt>()
        every { jwt.getClaimAsString("sub") } returns "attacker"
        every { jwt.getClaimAsString("tenant_id") } returns "tenant-1"
        val auth = mockk<Authentication>()
        every { auth.isAuthenticated } returns true
        every { auth.principal } returns jwt
        every { auth.name } returns "attacker"
        val context = mockk<SecurityContext>()
        every { context.authentication } returns auth
        SecurityContextHolder.setContext(context)
    }

    @AfterEach
    fun clear() = SecurityContextHolder.clearContext()

    @Test
    fun `update with mismatched idParam name is denied instead of trusting the body`() {
        val target = OrderController()
        assertThrows<ResourceNotFoundException> { proxy(target).updateWithMismatchedIdName("victim-order", attackerOrder) }
        assertFalse(target.handlerRan)
    }

    @Test
    fun `delete with mismatched idParam name is denied`() {
        val target = OrderController()
        assertThrows<ResourceNotFoundException> { proxy(target).deleteWithMismatchedIdName("victim-order", attackerOrder) }
        assertFalse(target.handlerRan)
    }

    @Test
    fun `delete single argument with mismatched idParam name is denied`() {
        val target = OrderController()
        assertThrows<ResourceNotFoundException> { proxy(target).deleteSingleWithMismatchedId("victim-order") }
        assertFalse(target.handlerRan)
    }

    @Test
    fun `class-level annotation with mismatched idParam name is denied`() {
        val target = ClassLevelController()
        assertThrows<ResourceNotFoundException> { proxy(target).update("victim-order", attackerOrder) }
        assertFalse(target.handlerRan)
    }

    @Test
    fun `body id that differs from the path id is denied`() {
        val target = OrderController()
        val body = attackerOrder.copy(id = "victim-order")
        assertThrows<ResourceNotFoundException> { proxy(target).update("attacker-order", body) }
        assertFalse(target.handlerRan)
    }

    @Test
    fun `body that changes the owner is denied`() {
        val target = OrderController()
        val body = attackerOrder.copy(ownerUserId = "victim")
        assertThrows<ResourceNotFoundException> { proxy(target).update("attacker-order", body) }
        assertFalse(target.handlerRan)
    }

    @Test
    fun `body matching the resolved resource is allowed`() {
        val target = OrderController()
        assertEquals("updated", proxy(target).update("attacker-order", attackerOrder.copy(note = "changed")))
    }

    @Test
    fun `create checks every resource argument`() {
        val target = OrderController()
        assertThrows<ResourceNotFoundException> { proxy(target).createBoth(attackerOrder, victimOrder) }
        assertFalse(target.handlerRan)
    }
}
