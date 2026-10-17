package io.komainu.security

import io.komainu.security.authorization.KomainuSecurityManager
import io.komainu.security.authorization.OwnedResource
import io.komainu.security.authorization.ResourceOperation
import io.komainu.security.spring.OwnershipAspect
import io.komainu.security.spring.RequireOwnership
import io.komainu.security.spring.ResourceNotFoundException
import io.mockk.*
import org.aspectj.lang.ProceedingJoinPoint
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals

class OwnershipAspectTest {

    data class SampleResource(
        override val id: String,
        override val ownerUserId: String,
        override val tenantId: String
    ) : OwnedResource<String>

    class DummyService {
        @RequireOwnership(entityClass = SampleResource::class, operation = ResourceOperation.READ)
        fun performAction(resource: SampleResource): String = "action-result"
    }

    private val sampleAnnotation: RequireOwnership =
        DummyService::class.java.getMethod("performAction", SampleResource::class.java)
            .getAnnotation(RequireOwnership::class.java)

    @Test
    fun `aspect delegates ownership verification to security manager and proceeds`() {
        val securityManager = mockk<KomainuSecurityManager>(relaxed = true)
        val aspect = OwnershipAspect(securityManager)

        val joinPoint = mockk<ProceedingJoinPoint>()
        val resource = SampleResource("res-1", "user-1", "tenant-1")

        every { joinPoint.args } returns arrayOf(resource)
        every { joinPoint.proceed() } returns "action-result"

        val result = aspect.enforceOwnership(joinPoint, sampleAnnotation)

        assertEquals("action-result", result)
        verify(exactly = 1) { securityManager.requireOwnership(resource, ResourceOperation.READ) }
    }

    @Test
    fun `aspect propagates ResourceNotFoundException when security manager denies access`() {
        val securityManager = mockk<KomainuSecurityManager>()
        val aspect = OwnershipAspect(securityManager)

        val joinPoint = mockk<ProceedingJoinPoint>()
        val resource = SampleResource("res-1", "victim", "tenant-1")

        every { joinPoint.args } returns arrayOf(resource)
        every { securityManager.requireOwnership(resource, ResourceOperation.READ) } throws ResourceNotFoundException("Resource not found")

        assertThrows<ResourceNotFoundException> {
            aspect.enforceOwnership(joinPoint, sampleAnnotation)
        }

        verify(exactly = 0) { joinPoint.proceed() }
    }
}
