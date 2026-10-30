package io.komagu.security

import io.komagu.security.authorization.KomaguSecurityManager
import io.komagu.security.authorization.OwnedResource
import io.komagu.security.authorization.ResourceOperation
import io.komagu.security.spring.OwnershipAspect
import io.komagu.security.spring.RequireOwnership
import io.komagu.security.spring.ResourceNotFoundException
import io.komagu.security.spring.ResourceOwnershipResolver
import io.mockk.*
import org.aspectj.lang.ProceedingJoinPoint
import org.aspectj.lang.reflect.MethodSignature
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.data.domain.PageImpl
import org.springframework.http.ResponseEntity
import java.util.Optional
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class OwnershipAspectTest {

    data class SampleResource(
        override val id: String,
        override val ownerUserId: String,
        override val tenantId: String
    ) : OwnedResource<String>

    class SampleResourceResolver(
        private val store: Map<String, SampleResource>
    ) : ResourceOwnershipResolver<SampleResource> {
        override fun supports(entityClass: Class<*>): Boolean =
            SampleResource::class.java.isAssignableFrom(entityClass)

        override fun resolve(id: Any): SampleResource? = store[id.toString()]
    }

    class DummyService {
        @RequireOwnership(entityClass = SampleResource::class, operation = ResourceOperation.READ)
        fun performAction(resource: SampleResource): String = "action-result"

        @RequireOwnership(entityClass = SampleResource::class, idParam = "id", operation = ResourceOperation.DELETE)
        fun deleteById(id: String): String = "deleted-$id"

        @RequireOwnership(entityClass = SampleResource::class, idParam = "id", operation = ResourceOperation.UPDATE)
        fun updateWithBody(id: String, body: SampleResource): String = "updated-$id"

        @RequireOwnership(entityClass = SampleResource::class, operation = ResourceOperation.READ)
        fun getOptional(found: Boolean): Optional<SampleResource> =
            if (found) Optional.of(SampleResource("res-opt", "user-1", "tenant-1")) else Optional.empty()

        @RequireOwnership(entityClass = SampleResource::class, operation = ResourceOperation.READ)
        fun getResponseEntity(): ResponseEntity<SampleResource> =
            ResponseEntity.ok(SampleResource("res-resp", "user-1", "tenant-1"))

        @RequireOwnership(entityClass = SampleResource::class, operation = ResourceOperation.READ)
        fun getCollection(): List<SampleResource> =
            listOf(SampleResource("res-c1", "user-1", "tenant-1"), SampleResource("res-c2", "user-1", "tenant-1"))

        @RequireOwnership(entityClass = SampleResource::class, operation = ResourceOperation.READ)
        fun getPage(): PageImpl<SampleResource> =
            PageImpl(listOf(SampleResource("res-p1", "user-1", "tenant-1")))

        @RequireOwnership(entityClass = SampleResource::class, operation = ResourceOperation.READ)
        fun uncheckableMethod(): String = "plain-string-no-resource"
    }

    @RequireOwnership(entityClass = SampleResource::class, operation = ResourceOperation.READ)
    class DummyClassAnnotatedService {
        fun serviceMethod(resource: SampleResource): String = "class-annotated-result"
    }

    private val sampleAnnotation: RequireOwnership =
        DummyService::class.java.getMethod("performAction", SampleResource::class.java)
            .getAnnotation(RequireOwnership::class.java)

    @Test
    fun `aspect delegates ownership verification to security manager and proceeds`() {
        val securityManager = mockk<KomaguSecurityManager>(relaxed = true)
        val aspect = OwnershipAspect(securityManager)

        val joinPoint = mockk<ProceedingJoinPoint>(relaxed = true)
        val resource = SampleResource("res-1", "user-1", "tenant-1")

        every { joinPoint.args } returns arrayOf(resource)
        every { joinPoint.proceed() } returns "action-result"

        val result = aspect.enforceOwnership(joinPoint, sampleAnnotation)

        assertEquals("action-result", result)
        verify(exactly = 1) { securityManager.requireOwnership(resource, ResourceOperation.READ) }
    }

    @Test
    fun `aspect propagates ResourceNotFoundException when security manager denies access`() {
        val securityManager = mockk<KomaguSecurityManager>()
        val aspect = OwnershipAspect(securityManager)

        val joinPoint = mockk<ProceedingJoinPoint>(relaxed = true)
        val resource = SampleResource("res-1", "victim", "tenant-1")

        every { joinPoint.args } returns arrayOf(resource)
        every { securityManager.requireOwnership(resource, ResourceOperation.READ) } throws ResourceNotFoundException("Resource not found")

        assertThrows<ResourceNotFoundException> {
            aspect.enforceOwnership(joinPoint, sampleAnnotation)
        }

        verify(exactly = 0) { joinPoint.proceed() }
    }

    @Test
    fun `aspect resolves resource from ID argument before proceeding`() {
        val resource = SampleResource("res-42", "user-1", "tenant-1")
        val resolver = SampleResourceResolver(mapOf("res-42" to resource))
        val securityManager = mockk<KomaguSecurityManager>(relaxed = true)
        val aspect = OwnershipAspect(securityManager, listOf(resolver))

        val method = DummyService::class.java.getMethod("deleteById", String::class.java)
        val annotation = method.getAnnotation(RequireOwnership::class.java)

        val signature = mockk<MethodSignature>()
        every { signature.method } returns method
        every { signature.parameterNames } returns arrayOf("id")

        val joinPoint = mockk<ProceedingJoinPoint>()
        every { joinPoint.signature } returns signature
        every { joinPoint.target } returns DummyService()
        every { joinPoint.args } returns arrayOf("res-42")
        every { joinPoint.proceed() } returns "deleted-res-42"

        val result = aspect.enforceOwnership(joinPoint, annotation)

        assertEquals("deleted-res-42", result)
        verify(exactly = 1) { securityManager.requireOwnership(resource, ResourceOperation.DELETE) }
        verify(exactly = 1) { joinPoint.proceed() }
    }

    @Test
    fun `mutating operation fails closed before proceed when resource cannot be resolved`() {
        // Resolver does not have "res-victim"
        val resolver = SampleResourceResolver(emptyMap())
        val securityManager = mockk<KomaguSecurityManager>(relaxed = true)
        val aspect = OwnershipAspect(securityManager, listOf(resolver))

        val method = DummyService::class.java.getMethod("deleteById", String::class.java)
        val annotation = method.getAnnotation(RequireOwnership::class.java)

        val signature = mockk<MethodSignature>()
        every { signature.method } returns method
        every { signature.parameterNames } returns arrayOf("id")

        val joinPoint = mockk<ProceedingJoinPoint>()
        every { joinPoint.signature } returns signature
        every { joinPoint.target } returns DummyService()
        every { joinPoint.args } returns arrayOf("res-victim")

        val ex = assertThrows<ResourceNotFoundException> {
            aspect.enforceOwnership(joinPoint, annotation)
        }
        assertTrue(ex.message!!.contains("not found"))

        // Critical: verify proceed() was NEVER invoked (no mutation occurred)
        verify(exactly = 0) { joinPoint.proceed() }
    }

    @Test
    fun `aspect unwraps Optional return value and checks ownership`() {
        val securityManager = mockk<KomaguSecurityManager>(relaxed = true)
        val aspect = OwnershipAspect(securityManager)

        val method = DummyService::class.java.getMethod("getOptional", Boolean::class.javaPrimitiveType)
        val annotation = method.getAnnotation(RequireOwnership::class.java)

        val signature = mockk<MethodSignature>()
        every { signature.method } returns method
        every { signature.parameterNames } returns arrayOf("found")

        val joinPoint = mockk<ProceedingJoinPoint>()
        val resource = SampleResource("res-opt", "user-1", "tenant-1")
        every { joinPoint.signature } returns signature
        every { joinPoint.target } returns DummyService()
        every { joinPoint.args } returns arrayOf(true)
        every { joinPoint.proceed() } returns Optional.of(resource)

        aspect.enforceOwnership(joinPoint, annotation)

        verify(exactly = 1) { securityManager.requireOwnership(resource, ResourceOperation.READ) }
    }

    @Test
    fun `aspect unwraps ResponseEntity return value and checks ownership`() {
        val securityManager = mockk<KomaguSecurityManager>(relaxed = true)
        val aspect = OwnershipAspect(securityManager)

        val method = DummyService::class.java.getMethod("getResponseEntity")
        val annotation = method.getAnnotation(RequireOwnership::class.java)

        val signature = mockk<MethodSignature>()
        every { signature.method } returns method
        every { signature.parameterNames } returns emptyArray()

        val joinPoint = mockk<ProceedingJoinPoint>()
        val resource = SampleResource("res-resp", "user-1", "tenant-1")
        every { joinPoint.signature } returns signature
        every { joinPoint.target } returns DummyService()
        every { joinPoint.args } returns emptyArray()
        every { joinPoint.proceed() } returns ResponseEntity.ok(resource)

        aspect.enforceOwnership(joinPoint, annotation)

        verify(exactly = 1) { securityManager.requireOwnership(resource, ResourceOperation.READ) }
    }

    @Test
    fun `aspect unwraps Collection and Page return values and checks each item`() {
        val securityManager = mockk<KomaguSecurityManager>(relaxed = true)
        val aspect = OwnershipAspect(securityManager)

        // 1. Collection check
        val methodCol = DummyService::class.java.getMethod("getCollection")
        val annotCol = methodCol.getAnnotation(RequireOwnership::class.java)

        val sigCol = mockk<MethodSignature>()
        every { sigCol.method } returns methodCol
        every { sigCol.parameterNames } returns emptyArray()

        val jpCol = mockk<ProceedingJoinPoint>()
        val c1 = SampleResource("res-c1", "user-1", "tenant-1")
        val c2 = SampleResource("res-c2", "user-1", "tenant-1")
        every { jpCol.signature } returns sigCol
        every { jpCol.target } returns DummyService()
        every { jpCol.args } returns emptyArray()
        every { jpCol.proceed() } returns listOf(c1, c2)

        aspect.enforceOwnership(jpCol, annotCol)

        verify(exactly = 1) { securityManager.requireOwnership(c1, ResourceOperation.READ) }
        verify(exactly = 1) { securityManager.requireOwnership(c2, ResourceOperation.READ) }

        // 2. Page check
        val methodPage = DummyService::class.java.getMethod("getPage")
        val annotPage = methodPage.getAnnotation(RequireOwnership::class.java)

        val sigPage = mockk<MethodSignature>()
        every { sigPage.method } returns methodPage
        every { sigPage.parameterNames } returns emptyArray()

        val jpPage = mockk<ProceedingJoinPoint>()
        val p1 = SampleResource("res-p1", "user-1", "tenant-1")
        every { jpPage.signature } returns sigPage
        every { jpPage.target } returns DummyService()
        every { jpPage.args } returns emptyArray()
        every { jpPage.proceed() } returns PageImpl(listOf(p1))

        aspect.enforceOwnership(jpPage, annotPage)

        verify(exactly = 1) { securityManager.requireOwnership(p1, ResourceOperation.READ) }
    }

    @Test
    fun `aspect enforces class-level annotation when method has no annotation`() {
        val securityManager = mockk<KomaguSecurityManager>(relaxed = true)
        val aspect = OwnershipAspect(securityManager)

        val targetService = DummyClassAnnotatedService()
        val method = DummyClassAnnotatedService::class.java.getMethod("serviceMethod", SampleResource::class.java)

        val signature = mockk<MethodSignature>()
        every { signature.method } returns method
        every { signature.parameterNames } returns arrayOf("resource")

        val resource = SampleResource("res-cls", "user-1", "tenant-1")
        val joinPoint = mockk<ProceedingJoinPoint>()
        every { joinPoint.signature } returns signature
        every { joinPoint.target } returns targetService
        every { joinPoint.args } returns arrayOf(resource)
        every { joinPoint.proceed() } returns "class-annotated-result"

        val result = aspect.enforceOwnership(joinPoint)

        assertEquals("class-annotated-result", result)
        verify(exactly = 1) { securityManager.requireOwnership(resource, ResourceOperation.READ) }
    }

    @Test
    fun `aspect fails closed when no resource or resolver could be checked`() {
        val securityManager = mockk<KomaguSecurityManager>(relaxed = true)
        val aspect = OwnershipAspect(securityManager)

        val method = DummyService::class.java.getMethod("uncheckableMethod")
        val annotation = method.getAnnotation(RequireOwnership::class.java)

        val signature = mockk<MethodSignature>()
        every { signature.method } returns method
        every { signature.parameterNames } returns emptyArray()

        val joinPoint = mockk<ProceedingJoinPoint>()
        every { joinPoint.signature } returns signature
        every { joinPoint.target } returns DummyService()
        every { joinPoint.args } returns emptyArray()
        every { joinPoint.proceed() } returns "plain-string-no-resource"

        val ex = assertThrows<ResourceNotFoundException> {
            aspect.enforceOwnership(joinPoint, annotation)
        }
        assertTrue(ex.message!!.contains("no resource was verified"))
    }

    @Test
    fun `aspect resolves route id and ignores attacker-owned body object denying access on victim resource`() {
        // Arrange: Invariant from Issue #206:
        // Attacker calls updateWithBody(id = "res-victim", body = attackerOwnedResource)
        // Aspect MUST resolve "res-victim" server-side and verify caller against the stored victim resource,
        // ignoring the attacker-controlled body object as an authorization subject.
        val victimResource = SampleResource("res-victim", "victim", "tenant-1")
        val attackerBody = SampleResource("res-victim", "attacker", "tenant-1")
        val resolver = SampleResourceResolver(mapOf("res-victim" to victimResource))

        val securityManager = mockk<KomaguSecurityManager>()
        every {
            securityManager.requireOwnership(victimResource, ResourceOperation.UPDATE)
        } throws ResourceNotFoundException("Resource of type SampleResource with id 'res-victim' not found")

        val aspect = OwnershipAspect(securityManager, listOf(resolver))

        val method = DummyService::class.java.getMethod(
            "updateWithBody",
            String::class.java,
            SampleResource::class.java
        )
        val annotation = method.getAnnotation(RequireOwnership::class.java)

        val signature = mockk<MethodSignature>()
        every { signature.method } returns method
        every { signature.parameterNames } returns arrayOf("id", "body")

        val joinPoint = mockk<ProceedingJoinPoint>()
        every { joinPoint.signature } returns signature
        every { joinPoint.target } returns DummyService()
        every { joinPoint.args } returns arrayOf("res-victim", attackerBody)

        // Act & Assert
        assertThrows<ResourceNotFoundException> {
            aspect.enforceOwnership(joinPoint, annotation)
        }

        // Method handler MUST NEVER be invoked
        verify(exactly = 0) { joinPoint.proceed() }
        // Verify victim resource was checked for authorization
        verify(exactly = 1) { securityManager.requireOwnership(victimResource, ResourceOperation.UPDATE) }
        // Verify attacker body was NEVER used to satisfy authorization
        verify(exactly = 0) { securityManager.requireOwnership(attackerBody, any()) }
    }

    @Test
    fun `aspect fails closed when route id does not exist even if body contains attacker-owned resource`() {
        // Resolver does not have "res-missing"
        val resolver = SampleResourceResolver(emptyMap())
        val attackerBody = SampleResource("res-missing", "attacker", "tenant-1")
        val securityManager = mockk<KomaguSecurityManager>(relaxed = true)
        val aspect = OwnershipAspect(securityManager, listOf(resolver))

        val method = DummyService::class.java.getMethod(
            "updateWithBody",
            String::class.java,
            SampleResource::class.java
        )
        val annotation = method.getAnnotation(RequireOwnership::class.java)

        val signature = mockk<MethodSignature>()
        every { signature.method } returns method
        every { signature.parameterNames } returns arrayOf("id", "body")

        val joinPoint = mockk<ProceedingJoinPoint>()
        every { joinPoint.signature } returns signature
        every { joinPoint.target } returns DummyService()
        every { joinPoint.args } returns arrayOf("res-missing", attackerBody)

        val ex = assertThrows<ResourceNotFoundException> {
            aspect.enforceOwnership(joinPoint, annotation)
        }
        assertTrue(ex.message!!.contains("not found"))

        // Critical: verify proceed() was NEVER invoked
        verify(exactly = 0) { joinPoint.proceed() }
        verify(exactly = 0) { securityManager.requireOwnership(attackerBody, any()) }
    }
}
