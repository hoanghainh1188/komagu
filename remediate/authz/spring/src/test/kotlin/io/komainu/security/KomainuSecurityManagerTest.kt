package io.komainu.security

import io.komainu.security.authorization.*
import io.komainu.security.spring.ResourceNotFoundException
import io.mockk.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.jwt.Jwt
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class KomainuSecurityManagerTest {

    private lateinit var auditSink: SecurityAuditSink
    private lateinit var securityManager: DefaultKomainuSecurityManager

    data class TestDocument(
        override val id: UUID,
        override val ownerUserId: String,
        override val tenantId: String,
        val content: String
    ) : OwnedResource<UUID>

    @BeforeEach
    fun setUp() {
        auditSink = mockk(relaxed = true)
        securityManager = DefaultKomainuSecurityManager(auditSink)
    }

    @AfterEach
    fun tearDown() {
        SecurityContextHolder.clearContext()
        clearAllMocks()
    }

    private fun setupSecurityContext(userId: String, tenantId: String) {
        val jwt = mockk<Jwt>()
        every { jwt.getClaimAsString("sub") } returns userId
        every { jwt.getClaimAsString("tenant_id") } returns tenantId

        val auth = mockk<Authentication>()
        every { auth.isAuthenticated } returns true
        every { auth.principal } returns jwt
        every { auth.name } returns userId

        val context = mockk<SecurityContext>()
        every { context.authentication } returns auth

        SecurityContextHolder.setContext(context)
    }

    @Test
    fun `requireOwnership succeeds when user owns resource in same tenant`() {
        // Arrange
        setupSecurityContext("user-100", "tenant-alpha")
        val doc = TestDocument(UUID.randomUUID(), "user-100", "tenant-alpha", "Sensitive data")

        // Act & Assert (Should not throw)
        securityManager.requireOwnership(doc, ResourceOperation.READ)
        verify(exactly = 0) { auditSink.emit(any()) }
    }

    @Test
    fun `requireOwnership throws ResourceNotFoundException and emits audit when owner mismatches`() {
        // Arrange: Invariant: Deny by default with HTTP 404 Not Found
        setupSecurityContext("attacker-999", "tenant-alpha")
        val victimDoc = TestDocument(UUID.randomUUID(), "victim-100", "tenant-alpha", "Confidential")

        // Act & Assert
        val exception = assertThrows<ResourceNotFoundException> {
            securityManager.requireOwnership(victimDoc, ResourceOperation.READ)
        }

        assertTrue(exception.message!!.contains("User ownership violation"))

        verify(exactly = 1) {
            auditSink.emit(match { event ->
                event.actorUserId == "attacker-999" &&
                        event.actorTenantId == "tenant-alpha" &&
                        event.resourceType == "TestDocument" &&
                        event.resourceId == victimDoc.id.toString() &&
                        event.reason.contains("User ownership violation")
            })
        }
    }

    @Test
    fun `requireOwnership throws ResourceNotFoundException when tenant mismatches`() {
        // Arrange
        setupSecurityContext("user-100", "tenant-beta")
        val doc = TestDocument(UUID.randomUUID(), "user-100", "tenant-alpha", "Cross tenant file")

        // Act & Assert
        assertThrows<ResourceNotFoundException> {
            securityManager.requireOwnership(doc, ResourceOperation.READ)
        }

        verify(exactly = 1) {
            auditSink.emit(match { it.reason.contains("Tenant boundary violation") })
        }
    }

    @Test
    fun `checkOwnership returns denied when unauthenticated`() {
        // Arrange
        SecurityContextHolder.clearContext()
        val doc = TestDocument(UUID.randomUUID(), "user-100", "tenant-alpha", "Data")

        // Act
        val decision = securityManager.checkOwnership(doc, ResourceOperation.READ)

        // Assert
        assertFalse(decision.granted)
        assertTrue(decision.failureReason!!.contains("unauthenticated"))
        verify(exactly = 1) { auditSink.emit(any()) }
    }
}
