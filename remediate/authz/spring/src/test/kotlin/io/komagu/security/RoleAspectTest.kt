package io.komagu.security

import io.komagu.security.authorization.DefaultKomaguSecurityManager
import io.komagu.security.authorization.SecurityAuditEvent
import io.komagu.security.authorization.SecurityAuditSink
import io.komagu.security.spring.AuthenticationRequiredException
import io.komagu.security.spring.RequireRole
import io.komagu.security.spring.ResourceNotFoundException
import io.komagu.security.spring.RoleAspect
import io.komagu.security.spring.RoleDeniedException
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.aop.aspectj.annotation.AspectJProxyFactory
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.context.request.ServletRequestAttributes
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RoleAspectTest {

    open class AdminService {
        @RequireRole("admin")
        open fun deleteUser(userId: String): String = "deleted-$userId"

        @RequireRole("admin", "auditor")
        open fun exportLogs(): String = "logs"

        @RequireRole("admin", hideAsNotFound = true)
        open fun hiddenEndpoint(): String = "hidden"

        @RequireRole("ROLE_admin")
        open fun prefixedRequirement(): String = "prefixed"

        @RequireRole
        open fun misconfigured(): String = "never"

        /** Simulates a controller that also receives client-controlled role data. */
        @RequireRole("admin")
        open fun promote(role: String, body: Map<String, Any?>): String = "promoted-$role"

        open fun unprotected(): String = "open"
    }

    @RequireRole("admin")
    open class AdminOnlyController {
        open fun dashboard(): String = "dashboard"

        @RequireRole("auditor")
        open fun auditTrail(): String = "audit"
    }

    private val events = mutableListOf<SecurityAuditEvent>()
    private val sink = SecurityAuditSink { events.add(it) }

    private fun aspect(hideDeniedAsNotFound: Boolean = false) =
        RoleAspect(DefaultKomaguSecurityManager(sink), sink, hideDeniedAsNotFound)

    private inline fun <reified T : Any> proxy(target: T, aspect: RoleAspect = aspect()): T {
        val factory = AspectJProxyFactory(target)
        factory.isProxyTargetClass = true
        factory.addAspect(aspect)
        return factory.getProxy()
    }

    private fun authenticate(user: String, vararg authorities: String) {
        val auth = TestingAuthenticationToken(user, null, *authorities)
        auth.details = mapOf("tenant_id" to "tenant-1")
        SecurityContextHolder.getContext().authentication = auth
    }

    @AfterEach
    fun clear() {
        SecurityContextHolder.clearContext()
        RequestContextHolder.resetRequestAttributes()
    }

    @Test
    fun `caller with the required role is allowed`() {
        authenticate("alice", "ROLE_admin")
        assertEquals("deleted-42", proxy(AdminService()).deleteUser("42"))
        assertTrue(events.isEmpty())
    }

    @Test
    fun `any one of several required roles is enough`() {
        authenticate("bob", "ROLE_auditor")
        assertEquals("logs", proxy(AdminService()).exportLogs())
    }

    @Test
    fun `caller without the role is denied with 403`() {
        authenticate("mallory", "ROLE_user")
        assertThrows<RoleDeniedException> { proxy(AdminService()).deleteUser("42") }
    }

    @Test
    fun `annotation attribute hides the endpoint with 404`() {
        authenticate("mallory", "ROLE_user")
        assertThrows<ResourceNotFoundException> { proxy(AdminService()).hiddenEndpoint() }
    }

    @Test
    fun `configured default hides every denied endpoint with 404`() {
        authenticate("mallory", "ROLE_user")
        assertThrows<ResourceNotFoundException> {
            proxy(AdminService(), aspect(hideDeniedAsNotFound = true)).deleteUser("42")
        }
    }

    @Test
    fun `unauthenticated caller gets 401`() {
        assertThrows<AuthenticationRequiredException> { proxy(AdminService()).deleteUser("42") }
    }

    @Test
    fun `anonymous token is treated as unauthenticated`() {
        SecurityContextHolder.getContext().authentication = AnonymousAuthenticationToken(
            "key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS", "ROLE_admin")
        )
        assertThrows<AuthenticationRequiredException> { proxy(AdminService()).deleteUser("42") }
    }

    @Test
    fun `role claimed in request parameter, header, body or argument is ignored`() {
        authenticate("mallory", "ROLE_user")
        val request = MockHttpServletRequest("POST", "/admin/promote")
        request.addParameter("role", "admin")
        request.addHeader("X-Role", "admin")
        request.contentType = "application/json"
        request.setContent("""{"role":"admin","isAdmin":true}""".toByteArray())
        RequestContextHolder.setRequestAttributes(ServletRequestAttributes(request))

        assertThrows<RoleDeniedException> {
            proxy(AdminService()).promote("admin", mapOf("role" to "admin", "isAdmin" to true))
        }
        assertEquals(1, events.size)
    }

    @Test
    fun `ROLE_ prefix is normalized on both sides, the name stays case-sensitive`() {
        authenticate("alice", "admin")
        assertEquals("deleted-1", proxy(AdminService()).deleteUser("1"))
        assertEquals("prefixed", proxy(AdminService()).prefixedRequirement())

        authenticate("carol", "ROLE_Admin", "SCOPE_admin")
        assertThrows<RoleDeniedException> { proxy(AdminService()).deleteUser("1") }
    }

    @Test
    fun `denial emits a RoleDenied audit event with actor and required roles`() {
        authenticate("mallory", "ROLE_user")
        assertThrows<RoleDeniedException> { proxy(AdminService()).exportLogs() }

        val event = events.single()
        assertEquals(SecurityAuditEvent.ROLE_DENIED, event.eventName)
        assertEquals("Komagu.Authorization.RoleDenied", event.eventName)
        assertEquals("mallory", event.actorUserId)
        assertEquals("tenant-1", event.actorTenantId)
        assertEquals("AdminService.exportLogs", event.resourceId)
        assertTrue(event.reason.contains("admin") && event.reason.contains("auditor"), event.reason)
    }

    @Test
    fun `failing audit sink does not change the denial`() {
        authenticate("mallory", "ROLE_user")
        val failing = SecurityAuditSink { error("sink down") }
        val aspect = RoleAspect(DefaultKomaguSecurityManager(failing), failing)
        assertThrows<RoleDeniedException> { proxy(AdminService(), aspect).deleteUser("42") }
    }

    @Test
    fun `empty role list fails fast before the method runs`() {
        authenticate("alice", "ROLE_admin")
        assertThrows<IllegalStateException> { proxy(AdminService()).misconfigured() }
        assertThrows<IllegalStateException> { aspect().requireAnyRole(listOf(" ")) }
    }

    @Test
    fun `class-level annotation applies and a method-level one overrides it`() {
        authenticate("bob", "ROLE_auditor")
        val controller = proxy(AdminOnlyController())
        assertThrows<RoleDeniedException> { controller.dashboard() }
        assertEquals("audit", controller.auditTrail())
    }

    @Test
    fun `unannotated method is not intercepted`() {
        assertEquals("open", proxy(AdminService()).unprotected())
    }
}
