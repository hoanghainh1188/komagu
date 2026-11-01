package io.komagu.security

import io.komagu.security.spring.KomaguSecurityAutoConfiguration
import io.komagu.security.spring.OwnershipAspect
import io.komagu.security.spring.ResourceNotFoundException
import io.komagu.security.spring.ResourceOwnershipResolver
import io.komagu.security.spring.RoleAspect
import io.komagu.security.spring.RoleDeniedException
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.assertThrows
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.test.context.runner.ApplicationContextRunner

class KomaguSecurityAutoConfigurationTest {

    private val contextRunner = ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(KomaguSecurityAutoConfiguration::class.java))

    @Test
    fun `ownership aspect is created when the app defines no resolvers`() {
        contextRunner.run { context ->
            assertThat(context).hasNotFailed()
            assertThat(context).hasSingleBean(OwnershipAspect::class.java)
        }
    }

    @Test
    fun `ownership aspect is created with app resolvers`() {
        contextRunner
            .withBean("orderResolver", ResourceOwnershipResolver::class.java, {
                object : ResourceOwnershipResolver<Any> {
                    override fun supports(entityClass: Class<*>) = true
                    override fun resolve(id: Any): Any? = null
                }
            })
            .run { context ->
                assertThat(context).hasNotFailed()
                assertThat(context).hasSingleBean(OwnershipAspect::class.java)
            }
    }

    @AfterEach
    fun clear() = SecurityContextHolder.clearContext()

    @Test
    fun `role aspect is auto-configured and denies with 403 by default`() {
        contextRunner.run { context ->
            assertThat(context).hasNotFailed()
            assertThat(context).hasSingleBean(RoleAspect::class.java)
            SecurityContextHolder.getContext().authentication = TestingAuthenticationToken("u", null, "ROLE_user")
            assertThrows<RoleDeniedException> {
                context.getBean(RoleAspect::class.java).requireAnyRole(listOf("admin"))
            }
        }
    }

    @Test
    fun `role denial maps to 404 when the hide property is set`() {
        contextRunner
            .withPropertyValues("${KomaguSecurityAutoConfiguration.HIDE_ROLE_DENIED_PROPERTY}=true")
            .run { context ->
                SecurityContextHolder.getContext().authentication = TestingAuthenticationToken("u", null, "ROLE_user")
                assertThrows<ResourceNotFoundException> {
                    context.getBean(RoleAspect::class.java).requireAnyRole(listOf("admin"))
                }
            }
    }
}
