package io.komagu.security

import io.komagu.security.spring.KomaguSecurityAutoConfiguration
import io.komagu.security.spring.OwnershipAspect
import io.komagu.security.spring.ResourceOwnershipResolver
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
}
