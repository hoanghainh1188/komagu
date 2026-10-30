package io.komagu.security.identity

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.boot.context.properties.bind.Binder
import org.springframework.boot.logging.DeferredLogFactory
import org.springframework.core.env.MapPropertySource
import org.springframework.core.env.PropertySource
import org.springframework.core.env.StandardEnvironment
import org.springframework.core.env.SystemEnvironmentPropertySource

class LegacyKomainuPropertiesPostProcessorTest {

    private val processor = LegacyKomainuPropertiesPostProcessor(DeferredLogFactory { it.get() })

    private fun bind(env: StandardEnvironment): KomaguOidcProperties =
        Binder.get(env).bind("komagu.security.oidc", KomaguOidcProperties::class.java).orElseGet { KomaguOidcProperties() }

    private fun envWith(vararg sources: PropertySource<*>): StandardEnvironment {
        val env = StandardEnvironment()
        env.propertySources.toList().forEach { env.propertySources.remove(it.name) }
        sources.forEach { env.propertySources.addLast(it) }
        return env
    }

    @Test
    fun `legacy properties bind to the komagu prefix`() {
        val env = envWith(
            MapPropertySource(
                "app",
                mapOf(
                    "komainu.security.oidc.issuer" to "https://auth.example.com",
                    "komainu.security.oidc.jwk-set-uri" to "https://auth.example.com/certs",
                    "komainu.security.oidc.clock-skew-seconds" to "30"
                )
            )
        )
        processor.postProcessEnvironment(env, null)

        val props = bind(env)
        assertEquals("https://auth.example.com", props.issuer)
        assertEquals("https://auth.example.com/certs", props.jwkSetUri)
        assertEquals(30L, props.clockSkewSeconds)
    }

    @Test
    fun `explicit komagu properties win over legacy ones`() {
        val env = envWith(
            MapPropertySource("low", mapOf("komagu.security.oidc.audience" to "new-api")),
            MapPropertySource("high", mapOf("komainu.security.oidc.audience" to "old-api"))
        )
        processor.postProcessEnvironment(env, null)

        assertEquals("new-api", bind(env).audience)
    }

    @Test
    fun `legacy environment variables are mapped`() {
        val env = envWith(
            SystemEnvironmentPropertySource(
                "systemEnvironment",
                mapOf<String, Any>("KOMAINU_SECURITY_OIDC_ALLOWINSECUREHTTPJWKS" to "true")
            )
        )
        processor.postProcessEnvironment(env, null)

        assertEquals(true, bind(env).allowInsecureHttpJwks)
    }

    @Test
    fun `nothing is added without legacy properties`() {
        val env = envWith(MapPropertySource("app", mapOf("komagu.security.oidc.audience" to "x")))
        processor.postProcessEnvironment(env, null)

        assertNull(env.propertySources.get(LegacyKomainuPropertiesPostProcessor.SOURCE_NAME))
    }

    @Test
    fun `post processor is registered in spring factories`() {
        val factories = javaClass.classLoader.getResource("META-INF/spring.factories")!!.readText()
        assertTrue("org.springframework.boot.env.EnvironmentPostProcessor" in factories)
        assertTrue(LegacyKomainuPropertiesPostProcessor::class.java.name in factories)
    }
}
