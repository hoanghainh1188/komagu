package io.komagu.security.identity

import org.springframework.boot.SpringApplication
import org.springframework.boot.context.config.ConfigDataEnvironmentPostProcessor
import org.springframework.boot.env.EnvironmentPostProcessor
import org.springframework.boot.logging.DeferredLogFactory
import org.springframework.core.Ordered
import org.springframework.core.env.ConfigurableEnvironment
import org.springframework.core.env.EnumerablePropertySource
import org.springframework.core.env.MapPropertySource

/**
 * Maps deprecated pre-rename `komainu.security.*` properties (and `KOMAINU_SECURITY_*` env vars)
 * onto `komagu.security.*` (#290). The mapped values are added last, so any `komagu.security.*`
 * value set explicitly still wins. Remove in the next major release.
 */
class LegacyKomainuPropertiesPostProcessor(logFactory: DeferredLogFactory) : EnvironmentPostProcessor, Ordered {

    private val log = logFactory.getLog(javaClass)

    override fun postProcessEnvironment(environment: ConfigurableEnvironment, application: SpringApplication?) {
        val mapped = linkedMapOf<String, Any>()
        // Property sources iterate highest precedence first, so the first legacy value seen wins.
        for (source in environment.propertySources) {
            if (source !is EnumerablePropertySource<*> || source.name == SOURCE_NAME) continue
            for (name in source.propertyNames) {
                val current = currentName(name) ?: continue
                if (current !in mapped) {
                    source.getProperty(name)?.let { mapped[current] = it }
                }
            }
        }
        if (mapped.isEmpty()) return
        log.warn(
            "komainu.security.* properties are deprecated, rename them to komagu.security.* " +
                "(mapped: ${mapped.keys.joinToString()})"
        )
        environment.propertySources.addLast(MapPropertySource(SOURCE_NAME, mapped))
    }

    override fun getOrder(): Int = ConfigDataEnvironmentPostProcessor.ORDER + 1

    companion object {
        const val SOURCE_NAME = "legacyKomainuProperties"
        private const val LEGACY_PREFIX = "komainu.security."
        private const val LEGACY_ENV_PREFIX = "KOMAINU_SECURITY_"
        private const val PREFIX = "komagu.security."

        fun currentName(name: String): String? = when {
            name.startsWith(LEGACY_PREFIX) -> PREFIX + name.removePrefix(LEGACY_PREFIX)
            name.startsWith(LEGACY_ENV_PREFIX) ->
                PREFIX + name.removePrefix(LEGACY_ENV_PREFIX).lowercase().replace('_', '.')
            else -> null
        }
    }
}
