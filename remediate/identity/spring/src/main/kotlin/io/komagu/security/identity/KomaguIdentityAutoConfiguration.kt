package io.komagu.security.identity

import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtIssuerValidator
import org.springframework.security.oauth2.jwt.JwtTimestampValidator
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.web.SecurityFilterChain
import java.time.Duration

/**
 * Spring Boot AutoConfiguration for Komagu OIDC / JWT Resource Server.
 */
@AutoConfiguration
@AutoConfigureBefore(name = ["org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration"])
@EnableWebSecurity
@EnableConfigurationProperties(KomaguOidcProperties::class)
class KomaguIdentityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    fun komaguJwtAuthenticationConverter(properties: KomaguOidcProperties): KomaguJwtAuthenticationConverter {
        return KomaguJwtAuthenticationConverter(
            userClaimName = properties.userClaimName,
            tenantClaimName = properties.tenantClaimName
        )
    }

    @Bean
    @ConditionalOnMissingBean(JwtDecoder::class)
    fun komaguJwtDecoder(
        properties: KomaguOidcProperties,
        @Value("\${spring.security.oauth2.resourceserver.jwt.issuer-uri:}") bootIssuerUri: String = ""
    ): JwtDecoder {
        val effectiveIssuer = when {
            properties.issuer.isNotBlank() -> properties.issuer.trim()
            bootIssuerUri.isNotBlank() -> bootIssuerUri.trim()
            else -> ""
        }

        check(properties.audience.isNotBlank()) { "komagu.security.oidc.audience must not be blank" }
        check(properties.clockSkewSeconds in 0L..120L) {
            "komagu.security.oidc.clock-skew-seconds must be between 0 and 120 (got ${properties.clockSkewSeconds})"
        }

        val decoder = buildDecoder(properties, effectiveIssuer)

        val expirationValidator = KomaguExpirationValidator()
        val timestampValidator = JwtTimestampValidator(Duration.ofSeconds(properties.clockSkewSeconds))
        val issuerValidator = JwtIssuerValidator(effectiveIssuer)
        val audienceValidator = KomaguAudienceValidator(properties.audience)
        val subjectValidator = KomaguSubjectValidator(properties.userClaimName)

        decoder.setJwtValidator(
            DelegatingOAuth2TokenValidator(
                expirationValidator,
                timestampValidator,
                issuerValidator,
                audienceValidator,
                subjectValidator
            )
        )
        return decoder
    }

    private fun buildDecoder(properties: KomaguOidcProperties, effectiveIssuer: String): NimbusJwtDecoder {
        val jwkUri = properties.jwkSetUri?.trim()
        return when {
            !jwkUri.isNullOrBlank() -> {
                check(effectiveIssuer.isNotBlank()) { "komagu.security.oidc.issuer must not be blank" }
                check(properties.allowInsecureHttpJwks || isHttps(jwkUri)) {
                    "komagu.security.oidc.jwk-set-uri must use HTTPS ($jwkUri). " +
                        "Set komagu.security.oidc.allow-insecure-http-jwks=true only for testing."
                }
                NimbusJwtDecoder.withJwkSetUri(jwkUri).build()
            }
            effectiveIssuer.isNotBlank() -> {
                check(properties.allowInsecureHttpJwks || isHttps(effectiveIssuer)) {
                    "OIDC issuer URI must use HTTPS ($effectiveIssuer). " +
                        "Set komagu.security.oidc.allow-insecure-http-jwks=true only for testing."
                }
                NimbusJwtDecoder.withIssuerLocation(effectiveIssuer).build()
            }
            else -> error(
                "Either komagu.security.oidc.jwk-set-uri or komagu.security.oidc.issuer " +
                    "(or spring.security.oauth2.resourceserver.jwt.issuer-uri) must be configured"
            )
        }
    }

    private fun isHttps(uri: String): Boolean = uri.lowercase().startsWith("https://")

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain::class)
    fun komaguSecurityFilterChain(
        http: HttpSecurity,
        converter: KomaguJwtAuthenticationConverter
    ): SecurityFilterChain {
        http
            .csrf { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .authorizeHttpRequests { auth ->
                auth.requestMatchers("/api/v1/auth/**", "/health/**", "/error").permitAll()
                auth.anyRequest().authenticated()
            }
            .oauth2ResourceServer { oauth2 ->
                oauth2.jwt { jwt ->
                    jwt.jwtAuthenticationConverter(converter)
                }
            }

        return http.build()
    }
}
