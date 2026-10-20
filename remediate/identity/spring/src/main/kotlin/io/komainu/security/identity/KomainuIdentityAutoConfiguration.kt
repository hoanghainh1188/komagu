package io.komainu.security.identity

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
 * Spring Boot AutoConfiguration for Komainu OIDC / JWT Resource Server.
 */
@AutoConfiguration
@AutoConfigureBefore(name = ["org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration"])
@EnableWebSecurity
@EnableConfigurationProperties(KomainuOidcProperties::class)
class KomainuIdentityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    fun komainuJwtAuthenticationConverter(properties: KomainuOidcProperties): KomainuJwtAuthenticationConverter {
        return KomainuJwtAuthenticationConverter(
            userClaimName = properties.userClaimName,
            tenantClaimName = properties.tenantClaimName
        )
    }

    @Bean
    @ConditionalOnMissingBean(JwtDecoder::class)
    fun komainuJwtDecoder(
        properties: KomainuOidcProperties,
        @Value("\${spring.security.oauth2.resourceserver.jwt.issuer-uri:}") bootIssuerUri: String = ""
    ): JwtDecoder {
        val effectiveIssuer = when {
            properties.issuer.isNotBlank() -> properties.issuer.trim()
            bootIssuerUri.isNotBlank() -> bootIssuerUri.trim()
            else -> ""
        }

        if (properties.audience.isBlank()) {
            throw IllegalStateException("komainu.security.oidc.audience must not be blank")
        }

        if (properties.clockSkewSeconds < 0L || properties.clockSkewSeconds > 120L) {
            throw IllegalStateException(
                "komainu.security.oidc.clock-skew-seconds must be between 0 and 120 (got ${properties.clockSkewSeconds})"
            )
        }

        val jwkUri = properties.jwkSetUri?.trim()
        val decoder: NimbusJwtDecoder = when {
            !jwkUri.isNullOrBlank() -> {
                if (effectiveIssuer.isBlank()) {
                    throw IllegalStateException("komainu.security.oidc.issuer must not be blank")
                }
                if (!properties.allowInsecureHttpJwks && !jwkUri.lowercase().startsWith("https://")) {
                    throw IllegalStateException(
                        "komainu.security.oidc.jwk-set-uri must use HTTPS ($jwkUri). " +
                        "Set komainu.security.oidc.allow-insecure-http-jwks=true only for testing."
                    )
                }
                NimbusJwtDecoder.withJwkSetUri(jwkUri).build()
            }
            effectiveIssuer.isNotBlank() -> {
                if (!properties.allowInsecureHttpJwks && !effectiveIssuer.lowercase().startsWith("https://")) {
                    throw IllegalStateException(
                        "OIDC issuer URI must use HTTPS ($effectiveIssuer). " +
                        "Set komainu.security.oidc.allow-insecure-http-jwks=true only for testing."
                    )
                }
                NimbusJwtDecoder.withIssuerLocation(effectiveIssuer).build()
            }
            else -> {
                throw IllegalStateException(
                    "Either komainu.security.oidc.jwk-set-uri or komainu.security.oidc.issuer " +
                    "(or spring.security.oauth2.resourceserver.jwt.issuer-uri) must be configured"
                )
            }
        }

        val expirationValidator = KomainuExpirationValidator()
        val timestampValidator = JwtTimestampValidator(Duration.ofSeconds(properties.clockSkewSeconds))
        val issuerValidator = JwtIssuerValidator(effectiveIssuer)
        val audienceValidator = KomainuAudienceValidator(properties.audience)
        val subjectValidator = KomainuSubjectValidator(properties.userClaimName)

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

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain::class)
    fun komainuSecurityFilterChain(
        http: HttpSecurity,
        converter: KomainuJwtAuthenticationConverter
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
