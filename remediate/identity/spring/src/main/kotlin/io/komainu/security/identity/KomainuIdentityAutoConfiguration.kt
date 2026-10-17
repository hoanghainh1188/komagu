package io.komainu.security.identity

import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtDecoders
import org.springframework.security.oauth2.jwt.JwtValidators
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.web.SecurityFilterChain
import java.time.Duration

/**
 * Spring Boot AutoConfiguration for Komainu OIDC / JWT Resource Server.
 */
@AutoConfiguration
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
    @ConditionalOnProperty(prefix = "komainu.security.oidc", name = ["jwk-set-uri"])
    @ConditionalOnMissingBean
    fun jwkSetUriJwtDecoder(properties: KomainuOidcProperties): JwtDecoder {
        val decoder = NimbusJwtDecoder.withJwkSetUri(properties.jwkSetUri!!).build()

        val defaultValidators = if (properties.issuer.isNotBlank()) {
            JwtValidators.createDefaultWithIssuer(properties.issuer)
        } else {
            JwtValidators.createDefault()
        }

        val audienceValidator = KomainuAudienceValidator(properties.audience)
        decoder.setJwtValidator(DelegatingOAuth2TokenValidator(defaultValidators, audienceValidator))
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
