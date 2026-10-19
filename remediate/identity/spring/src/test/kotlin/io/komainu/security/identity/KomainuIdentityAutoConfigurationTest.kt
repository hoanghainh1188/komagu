package io.komainu.security.identity

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.test.context.runner.ApplicationContextRunner

class KomainuIdentityAutoConfigurationTest {

    private val contextRunner = ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(KomainuIdentityAutoConfiguration::class.java))

    @Test
    fun `fails startup when jwk-set-uri is set but issuer is blank`() {
        contextRunner
            .withPropertyValues(
                "komainu.security.oidc.jwk-set-uri=https://auth.example.com/certs",
                "komainu.security.oidc.issuer=",
                "komainu.security.oidc.audience=my-api"
            )
            .run { context ->
                assertThat(context).hasFailed()
                assertThat(context.startupFailure)
                    .hasRootCauseInstanceOf(IllegalStateException::class.java)
                    .hasRootCauseMessage("komainu.security.oidc.issuer must not be blank")
            }
    }

    @Test
    fun `fails startup when jwk-set-uri is set but audience is blank`() {
        contextRunner
            .withPropertyValues(
                "komainu.security.oidc.jwk-set-uri=https://auth.example.com/certs",
                "komainu.security.oidc.issuer=https://auth.example.com",
                "komainu.security.oidc.audience="
            )
            .run { context ->
                assertThat(context).hasFailed()
                assertThat(context.startupFailure)
                    .hasRootCauseInstanceOf(IllegalStateException::class.java)
                    .hasRootCauseMessage("komainu.security.oidc.audience must not be blank")
            }
    }

    @Test
    fun `fails startup when jwk-set-uri uses plaintext HTTP and allowInsecureHttpJwks is false`() {
        contextRunner
            .withPropertyValues(
                "komainu.security.oidc.jwk-set-uri=http://auth.example.com/certs",
                "komainu.security.oidc.issuer=https://auth.example.com",
                "komainu.security.oidc.audience=my-api"
            )
            .run { context ->
                assertThat(context).hasFailed()
                assertThat(context.startupFailure)
                    .hasRootCauseInstanceOf(IllegalStateException::class.java)
                assertThat(context.startupFailure?.cause?.message ?: context.startupFailure?.message)
                    .contains("must use HTTPS")
            }
    }

    @Test
    fun `starts up successfully when allowInsecureHttpJwks is true`() {
        contextRunner
            .withPropertyValues(
                "komainu.security.oidc.jwk-set-uri=http://localhost:8080/certs",
                "komainu.security.oidc.allow-insecure-http-jwks=true",
                "komainu.security.oidc.issuer=https://auth.example.com",
                "komainu.security.oidc.audience=my-api"
            )
            .run { context ->
                assertThat(context).hasNotFailed()
                assertThat(context).hasSingleBean(org.springframework.security.oauth2.jwt.JwtDecoder::class.java)
            }
    }
}
