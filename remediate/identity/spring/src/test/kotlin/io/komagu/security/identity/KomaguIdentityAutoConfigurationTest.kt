package io.komagu.security.identity

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.sun.net.httpserver.HttpServer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.test.context.runner.ApplicationContextRunner
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtValidationException
import java.net.InetSocketAddress

class KomaguIdentityAutoConfigurationTest {

    private val contextRunner = ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(KomaguIdentityAutoConfiguration::class.java))

    @Test
    fun `fails startup when jwk-set-uri is set but issuer is blank`() {
        contextRunner
            .withPropertyValues(
                "komagu.security.oidc.jwk-set-uri=https://auth.example.com/certs",
                "komagu.security.oidc.issuer=",
                "komagu.security.oidc.audience=my-api"
            )
            .run { context ->
                assertThat(context).hasFailed()
                assertThat(context.startupFailure)
                    .hasRootCauseInstanceOf(IllegalStateException::class.java)
                    .hasRootCauseMessage("komagu.security.oidc.issuer must not be blank")
            }
    }

    @Test
    fun `fails startup when jwk-set-uri is set but audience is blank`() {
        contextRunner
            .withPropertyValues(
                "komagu.security.oidc.jwk-set-uri=https://auth.example.com/certs",
                "komagu.security.oidc.issuer=https://auth.example.com",
                "komagu.security.oidc.audience="
            )
            .run { context ->
                assertThat(context).hasFailed()
                assertThat(context.startupFailure)
                    .hasRootCauseInstanceOf(IllegalStateException::class.java)
                    .hasRootCauseMessage("komagu.security.oidc.audience must not be blank")
            }
    }

    @Test
    fun `fails startup when jwk-set-uri uses plaintext HTTP and allowInsecureHttpJwks is false`() {
        contextRunner
            .withPropertyValues(
                "komagu.security.oidc.jwk-set-uri=http://auth.example.com/certs",
                "komagu.security.oidc.issuer=https://auth.example.com",
                "komagu.security.oidc.audience=my-api"
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
                "komagu.security.oidc.jwk-set-uri=http://localhost:8080/certs",
                "komagu.security.oidc.allow-insecure-http-jwks=true",
                "komagu.security.oidc.issuer=https://auth.example.com",
                "komagu.security.oidc.audience=my-api"
            )
            .run { context ->
                assertThat(context).hasNotFailed()
                assertThat(context).hasSingleBean(org.springframework.security.oauth2.jwt.JwtDecoder::class.java)
            }
    }

    @Test
    fun `production jwkSetUriJwtDecoder rejects tokens without exp, sub, iss, or aud`() {
        val jwtFactory = TestJwtFactory()
        val rsaKey = RSAKey.Builder(jwtFactory.publicKey)
            .keyID("komagu-test-key-1")
            .build()
        val jwkSetJson = JWKSet(rsaKey).toString()

        // Start an embedded lightweight HTTP server serving the JWKS
        val server = HttpServer.create(InetSocketAddress(0), 0)
        server.createContext("/certs") { exchange ->
            val responseBytes = jwkSetJson.toByteArray(Charsets.UTF_8)
            exchange.responseHeaders.set("Content-Type", "application/json")
            exchange.sendResponseHeaders(200, responseBytes.size.toLong())
            exchange.responseBody.use { it.write(responseBytes) }
        }
        server.start()

        val port = server.address.port
        val issuer = "https://auth.komagu.test/realms/komagu"
        val audience = "komagu-api"

        try {
            contextRunner
                .withPropertyValues(
                    "komagu.security.oidc.jwk-set-uri=http://127.0.0.1:$port/certs",
                    "komagu.security.oidc.allow-insecure-http-jwks=true",
                    "komagu.security.oidc.issuer=$issuer",
                    "komagu.security.oidc.audience=$audience"
                )
                .run { context ->
                    assertThat(context).hasNotFailed()
                    val decoder = context.getBean(JwtDecoder::class.java)

                    // 1. Valid token passes
                    val validToken = jwtFactory.createToken(
                        issuer = issuer,
                        audience = audience,
                        subject = "valid-user"
                    )
                    val jwt = decoder.decode(validToken)
                    assertThat(jwt.subject).isEqualTo("valid-user")

                    // 2. Token without 'exp' claim is rejected (Invariant from Issue #207)
                    val noExpToken = jwtFactory.createToken(
                        issuer = issuer,
                        audience = audience,
                        subject = "valid-user",
                        expirationTime = null
                    )
                    val expEx = assertThrows<JwtValidationException> {
                        decoder.decode(noExpToken)
                    }
                    assertThat(expEx.message).contains("exp")

                    // 3. Token without 'sub' claim is rejected
                    val noSubToken = jwtFactory.createToken(
                        issuer = issuer,
                        audience = audience,
                        subject = null
                    )
                    val subEx = assertThrows<JwtValidationException> {
                        decoder.decode(noSubToken)
                    }
                    assertThat(subEx.message).contains("sub")

                    // 4. Token with mismatched issuer is rejected
                    val wrongIssToken = jwtFactory.createToken(
                        issuer = "https://untrusted.issuer.com",
                        audience = audience,
                        subject = "valid-user"
                    )
                    assertThrows<JwtValidationException> {
                        decoder.decode(wrongIssToken)
                    }

                    // 5. Token with mismatched audience is rejected
                    val wrongAudToken = jwtFactory.createToken(
                        issuer = issuer,
                        audience = "wrong-aud",
                        subject = "valid-user"
                    )
                    assertThrows<JwtValidationException> {
                        decoder.decode(wrongAudToken)
                    }
                }
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun `fails startup when neither jwk-set-uri nor issuer is configured`() {
        contextRunner
            .withPropertyValues(
                "komagu.security.oidc.audience=my-api"
            )
            .run { context ->
                assertThat(context).hasFailed()
                assertThat(context.startupFailure)
                    .hasRootCauseInstanceOf(IllegalStateException::class.java)
                assertThat(context.startupFailure?.cause?.message ?: context.startupFailure?.message)
                    .contains("Either komagu.security.oidc.jwk-set-uri or komagu.security.oidc.issuer")
            }
    }

    @Test
    fun `fails startup when clockSkewSeconds is out of bounds`() {
        // Exceeds 120 seconds
        contextRunner
            .withPropertyValues(
                "komagu.security.oidc.jwk-set-uri=https://auth.example.com/certs",
                "komagu.security.oidc.issuer=https://auth.example.com",
                "komagu.security.oidc.audience=my-api",
                "komagu.security.oidc.clock-skew-seconds=315360000"
            )
            .run { context ->
                assertThat(context).hasFailed()
                assertThat(context.startupFailure)
                    .hasRootCauseInstanceOf(IllegalStateException::class.java)
                assertThat(context.startupFailure?.cause?.message ?: context.startupFailure?.message)
                    .contains("clock-skew-seconds must be between 0 and 120")
            }

        // Negative clock skew
        contextRunner
            .withPropertyValues(
                "komagu.security.oidc.jwk-set-uri=https://auth.example.com/certs",
                "komagu.security.oidc.issuer=https://auth.example.com",
                "komagu.security.oidc.audience=my-api",
                "komagu.security.oidc.clock-skew-seconds=-10"
            )
            .run { context ->
                assertThat(context).hasFailed()
                assertThat(context.startupFailure)
                    .hasRootCauseInstanceOf(IllegalStateException::class.java)
                assertThat(context.startupFailure?.cause?.message ?: context.startupFailure?.message)
                    .contains("clock-skew-seconds must be between 0 and 120")
            }
    }

    @Test
    fun `issuer-uri only configuration applies full Komagu validator chain rejecting tokens without exp, sub, or aud`() {
        val jwtFactory = TestJwtFactory()
        val rsaKey = RSAKey.Builder(jwtFactory.publicKey)
            .keyID("komagu-test-key-1")
            .build()
        val jwkSetJson = JWKSet(rsaKey).toString()

        val server = HttpServer.create(InetSocketAddress(0), 0)
        val port = server.address.port
        val issuerUrl = "http://127.0.0.1:$port"
        val openIdConfig = """
            {
                "issuer": "$issuerUrl",
                "jwks_uri": "$issuerUrl/certs",
                "response_types_supported": ["code"]
            }
        """.trimIndent()

        server.createContext("/.well-known/openid-configuration") { exchange ->
            val bytes = openIdConfig.toByteArray(Charsets.UTF_8)
            exchange.responseHeaders.set("Content-Type", "application/json")
            exchange.sendResponseHeaders(200, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        server.createContext("/certs") { exchange ->
            val responseBytes = jwkSetJson.toByteArray(Charsets.UTF_8)
            exchange.responseHeaders.set("Content-Type", "application/json")
            exchange.sendResponseHeaders(200, responseBytes.size.toLong())
            exchange.responseBody.use { it.write(responseBytes) }
        }
        server.start()

        val audience = "komagu-api"

        try {
            // Configure ONLY spring.security.oauth2.resourceserver.jwt.issuer-uri
            contextRunner
                .withPropertyValues(
                    "spring.security.oauth2.resourceserver.jwt.issuer-uri=$issuerUrl",
                    "komagu.security.oidc.allow-insecure-http-jwks=true",
                    "komagu.security.oidc.audience=$audience"
                )
                .run { context ->
                    assertThat(context).hasNotFailed()
                    val decoder = context.getBean(JwtDecoder::class.java)

                    // 1. Valid token passes
                    val validToken = jwtFactory.createToken(
                        issuer = issuerUrl,
                        audience = audience,
                        subject = "valid-issuer-user"
                    )
                    val jwt = decoder.decode(validToken)
                    assertThat(jwt.subject).isEqualTo("valid-issuer-user")

                    // 2. Token without 'exp' claim is rejected by Komagu validator
                    val noExpToken = jwtFactory.createToken(
                        issuer = issuerUrl,
                        audience = audience,
                        subject = "valid-issuer-user",
                        expirationTime = null
                    )
                    val expEx = assertThrows<JwtValidationException> {
                        decoder.decode(noExpToken)
                    }
                    assertThat(expEx.message).contains("exp")

                    // 3. Token without 'sub' claim is rejected by Komagu validator
                    val noSubToken = jwtFactory.createToken(
                        issuer = issuerUrl,
                        audience = audience,
                        subject = null
                    )
                    val subEx = assertThrows<JwtValidationException> {
                        decoder.decode(noSubToken)
                    }
                    assertThat(subEx.message).contains("sub")

                    // 4. Token with wrong audience is rejected
                    val wrongAudToken = jwtFactory.createToken(
                        issuer = issuerUrl,
                        audience = "wrong-aud",
                        subject = "valid-issuer-user"
                    )
                    assertThrows<JwtValidationException> {
                        decoder.decode(wrongAudToken)
                    }
                }
        } finally {
            server.stop(0)
        }
    }
}
