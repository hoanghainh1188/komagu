package io.komainu.security.identity

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Bean
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.jwt.*
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.time.Duration
import java.time.Instant

@SpringBootTest(classes = [TokenValidationIntegrationTest.TestApplication::class])
@AutoConfigureMockMvc
class TokenValidationIntegrationTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    companion object {
        const val EXPECTED_ISSUER = "https://auth.komainu.test/realms/komainu"
        const val EXPECTED_AUDIENCE = "komainu-api"
        val jwtFactory = TestJwtFactory()
    }

    @SpringBootApplication
    @RestController
    class TestApplication {

        @Bean
        fun jwtDecoder(): JwtDecoder {
            val decoder = NimbusJwtDecoder.withPublicKey(jwtFactory.publicKey).build()

            val timestampValidator = JwtTimestampValidator(Duration.ZERO)
            val issuerValidator = JwtIssuerValidator(EXPECTED_ISSUER)
            val audienceValidator = KomainuAudienceValidator(EXPECTED_AUDIENCE)
            val subjectValidator = KomainuSubjectValidator()

            decoder.setJwtValidator(
                DelegatingOAuth2TokenValidator(timestampValidator, issuerValidator, audienceValidator, subjectValidator)
            )

            return decoder
        }

        @GetMapping("/api/test/secure")
        fun secureEndpoint(@AuthenticationPrincipal jwt: Jwt): Map<String, Any> {
            return mapOf(
                "status" to "authenticated",
                "userId" to jwt.subject,
                "tenantId" to (jwt.getClaimAsString("tenant_id") ?: "")
            )
        }
    }

    @Test
    fun `valid token returns 200 OK`() {
        val validToken = jwtFactory.createToken(
            issuer = EXPECTED_ISSUER,
            audience = EXPECTED_AUDIENCE,
            subject = "alice-100",
            tenantId = "tenant-alpha"
        )

        mockMvc.get("/api/test/secure") {
            header("Authorization", "Bearer $validToken")
        }.andExpect {
            status { isOk() }
            jsonPath("$.status") { value("authenticated") }
            jsonPath("$.userId") { value("alice-100") }
            jsonPath("$.tenantId") { value("tenant-alpha") }
        }
    }

    @Test
    fun `missing token returns 401 Unauthorized`() {
        mockMvc.get("/api/test/secure")
            .andExpect {
                status { isUnauthorized() }
            }
    }

    @Test
    fun `expired token returns 401 Unauthorized`() {
        val expiredToken = jwtFactory.createToken(
            issuer = EXPECTED_ISSUER,
            audience = EXPECTED_AUDIENCE,
            issueTime = Instant.now().minusSeconds(7200),
            expirationTime = Instant.now().minusSeconds(3600)
        )

        mockMvc.get("/api/test/secure") {
            header("Authorization", "Bearer $expiredToken")
        }.andExpect {
            status { isUnauthorized() }
        }
    }

    @Test
    fun `wrong issuer returns 401 Unauthorized`() {
        val wrongIssuerToken = jwtFactory.createToken(
            issuer = "https://untrusted-idp.example.com/realms/rogue",
            audience = EXPECTED_AUDIENCE
        )

        mockMvc.get("/api/test/secure") {
            header("Authorization", "Bearer $wrongIssuerToken")
        }.andExpect {
            status { isUnauthorized() }
        }
    }

    @Test
    fun `wrong audience returns 401 Unauthorized`() {
        val wrongAudienceToken = jwtFactory.createToken(
            issuer = EXPECTED_ISSUER,
            audience = "wrong-target-api"
        )

        mockMvc.get("/api/test/secure") {
            header("Authorization", "Bearer $wrongAudienceToken")
        }.andExpect {
            status { isUnauthorized() }
        }
    }

    @Test
    fun `bad signature returns 401 Unauthorized`() {
        // Sign token with a different private key
        val rogueKpg = KeyPairGenerator.getInstance("RSA")
        rogueKpg.initialize(2048)
        val roguePrivateKey = rogueKpg.generateKeyPair().private as RSAPrivateKey

        val badSigToken = jwtFactory.createToken(
            issuer = EXPECTED_ISSUER,
            audience = EXPECTED_AUDIENCE,
            customSignerPrivateKey = roguePrivateKey
        )

        mockMvc.get("/api/test/secure") {
            header("Authorization", "Bearer $badSigToken")
        }.andExpect {
            status { isUnauthorized() }
        }
    }

    @Test
    fun `missing subject returns 401 Unauthorized`() {
        val noSubToken = jwtFactory.createToken(
            issuer = EXPECTED_ISSUER,
            audience = EXPECTED_AUDIENCE,
            subject = null
        )

        mockMvc.get("/api/test/secure") {
            header("Authorization", "Bearer $noSubToken")
        }.andExpect {
            status { isUnauthorized() }
        }
    }

    @Test
    fun `blank subject returns 401 Unauthorized`() {
        val blankSubToken = jwtFactory.createToken(
            issuer = EXPECTED_ISSUER,
            audience = EXPECTED_AUDIENCE,
            subject = "   "
        )

        mockMvc.get("/api/test/secure") {
            header("Authorization", "Bearer $blankSubToken")
        }.andExpect {
            status { isUnauthorized() }
        }
    }

    @Test
    fun `recently expired token with 0s clock skew returns 401 Unauthorized`() {
        // Expired 5 seconds ago - would pass under default 60s skew, must fail under 0s skew
        val recentlyExpiredToken = jwtFactory.createToken(
            issuer = EXPECTED_ISSUER,
            audience = EXPECTED_AUDIENCE,
            issueTime = Instant.now().minusSeconds(300),
            expirationTime = Instant.now().minusSeconds(5)
        )

        mockMvc.get("/api/test/secure") {
            header("Authorization", "Bearer $recentlyExpiredToken")
        }.andExpect {
            status { isUnauthorized() }
        }
    }
}
