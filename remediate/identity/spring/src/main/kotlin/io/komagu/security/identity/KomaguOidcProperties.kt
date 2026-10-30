package io.komagu.security.identity

import org.springframework.boot.context.properties.ConfigurationProperties

/**
 * Configuration properties for Komagu OpenID Connect / JWT authentication.
 */
@ConfigurationProperties(prefix = "komagu.security.oidc")
data class KomaguOidcProperties(
    /**
     * OIDC Issuer URL (e.g. "https://auth.komagu.test/realms/komagu"). Must not be blank.
     */
    var issuer: String = "",

    /**
     * Expected resource server audience (default: "komainu-api"). Must not be blank.
     * The pre-rename default is kept so issued tokens stay valid (#290).
     */
    var audience: String = "komainu-api",

    /**
     * JSON Web Key Set (JWKS) endpoint URI. Must use HTTPS unless allowInsecureHttpJwks is true.
     */
    var jwkSetUri: String? = null,

    /**
     * Allowed clock drift in seconds for token expiration validation (must be between 0 and 120). Default is 0.
     */
    var clockSkewSeconds: Long = 0L,

    /**
     * Explicit flag to permit unencrypted http:// JWKS endpoints in isolated test environments.
     */
    var allowInsecureHttpJwks: Boolean = false,

    /**
     * Claim name containing the unique user subject identifier. Default is "sub".
     */
    var userClaimName: String = "sub",

    /**
     * Claim name containing the organization tenant identifier. Default is "tenant_id".
     */
    var tenantClaimName: String = "tenant_id"
)
