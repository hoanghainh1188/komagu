package io.komainu.security.identity

import org.springframework.boot.context.properties.ConfigurationProperties

/**
 * Configuration properties for Komainu OpenID Connect / JWT authentication.
 */
@ConfigurationProperties(prefix = "komainu.security.oidc")
data class KomainuOidcProperties(
    /**
     * OIDC Issuer URL (e.g. "https://auth.komainu.test/realms/komainu"). Must not be blank.
     */
    var issuer: String = "",

    /**
     * Expected resource server audience (default: "komainu-api"). Must not be blank.
     */
    var audience: String = "komainu-api",

    /**
     * JSON Web Key Set (JWKS) endpoint URI. Must use HTTPS unless allowInsecureHttpJwks is true.
     */
    var jwkSetUri: String? = null,

    /**
     * Allowed clock drift in seconds for token expiration validation. Default is 0.
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
