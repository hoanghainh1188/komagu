package io.komainu.security.identity

import org.springframework.boot.context.properties.ConfigurationProperties

/**
 * Configuration properties for Komainu OpenID Connect / JWT authentication.
 */
@ConfigurationProperties(prefix = "komainu.security.oidc")
data class KomainuOidcProperties(
    /**
     * OIDC Issuer URL (e.g. "https://auth.komainu.test/realms/komainu").
     */
    var issuer: String = "",

    /**
     * Expected resource server audience (default: "komainu-api").
     */
    var audience: String = "komainu-api",

    /**
     * JSON Web Key Set (JWKS) endpoint URI.
     */
    var jwkSetUri: String? = null,

    /**
     * Allowed clock drift in seconds for token expiration validation. Default is 0.
     */
    var clockSkewSeconds: Long = 0L,

    /**
     * Claim name containing the unique user subject identifier. Default is "sub".
     */
    var userClaimName: String = "sub",

    /**
     * Claim name containing the organization tenant identifier. Default is "tenant_id".
     */
    var tenantClaimName: String = "tenant_id"
)
