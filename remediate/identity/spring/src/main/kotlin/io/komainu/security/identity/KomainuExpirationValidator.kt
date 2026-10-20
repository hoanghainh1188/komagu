package io.komainu.security.identity

import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jwt.Jwt

/**
 * Validates that the JWT contains a non-null expiration ('exp') claim,
 * preventing tokens without an expiration date from remaining valid indefinitely.
 */
class KomainuExpirationValidator : OAuth2TokenValidator<Jwt> {

    private val error = OAuth2Error(
        "invalid_token",
        "The 'exp' (expiration) claim is mandatory and cannot be missing or null.",
        "https://tools.ietf.org/html/rfc7519#section-4.1.4"
    )

    override fun validate(jwt: Jwt): OAuth2TokenValidatorResult {
        return if (jwt.expiresAt != null) {
            OAuth2TokenValidatorResult.success()
        } else {
            OAuth2TokenValidatorResult.failure(error)
        }
    }
}
