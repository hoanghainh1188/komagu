package io.komainu.security.identity

import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jwt.Jwt

/**
 * Validates that the JWT contains the configured resource server audience.
 */
class KomainuAudienceValidator(
    private val expectedAudience: String
) : OAuth2TokenValidator<Jwt> {

    private val error = OAuth2Error(
        "invalid_token",
        "The token audience does not contain the required audience '$expectedAudience'",
        null
    )

    override fun validate(jwt: Jwt): OAuth2TokenValidatorResult {
        val audiences = jwt.audience ?: emptyList()
        return if (audiences.contains(expectedAudience)) {
            OAuth2TokenValidatorResult.success()
        } else {
            OAuth2TokenValidatorResult.failure(error)
        }
    }
}
