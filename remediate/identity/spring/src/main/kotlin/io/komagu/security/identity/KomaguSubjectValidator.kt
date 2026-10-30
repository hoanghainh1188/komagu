package io.komagu.security.identity

import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jwt.Jwt

/**
 * Validates that the JWT contains a non-blank subject ('sub') claim, preventing anonymous identity collision.
 */
class KomaguSubjectValidator(
    private val subjectClaimName: String = "sub"
) : OAuth2TokenValidator<Jwt> {

    override fun validate(jwt: Jwt): OAuth2TokenValidatorResult {
        val sub = jwt.getClaimAsString(subjectClaimName) ?: jwt.subject
        if (sub.isNullOrBlank()) {
            val error = OAuth2Error(
                "invalid_token",
                "The '$subjectClaimName' claim is mandatory and cannot be blank.",
                "https://tools.ietf.org/html/rfc7519#section-4.1.2"
            )
            return OAuth2TokenValidatorResult.failure(error)
        }
        return OAuth2TokenValidatorResult.success()
    }
}
