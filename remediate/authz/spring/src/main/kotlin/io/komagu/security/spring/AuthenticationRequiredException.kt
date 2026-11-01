package io.komagu.security.spring

import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.ResponseStatus

/**
 * Thrown when a role-protected method is invoked without an authenticated principal.
 * Mapped to HTTP 401 Unauthorized.
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED, reason = "Authentication required")
class AuthenticationRequiredException(
    message: String = "Authentication required",
    cause: Throwable? = null
) : RuntimeException(message, cause)
