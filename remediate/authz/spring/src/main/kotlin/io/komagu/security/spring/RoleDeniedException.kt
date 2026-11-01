package io.komagu.security.spring

import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.ResponseStatus

/**
 * Thrown when an authenticated caller lacks every role required by [RequireRole].
 * Mapped to HTTP 403 Forbidden. Use `hideAsNotFound` to answer 404 instead and hide the endpoint.
 */
@ResponseStatus(HttpStatus.FORBIDDEN, reason = "Forbidden")
class RoleDeniedException(
    message: String = "Forbidden",
    cause: Throwable? = null
) : RuntimeException(message, cause)
