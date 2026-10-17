package io.komainu.security.spring

import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.ResponseStatus

/**
 * Thrown when an object-level authorization check fails.
 * Invariant: Always mapped to HTTP 404 Not Found to eliminate ID enumeration and information disclosure.
 */
@ResponseStatus(HttpStatus.NOT_FOUND, reason = "Resource not found")
class ResourceNotFoundException(
    message: String = "Resource not found",
    cause: Throwable? = null
) : RuntimeException(message, cause)
