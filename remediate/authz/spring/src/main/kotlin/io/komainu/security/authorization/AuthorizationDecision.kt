package io.komainu.security.authorization

/**
 * Encapsulates the authorization evaluation outcome.
 */
data class AuthorizationDecision(
    val granted: Boolean,
    val failureReason: String? = null
) {
    companion object {
        fun granted(): AuthorizationDecision = AuthorizationDecision(granted = true)
        fun denied(reason: String): AuthorizationDecision = AuthorizationDecision(granted = false, failureReason = reason)
    }
}
