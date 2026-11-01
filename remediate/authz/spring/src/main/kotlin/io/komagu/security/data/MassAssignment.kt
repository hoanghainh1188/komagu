@file:JvmName("MassAssignment")

package io.komagu.security.data

/**
 * Mass-assignment defense for map-shaped input (e.g. a JSON body bound to `Map<String, Any?>`).
 *
 * Returns a NEW map holding only the entries of [source] whose keys are listed in [allowed]
 * (exact, case-sensitive match, source order kept). [source] is never mutated. Privileged fields such as
 * `role`, `isAdmin` or `balance` are dropped unless explicitly allowed.
 *
 * Prefer a dedicated request DTO that declares only the client-editable fields; use this helper when the
 * input must stay a map (patch endpoints, legacy controllers).
 */
fun allowFields(source: Map<String, Any?>, vararg allowed: String): Map<String, Any?> {
    val allowedKeys = allowed.toSet()
    return source.filterKeys { it in allowedKeys }
}
