package io.komainu.security.authorization

/**
 * Operations subject to object-level authorization evaluation.
 */
enum class ResourceOperation {
    READ,
    CREATE,
    UPDATE,
    DELETE
}
