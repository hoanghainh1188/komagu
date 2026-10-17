package io.komainu.security.spring

import io.komainu.security.authorization.ResourceOperation
import kotlin.reflect.KClass

/**
 * Declarative annotation to enforce object ownership at controller or service method boundaries.
 * Invariant: Any mismatch throws ResourceNotFoundException mapped to HTTP 404 Not Found.
 */
@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
@MustBeDocumented
annotation class RequireOwnership(
    val entityClass: KClass<*> = Any::class,
    val idParam: String = "id",
    val operation: ResourceOperation = ResourceOperation.READ
)
