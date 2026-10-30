package io.komagu.security.spring

import io.komagu.security.authorization.ResourceOperation
import kotlin.reflect.KClass

/**
 * Declarative annotation to enforce object ownership at controller or service method and class boundaries.
 * Invariant: Any mismatch throws ResourceNotFoundException mapped to HTTP 404 Not Found.
 *
 * NOTE ON SPRING PROXY BYPASS (Self-Invocation):
 * Spring AOP proxies intercept calls entering from outside the bean. Calling an annotated method from
 * within the same class (`this.method()`) bypasses the proxy and will NOT enforce ownership checks.
 */
@Target(AnnotationTarget.FUNCTION, AnnotationTarget.CLASS)
@Retention(AnnotationRetention.RUNTIME)
@MustBeDocumented
annotation class RequireOwnership(
    val entityClass: KClass<*> = Any::class,
    val idParam: String = "id",
    val operation: ResourceOperation = ResourceOperation.READ
)
