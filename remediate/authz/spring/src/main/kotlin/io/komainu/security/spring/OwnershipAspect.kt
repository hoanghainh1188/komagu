package io.komainu.security.spring

import io.komainu.security.authorization.KomainuSecurityManager
import io.komainu.security.authorization.OwnedResource
import org.aspectj.lang.ProceedingJoinPoint
import org.aspectj.lang.annotation.Around
import org.aspectj.lang.annotation.Aspect
import org.aspectj.lang.reflect.MethodSignature

/**
 * Spring AOP Aspect intercepting methods annotated with @RequireOwnership.
 * Enforces ownership checks on method arguments or return values.
 */
@Aspect
class OwnershipAspect(
    private val securityManager: KomainuSecurityManager
) {

    @Around("@annotation(requireOwnership)")
    fun enforceOwnership(joinPoint: ProceedingJoinPoint, requireOwnership: RequireOwnership): Any? {
        val targetClass = if (requireOwnership.entityClass != Any::class) {
            requireOwnership.entityClass.java
        } else null

        // 1. Inspect input parameters
        val args = joinPoint.args
        for (arg in args) {
            if (arg != null) {
                if (arg is OwnedResource<*> || (targetClass != null && targetClass.isInstance(arg))) {
                    securityManager.requireOwnership(arg, requireOwnership.operation)
                }
            }
        }

        // 2. Execute target method
        val result = joinPoint.proceed()

        // 3. Inspect return value if it represents the protected resource
        if (result != null) {
            if (result is OwnedResource<*> || (targetClass != null && targetClass.isInstance(result))) {
                securityManager.requireOwnership(result, requireOwnership.operation)
            }
        }

        return result
    }
}
