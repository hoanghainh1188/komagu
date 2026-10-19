package io.komainu.security.spring

import io.komainu.security.authorization.KomainuSecurityManager
import io.komainu.security.authorization.OwnedResource
import io.komainu.security.authorization.ResourceOperation
import org.aspectj.lang.ProceedingJoinPoint
import org.aspectj.lang.annotation.Around
import org.aspectj.lang.annotation.Aspect
import org.aspectj.lang.reflect.MethodSignature

/**
 * Spring AOP Aspect intercepting methods and classes annotated with @RequireOwnership.
 * Enforces pre-invocation ownership checks on arguments and ID resolvers,
 * pre-mutation gates on UPDATE/DELETE, and post-invocation checks on unwrapped return types.
 */
@Aspect
class OwnershipAspect(
    private val securityManager: KomainuSecurityManager,
    private val resolvers: List<ResourceOwnershipResolver<*>> = emptyList()
) {

    @Around("@annotation(io.komainu.security.spring.RequireOwnership) || @within(io.komainu.security.spring.RequireOwnership)")
    fun enforceOwnership(joinPoint: ProceedingJoinPoint): Any? {
        val signature = try {
            joinPoint.signature as? MethodSignature
        } catch (_: Exception) {
            null
        }
        val method = signature?.method
        val annotation = method?.getAnnotation(RequireOwnership::class.java)
            ?: joinPoint.target?.javaClass?.getAnnotation(RequireOwnership::class.java)
            ?: return joinPoint.proceed()

        return executeEnforcement(joinPoint, annotation)
    }

    /** Overload for programmatic and legacy unit-test invocations */
    fun enforceOwnership(joinPoint: ProceedingJoinPoint, requireOwnership: RequireOwnership): Any? {
        return executeEnforcement(joinPoint, requireOwnership)
    }

    private fun executeEnforcement(
        joinPoint: ProceedingJoinPoint,
        requireOwnership: RequireOwnership
    ): Any? {
        val targetClass = if (requireOwnership.entityClass != Any::class) {
            requireOwnership.entityClass.java
        } else null

        val signature = try {
            joinPoint.signature as? MethodSignature
        } catch (_: Exception) {
            null
        }
        val method = signature?.method
        val paramNames = signature?.parameterNames ?: emptyArray()
        val args = joinPoint.args ?: emptyArray()

        var preInvocationChecked = false

        // 1. Inspect input parameters
        for (i in args.indices) {
            val arg = args[i] ?: continue

            // Direct OwnedResource or targetClass instance
            if (arg is OwnedResource<*> || (targetClass != null && targetClass.isInstance(arg))) {
                securityManager.requireOwnership(arg, requireOwnership.operation)
                preInvocationChecked = true
                continue
            }

            // ID-based resolution if resolver exists and param matches idParam
            if (targetClass != null) {
                val paramName = paramNames.getOrNull(i)
                val matchesIdParam = paramName == requireOwnership.idParam || (args.size == 1 && (arg is Number || arg is String))
                if (matchesIdParam) {
                    val resolver = resolvers.find { it.supports(targetClass) }
                    if (resolver != null) {
                        val resolved = resolver.resolve(arg)
                            ?: throw ResourceNotFoundException("Resource of type ${targetClass.simpleName} with id '$arg' not found")
                        securityManager.requireOwnership(resolved, requireOwnership.operation)
                        preInvocationChecked = true
                    }
                }
            }
        }

        // 2. Pre-mutation gate: for UPDATE / DELETE, fail closed before proceed() if no resource was verified
        val isMutation = requireOwnership.operation == ResourceOperation.UPDATE ||
                requireOwnership.operation == ResourceOperation.DELETE
        if (isMutation && !preInvocationChecked) {
            throw ResourceNotFoundException(
                "Access denied: mutating operation '${requireOwnership.operation}' requires pre-invocation ownership verification, but no valid resource could be resolved"
            )
        }

        // 3. Execute target method
        val result = joinPoint.proceed()

        // 4. Inspect return value for READ operations
        var postInvocationChecked = false
        val extractedResources = unwrapValue(result)
        for (res in extractedResources) {
            if (res is OwnedResource<*> || (targetClass != null && targetClass.isInstance(res))) {
                securityManager.requireOwnership(res, requireOwnership.operation)
                postInvocationChecked = true
            }
        }

        // 5. Fail-closed: if neither input nor output could be verified, deny access
        if (!preInvocationChecked && !postInvocationChecked) {
            throw ResourceNotFoundException(
                "Access denied: @RequireOwnership enforced on '${method?.name ?: "method"}' but no resource was verified"
            )
        }

        return result
    }

    private fun unwrapValue(value: Any?): List<Any> {
        if (value == null) return emptyList()
        if (value is java.util.Optional<*>) {
            return if (value.isPresent) unwrapValue(value.get()) else emptyList()
        }
        if (value is Iterable<*>) {
            return value.filterNotNull().flatMap { unwrapValue(it) }
        }
        if (value is Array<*>) {
            return value.filterNotNull().flatMap { unwrapValue(it) }
        }

        val className = value.javaClass.name
        // Unwrap org.springframework.http.ResponseEntity
        if (className == "org.springframework.http.ResponseEntity") {
            try {
                val bodyMethod = value.javaClass.getMethod("getBody")
                val body = bodyMethod.invoke(value)
                return unwrapValue(body)
            } catch (_: Exception) {}
        }
        // Unwrap Spring Data Page / Slice
        if (className.endsWith("Page") || className.endsWith("Slice")) {
            try {
                val contentMethod = value.javaClass.getMethod("getContent")
                val content = contentMethod.invoke(value)
                return unwrapValue(content)
            } catch (_: Exception) {}
        }

        return listOf(value)
    }
}
