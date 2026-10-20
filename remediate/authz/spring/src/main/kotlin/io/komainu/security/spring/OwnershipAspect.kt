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
        val isMutation = requireOwnership.operation == ResourceOperation.UPDATE ||
                requireOwnership.operation == ResourceOperation.DELETE

        // 1. Determine if an ID parameter is present for ID-based resolution
        var idArg: Any? = null
        val idParamIndex = paramNames.indexOf(requireOwnership.idParam)
        if (idParamIndex != -1 && idParamIndex < args.size) {
            idArg = args[idParamIndex]
        } else if (args.size == 1 && (args[0] is Number || args[0] is String || args[0] is java.util.UUID)) {
            idArg = args[0]
        } else if (targetClass != null && paramNames.isEmpty()) {
            // Fallback when parameter names are not preserved in bytecode:
            // Find argument matching ID types (String, Number, UUID)
            idArg = args.firstOrNull { it is Number || it is String || it is java.util.UUID }
        }

        if (idArg != null) {
            // ID-addressed operation: The resource MUST be resolved server-side from the ID.
            // Client-supplied body objects MUST NEVER be used as the authorization subject.
            if (targetClass != null) {
                val resolver = resolvers.find { it.supports(targetClass) }
                    ?: throw ResourceNotFoundException(
                        "No ResourceOwnershipResolver found for entity ${targetClass.simpleName} to resolve id '$idArg'"
                    )
                val resolved = resolver.resolve(idArg)
                    ?: throw ResourceNotFoundException("Resource of type ${targetClass.simpleName} with id '$idArg' not found")

                securityManager.requireOwnership(resolved, requireOwnership.operation)

                // A bound object of the entity type must describe the same resource: same id when it
                // carries one, and no change of owner or tenant (else the method could act on body.id).
                for (arg in args) {
                    if (arg == null || arg === idArg) continue
                    if ((arg is OwnedResource<*> || targetClass.isInstance(arg)) &&
                        !describesSameResource(arg, resolved, idArg)
                    ) {
                        throw ResourceNotFoundException(
                            "Argument of type ${arg.javaClass.simpleName} does not match resolved ${targetClass.simpleName} '$idArg'"
                        )
                    }
                }

                preInvocationChecked = true
            } else {
                // targetClass not specified but id is present: fail-closed
                throw ResourceNotFoundException(
                    "Cannot resolve resource by ID '$idArg' because entityClass is not specified on @RequireOwnership"
                )
            }
        } else {
            // No id under the configured parameter name. Mutations are id-addressed by definition, so a
            // missing id means a misconfigured idParam: never authorize a client-supplied object instead.
            if (isMutation) {
                throw ResourceNotFoundException(
                    "Access denied: '${requireOwnership.operation}' requires the '${requireOwnership.idParam}' parameter to resolve the resource server-side"
                )
            }
            // Non-ID operation (e.g. creation or batch operations): inspect input parameters for OwnedResource / targetClass instances
            for (i in args.indices) {
                val arg = args[i] ?: continue
                if (arg is OwnedResource<*> || (targetClass != null && targetClass.isInstance(arg))) {
                    securityManager.requireOwnership(arg, requireOwnership.operation)
                    preInvocationChecked = true
                }
            }
        }

        // 2. Pre-mutation gate: for UPDATE / DELETE, fail closed before proceed() if no resource was verified
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

    private fun describesSameResource(candidate: Any, resolved: Any, idArg: Any): Boolean {
        val candidateId = readProperty(candidate, "id")
        if (candidateId != null && candidateId.toString().isNotEmpty() && candidateId.toString() != idArg.toString()) {
            return false
        }
        for (field in listOf("ownerUserId", "tenantId")) {
            val claimed = readProperty(candidate, field)?.toString()
            if (!claimed.isNullOrEmpty() && claimed != readProperty(resolved, field)?.toString()) {
                return false
            }
        }
        return true
    }

    private fun readProperty(target: Any, name: String): Any? {
        if (target is OwnedResource<*>) {
            return when (name) {
                "id" -> target.id
                "ownerUserId" -> target.ownerUserId
                "tenantId" -> target.tenantId
                else -> null
            }
        }
        val getter = "get" + name.replaceFirstChar { it.uppercase() }
        return try {
            target.javaClass.getMethod(getter).invoke(target)
        } catch (_: Exception) {
            null
        }
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
