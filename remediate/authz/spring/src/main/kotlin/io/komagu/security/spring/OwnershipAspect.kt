package io.komagu.security.spring

import io.komagu.security.authorization.KomaguSecurityManager
import io.komagu.security.authorization.OwnedResource
import io.komagu.security.authorization.ResourceOperation
import org.aspectj.lang.ProceedingJoinPoint
import org.aspectj.lang.annotation.Around
import org.aspectj.lang.annotation.Aspect
import org.aspectj.lang.reflect.MethodSignature

/**
 * Spring AOP Aspect intercepting methods and classes annotated with @RequireOwnership.
 * Enforces pre-invocation ownership checks on arguments and ID resolvers,
 * pre-mutation gates on UPDATE/DELETE, and post-invocation checks on unwrapped return types.
 *
 * NOTE ON PROXY BYPASS (Self-Invocation):
 * Spring AOP uses dynamic proxies or CGLIB proxies. Direct method calls within the same class
 * (self-invocation, e.g., `this.deleteOrder(id)`) bypass the proxy and will NOT trigger
 * this aspect. All protected invocations must cross the proxy boundary via injected bean references
 * or application context lookups.
 */
@Aspect
class OwnershipAspect(
    private val securityManager: KomaguSecurityManager,
    private val resolvers: List<ResourceOwnershipResolver<*>> = emptyList()
) {

    @Around("@annotation(io.komagu.security.spring.RequireOwnership) || @within(io.komagu.security.spring.RequireOwnership)")
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
        val operation = requireOwnership.operation
        val targetClass = if (requireOwnership.entityClass != Any::class) {
            requireOwnership.entityClass.java
        } else null

        val signature = try {
            joinPoint.signature as? MethodSignature
        } catch (_: Exception) {
            null
        }
        val args: Array<Any?> = joinPoint.args ?: emptyArray()

        // 1. Determine if an ID parameter is present for ID-based resolution
        val idArg = findIdArg(signature?.parameterNames ?: emptyArray(), args, requireOwnership.idParam, targetClass)
        val preInvocationChecked = if (idArg != null) {
            verifyById(idArg, args, targetClass, operation)
            true
        } else {
            verifyInputs(args, targetClass, requireOwnership)
        }

        // 2. Pre-mutation gate: for UPDATE / DELETE, fail closed before proceed() if no resource was verified
        if (isMutation(operation) && !preInvocationChecked) {
            deny(
                "Access denied: mutating operation '$operation' requires pre-invocation ownership verification, but no valid resource could be resolved"
            )
        }

        // 3. Execute target method
        val result = joinPoint.proceed()

        // 4. Inspect return value for READ operations
        val postInvocationChecked = verifyOwned(unwrapValue(result), targetClass, operation)

        // 5. Fail-closed: if neither input nor output could be verified, deny access
        if (!preInvocationChecked && !postInvocationChecked) {
            deny(
                "Access denied: @RequireOwnership enforced on '${signature?.method?.name ?: "method"}' but no resource was verified"
            )
        }

        return result
    }

    /**
     * ID-addressed operation: the resource MUST be resolved server-side from the ID.
     * Client-supplied body objects MUST NEVER be used as the authorization subject.
     */
    private fun verifyById(idArg: Any, args: Array<Any?>, targetClass: Class<*>?, operation: ResourceOperation) {
        // targetClass not specified but id is present: fail-closed
        val type = targetClass ?: deny(
            "Cannot resolve resource by ID '$idArg' because entityClass is not specified on @RequireOwnership"
        )
        val resolver = resolvers.find { it.supports(type) } ?: deny(
            "No ResourceOwnershipResolver found for entity ${type.simpleName} to resolve id '$idArg'"
        )
        val resolved = resolver.resolve(idArg)
            ?: deny("Resource of type ${type.simpleName} with id '$idArg' not found")

        securityManager.requireOwnership(resolved, operation)

        // A bound object of the entity type must describe the same resource: same id when it
        // carries one, and no change of owner or tenant (else the method could act on body.id).
        val mismatch = args.firstOrNull { arg ->
            arg != null && arg !== idArg &&
                (arg is OwnedResource<*> || type.isInstance(arg)) &&
                !describesSameResource(arg, resolved, idArg)
        }
        if (mismatch != null) {
            deny("Argument of type ${mismatch.javaClass.simpleName} does not match resolved ${type.simpleName} '$idArg'")
        }
    }

    /** No id under the configured parameter name: check owned objects passed in. Returns true if one was verified. */
    private fun verifyInputs(args: Array<Any?>, targetClass: Class<*>?, requireOwnership: RequireOwnership): Boolean {
        // Mutations are id-addressed by definition, so a missing id means a misconfigured idParam:
        // never authorize a client-supplied object instead.
        if (isMutation(requireOwnership.operation)) {
            deny(
                "Access denied: '${requireOwnership.operation}' requires the '${requireOwnership.idParam}' parameter to resolve the resource server-side"
            )
        }
        // Non-ID operation (e.g. creation or batch operations): inspect input parameters for OwnedResource / targetClass instances
        return verifyOwned(args.filterNotNull(), targetClass, requireOwnership.operation)
    }

    /** Requires ownership of every owned value; returns true if at least one was checked. */
    private fun verifyOwned(values: List<Any>, targetClass: Class<*>?, operation: ResourceOperation): Boolean {
        val owned = values.filter { it is OwnedResource<*> || (targetClass != null && targetClass.isInstance(it)) }
        owned.forEach { securityManager.requireOwnership(it, operation) }
        return owned.isNotEmpty()
    }
}

private fun isMutation(operation: ResourceOperation): Boolean =
    operation == ResourceOperation.UPDATE || operation == ResourceOperation.DELETE

private fun isIdValue(value: Any?): Boolean = value is Number || value is String || value is java.util.UUID

private fun findIdArg(paramNames: Array<String>, args: Array<Any?>, idParam: String, targetClass: Class<*>?): Any? {
    val idParamIndex = paramNames.indexOf(idParam)
    return when {
        idParamIndex != -1 && idParamIndex < args.size -> args[idParamIndex]
        paramNames.isNotEmpty() -> null
        // Fallback ONLY when parameter names are not preserved in bytecode (no -parameters flag):
        args.size == 1 && isIdValue(args[0]) -> args[0]
        targetClass != null -> args.firstOrNull { isIdValue(it) }
        else -> null
    }
}

/** Deny by default: every refusal is a 404, so callers cannot probe which resources exist. */
private fun deny(reason: String): Nothing = throw ResourceNotFoundException(reason)

private fun describesSameResource(candidate: Any, resolved: Any, idArg: Any): Boolean {
    val candidateId = readProperty(candidate, "id")?.toString()
    val sameId = candidateId.isNullOrEmpty() || candidateId == idArg.toString()
    return sameId && listOf("ownerUserId", "tenantId").all { field ->
        val claimed = readProperty(candidate, field)?.toString()
        claimed.isNullOrEmpty() || claimed == readProperty(resolved, field)?.toString()
    }
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

private fun unwrapValue(value: Any?): List<Any> = when (value) {
    null -> emptyList()
    is java.util.Optional<*> -> if (value.isPresent) unwrapValue(value.get()) else emptyList()
    // Iterable (e.g., List, Set)
    is Iterable<*> -> value.filterNotNull().flatMap { unwrapValue(it) }
    is Array<*> -> value.filterNotNull().flatMap { unwrapValue(it) }
    // Map values
    is Map<*, *> -> value.values.filterNotNull().flatMap { unwrapValue(it) }
    // Java Stream: convert to a list first, then recursively unwrap each element.
    is java.util.stream.Stream<*> -> value.filter { it != null }.toList().flatMap { unwrapValue(it) }
    // Reactor Mono would need Reactor on the classpath; it is not unwrapped.
    is java.util.concurrent.CompletableFuture<*> -> unwrapValue(value.get())
    else -> unwrapContainer(value)
}

/** ResponseEntity body and Spring Data Page / Slice content, read by reflection; anything else is a single value. */
private fun unwrapContainer(value: Any): List<Any> {
    val className = value.javaClass.name
    val accessor = when {
        className == "org.springframework.http.ResponseEntity" -> "getBody"
        className.endsWith("Page") || className.endsWith("Slice") -> "getContent"
        else -> null
    }
    // Any failure, including one while unwrapping the inner value, keeps the container as a single value.
    val inner = accessor?.let { name ->
        runCatching { unwrapValue(value.javaClass.getMethod(name).invoke(value)) }.getOrNull()
    }
    return inner ?: listOf(value)
}
