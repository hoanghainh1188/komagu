package io.komagu.security.spring

/**
 * Declarative function-level authorization (BFLA defense) for controller or service methods and classes.
 *
 * The caller is allowed when the authenticated principal in Spring Security's `SecurityContextHolder`
 * holds at least one of the listed roles. Roles are read only from the principal's granted authorities,
 * never from request parameters, bodies or headers.
 *
 * Role matching rule: a single leading `ROLE_` prefix is stripped from both the granted authority and the
 * required role, then the names are compared exactly and case-sensitively. So `ROLE_admin` and `admin`
 * both satisfy `@RequireRole("admin")` (and `@RequireRole("ROLE_admin")`), while `Admin` and `SCOPE_admin`
 * do not. JWT scopes or custom role claims must be mapped to granted authorities by the application's
 * `JwtAuthenticationConverter`.
 *
 * Outcomes:
 * - not authenticated: [AuthenticationRequiredException] (HTTP 401);
 * - authenticated but no matching role: [RoleDeniedException] (HTTP 403), or [ResourceNotFoundException]
 *   (HTTP 404) when [hideAsNotFound] is true or `komagu.security.role.hide-denied-as-not-found=true`;
 * - empty or blank role list: [IllegalStateException] before the method runs (misconfiguration, fail fast).
 *
 * A method-level annotation takes precedence over a class-level one.
 *
 * NOTE ON SPRING PROXY BYPASS (Self-Invocation):
 * Spring AOP proxies intercept calls entering from outside the bean. Calling an annotated method from
 * within the same class (`this.method()`) bypasses the proxy and will NOT enforce role checks.
 */
@Target(AnnotationTarget.FUNCTION, AnnotationTarget.CLASS)
@Retention(AnnotationRetention.RUNTIME)
@MustBeDocumented
annotation class RequireRole(
    vararg val value: String,
    val hideAsNotFound: Boolean = false
)
