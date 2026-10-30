package io.komagu.portal

import io.komagu.portal.model.DocumentEntity
import io.komagu.portal.model.OrderEntity
import io.komagu.portal.repository.DocumentRepository
import io.komagu.portal.repository.OrderRepository
import io.komagu.security.identity.KomaguIdentityAutoConfiguration
import io.komagu.security.spring.ResourceNotFoundException
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.boot.CommandLineRunner
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.filter.OncePerRequestFilter
import java.math.BigDecimal
import java.time.Instant

// The demo authenticates with fixed persona tokens (DemoTokenFilter), not a real OIDC provider,
// so the identity module's JWT decoder, which requires komagu.security.oidc.*, is left out.
@SpringBootApplication(exclude = [KomaguIdentityAutoConfiguration::class])
class Application {
    @Bean
    fun seedDataRunner(
        orderRepository: OrderRepository,
        documentRepository: DocumentRepository
    ) = CommandLineRunner {
        if (orderRepository.count() == 0L) {
            orderRepository.saveAll(
                listOf(
                    OrderEntity(
                        id = "ord-001",
                        tenantId = "tenant-alpha",
                        ownerUserId = "user-a",
                        totalAmount = BigDecimal("1250.00"),
                        status = "completed",
                        description = "Q3 Dedicated Cloud Cluster Payment",
                        createdAt = Instant.parse("2026-10-01T00:00:00Z")
                    ),
                    OrderEntity(
                        id = "ord-002",
                        tenantId = "tenant-alpha",
                        ownerUserId = "user-a",
                        totalAmount = BigDecimal("450.00"),
                        status = "pending",
                        description = "Annual Developer Tooling Licenses",
                        createdAt = Instant.parse("2026-10-05T00:00:00Z")
                    ),
                    OrderEntity(
                        id = "ord-003",
                        tenantId = "tenant-alpha",
                        ownerUserId = "user-b",
                        totalAmount = BigDecimal("89.00"),
                        status = "completed",
                        description = "VPN Gateway Extension",
                        createdAt = Instant.parse("2026-10-10T00:00:00Z")
                    ),
                    OrderEntity(
                        id = "ord-004",
                        tenantId = "tenant-beta",
                        ownerUserId = "user-c",
                        totalAmount = BigDecimal("5000.00"),
                        status = "completed",
                        description = "Strategic Security Architecture Audit",
                        createdAt = Instant.parse("2026-10-12T00:00:00Z")
                    )
                )
            )

            documentRepository.saveAll(
                listOf(
                    DocumentEntity(
                        id = "doc-001",
                        tenantId = "tenant-alpha",
                        ownerUserId = "user-a",
                        title = "Tenant Alpha Q3 Financial Summary",
                        content = "CONFIDENTIAL: Alpha Corp financial balance and quarterly EBITDA.",
                        isConfidential = true,
                        createdAt = Instant.parse("2026-10-02T00:00:00Z")
                    ),
                    DocumentEntity(
                        id = "doc-002",
                        tenantId = "tenant-beta",
                        ownerUserId = "user-c",
                        title = "Beta Corp Merger & Acquisition Term Sheet",
                        content = "STRICTLY PRIVATE: Merger terms between Beta Holdings and Acquirer.",
                        isConfidential = true,
                        createdAt = Instant.parse("2026-10-14T00:00:00Z")
                    )
                )
            )
        }
    }
}

fun main(args: Array<String>) {
    runApplication<Application>(*args)
}

@ControllerAdvice
class GlobalSecurityExceptionHandler {
    @ExceptionHandler(ResourceNotFoundException::class)
    fun handleResourceNotFound(ex: ResourceNotFoundException): ResponseEntity<Map<String, String>> {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(mapOf("error" to (ex.message ?: "Not found")))
    }
}

@Configuration
@EnableWebSecurity
class WebSecurityConfig {
    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .csrf { it.disable() }
            .cors { }
            .authorizeHttpRequests { it.anyRequest().permitAll() }
            .addFilterBefore(DemoTokenFilter(), UsernamePasswordAuthenticationFilter::class.java)

        return http.build()
    }
}

class DemoTokenFilter : OncePerRequestFilter() {
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val authHeader = request.getHeader("Authorization")
        if (!authHeader.isNullOrBlank()) {
            val token = if (authHeader.startsWith("Bearer ", ignoreCase = true)) {
                authHeader.substring(7).trim()
            } else {
                authHeader.trim()
            }

            val (userId, tenantId) = when (token) {
                "token-user-a" -> "user-a" to "tenant-alpha"
                "token-user-b" -> "user-b" to "tenant-alpha"
                "token-user-c" -> "user-c" to "tenant-beta"
                else -> token to "tenant-alpha"
            }

            val jwt = Jwt.withTokenValue(token)
                .header("alg", "none")
                .claim("sub", userId)
                .claim("tenant_id", tenantId)
                .build()

            val auth = UsernamePasswordAuthenticationToken(
                jwt,
                token,
                listOf(SimpleGrantedAuthority("ROLE_USER"))
            )
            SecurityContextHolder.getContext().authentication = auth
        }
        filterChain.doFilter(request, response)
    }
}
