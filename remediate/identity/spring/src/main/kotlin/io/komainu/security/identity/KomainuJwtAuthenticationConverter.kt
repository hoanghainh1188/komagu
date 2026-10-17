package io.komainu.security.identity

import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken

/**
 * Converts validated JWT into JwtAuthenticationToken with structured tenant details and authorities.
 */
class KomainuJwtAuthenticationConverter(
    private val userClaimName: String = "sub",
    private val tenantClaimName: String = "tenant_id"
) : Converter<Jwt, AbstractAuthenticationToken> {

    override fun convert(jwt: Jwt): AbstractAuthenticationToken {
        val authorities = mutableListOf<GrantedAuthority>()

        // Extract realm roles if present (Keycloak realm_access.roles or standard roles claim)
        val roles = jwt.getClaimAsStringList("roles") ?: emptyList()
        for (role in roles) {
            authorities.add(SimpleGrantedAuthority("ROLE_$role"))
        }

        val principalClaimValue = jwt.getClaimAsString(userClaimName) ?: jwt.subject ?: "unknown"

        val token = JwtAuthenticationToken(jwt, authorities, principalClaimValue)

        val tenantId = jwt.getClaimAsString(tenantClaimName)
        if (!tenantId.isNullOrBlank()) {
            token.details = mapOf("tenant_id" to tenantId)
        }

        return token
    }
}
