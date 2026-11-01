package io.komagu.security.spring

import io.komagu.security.authorization.DefaultKomaguSecurityManager
import io.komagu.security.authorization.KomaguSecurityManager
import io.komagu.security.authorization.LoggingSecurityAuditSink
import io.komagu.security.authorization.SecurityAuditSink
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean
import org.springframework.core.env.Environment

/**
 * Spring Boot AutoConfiguration for Komagu Authorization module.
 */
@AutoConfiguration
class KomaguSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(SecurityAuditSink::class)
    fun securityAuditSink(): SecurityAuditSink {
        return LoggingSecurityAuditSink()
    }

    @Bean
    @ConditionalOnMissingBean(KomaguSecurityManager::class)
    fun komaguSecurityManager(auditSink: SecurityAuditSink): KomaguSecurityManager {
        return DefaultKomaguSecurityManager(auditSink)
    }

    @Bean
    @ConditionalOnMissingBean(OwnershipAspect::class)
    fun ownershipAspect(
        securityManager: KomaguSecurityManager,
        // ObjectProvider, not List: Spring passes null for a List with no matching beans,
        // and a Kotlin default value is not applied to bean method parameters.
        resolvers: ObjectProvider<ResourceOwnershipResolver<*>>
    ): OwnershipAspect {
        return OwnershipAspect(securityManager, resolvers.orderedStream().toList())
    }

    /**
     * Role (function-level) aspect for @RequireRole. Set `komagu.security.role.hide-denied-as-not-found=true`
     * to answer role denials with 404 instead of 403 for every annotated endpoint.
     */
    @Bean
    @ConditionalOnMissingBean(RoleAspect::class)
    fun roleAspect(
        securityManager: KomaguSecurityManager,
        auditSink: SecurityAuditSink,
        environment: Environment
    ): RoleAspect {
        val hideAsNotFound = environment.getProperty(HIDE_ROLE_DENIED_PROPERTY, Boolean::class.javaObjectType, false)
        return RoleAspect(securityManager, auditSink, hideAsNotFound)
    }

    companion object {
        const val HIDE_ROLE_DENIED_PROPERTY = "komagu.security.role.hide-denied-as-not-found"
    }
}
