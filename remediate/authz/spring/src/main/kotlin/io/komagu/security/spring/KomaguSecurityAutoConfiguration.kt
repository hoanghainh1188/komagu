package io.komagu.security.spring

import io.komagu.security.authorization.DefaultKomaguSecurityManager
import io.komagu.security.authorization.KomaguSecurityManager
import io.komagu.security.authorization.LoggingSecurityAuditSink
import io.komagu.security.authorization.SecurityAuditSink
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean

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
}
