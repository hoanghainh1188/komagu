package io.komainu.security.spring

import io.komainu.security.authorization.DefaultKomainuSecurityManager
import io.komainu.security.authorization.KomainuSecurityManager
import io.komainu.security.authorization.LoggingSecurityAuditSink
import io.komainu.security.authorization.SecurityAuditSink
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean

/**
 * Spring Boot AutoConfiguration for Komainu Authorization module.
 */
@AutoConfiguration
class KomainuSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(SecurityAuditSink::class)
    fun securityAuditSink(): SecurityAuditSink {
        return LoggingSecurityAuditSink()
    }

    @Bean
    @ConditionalOnMissingBean(KomainuSecurityManager::class)
    fun komainuSecurityManager(auditSink: SecurityAuditSink): KomainuSecurityManager {
        return DefaultKomainuSecurityManager(auditSink)
    }

    @Bean
    @ConditionalOnMissingBean(OwnershipAspect::class)
    fun ownershipAspect(securityManager: KomainuSecurityManager): OwnershipAspect {
        return OwnershipAspect(securityManager)
    }
}
