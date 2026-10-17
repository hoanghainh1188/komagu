package io.komainu.security.query.detekt

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.RuleSet
import io.gitlab.arturbosch.detekt.api.RuleSetProvider

/**
 * Detekt RuleSetProvider exposing Komainu security rules.
 */
class KomainuRuleSetProvider : RuleSetProvider {
    override val ruleSetId: String = "komainu-security"

    override fun instance(config: Config): RuleSet {
        return RuleSet(
            ruleSetId,
            listOf(
                StringBuiltSqlQueryRule(config)
            )
        )
    }
}
