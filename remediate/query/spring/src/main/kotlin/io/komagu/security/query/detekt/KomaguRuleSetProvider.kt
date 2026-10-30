package io.komagu.security.query.detekt

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.RuleSet
import io.gitlab.arturbosch.detekt.api.RuleSetProvider

/**
 * Detekt RuleSetProvider exposing Komagu security rules.
 */
class KomaguRuleSetProvider : RuleSetProvider {
    // Kept after the rename so existing detekt.yml sections and @Suppress ids still apply (#290).
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
