package io.komagu.security.query.detekt

import io.gitlab.arturbosch.detekt.api.CodeSmell
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Entity
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Rule
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.lexer.KtTokens
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * Detekt rule detecting SQL/JPQL queries constructed via string concatenation or string templates.
 * Enforces Layer 5 parameterized query requirements of the Komagu modernization architecture.
 */
class StringBuiltSqlQueryRule(config: Config = Config.empty) : Rule(config) {

    override val issue = Issue(
        id = "StringBuiltSqlQuery",
        severity = Severity.Security,
        description = "SQL or JPQL query is constructed via string concatenation or string template. Use parameterized queries with bound variables (:param or ?).",
        debt = Debt.FIVE_MINS
    )

    private val targetSqlMethods = setOf(
        "createQuery",
        "createNativeQuery",
        "query",
        "queryForList",
        "queryForObject",
        "queryForRowSet",
        "execute",
        "sql"
    )

    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)

        val callee = expression.calleeExpression?.text
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression()
        if (callee == null || callee !in targetSqlMethods || firstArg == null) {
            return
        }

        val construction = when {
            // 1. String template with variable interpolation: "SELECT * FROM orders WHERE id = $orderId"
            firstArg is KtStringTemplateExpression && firstArg.hasInterpolation() -> "uses string template interpolation"
            // 2. Binary string concatenation: "SELECT * FROM orders WHERE id = " + orderId
            firstArg is KtBinaryExpression && firstArg.operationToken == KtTokens.PLUS ->
                "is built using binary string concatenation (+)"
            else -> null
        }
        if (construction != null) {
            report(
                CodeSmell(
                    issue = issue,
                    entity = Entity.from(firstArg),
                    message = "SQL/JPQL query in '$callee' $construction. All parameters must be passed as parameterized bindings."
                )
            )
        }
    }
}
