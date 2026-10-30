package io.komagu.security.query.detekt

import io.gitlab.arturbosch.detekt.api.*
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

        val callee = expression.calleeExpression?.text ?: return
        if (!targetSqlMethods.contains(callee)) {
            return
        }

        val arguments = expression.valueArguments
        if (arguments.isEmpty()) {
            return
        }

        val firstArg = arguments[0].getArgumentExpression() ?: return

        // 1. String template with variable interpolation: "SELECT * FROM orders WHERE id = $orderId"
        if (firstArg is KtStringTemplateExpression && firstArg.hasInterpolation()) {
            report(
                CodeSmell(
                    issue = issue,
                    entity = Entity.from(firstArg),
                    message = "SQL/JPQL query in '$callee' uses string template interpolation. All parameters must be passed as parameterized bindings."
                )
            )
            return
        }

        // 2. Binary string concatenation: "SELECT * FROM orders WHERE id = " + orderId
        if (firstArg is KtBinaryExpression && firstArg.operationToken == KtTokens.PLUS) {
            report(
                CodeSmell(
                    issue = issue,
                    entity = Entity.from(firstArg),
                    message = "SQL/JPQL query in '$callee' is built using binary string concatenation (+). All parameters must be passed as parameterized bindings."
                )
            )
        }
    }
}
