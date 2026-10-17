package io.komainu.security.query

import io.gitlab.arturbosch.detekt.test.lint
import io.komainu.security.query.detekt.StringBuiltSqlQueryRule
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class StringBuiltSqlQueryRuleTest {

    private val rule = StringBuiltSqlQueryRule()

    @Test
    fun `flags string concatenation in createQuery`() {
        val code = """
            class OrderService(private val em: FakeEntityManager) {
                fun findOrders(orderId: String) {
                    val q = em.createQuery("SELECT o FROM Order o WHERE o.id = " + orderId)
                }
            }
            interface FakeEntityManager {
                fun createQuery(sql: String): Any
            }
        """.trimIndent()

        val findings = rule.lint(code)
        assertEquals(1, findings.size)
        assertEquals("StringBuiltSqlQuery", findings[0].id)
    }

    @Test
    fun `flags string template interpolation in createNativeQuery`() {
        val code = """
            class OrderService(private val em: FakeEntityManager) {
                fun findOrders(orderId: String) {
                    val q = em.createNativeQuery("SELECT * FROM orders WHERE id = ${'$'}orderId")
                }
            }
            interface FakeEntityManager {
                fun createNativeQuery(sql: String): Any
            }
        """.trimIndent()

        val findings = rule.lint(code)
        assertEquals(1, findings.size)
        assertEquals("StringBuiltSqlQuery", findings[0].id)
    }

    @Test
    fun `does not flag safe parameterized queries with parameter placeholder`() {
        val code = """
            class OrderService(private val em: FakeEntityManager) {
                fun findOrders(orderId: String) {
                    val q = em.createQuery("SELECT o FROM Order o WHERE o.id = :orderId")
                }
            }
            interface FakeEntityManager {
                fun createQuery(sql: String): Any
            }
        """.trimIndent()

        val findings = rule.lint(code)
        assertEquals(0, findings.size)
    }

    @Test
    fun `does not flag unrelated methods using string templates`() {
        val code = """
            class OrderService {
                fun logSomething(name: String) {
                    println("Hello, ${'$'}name!")
                }
            }
        """.trimIndent()

        val findings = rule.lint(code)
        assertEquals(0, findings.size)
    }
}
