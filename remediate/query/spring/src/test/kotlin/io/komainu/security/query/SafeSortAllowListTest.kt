package io.komainu.security.query

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SafeSortAllowListTest {

    private val allowList = SafeSortAllowList(listOf("id", "created_at", "total_amount", "status"))

    @Test
    fun `validateColumnName returns valid column name`() {
        assertEquals("created_at", allowList.validateColumnName("created_at"))
        assertEquals("status", allowList.validateColumnName("STATUS"))
        assertEquals("total_amount", allowList.validateColumnName("total_amount"))
    }

    @Test
    fun `validateColumnName throws SecurityException on unauthorized column`() {
        val ex = assertThrows<SecurityException> {
            allowList.validateColumnName("credit_card_number")
        }
        assertTrue(ex.message!!.contains("Unauthorized sort column"))
    }

    @Test
    fun `validateColumnName throws SecurityException on SQL injection attempt`() {
        val payloads = listOf(
            "id; DROP TABLE orders;--",
            "created_at' OR '1'='1",
            "total_amount UNION SELECT * FROM users",
            "id, status",
            "../etc/passwd"
        )

        for (payload in payloads) {
            val ex = assertThrows<SecurityException>("Expected payload '$payload' to be rejected") {
                allowList.validateColumnName(payload)
            }
            assertTrue(ex.message!!.contains("SQL injection") || ex.message!!.contains("Unauthorized"))
        }
    }

    @Test
    fun `buildSortClause returns safe clause`() {
        assertEquals("created_at ASC", allowList.buildSortClause("created_at", "ASC"))
        assertEquals("total_amount DESC", allowList.buildSortClause("total_amount", "DESC"))
    }
}
