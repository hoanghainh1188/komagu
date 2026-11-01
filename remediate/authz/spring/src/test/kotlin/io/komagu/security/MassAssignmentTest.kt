package io.komagu.security

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import io.komagu.security.data.allowFields
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.math.BigDecimal
import kotlin.test.assertEquals

class MassAssignmentTest {

    /** Persistent entity: role, isAdmin and balance are privileged and server-controlled. */
    data class UserAccount(
        val id: String,
        val name: String,
        val email: String,
        val role: String,
        val isAdmin: Boolean,
        val balance: BigDecimal
    )

    /**
     * Request DTO: declares ONLY the fields a user may edit on their own profile.
     *
     * Jackson's own default is FAIL_ON_UNKNOWN_PROPERTIES = true, so `role` / `isAdmin` / `balance` in the body
     * make deserialization fail (map that to 400). Spring Boot's auto-configured ObjectMapper turns the feature
     * OFF, so those fields are silently ignored instead. Either way they can never reach the entity, because the
     * DTO has nowhere to put them and [applyTo] copies the allowed fields explicitly.
     */
    data class ProfileUpdate(val name: String, val email: String) {
        fun applyTo(account: UserAccount): UserAccount = account.copy(name = name, email = email)
    }

    private val attackBody =
        """{"name":"Mallory","email":"m@example.test","role":"admin","isAdmin":true,"balance":1000000}"""

    private val stored = UserAccount("u-1", "Alice", "a@example.test", "user", false, BigDecimal("10.00"))

    @Test
    fun `allowFields keeps only allowed keys and returns a new map`() {
        val source = mapOf("name" to "Mallory", "email" to "m@example.test", "role" to "admin", "isAdmin" to true)
        val snapshot = source.toMap()

        val filtered = allowFields(source, "name", "email")

        assertEquals(mapOf("name" to "Mallory", "email" to "m@example.test"), filtered)
        assertEquals(snapshot, source)
        assertEquals(emptyMap(), allowFields(source))
        assertEquals(emptyMap(), allowFields(source, "Name"))
    }

    @Test
    fun `allowFields keeps explicit null values of allowed keys`() {
        assertEquals(mapOf("email" to null), allowFields(mapOf("email" to null, "role" to null), "email"))
    }

    @Test
    fun `strict mapper rejects privileged fields in the body`() {
        val strict = jacksonObjectMapper().enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
        assertThrows<UnrecognizedPropertyException> { strict.readValue<ProfileUpdate>(attackBody) }
    }

    @Test
    fun `lenient mapper ignores privileged fields and the explicit copy cannot change them`() {
        // Same setting as Spring Boot's default ObjectMapper.
        val lenient = jacksonObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
        val update = lenient.readValue<ProfileUpdate>(attackBody)

        val saved = update.applyTo(stored)

        assertEquals("Mallory", saved.name)
        assertEquals("m@example.test", saved.email)
        assertEquals("user", saved.role)
        assertEquals(false, saved.isAdmin)
        assertEquals(BigDecimal("10.00"), saved.balance)
        assertEquals("u-1", saved.id)
    }
}
