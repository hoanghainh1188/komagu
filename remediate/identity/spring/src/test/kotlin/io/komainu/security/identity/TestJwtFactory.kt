package io.komainu.security.identity

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.util.Date

class TestJwtFactory {

    val publicKey: RSAPublicKey
    val privateKey: RSAPrivateKey

    init {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val kp = kpg.generateKeyPair()
        publicKey = kp.public as RSAPublicKey
        privateKey = kp.private as RSAPrivateKey
    }

    fun createToken(
        issuer: String = "https://auth.komainu.test/realms/komainu",
        audience: String = "komainu-api",
        subject: String = "alice-100",
        tenantId: String = "tenant-alpha",
        issueTime: Instant = Instant.now(),
        expirationTime: Instant = Instant.now().plusSeconds(3600),
        customSignerPrivateKey: RSAPrivateKey? = null
    ): String {
        val claimsSet = JWTClaimsSet.Builder()
            .issuer(issuer)
            .audience(audience)
            .subject(subject)
            .issueTime(Date.from(issueTime))
            .expirationTime(Date.from(expirationTime))
            .claim("tenant_id", tenantId)
            .claim("roles", listOf("Member"))
            .build()

        val header = JWSHeader.Builder(JWSAlgorithm.RS256)
            .keyID("komainu-test-key-1")
            .build()

        val signedJWT = SignedJWT(header, claimsSet)
        signedJWT.sign(RSASSASigner(customSignerPrivateKey ?: privateKey))

        return signedJWT.serialize()
    }
}
