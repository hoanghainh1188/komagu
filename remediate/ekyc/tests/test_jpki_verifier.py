#!/usr/bin/env python3
"""Automated verification tests for Mock J-LIS CA & CRL Verification Engine (Issue #189)."""

from __future__ import annotations

import datetime
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from remediate.ekyc.server.api import EKYCService
from remediate.ekyc.server.jpki_verifier import (
    HAS_CRYPTOGRAPHY,
    InMemoryNonceStore,
    JPKIVerificationEngine,
    MockJPKIVerificationEngine,
    NonceRateLimitExceededError,
    NonceStoreCapacityExceededError,
)
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from remediate.ekyc.server.mock_jlis_ca import MockJLISCertificateAuthority
except ImportError:
    MockJLISCertificateAuthority = None


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography library required for JPKI X.509 verification")
class TestMockJLISAndVerifier(unittest.TestCase):
    """Test suite verifying Mock J-LIS CA, CRL verification, and JPKI signatures."""

    def setUp(self) -> None:
        if MockJLISCertificateAuthority is None:
            self.skipTest("MockJLISCertificateAuthority unavailable")
        self.ca = MockJLISCertificateAuthority()
        self.engine = MockJPKIVerificationEngine(ca=self.ca)

    def test_mock_ca_hierarchy_initialization(self) -> None:
        """Root CA and Intermediate Sub-CA must be initialized with valid X.509 chains."""
        self.assertIsNotNone(self.ca.root_cert)
        self.assertIsNotNone(self.ca.sub_cert)

        # Root Subject checks
        root_pem = self.ca.get_root_ca_pem()
        self.assertIn("BEGIN CERTIFICATE", root_pem)
        self.assertEqual(
            self.ca.root_cert.subject.rfc4514_string(),
            "CN=J-LIS Public Authentication Service Root CA,O=J-LIS,C=JP",
        )

        # Sub-CA Subject & Issuer checks
        sub_pem = self.ca.get_intermediate_ca_pem()
        self.assertIn("BEGIN CERTIFICATE", sub_pem)
        self.assertEqual(
            self.ca.sub_cert.subject.rfc4514_string(),
            "CN=J-LIS Individual Authentication Sub-CA,O=J-LIS,C=JP",
        )
        self.assertEqual(self.ca.sub_cert.issuer, self.ca.root_cert.subject)

    def test_issue_and_verify_valid_rsa_certificate(self) -> None:
        """User authentication with RSA-2048 certificate must succeed against active nonce."""
        cert, priv_key, cert_pem = self.ca.issue_user_certificate(
            subject_cn="TARO YAMADA",
            key_type="rsa",
        )
        nonce = self.engine.generate_challenge()
        sig_hex = self.ca.sign_nonce(priv_key, nonce)

        ok, msg = self.engine.verify_signature(
            challenge_nonce=nonce,
            signature_hex=sig_hex,
            certificate_pem=cert_pem,
            attributes={"name": "TARO YAMADA"},
        )
        self.assertTrue(ok)
        self.assertIn("successfully verified", msg)

    def test_issue_and_verify_valid_ecdsa_certificate(self) -> None:
        """User authentication with ECDSA P-256 certificate must succeed against active nonce."""
        cert, priv_key, cert_pem = self.ca.issue_user_certificate(
            subject_cn="HANAKO TANAKA",
            key_type="ec",
        )
        nonce = self.engine.generate_challenge()
        sig_hex = self.ca.sign_nonce(priv_key, nonce)

        ok, msg = self.engine.verify_signature(
            challenge_nonce=nonce,
            signature_hex=sig_hex,
            certificate_pem=cert_pem,
            attributes={"name": "HANAKO TANAKA"},
        )
        self.assertTrue(ok)
        self.assertIn("successfully verified", msg)

    def test_reject_expired_certificate(self) -> None:
        """Expired certificate must be rejected with explicit error message."""
        cert, priv_key, cert_pem = self.ca.issue_user_certificate(
            subject_cn="EXPIRED USER",
            expired=True,
        )
        nonce = self.engine.generate_challenge()
        sig_hex = self.ca.sign_nonce(priv_key, nonce)

        ok, msg = self.engine.verify_signature(
            challenge_nonce=nonce,
            signature_hex=sig_hex,
            certificate_pem=cert_pem,
        )
        self.assertFalse(ok)
        self.assertIn("Certificate has expired", msg)

    def test_reject_revoked_certificate_in_crl(self) -> None:
        """Revoked certificate must be rejected via CRL check."""
        cert, priv_key, cert_pem = self.ca.issue_user_certificate(
            subject_cn="REVOKED USER",
        )
        # Revoke certificate
        self.ca.revoke_certificate(cert.serial_number)
        self.assertTrue(self.ca.is_revoked(cert.serial_number))

        # Ensure CRL contains serial
        crl = self.ca.generate_crl()
        self.assertIsNotNone(crl.get_revoked_certificate_by_serial_number(cert.serial_number))

        nonce = self.engine.generate_challenge()
        sig_hex = self.ca.sign_nonce(priv_key, nonce)

        ok, msg = self.engine.verify_signature(
            challenge_nonce=nonce,
            signature_hex=sig_hex,
            certificate_pem=cert_pem,
        )
        self.assertFalse(ok)
        self.assertIn("has been revoked", msg)

    def test_reject_untrusted_issuer_certificate(self) -> None:
        """Certificate signed by rogue CA must fail chain of trust verification."""
        rogue_ca = MockJLISCertificateAuthority()
        _, rogue_key, rogue_pem = rogue_ca.issue_user_certificate(
            subject_cn="ROGUE USER",
        )
        nonce = self.engine.generate_challenge()
        sig_hex = rogue_ca.sign_nonce(rogue_key, nonce)

        ok, msg = self.engine.verify_signature(
            challenge_nonce=nonce,
            signature_hex=sig_hex,
            certificate_pem=rogue_pem,
        )
        self.assertFalse(ok)
        self.assertIn("Untrusted certificate", msg)

    def test_reject_tampered_signature_and_nonce_replay(self) -> None:
        """Tampered signatures and replayed nonces must be blocked."""
        cert, priv_key, cert_pem = self.ca.issue_user_certificate("TAMPER TEST")
        nonce = self.engine.generate_challenge()
        sig_hex = self.ca.sign_nonce(priv_key, nonce)

        # 1. Tamper with signature
        tampered_hex = sig_hex[:-4] + "dead"
        ok_tamper, msg_tamper = self.engine.verify_signature(
            challenge_nonce=nonce,
            signature_hex=tampered_hex,
            certificate_pem=cert_pem,
        )
        self.assertFalse(ok_tamper)
        self.assertIn("Signature verification failed", msg_tamper)

        # 2. Replay original nonce (nonce was consumed on first call)
        ok_replay, msg_replay = self.engine.verify_signature(
            challenge_nonce=nonce,
            signature_hex=sig_hex,
            certificate_pem=cert_pem,
        )
        self.assertFalse(ok_replay)
        self.assertIn("Invalid or expired challenge nonce", msg_replay)

    def test_zero_pii_architectural_guarantee(self) -> None:
        """Ensure no raw photos or 12-digit My Number are processed or required."""
        cert, priv_key, cert_pem = self.ca.issue_user_certificate("ZERO PII TEST")
        nonce = self.engine.generate_challenge()
        sig_hex = self.ca.sign_nonce(priv_key, nonce)

        # Must succeed strictly with public key and nonce signature
        ok, _ = self.engine.verify_signature(
            challenge_nonce=nonce,
            signature_hex=sig_hex,
            certificate_pem=cert_pem,
        )
        self.assertTrue(ok)
        self.assertNotIn("image", cert_pem.lower())
        self.assertNotIn("photo", cert_pem.lower())

    def test_reject_ca_certificate_as_leaf(self) -> None:
        """Issue #213: Intermediate or Root CA certs (BasicConstraints ca=True) must be rejected as leaf."""
        sub_ca_pem = self.ca.get_intermediate_ca_pem()
        nonce = self.engine.generate_challenge()
        fake_sig = "12" * 256
        ok, msg = self.engine.verify_signature(
            challenge_nonce=nonce,
            signature_hex=fake_sig,
            certificate_pem=sub_ca_pem,
        )
        self.assertFalse(ok)
        self.assertIn("ca certificate cannot be presented as user leaf certificate", msg.lower())

    def test_reject_cert_with_forbidden_key_usage(self) -> None:
        """Issue #213: Certificates with CA key usages (key_cert_sign, crl_sign) or missing signing flags must be rejected."""
        user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        user_subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "JP"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "ILLEGAL USAGE USER"),
        ])
        # 1. Missing digital_signature / content_commitment
        cert_no_sig = (
            x509.CertificateBuilder()
            .subject_name(user_subject)
            .issuer_name(self.ca.sub_cert.subject)
            .public_key(user_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.ca.sub_private_key, hashes.SHA256())
        )
        cert_pem1 = cert_no_sig.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        nonce = self.engine.generate_challenge()
        fake_sig = "34" * 256
        ok1, msg1 = self.engine.verify_signature(
            challenge_nonce=nonce,
            signature_hex=fake_sig,
            certificate_pem=cert_pem1,
        )
        self.assertFalse(ok1)
        self.assertIn("key usage violation", msg1.lower())
        self.assertIn("required", msg1.lower())

        # 2. Has digital_signature but ALSO has prohibited key_cert_sign
        cert_forbidden = (
            x509.CertificateBuilder()
            .subject_name(user_subject)
            .issuer_name(self.ca.sub_cert.subject)
            .public_key(user_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,  # Prohibited
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.ca.sub_private_key, hashes.SHA256())
        )
        cert_pem2 = cert_forbidden.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        nonce2 = self.engine.generate_challenge()
        ok2, msg2 = self.engine.verify_signature(
            challenge_nonce=nonce2,
            signature_hex=fake_sig,
            certificate_pem=cert_pem2,
        )
        self.assertFalse(ok2)
        self.assertIn("must not possess key_cert_sign", msg2.lower())

    def test_nonce_rate_limiting_per_client(self) -> None:
        """Issue #213: Clients exceeding challenge rate limit must be blocked."""
        store = InMemoryNonceStore(rate_limit_per_client=3, rate_limit_window_seconds=60)
        # 3 requests from client_a succeed
        for _ in range(3):
            store.generate_and_store(client_id="client_a")

        # 4th request from client_a must fail with rate limit error
        with self.assertRaises(NonceRateLimitExceededError):
            store.generate_and_store(client_id="client_a")

        # Different client (client_b) can still obtain challenges
        nonce_b = store.generate_and_store(client_id="client_b")
        self.assertIsNotNone(nonce_b)

    def test_nonce_capacity_rejection_without_eviction(self) -> None:
        """Issue #213: When eviction is disabled, store raises NonceStoreCapacityExceededError on full."""
        store = InMemoryNonceStore(max_active_nonces=2, evict_on_capacity=False, rate_limit_per_client=10)
        store.generate_and_store(client_id="user1")
        store.generate_and_store(client_id="user2")

        with self.assertRaises(NonceStoreCapacityExceededError):
            store.generate_and_store(client_id="user3")

    def test_api_status_codes_for_nonce_errors(self) -> None:
        """Issue #213: API maps NonceRateLimitExceededError to 429 and NonceStoreCapacityExceededError to 503."""
        # Rate limit mapping -> 429
        store_rl = InMemoryNonceStore(rate_limit_per_client=1)
        engine_rl = MockJPKIVerificationEngine(ca=self.ca, nonce_store=store_rl)
        service_rl = EKYCService(verifier=engine_rl)

        status, _ = service_rl.handle_request_challenge(client_ip="192.168.1.1")
        self.assertEqual(status, 200)

        status2, resp2 = service_rl.handle_request_challenge(client_ip="192.168.1.1")
        self.assertEqual(status2, 429)
        self.assertEqual(resp2["error"], "TOO_MANY_REQUESTS")

        # Capacity limit mapping -> 503
        store_cap = InMemoryNonceStore(max_active_nonces=1, evict_on_capacity=False, rate_limit_per_client=10)
        engine_cap = MockJPKIVerificationEngine(ca=self.ca, nonce_store=store_cap)
        service_cap = EKYCService(verifier=engine_cap)

        status_cap1, _ = service_cap.handle_request_challenge(client_ip="10.0.0.1")
        self.assertEqual(status_cap1, 200)

        status_cap2, resp_cap2 = service_cap.handle_request_challenge(client_ip="10.0.0.2")
        self.assertEqual(status_cap2, 503)
        self.assertEqual(resp_cap2["error"], "SERVICE_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
