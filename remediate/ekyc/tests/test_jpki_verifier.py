#!/usr/bin/env python3
"""Automated verification tests for Mock J-LIS CA & CRL Verification Engine (Issue #189)."""

from __future__ import annotations

import datetime
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from remediate.ekyc.server.jpki_verifier import (
    JPKIVerificationEngine,
    MockJPKIVerificationEngine,
)
from remediate.ekyc.server.mock_jlis_ca import MockJLISCertificateAuthority


class TestMockJLISAndVerifier(unittest.TestCase):
    """Test suite verifying Mock J-LIS CA, CRL verification, and JPKI signatures."""

    def setUp(self) -> None:
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


if __name__ == "__main__":
    unittest.main()
