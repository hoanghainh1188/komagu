#!/usr/bin/env python3
"""Regression tests for #204: JPKI / driver-licence verification must fail closed."""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from remediate.ekyc.client.nfc_reader import NFCReaderSession
from remediate.ekyc.server.api import EKYCService
from remediate.ekyc.server.jpki_verifier import (
    HAS_CRYPTOGRAPHY,
    SIMULATION_ENV_FLAG,
    JPKIVerificationEngine,
    MockJPKIVerificationEngine,
)
from remediate.ekyc.server.tokenization import ZeroPIITokenizer

if HAS_CRYPTOGRAPHY:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
    from cryptography.x509.oid import NameOID

    from remediate.ekyc.server.mock_jlis_ca import MockJLISCertificateAuthority

# Production-like environment: CI and test-framework imports must not enable simulation.
NO_OPT_IN = {"CI": "true", "KOMAGU_ENV": "dev", SIMULATION_ENV_FLAG: ""}


def _simulated_signature(nonce: str) -> str:
    return hashlib.sha256(b"JPKI-SE-KEY:" + nonce.encode("utf-8")).hexdigest()


def _token_claims(token: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(token.split(".", 1)[0]))


class TestSimulationRequiresExplicitOptIn(unittest.TestCase):
    def test_engine_refuses_simulation_without_flag(self) -> None:
        with patch.dict(os.environ, NO_OPT_IN):
            with self.assertRaises(RuntimeError):
                JPKIVerificationEngine(allow_simulation=True)

    def test_default_service_rejects_simulated_signature_under_ci(self) -> None:
        with patch.dict(os.environ, NO_OPT_IN):
            service = EKYCService()
            _, chal = service.handle_request_challenge()
            nonce = chal["challenge_nonce"]
            status, _ = service.handle_verify_jpki(
                {"challenge_nonce": nonce, "signature_hex": _simulated_signature(nonce)}
            )
        self.assertEqual(status, 401)

    def test_simulation_works_with_explicit_flag(self) -> None:
        with patch.dict(os.environ, {SIMULATION_ENV_FLAG: "1"}):
            engine = JPKIVerificationEngine(allow_simulation=True)
            nonce = engine.generate_challenge()
            ok, msg = engine.verify_signature(nonce, _simulated_signature(nonce))
        self.assertTrue(ok, msg)


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography library required")
class TestCertificateChainFailsClosed(unittest.TestCase):
    def test_self_signed_certificate_rejected_without_trust_anchors(self) -> None:
        priv_pem, cert_pem = NFCReaderSession.generate_test_keypair(common_name="Victim Taro")
        engine = JPKIVerificationEngine()
        nonce = engine.generate_challenge()
        session = NFCReaderSession(document_type="my_number")
        session.verify_pin("1234")
        sig = session.sign_challenge(nonce, private_key_pem=priv_pem)["signature_hex"]
        ok, msg = engine.verify_signature(nonce, sig, certificate_pem=cert_pem, attributes={"name": "Victim Taro"})
        self.assertFalse(ok)
        self.assertIn("trust anchor", msg.lower())

    def test_default_service_rejects_self_signed_certificate(self) -> None:
        priv_pem, cert_pem = NFCReaderSession.generate_test_keypair(common_name="Victim Taro")
        with patch.dict(os.environ, NO_OPT_IN):
            service = EKYCService()
            _, chal = service.handle_request_challenge()
            nonce = chal["challenge_nonce"]
            session = NFCReaderSession(document_type="my_number")
            session.verify_pin("1234")
            sig = session.sign_challenge(nonce, private_key_pem=priv_pem)["signature_hex"]
            status, resp = service.handle_verify_jpki(
                {"challenge_nonce": nonce, "signature_hex": sig, "certificate_pem": cert_pem}
            )
        self.assertEqual(status, 401, resp)

    def test_missing_revocation_checker_rejected(self) -> None:
        ca = MockJLISCertificateAuthority()
        engine = JPKIVerificationEngine(trusted_certs=[ca.root_cert, ca.sub_cert])
        _, key, cert_pem = ca.issue_user_certificate(subject_cn="TARO YAMADA")
        nonce = engine.generate_challenge()
        ok, msg = engine.verify_signature(nonce, ca.sign_nonce(key, nonce), certificate_pem=cert_pem)
        self.assertFalse(ok)
        self.assertIn("revocation", msg.lower())

    def test_parent_with_unsupported_key_type_is_not_trusted(self) -> None:
        # Old behaviour: a non-RSA/EC parent key was marked trusted without any signature check.
        now = datetime.datetime.now(datetime.timezone.utc)
        parent_key = ed25519.Ed25519PrivateKey.generate()
        parent_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Trusted Ed25519 CA")])
        parent = (
            x509.CertificateBuilder().subject_name(parent_name).issuer_name(parent_name)
            .public_key(parent_key.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(parent_key, None)
        )
        attacker_ca_key = ed25519.Ed25519PrivateKey.generate()
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Victim Taro")]))
            .issuer_name(parent_name)
            .public_key(leaf_key.public_key()).serial_number(2)
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
            .sign(attacker_ca_key, None)
        )
        engine = JPKIVerificationEngine(trusted_certs=[parent], crl_checker=lambda serial: False)
        nonce = engine.generate_challenge()
        sig = MockJLISCertificateAuthority.sign_nonce(None, leaf_key, nonce)
        leaf_pem = leaf.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        ok, msg = engine.verify_signature(nonce, sig, certificate_pem=leaf_pem)
        self.assertFalse(ok, msg)


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography library required")
class TestAttributesBoundToCertificate(unittest.TestCase):
    def setUp(self) -> None:
        self.ca = MockJLISCertificateAuthority()
        self.engine = MockJPKIVerificationEngine(ca=self.ca)
        self.tokenizer = ZeroPIITokenizer(hmac_key=b"k" * 32)
        self.service = EKYCService(verifier=self.engine, tokenizer=self.tokenizer)

    def _signed_request(self, cert_attributes: dict, claimed: dict) -> dict:
        _, key, cert_pem = self.ca.issue_user_certificate(
            subject_cn=cert_attributes["name"], attributes=cert_attributes
        )
        _, chal = self.service.handle_request_challenge()
        nonce = chal["challenge_nonce"]
        return {
            "challenge_nonce": nonce,
            "signature_hex": self.ca.sign_nonce(key, nonce),
            "certificate_pem": cert_pem,
            "attributes": claimed,
        }

    def test_unbound_client_attribute_rejected(self) -> None:
        req = self._signed_request({"name": "TARO YAMADA"}, {"name": "TARO YAMADA", "date_of_birth": "1990-01-01"})
        status, resp = self.service.handle_verify_jpki(req)
        self.assertEqual(status, 401, resp)
        self.assertIn("not bound", resp["message"])

    def test_token_built_from_certificate_attributes_only(self) -> None:
        cert_attrs = {"name": "TARO YAMADA", "date_of_birth": "1985-04-12"}
        req = self._signed_request(cert_attrs, {})
        status, resp = self.service.handle_verify_jpki(req)
        self.assertEqual(status, 200, resp)
        expected = self.tokenizer.generate_blind_hash("TARO YAMADA", "1985-04-12")
        self.assertEqual(resp["verification"]["blind_hash"], expected)


class TestDriverLicenceSODFailsClosed(unittest.TestCase):
    FORGED_SOD = "30" + "00" * 40

    def test_engine_rejects_structurally_valid_forged_sod(self) -> None:
        ok, msg = JPKIVerificationEngine().verify_driver_license_sod(bytes.fromhex(self.FORGED_SOD))
        self.assertFalse(ok)
        self.assertIn("not configured", msg)

    def test_api_rejects_forged_sod(self) -> None:
        with patch.dict(os.environ, NO_OPT_IN):
            status, _ = EKYCService().handle_verify_driver_license(
                {"sod_hex": self.FORGED_SOD, "attributes": {"name": "Victim Taro"}}
            )
        self.assertEqual(status, 401)

    def test_injected_verifier_drives_token_and_label(self) -> None:
        engine = JPKIVerificationEngine(
            sod_verifier=lambda sod: (True, "SOD verified", {"name": "HANAKO TANAKA", "date_of_birth": "1990-02-03"})
        )
        tokenizer = ZeroPIITokenizer(hmac_key=b"k" * 32)
        status, resp = EKYCService(verifier=engine, tokenizer=tokenizer).handle_verify_driver_license(
            {"sod_hex": self.FORGED_SOD}
        )
        self.assertEqual(status, 200, resp)
        self.assertEqual(resp["verification"]["blind_hash"], tokenizer.generate_blind_hash("HANAKO TANAKA", "1990-02-03"))
        claims = _token_claims(resp["verification"]["identity_token"])
        self.assertEqual(claims["verified_via"], "DRIVER_LICENSE_IC_SOD")

    def test_client_attribute_not_from_sod_rejected(self) -> None:
        engine = JPKIVerificationEngine(sod_verifier=lambda sod: (True, "SOD verified", {"name": "HANAKO TANAKA"}))
        status, resp = EKYCService(verifier=engine).handle_verify_driver_license(
            {"sod_hex": self.FORGED_SOD, "attributes": {"name": "Victim Taro"}}
        )
        self.assertEqual(status, 401, resp)


if __name__ == "__main__":
    unittest.main()
