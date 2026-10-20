#!/usr/bin/env python3
"""Comprehensive test suite for Zero-PII Tokenization & OIDC Integration (Issue #190)."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import sys
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from assess.lsa.scripts.merge_findings import _validate_node
from remediate.ekyc.client.nfc_reader import AID_MY_NUMBER_JPKI, NFCReaderSession
from remediate.ekyc.server.jpki_verifier import HAS_CRYPTOGRAPHY, MockJPKIVerificationEngine
from remediate.ekyc.server.tokenization import (
    ProhibitedIdentifierError,
    RawImageRejectionError,
    ZeroPIITokenizer,
    create_verification_record,
    reject_prohibited_identifiers,
    reject_raw_images,
)

SCHEMA_PATH = REPO_ROOT / "contracts" / "schemas" / "ekyc-verification.schema.json"


class TestZeroPIITokenizationAndOIDC(unittest.TestCase):
    """Verifies Zero-PII blind tokenization, OID4IDA verified_claims, and contract compliance."""

    def setUp(self) -> None:
        self.tokenizer = ZeroPIITokenizer(hmac_key=b"test-secret-hmac-key-for-ekyc-0123456789")
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            self.schema = json.load(f)

    def _validate_schema(self, instance: Dict[str, Any]) -> List[str]:
        """Validate instance against ekyc-verification.schema.json using pure stdlib validator."""
        errs: List[str] = []
        _validate_node(instance, self.schema, self.schema, "", errs)
        return errs

    def test_01_reject_raw_my_number_prohibited_keys(self) -> None:
        """Payers must strictly reject My Number / Individual Number field keys."""
        bad_payloads = [
            {"name": "山田 太郎", "my_number": "123456789012"},
            {"name": "山田 太郎", "individual_number": "123456789012"},
            {"name": "山田 太郎", "kojin_bango": "123456789012"},
            {"attributes": {"name": "山田 太郎", "my_number": "123456789012"}},
        ]
        for payload in bad_payloads:
            with self.assertRaises(ProhibitedIdentifierError):
                reject_prohibited_identifiers(payload)

    def test_02_reject_12_digit_numeric_values(self) -> None:
        """Payloads containing 12-digit numeric sequences (raw My Number) must be blocked."""
        bad_values = [
            {"name": "山田 太郎", "note": "123456789012"},
            {"name": "山田 太郎", "reference": "1234-5678-9012"},
            {"name": "山田 太郎", "code": 123456789012},
        ]
        for payload in bad_values:
            with self.assertRaises(ProhibitedIdentifierError):
                reject_prohibited_identifiers(payload)

    def test_03_reject_raw_images_and_base64_streams(self) -> None:
        """Payloads containing raw image byte markers or image field keys must be rejected."""
        with self.assertRaises(RawImageRejectionError):
            reject_raw_images({"photo": "dummy"})

        with self.assertRaises(RawImageRejectionError):
            reject_raw_images({"attributes": {"image": "data:image/png;base64,iVBORw0KGgo"}})

        with self.assertRaises(RawImageRejectionError):
            reject_raw_images(b"\xff\xd8\xff\xe0\x00\x10JFIF")

    def test_04_tenant_isolated_blind_hashing(self) -> None:
        """Different tenants must produce distinct blind hashes to prevent cross-tenant correlation."""
        name = "山田 太郎"
        dob = "1985-05-20"

        hash_tenant_a = self.tokenizer.generate_blind_hash(name, dob, tenant_id="tenant-acme-corp")
        hash_tenant_b = self.tokenizer.generate_blind_hash(name, dob, tenant_id="tenant-globex-inc")
        hash_tenant_a_dup = self.tokenizer.generate_blind_hash(name, dob, tenant_id="tenant-acme-corp")

        self.assertNotEqual(hash_tenant_a, hash_tenant_b, "Blind hashes must not correlate across tenants")
        self.assertEqual(hash_tenant_a, hash_tenant_a_dup, "Blind hash must remain consistent within tenant")

    def test_05_jwk_thumbprint_calculation(self) -> None:
        """Calculates RFC 7638 SHA-256 JWK thumbprint."""
        # RFC 7638 Appendix A.1 example
        rsa_jwk = {
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fTr4CqLUS6HzE-ESbgLMNU3C64ZNl5F8Ni2267315RZTrxo81640ep164-9Uv59UaVQ",
            "e": "AQAB",
        }
        thumbprint = ZeroPIITokenizer.compute_jwk_thumbprint(rsa_jwk)
        self.assertEqual(thumbprint, "7ceTZ8eHF4I0zzFLfeoTg647f7wAlKFS5QHyswqPJIU")

    def test_06_oid4ida_token_issuance_and_claims(self) -> None:
        """Issues OID4IDA compliant verified_claims token with standard metadata."""
        attrs = {
            "name": "山田 太郎",
            "date_of_birth": "1985-05-20",
            "address": "東京都千代田区霞が関2-1-2",
            "gender": "male",
        }
        token_data = self.tokenizer.issue_oidc_token(
            verified_attributes=attrs,
            tenant_id="tenant-alpha",
            audience="client-portal-app",
        )
        jwt_token = token_data["jwt"]
        self.assertIn(".", jwt_token)
        self.assertEqual(len(jwt_token.split(".")), 3)

        # Verify token
        ok, claims, err = self.tokenizer.verify_oidc_token(
            jwt_token,
            expected_audience="client-portal-app",
            expected_tenant_id="tenant-alpha",
        )
        self.assertTrue(ok, f"Verification failed: {err}")
        self.assertIsNotNone(claims)
        self.assertIn("verified_claims", claims)
        self.assertEqual(claims["verified_claims"]["verification"]["trust_framework"], "jp_ekyc_2027")
        self.assertEqual(claims["verified_claims"]["claims"]["name"], "山田 太郎")
        self.assertNotIn("image", claims["verified_claims"]["claims"])
        self.assertNotIn("photo", claims["verified_claims"]["claims"])

    def test_07_proof_of_possession_token_binding(self) -> None:
        """Binds token to client JWK thumbprint and verifies proof-of-possession."""
        attrs = {"name": "山田 太郎", "birthdate": "1985-05-20"}
        client_jkt = "client-dpop-thumbprint-xyz-12345"

        token_data = self.tokenizer.issue_oidc_token(
            verified_attributes=attrs,
            tenant_id="tenant-beta",
            client_jkt=client_jkt,
        )
        jwt_token = token_data["jwt"]

        # Valid with correct client_jkt
        ok, claims, _ = self.tokenizer.verify_oidc_token(
            jwt_token,
            expected_client_jkt=client_jkt,
        )
        self.assertTrue(ok)
        self.assertEqual(claims["cnf"]["jkt"], client_jkt)

        # Fail with mismatched client_jkt
        ok, _, err = self.tokenizer.verify_oidc_token(
            jwt_token,
            expected_client_jkt="wrong-attacker-thumbprint",
        )
        self.assertFalse(ok)
        self.assertIn("thumbprint mismatch", str(err))

    def test_08_token_expiration_and_tampering(self) -> None:
        """Expired or tampered OIDC tokens must be rejected."""
        attrs = {"name": "山田 太郎", "date_of_birth": "1985-05-20"}
        # Issue expired token
        token_data = self.tokenizer.issue_oidc_token(
            verified_attributes=attrs,
            tenant_id="tenant-delta",
            ttl_minutes=-1,
        )
        ok, _, err = self.tokenizer.verify_oidc_token(token_data["jwt"])
        self.assertFalse(ok)
        self.assertIn("expired", str(err))

        # Tampered payload
        valid_data = self.tokenizer.issue_oidc_token(attrs, tenant_id="tenant-delta")
        parts = valid_data["jwt"].split(".")
        tampered_jwt = f"{parts[0]}.{parts[1]}xyz.{parts[2]}"
        ok, _, err = self.tokenizer.verify_oidc_token(tampered_jwt)
        self.assertFalse(ok)

    def test_09_verification_record_schema_validation(self) -> None:
        """Generated verification record conforms strictly to ekyc-verification.schema.json."""
        attrs = {
            "name": "山田 太郎",
            "date_of_birth": "1985-05-20",
            "address": "東京都千代田区霞が関2-1-2",
        }
        token_data = self.tokenizer.issue_oidc_token(
            verified_attributes=attrs,
            tenant_id="tenant-bank-01",
            client_jkt="thumbprint-1234",
        )

        record = create_verification_record(
            verification_id="verif-uuid-9876-5432-1098",
            tenant_id="tenant-bank-01",
            tokenized_identity={
                "blind_hash": token_data["blind_hash"],
                "identity_token": token_data["jwt"],
                "expires_at": token_data["expires_at"],
                "token_binding": {
                    "type": "dpop_jkt",
                    "thumbprint": "thumbprint-1234",
                },
            },
            audit_trail={
                "jlis_cert_serial_hash": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
                "crl_checked": True,
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2031-01-01T00:00:00Z",
                "raw_images_stored": False,
                "individual_number_stored": False,
            },
            oidc_claims=token_data["claims"]["verified_claims"],
        )

        errs = self._validate_schema(record)
        self.assertEqual(errs, [], f"Schema validation errors found: {errs}")

    def test_10_schema_rejects_raw_images_stored_violation(self) -> None:
        """Schema must reject records where raw_images_stored is not false."""
        bad_record = {
            "verification_id": "test-id",
            "tenant_id": "test-tenant",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "verified",
            "verification_method": "jpki_nfc",
            "trust_framework": "jp_ekyc_2027",
            "tokenized_identity": {
                "blind_hash": "dummy-hash",
                "identity_token": "dummy.jwt.token",
                "expires_at": "2026-10-20T12:00:00Z",
            },
            "audit_trail": {
                "jlis_cert_serial_hash": "abc",
                "crl_checked": True,
                "raw_images_stored": True,  # Invariant violation!
                "individual_number_stored": False,
            },
        }
        errs = self._validate_schema(bad_record)
        self.assertTrue(any("raw_images_stored" in e for e in errs), "Schema must flag raw_images_stored violation")

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography library required for JPKI NFC integration test")
    def test_11_end_to_end_nfc_to_oidc_flow(self) -> None:
        """Complete e2e workflow: NFC reader -> Mock JPKI CA -> Zero-PII Tokenizer -> Schema Record."""
        # 1. NFC client session
        nfc = NFCReaderSession(document_type="my_number")
        ok, sw = nfc.select_application(AID_MY_NUMBER_JPKI)
        self.assertTrue(ok)
        nfc.verify_pin("1234")
        client_attrs = nfc.read_verified_attributes()

        # 2. Server challenge generation
        verifier = MockJPKIVerificationEngine()
        challenge_nonce = verifier.generate_challenge(ttl_seconds=120)

        # 3. Client signs challenge nonce via Mock J-LIS CA user cert
        user_cert, user_key, cert_pem = verifier.ca.issue_user_certificate(
            subject_cn=client_attrs["name"],
            attributes=client_attrs,
        )
        sig_hex = verifier.ca.sign_nonce(user_key, challenge_nonce)

        # 4. Server verifies JPKI signature & CRL status
        verified, msg = verifier.verify_signature(
            challenge_nonce=challenge_nonce,
            signature_hex=sig_hex,
            certificate_pem=cert_pem,
            attributes=client_attrs,
        )
        self.assertTrue(verified, f"JPKI verification failed: {msg}")

        # 5. Tokenize into OID4IDA verified_claims JWT (Zero-PII)
        token_result = self.tokenizer.issue_oidc_token(
            verified_attributes=client_attrs,
            tenant_id="tenant-pilot-production",
            client_jkt="dpop-client-thumbprint-5566",
        )

        # 6. Build contract record and validate schema
        cert_serial_hash = hashlib.sha256(str(user_cert.serial_number).encode("utf-8")).hexdigest()
        record = create_verification_record(
            verification_id="verif-prod-e2e-001",
            tenant_id="tenant-pilot-production",
            tokenized_identity={
                "blind_hash": token_result["blind_hash"],
                "identity_token": token_result["jwt"],
                "expires_at": token_result["expires_at"],
                "token_binding": {
                    "type": "dpop_jkt",
                    "thumbprint": "dpop-client-thumbprint-5566",
                },
            },
            audit_trail={
                "jlis_cert_serial_hash": cert_serial_hash,
                "crl_checked": True,
                "not_before": user_cert.not_valid_before_utc.isoformat(),
                "not_after": user_cert.not_valid_after_utc.isoformat(),
                "raw_images_stored": False,
                "individual_number_stored": False,
            },
            oidc_claims=token_result["claims"]["verified_claims"],
        )

        errs = self._validate_schema(record)
        self.assertEqual(errs, [])

    def test_embedded_my_number_in_text_rejected(self) -> None:
        """Issue #213: Embedded 12-digit My Number in text fields must be strictly rejected."""
        payload_embedded = {
            "name": "山田 太郎",
            "address": "東京都千代田区1-1 (マイナンバー: 123456789012)",
        }
        with self.assertRaises(ProhibitedIdentifierError):
            reject_prohibited_identifiers(payload_embedded)

        payload_hyphenated = {
            "name": "山田 太郎",
            "memo": "Ref ID 1234-5678-9012 for user",
        }
        with self.assertRaises(ProhibitedIdentifierError):
            reject_prohibited_identifiers(payload_hyphenated)

        # Non-12-digit numbers (e.g. 10 or 11 digits) should not trigger false positives
        payload_phone = {
            "name": "山田 太郎",
            "phone": "03-1234-5678",
            "postal_code": "100-0001",
        }
        # Should not raise
        reject_prohibited_identifiers(payload_phone)

    def test_hex_image_in_sod_hex_rejected(self) -> None:
        """Issue #213: Hex-encoded JPEG/PNG in sod_hex must be rejected as raw image smuggling."""
        # JPEG header: ffd8ffe0
        fake_jpeg_sod = "ffd8ffe000104a46494600010101006000600000" + "aa" * 30
        payload_jpeg = {
            "sod_hex": fake_jpeg_sod,
            "document_type": "driver_license",
        }
        with self.assertRaises(RawImageRejectionError):
            reject_raw_images(payload_jpeg)

        # PNG header: 89504e47
        fake_png_sod = "89504e470d0a1a0a0000000d49484452" + "bb" * 30
        payload_png = {
            "sod_hex": fake_png_sod,
            "document_type": "driver_license",
        }
        with self.assertRaises(RawImageRejectionError):
            reject_raw_images(payload_png)

    def test_data_uri_and_base64_image_variants_rejected(self) -> None:
        """Issue #213: Alternative image formats (WebP, BMP) and embedded data URIs must be rejected."""
        payloads = [
            {"avatar": "data:image/webp;base64,UklGRkAAAABXRUJQVlA4WAoAAAAQAAAA"},
            {"scan": "data:image/bmp;base64,Qk02AAAAAAAAADYAAAAoAAAA"},
            {"note": "User uploaded avatar: data:image/png;base64,iVBORw0KGgoAAA"},
        ]
        for p in payloads:
            with self.subTest(payload=p):
                with self.assertRaises(RawImageRejectionError):
                    reject_raw_images(p)

    def test_oversized_fields_and_payloads_rejected(self) -> None:
        """Issue #213: Oversized string fields and aggregate payloads must be rejected."""
        # Name field exceeds limit (255)
        payload_long_name = {
            "name": "A" * 256,
        }
        with self.assertRaises(RawImageRejectionError):
            reject_raw_images(payload_long_name)

        # Address field exceeds limit (1024)
        payload_long_address = {
            "address": "B" * 1025,
        }
        with self.assertRaises(RawImageRejectionError):
            reject_raw_images(payload_long_address)

        # Aggregate payload exceeds limit (65536)
        oversized_payload = {
            "notes": "C" * 70000,
        }
        with self.assertRaises(RawImageRejectionError):
            reject_raw_images(oversized_payload)

    def test_tokenizer_requires_hmac_key_in_production(self) -> None:
        """Issue #213: ZeroPIITokenizer must reject missing HMAC key outside test environments."""
        with patch.dict(os.environ, {"KOMAINU_EKYC_REQUIRE_HMAC_KEY": "1"}, clear=False):
            # Ensure env var KOMAINU_EKYC_HMAC_KEY is removed
            with patch.dict(os.environ, {"KOMAINU_EKYC_HMAC_KEY": ""}):
                with self.assertRaises(RuntimeError) as ctx:
                    ZeroPIITokenizer()
                self.assertIn("KOMAINU_EKYC_HMAC_KEY", str(ctx.exception))

        # Explicit allow_ephemeral_key=False must also fail when key is unset
        with patch.dict(os.environ, {"KOMAINU_EKYC_HMAC_KEY": ""}):
            with self.assertRaises(RuntimeError):
                ZeroPIITokenizer(allow_ephemeral_key=False)


if __name__ == "__main__":
    unittest.main()
