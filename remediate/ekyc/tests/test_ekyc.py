#!/usr/bin/env python3
"""Unit & Acceptance Tests for Boilerplate 2: Zero-PII eKYC & NFC Verification."""

from __future__ import annotations

import os
import time
import unittest
from unittest.mock import patch

from remediate.ekyc.client.nfc_reader import (
    AID_MY_NUMBER_JPKI,
    APDUCommand,
    NFCReaderSession,
)
from remediate.ekyc.server.api import EKYCService
from remediate.ekyc.server.jpki_verifier import (
    HAS_CRYPTOGRAPHY,
    JPKIVerificationEngine,
    MockJPKIVerificationEngine,
)
from remediate.ekyc.server.tokenization import (
    RawImageRejectionError,
    ZeroPIITokenizer,
    reject_raw_images,
)


class TestZeroPIIeKYC(unittest.TestCase):
    def test_01_legal_compliance_document_exists(self) -> None:
        """Verifies legal review document citing the 2027 NPA ordinance exists."""
        legal_doc = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "LEGAL_COMPLIANCE_2027.md",
        )
        self.assertTrue(os.path.isfile(legal_doc), "Legal compliance document must exist")
        with open(legal_doc, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("犯罪収益移転防止法施行規則改正", content)
        self.assertIn("2027年4月1日施行", content)
        self.assertIn("ZERO RAW ID IMAGES STORED ON SERVER", content)
        self.assertIn("Scope & Production J-LIS Integration Notice", content)

    def test_02_nfc_apdu_command_formatting(self) -> None:
        """Verifies ISO/IEC 7816-4 APDU command encoding."""
        cmd = APDUCommand.select_application(AID_MY_NUMBER_JPKI)
        raw = cmd.to_bytes()
        self.assertEqual(raw[0], 0x00)  # CLA
        self.assertEqual(raw[1], 0xA4)  # INS (SELECT FILE)
        self.assertEqual(raw[2], 0x04)  # P1
        self.assertEqual(raw[3], 0x0C)  # P2
        self.assertEqual(raw[4], 10)    # Length of AID (10 bytes)

    def test_03_nfc_my_number_jpki_session(self) -> None:
        """Verifies client NFC session selects JPKI AP, verifies PIN, and reads attributes."""
        session = NFCReaderSession(document_type="my_number")
        ok, sw = session.select_application(AID_MY_NUMBER_JPKI)
        self.assertTrue(ok)
        self.assertEqual(sw, "9000")

        # Must fail before PIN
        with self.assertRaises(PermissionError):
            session.read_verified_attributes()

        # Verify PIN
        pin_ok, pin_sw = session.verify_pin("1234")
        self.assertTrue(pin_ok)
        self.assertEqual(pin_sw, "9000")

        attrs = session.read_verified_attributes()
        self.assertIn("name", attrs)
        self.assertEqual(attrs["name"], "山田 太郎")
        # Ensure Zero-PII: no image or photo field
        self.assertNotIn("image", attrs)
        self.assertNotIn("photo", attrs)

    def test_04_jpki_verifier_challenge_lifecycle(self) -> None:
        """Verifies challenge nonces are single-use to prevent replay attacks."""
        engine = MockJPKIVerificationEngine()
        nonce = engine.generate_challenge(ttl_seconds=300)
        self.assertTrue(len(nonce) >= 32)

        # First validation must succeed
        self.assertTrue(engine.validate_nonce(nonce))
        # Second validation must fail (replay attack blocked)
        self.assertFalse(engine.validate_nonce(nonce))

    def test_05_jpki_signature_verification(self) -> None:
        """Verifies client signature against server challenge in simulation harness."""
        engine = MockJPKIVerificationEngine()
        session = NFCReaderSession(document_type="my_number")
        session.verify_pin("1234")

        nonce = engine.generate_challenge(ttl_seconds=300)
        sig_data = session.sign_challenge(nonce)

        valid, msg = engine.verify_signature(
            challenge_nonce=nonce,
            signature_hex=sig_data["signature_hex"],
        )
        self.assertTrue(valid, f"Verification failed: {msg}")

    def test_06_strict_raw_image_rejection(self) -> None:
        """Verifies that any payload containing images or unapproved fields is rejected."""
        clean_payload = {
            "name": "Yamada Taro",
            "date_of_birth": "1985-04-12",
            "address": "Tokyo",
        }
        # Must pass without error
        reject_raw_images(clean_payload)

        # Payload with photo key must raise error
        dirty_payload_1 = {"name": "Yamada Taro", "id_photo": "some_data"}
        with self.assertRaises(RawImageRejectionError):
            reject_raw_images(dirty_payload_1)

        # Payload with base64 image data must raise error
        dirty_payload_2 = {"data": "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQ..."}
        with self.assertRaises(RawImageRejectionError):
            reject_raw_images(dirty_payload_2)

        # Payload with binary image header must raise error
        dirty_payload_3 = {"name": b"\xff\xd8\xff\xe0\x00\x10JFIF"}
        with self.assertRaises(RawImageRejectionError):
            reject_raw_images(dirty_payload_3)

    def test_07_zero_pii_blind_tokenization(self) -> None:
        """Verifies blind hash generation and identity token issuance."""
        tokenizer = ZeroPIITokenizer()
        blind_1 = tokenizer.generate_blind_hash("Yamada Taro", "1985-04-12")
        blind_2 = tokenizer.generate_blind_hash("Yamada Taro", "1985-04-12")
        blind_other = tokenizer.generate_blind_hash("Tanaka Hanako", "1990-01-01")

        self.assertEqual(blind_1, blind_2)  # Deterministic for deduplication
        self.assertNotEqual(blind_1, blind_other)

        token_result = tokenizer.issue_identity_token(
            {"name": "Yamada Taro", "date_of_birth": "1985-04-12"}
        )
        self.assertIn("identity_token", token_result)
        self.assertEqual(token_result["status"], "VERIFIED_ZERO_PII")
        self.assertEqual(token_result["blind_hash"], blind_1)

    def test_08_api_end_to_end_flow(self) -> None:
        """Verifies end-to-end eKYC flow via EKYCService."""
        service = EKYCService()

        # Step 1: Request Challenge Nonce
        status, chal_resp = service.handle_request_challenge()
        self.assertEqual(status, 200)
        nonce = chal_resp["challenge_nonce"]

        # Step 2: Client signs challenge via NFC
        session = NFCReaderSession(document_type="my_number")
        session.verify_pin("1234")
        sig_data = session.sign_challenge(nonce)
        attrs = session.read_verified_attributes()

        # Step 3: Server verifies JPKI signature
        verify_req = {
            "challenge_nonce": nonce,
            "signature_hex": sig_data["signature_hex"],
            "attributes": attrs,
        }
        v_status, v_resp = service.handle_verify_jpki(verify_req)
        self.assertEqual(v_status, 200)
        self.assertEqual(v_resp["status"], "success")
        self.assertEqual(v_resp["verification"]["status"], "VERIFIED_ZERO_PII")

    def test_09_api_rejects_payload_with_image(self) -> None:
        """Verifies API returns 422 Unprocessable Entity when client attempts image upload."""
        service = EKYCService()
        status, chal_resp = service.handle_request_challenge()
        nonce = chal_resp["challenge_nonce"]

        # Attempt to upload legacy photo
        invalid_req = {
            "challenge_nonce": nonce,
            "signature_hex": "1234567890abcdef1234567890abcdef",
            "front_image": "base64_prohibited_image_data",
        }
        v_status, v_resp = service.handle_verify_jpki(invalid_req)
        self.assertEqual(v_status, 422)
        self.assertEqual(v_resp["error"], "UNPROCESSABLE_ENTITY")
        self.assertIn("prohibited", v_resp["message"].lower())

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "Requires 'cryptography' library")
    def test_10_jpki_cryptographic_verification_with_x509_cert(self) -> None:
        """Verifies real asymmetric cryptographic signature verification with X.509 cert."""
        priv_pem, cert_pem = NFCReaderSession.generate_test_keypair(common_name="山田 太郎")
        engine = JPKIVerificationEngine(allow_simulation=False)

        nonce = engine.generate_challenge(ttl_seconds=300)
        session = NFCReaderSession(document_type="my_number")
        session.verify_pin("1234")

        sig_payload = session.sign_challenge(nonce, private_key_pem=priv_pem)
        attributes = session.read_verified_attributes()

        valid, msg = engine.verify_signature(
            challenge_nonce=nonce,
            signature_hex=sig_payload["signature_hex"],
            certificate_pem=cert_pem,
            attributes=attributes,
        )
        self.assertTrue(valid, f"Cryptographic verification should pass: {msg}")

        # Forged signature verification must fail
        forged_nonce = engine.generate_challenge(ttl_seconds=300)
        forged_sig = "ab" * 256  # Invalid 256-byte signature
        valid_forged, _ = engine.verify_signature(
            challenge_nonce=forged_nonce,
            signature_hex=forged_sig,
            certificate_pem=cert_pem,
            attributes=attributes,
        )
        self.assertFalse(valid_forged)

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "Requires 'cryptography' library")
    def test_11_jpki_attribute_binding_mismatch_rejected(self) -> None:
        """Verifies that an attribute swap attack is rejected when cert CN does not match claimed name."""
        priv_pem, cert_pem = NFCReaderSession.generate_test_keypair(common_name="山田 太郎")
        engine = JPKIVerificationEngine(allow_simulation=False)

        nonce = engine.generate_challenge(ttl_seconds=300)
        session = NFCReaderSession(document_type="my_number")
        session.verify_pin("1234")

        sig_payload = session.sign_challenge(nonce, private_key_pem=priv_pem)

        # Attacker claims different name than cert Subject CN
        spoofed_attributes = {
            "name": "悪意の 攻撃者",  # Mismatch with "山田 太郎"
            "date_of_birth": "1985-04-12",
        }

        valid, msg = engine.verify_signature(
            challenge_nonce=nonce,
            signature_hex=sig_payload["signature_hex"],
            certificate_pem=cert_pem,
            attributes=spoofed_attributes,
        )
        self.assertFalse(valid)
        self.assertIn("Attribute binding mismatch", msg)

    def test_12_simulation_blocked_in_production(self) -> None:
        """Verifies simulation mode cannot be activated in production environments."""
        with patch.dict(os.environ, {"KOMAINU_ENV": "production", "CI": ""}), \
             patch("remediate.ekyc.server.jpki_verifier._is_test_environment", return_value=False):
            with self.assertRaises(RuntimeError):
                JPKIVerificationEngine(allow_simulation=True)

    def test_13_sod_verification_hardening(self) -> None:
        """Verifies driver license SOD minimum size and ASN.1 DER sequence header requirements."""
        engine = MockJPKIVerificationEngine()

        # Too short (< 32 bytes)
        too_short_sod = b"\x30\x10" + b"\x00" * 14
        valid_short, msg = engine.verify_driver_license_sod(too_short_sod)
        self.assertFalse(valid_short)
        self.assertIn("minimum 32 bytes", msg)

        # Not ASN.1 DER sequence (tag != 0x30)
        invalid_tag_sod = b"\x04\x20" + b"\x00" * 32
        valid_tag, msg = engine.verify_driver_license_sod(invalid_tag_sod)
        self.assertFalse(valid_tag)
        self.assertIn("ASN.1 DER sequence", msg)

        # Valid mock SOD (tag 0x30, length >= 32)
        valid_sod = b"\x30\x20" + b"\x00" * 32
        valid_ok, msg = engine.verify_driver_license_sod(valid_sod)
        self.assertTrue(valid_ok)

    def test_14_api_driver_license_invalid_hex_returns_400(self) -> None:
        """Verifies API returns 400 Bad Request on invalid sod_hex encoding instead of 500 error."""
        service = EKYCService()
        req = {
            "sod_hex": "not_valid_hex_sequence_zz!!",
            "attributes": {"name": "Test User"},
        }
        status, resp = service.handle_verify_driver_license(req)
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"], "BAD_REQUEST")
        self.assertIn("hex", resp["message"].lower())

    def test_15_bounded_nonce_store_fifo_eviction(self) -> None:
        """Verifies nonce storage adheres to capacity limit and evicts oldest entries."""
        engine = JPKIVerificationEngine(max_active_nonces=3, allow_simulation=True)
        n1 = engine.generate_challenge()
        n2 = engine.generate_challenge()
        n3 = engine.generate_challenge()
        self.assertEqual(len(engine._active_nonces), 3)

        # Adding 4th nonce must evict n1 (FIFO)
        n4 = engine.generate_challenge()
        self.assertEqual(len(engine._active_nonces), 3)
        self.assertNotIn(n1, engine._active_nonces)
        self.assertIn(n2, engine._active_nonces)
        self.assertIn(n3, engine._active_nonces)
        self.assertIn(n4, engine._active_nonces)

    def test_16_identity_token_verification_and_expiry(self) -> None:
        """Verifies HMAC signature check and expiration enforcement on identity tokens."""
        tokenizer = ZeroPIITokenizer(signing_key=b"test-secret-key-32-bytes-long!!")
        token_info = tokenizer.issue_identity_token({"name": "Yamada Taro"})
        raw_token = token_info["identity_token"]

        # Valid token verification
        is_valid, payload, err = tokenizer.verify_identity_token(raw_token)
        self.assertTrue(is_valid)
        self.assertIsNotNone(payload)
        self.assertIsNone(err)

        # Tampered payload verification
        import base64
        parts = raw_token.split(".")
        fake_payload = base64.urlsafe_b64encode(b'{"token_id": "fake", "exp": 9999999999}').decode("utf-8")
        tampered_token = f"{fake_payload}.{parts[1]}"
        is_valid_t, _, err_t = tokenizer.verify_identity_token(tampered_token)
        self.assertFalse(is_valid_t)
        self.assertIn("Invalid HMAC signature", err_t or "")

        # Expired token verification
        expired_info = tokenizer.issue_identity_token({"name": "Yamada Taro"}, ttl_minutes=-10)
        is_valid_exp, _, err_exp = tokenizer.verify_identity_token(expired_info["identity_token"])
        self.assertFalse(is_valid_exp)
        self.assertIn("expired", err_exp or "")


if __name__ == "__main__":
    unittest.main()
