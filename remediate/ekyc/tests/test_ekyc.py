#!/usr/bin/env python3
"""Unit & Acceptance Tests for Boilerplate 2: Zero-PII eKYC & NFC Verification."""

from __future__ import annotations

import os
import unittest

from remediate.ekyc.client.nfc_reader import (
    AID_MY_NUMBER_JPKI,
    APDUCommand,
    NFCReaderSession,
)
from remediate.ekyc.server.api import EKYCService
from remediate.ekyc.server.jpki_verifier import JPKIVerificationEngine
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
        engine = JPKIVerificationEngine()
        nonce = engine.generate_challenge(ttl_seconds=300)
        self.assertTrue(len(nonce) >= 32)

        # First validation must succeed
        self.assertTrue(engine.validate_nonce(nonce))
        # Second validation must fail (replay attack blocked)
        self.assertFalse(engine.validate_nonce(nonce))

    def test_05_jpki_signature_verification(self) -> None:
        """Verifies client signature against server challenge."""
        engine = JPKIVerificationEngine()
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
        """Verifies that any payload containing images is rejected (Zero-PII invariant)."""
        clean_payload = {"name": "Yamada Taro", "dob": "1985-04-12"}
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


if __name__ == "__main__":
    unittest.main()
