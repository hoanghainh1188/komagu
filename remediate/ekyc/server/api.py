#!/usr/bin/env python3
"""Zero-PII eKYC REST API Handlers.

Provides standard endpoints for remote identity verification under the 2027
Japanese Criminal Proceeds Transfer Prevention Act regulations.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Tuple

from remediate.ekyc.server.jpki_verifier import JPKIVerificationEngine
from remediate.ekyc.server.tokenization import (
    RawImageRejectionError,
    ZeroPIITokenizer,
    reject_raw_images,
)


class EKYCService:
    """Core controller for Zero-PII remote identity verification."""

    def __init__(self):
        self.verifier = JPKIVerificationEngine()
        self.tokenizer = ZeroPIITokenizer()

    def handle_request_challenge(self) -> Tuple[int, Dict[str, Any]]:
        """POST /api/v1/ekyc/challenge -> Issues single-use challenge nonce."""
        nonce = self.verifier.generate_challenge(ttl_seconds=300)
        return 200, {
            "status": "success",
            "challenge_nonce": nonce,
            "ttl_seconds": 300,
            "accepted_algorithms": ["SHA256withRSA", "SHA256withECDSA"],
        }

    def handle_verify_jpki(self, request_payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """POST /api/v1/ekyc/verify-jpki -> Validates JPKI signature & issues Zero-PII token."""
        # Step 1: Strict Zero-PII Check: reject if raw photo/image is passed
        try:
            reject_raw_images(request_payload)
        except RawImageRejectionError as e:
            return 422, {
                "error": "UNPROCESSABLE_ENTITY",
                "message": str(e),
                "remediation": "Remove all image/photo fields. Only cryptographic signatures and verified attributes are accepted.",
            }

        challenge_nonce = request_payload.get("challenge_nonce", "")
        signature_hex = request_payload.get("signature_hex", "")
        attributes = request_payload.get("attributes", {})

        if not challenge_nonce or not signature_hex:
            return 400, {
                "error": "BAD_REQUEST",
                "message": "Missing required fields: challenge_nonce or signature_hex",
            }

        # Step 2: Cryptographic Signature Verification
        valid, msg = self.verifier.verify_signature(
            challenge_nonce=challenge_nonce,
            signature_hex=signature_hex,
            document_type="my_number",
        )
        if not valid:
            return 401, {
                "error": "SIGNATURE_VERIFICATION_FAILED",
                "message": msg,
            }

        # Step 3: Zero-PII Tokenization
        token_data = self.tokenizer.issue_identity_token(verified_attributes=attributes)

        return 200, {
            "status": "success",
            "message": "Identity successfully verified via JPKI without storing raw images",
            "verification": token_data,
        }

    def handle_verify_driver_license(self, request_payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """POST /api/v1/ekyc/verify-driver-license -> Validates IC chip signature."""
        try:
            reject_raw_images(request_payload)
        except RawImageRejectionError as e:
            return 422, {
                "error": "UNPROCESSABLE_ENTITY",
                "message": str(e),
            }

        sod_hex = request_payload.get("sod_hex", "")
        if not sod_hex:
            return 400, {"error": "BAD_REQUEST", "message": "Missing sod_hex payload"}

        sod_bytes = bytes.fromhex(sod_hex) if sod_hex else b""
        valid, msg = self.verifier.verify_driver_license_sod(sod_bytes)
        if not valid:
            return 401, {"error": "VERIFICATION_FAILED", "message": msg}

        attributes = request_payload.get("attributes", {})
        token_data = self.tokenizer.issue_identity_token(verified_attributes=attributes)

        return 200, {
            "status": "success",
            "verification": token_data,
        }
