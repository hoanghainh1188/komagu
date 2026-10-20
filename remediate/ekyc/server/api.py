#!/usr/bin/env python3
"""Zero-PII eKYC REST API Handlers.

Provides standard endpoints for remote identity verification under the 2027
Japanese Criminal Proceeds Transfer Prevention Act regulations.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional, Tuple

from remediate.ekyc.server.jpki_verifier import (
    JPKIVerificationEngine,
    NonceRateLimitExceededError,
    NonceStoreCapacityExceededError,
    _check_attribute_binding,
    _simulation_opted_in,
)
from remediate.ekyc.server.tokenization import (
    RawImageRejectionError,
    ZeroPIITokenizer,
    reject_raw_images,
)


class EKYCService:
    """Core controller for Zero-PII remote identity verification."""

    def __init__(
        self,
        verifier: Optional[JPKIVerificationEngine] = None,
        tokenizer: Optional[ZeroPIITokenizer] = None,
    ):
        if verifier is None:
            # No trust anchors, revocation checker or SOD verifier: every certificate and SOD
            # is rejected until a configured verifier is passed in. Simulation needs an
            # explicit opt-in (see SIMULATION_ENV_FLAG).
            self.verifier = JPKIVerificationEngine(
                allow_simulation=_simulation_opted_in()
            )
        else:
            self.verifier = verifier

        self.tokenizer = tokenizer or ZeroPIITokenizer()

    def handle_request_challenge(self, client_ip: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
        """POST /api/v1/ekyc/challenge -> Issues single-use challenge nonce."""
        try:
            nonce = self.verifier.generate_challenge(ttl_seconds=300, client_id=client_ip)
            return 200, {
                "status": "success",
                "challenge_nonce": nonce,
                "ttl_seconds": 300,
                "accepted_algorithms": ["SHA256withRSA", "SHA256withECDSA"],
            }
        except NonceRateLimitExceededError as e:
            return 429, {
                "error": "TOO_MANY_REQUESTS",
                "message": str(e),
            }
        except NonceStoreCapacityExceededError as e:
            return 503, {
                "error": "SERVICE_UNAVAILABLE",
                "message": str(e),
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
        certificate_pem = request_payload.get("certificate_pem")
        attributes = request_payload.get("attributes", {})

        if not challenge_nonce or not signature_hex:
            return 400, {
                "error": "BAD_REQUEST",
                "message": "Missing required fields: challenge_nonce or signature_hex",
            }

        # Step 2: Cryptographic Signature Verification (returns the certificate-bound attributes)
        valid, msg, verified_attributes = self.verifier.verify_identity(
            challenge_nonce=challenge_nonce,
            signature_hex=signature_hex,
            document_type="my_number",
            certificate_pem=certificate_pem,
            attributes=attributes,
        )
        if not valid:
            return 401, {
                "error": "SIGNATURE_VERIFICATION_FAILED",
                "message": msg,
            }

        # Step 3: Zero-PII Tokenization from verified attributes only
        token_data = self.tokenizer.issue_identity_token(
            verified_attributes=verified_attributes,
            verified_via="JPKI_NFC_CRYPTO",
        )

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

        try:
            sod_bytes = bytes.fromhex(sod_hex)
        except ValueError:
            return 400, {
                "error": "BAD_REQUEST",
                "message": "Invalid sod_hex payload: must be valid hexadecimal string",
            }

        valid, msg, verified_attributes = self.verifier.verify_driver_license(sod_bytes)
        if not valid:
            return 401, {"error": "VERIFICATION_FAILED", "message": msg}

        binding_error = _check_attribute_binding(request_payload.get("attributes", {}), verified_attributes)
        if binding_error:
            return 401, {"error": "VERIFICATION_FAILED", "message": binding_error}

        token_data = self.tokenizer.issue_identity_token(
            verified_attributes=verified_attributes,
            verified_via="DRIVER_LICENSE_IC_SOD",
        )

        return 200, {
            "status": "success",
            "verification": token_data,
        }
