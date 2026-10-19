#!/usr/bin/env python3
"""Zero-PII Tokenization & Strict Image Rejection Engine.

Enforces zero-storage of raw identification photos (生画像非保持化) to eliminate
the risk of catastrophic identity leaks (e.g., Times Car 6.6M account breach).
Extracts and tokenizes only legally mandated attributes under the Japanese
Criminal Proceeds Transfer Prevention Act (犯収法).
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, List, Optional, Set, Tuple

# Allowed fields in API requests under Zero-PII contract
ALLOWED_TOP_LEVEL_FIELDS: Set[str] = {
    "challenge_nonce",
    "signature_hex",
    "certificate_pem",
    "attributes",
    "sod_hex",
    "document_type",
}

# Allowed verified personal attributes under 2027 amendments
ALLOWED_ATTRIBUTE_FIELDS: Set[str] = {
    "name",
    "date_of_birth",
    "address",
    "gender",
    "document_issuer",
    "nationality",
}

# Known binary signatures for image files
IMAGE_MAGIC_BYTES = [
    b"\xff\xd8\xff",        # JPEG
    b"\x89PNG\r\n\x1a\n",    # PNG
    b"GIF87a", b"GIF89a",   # GIF
    b"RIFF",                # WEBP (starts with RIFF....WEBP)
    b"BM",                  # BMP
]

SUSPICIOUS_IMAGE_KEYS = {
    "image", "photo", "raw_image", "card_image", "front_image",
    "back_image", "selfie", "id_photo", "face_image", "scan"
}


class RawImageRejectionError(ValueError):
    """Raised when an eKYC payload contains prohibited raw image data or unpermitted fields."""
    pass


def reject_raw_images(payload: Any, is_top_level: bool = True) -> None:
    """Enforces Zero-PII Rule: Rejects payloads with unpermitted fields, raw images, or photo streams."""
    if isinstance(payload, dict):
        has_api_keys = any(k in ALLOWED_TOP_LEVEL_FIELDS for k in payload)

        for k, v in payload.items():
            lower_k = str(k).strip().lower()

            # Denylist check: reject any image-related field names
            if (
                lower_k in SUSPICIOUS_IMAGE_KEYS
                or "image" in lower_k
                or "photo" in lower_k
                or "selfie" in lower_k
            ):
                raise RawImageRejectionError(
                    f"Prohibited field detected: '{k}'. Under 2027 eKYC Zero-PII rules, raw images must not be transmitted."
                )

            # Allowlist check for top-level API payloads vs attribute dictionaries
            if is_top_level and has_api_keys:
                if k not in ALLOWED_TOP_LEVEL_FIELDS:
                    raise RawImageRejectionError(
                        f"Unpermitted field detected: '{k}'. Only allow-listed eKYC fields are permitted."
                    )
            else:
                if k not in ALLOWED_ATTRIBUTE_FIELDS:
                    raise RawImageRejectionError(
                        f"Unpermitted attribute field: '{k}'. Only allow-listed identity attributes are accepted."
                    )

            if k == "attributes" and isinstance(v, dict):
                reject_raw_images(v, is_top_level=False)
            elif isinstance(v, (dict, list)):
                reject_raw_images(v, is_top_level=False)
            elif isinstance(v, (str, bytes)):
                reject_raw_images(v, is_top_level=False)

    elif isinstance(payload, list):
        for item in payload:
            reject_raw_images(item, is_top_level=False)

    elif isinstance(payload, str):
        stripped = payload.strip()
        lower_stripped = stripped.lower()
        if (
            lower_stripped.startswith("data:image/")
            or lower_stripped.startswith("/9j/")
            or lower_stripped.startswith("ivborw0kggo")
        ):
            raise RawImageRejectionError("Prohibited base64 image data stream detected in payload.")

    elif isinstance(payload, bytes):
        for magic in IMAGE_MAGIC_BYTES:
            if payload.startswith(magic):
                raise RawImageRejectionError("Prohibited binary image stream detected in payload.")


class ZeroPIITokenizer:
    """Tokenizes verified identity attributes into blind deduplication hashes and tamper-proof tokens."""

    def __init__(
        self,
        hmac_key: Optional[bytes] = None,
        signing_key: Optional[bytes] = None,
    ):
        key = hmac_key or signing_key
        if key:
            self.hmac_key = key
        elif "KOMAINU_EKYC_HMAC_KEY" in os.environ and os.environ["KOMAINU_EKYC_HMAC_KEY"]:
            self.hmac_key = os.environ["KOMAINU_EKYC_HMAC_KEY"].encode("utf-8")
        else:
            self.hmac_key = secrets.token_bytes(32)

    def generate_blind_hash(self, name: str, date_of_birth: str) -> str:
        """Create a one-way blind index hash for deduplication without storing raw identity."""
        normalized = f"{name.strip().lower()}:{date_of_birth.strip()}".encode("utf-8")
        return hmac.new(self.hmac_key, normalized, hashlib.sha256).hexdigest()

    def issue_identity_token(
        self,
        verified_attributes: Dict[str, str],
        issuer: str = "Komainu-eKYC-Gateway",
        ttl_minutes: int = 60,
    ) -> Dict[str, Any]:
        """Issue an ephemeral, tamper-proof Verified Identity Token without storing raw images."""
        # Strictly enforce no images or unpermitted fields present
        reject_raw_images(verified_attributes, is_top_level=False)

        now = datetime.datetime.now(datetime.timezone.utc)
        exp = now + datetime.timedelta(minutes=ttl_minutes)

        blind_hash = self.generate_blind_hash(
            name=verified_attributes.get("name", ""),
            date_of_birth=verified_attributes.get("date_of_birth", ""),
        )

        token_id = secrets.token_urlsafe(16)
        claims = {
            "token_id": token_id,
            "iss": issuer,
            "sub_blind_hash": blind_hash,
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "verified_via": "JPKI_NFC_CRYPTO",
            "regulatory_compliance": "JP_CRIMINAL_PROCEEDS_ACT_2027",
            "has_raw_images_stored": False,
        }

        # Signature of token claims
        claims_bytes = json.dumps(claims, sort_keys=True).encode("utf-8")
        sig = hmac.new(self.hmac_key, claims_bytes, hashlib.sha256).hexdigest()

        return {
            "identity_token": f"{base64.urlsafe_b64encode(claims_bytes).decode('utf-8')}.{sig}",
            "blind_hash": blind_hash,
            "expires_at": exp.isoformat(),
            "status": "VERIFIED_ZERO_PII",
        }

    def verify_identity_token(
        self, token_str: str
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """Verify the cryptographic HMAC integrity and expiration of an issued identity token."""
        if not token_str or "." not in token_str:
            return False, None, "Malformed identity token structure"

        parts = token_str.split(".")
        if len(parts) != 2:
            return False, None, "Malformed identity token: expected payload.signature"

        payload_b64, sig_hex = parts[0], parts[1]
        try:
            padded = payload_b64 + "=" * (-len(payload_b64) % 4)
            claims_bytes = base64.urlsafe_b64decode(padded.encode("ascii"))
            claims = json.loads(claims_bytes.decode("utf-8"))
        except Exception as ex:
            return False, None, f"Invalid token encoding: {ex}"

        # Verify HMAC signature
        expected_sig = hmac.new(self.hmac_key, claims_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig_hex.lower(), expected_sig.lower()):
            return False, None, "Invalid HMAC signature: token may have been tampered with"

        # Verify expiration
        exp = claims.get("exp")
        if exp is None:
            return False, None, "Identity token missing 'exp' claim"
        if time.time() > float(exp):
            return False, None, "Identity token has expired"

        return True, claims, None
