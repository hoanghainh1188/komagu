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
import secrets
from typing import Any, Dict, List, Optional, Set

# Known binary signatures for image files
IMAGE_MAGIC_BYTES = [
    b"\xff\xd8\xff",        # JPEG
    b"\x89PNG\r\n\x1a\n",    # PNG
    b"GIF87a", b"GIF89a",   # GIF
    b"RIFF",                # WEBP (starts with RIFF....WEBP)
]

SUSPICIOUS_IMAGE_KEYS = {
    "image", "photo", "raw_image", "card_image", "front_image",
    "back_image", "selfie", "id_photo", "face_image", "scan"
}


class RawImageRejectionError(ValueError):
    """Raised when an eKYC payload contains prohibited raw image data."""
    pass


def reject_raw_images(payload: Any) -> None:
    """Enforces Zero-PII Rule: Rejects any payload containing raw images or base64 photo buffers."""
    if isinstance(payload, dict):
        for k, v in payload.items():
            lower_k = str(k).lower()
            if lower_k in SUSPICIOUS_IMAGE_KEYS:
                raise RawImageRejectionError(
                    f"Prohibited field detected: '{k}'. Under 2027 eKYC Zero-PII rules, raw images must not be transmitted."
                )
            reject_raw_images(v)
    elif isinstance(payload, list):
        for item in payload:
            reject_raw_images(item)
    elif isinstance(payload, str):
        # Check for base64 image data URI prefix
        if payload.startswith("data:image/") or payload.startswith("/9j/") or payload.startswith("iVBORw0KGgo"):
            raise RawImageRejectionError("Prohibited base64 image data stream detected in payload.")
    elif isinstance(payload, bytes):
        for magic in IMAGE_MAGIC_BYTES:
            if payload.startswith(magic):
                raise RawImageRejectionError("Prohibited binary image stream detected in payload.")


class ZeroPIITokenizer:
    """Tokenizes verified identity attributes into blind deduplication hashes and tamper-proof tokens."""

    def __init__(self, hmac_key: Optional[bytes] = None):
        self.hmac_key = hmac_key or secrets.token_bytes(32)

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
        # Strictly enforce no images present
        reject_raw_images(verified_attributes)

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
