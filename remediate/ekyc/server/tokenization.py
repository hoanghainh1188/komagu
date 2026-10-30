#!/usr/bin/env python3
"""Zero-PII Tokenization & Strict Image / My Number Rejection Engine.

Enforces zero-storage of raw identification photos (生画像非保持化) and
strictly rejects Japanese Individual Numbers (個人番号 / My Number) to eliminate
the risk of catastrophic identity leaks (e.g., Times Car 6.6M account breach).
Extracts and tokenizes only legally mandated attributes under the Japanese
Criminal Proceeds Transfer Prevention Act (犯収法 2027年改正).
Provides OID4IDA (OpenID Connect for Identity Assurance 1.0) verified_claims
token generation and proof-of-possession (PoP) token binding.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    """Read KOMAGU_<name>."""
    return os.environ.get("KOMAGU_" + name, default)


# Allowed fields in API requests under Zero-PII contract
ALLOWED_TOP_LEVEL_FIELDS: Set[str] = {
    "challenge_nonce",
    "signature_hex",
    "certificate_pem",
    "attributes",
    "sod_hex",
    "document_type",
    "client_jkt",
    "tenant_id",
}

# Allowed verified personal attributes under 2027 amendments
ALLOWED_ATTRIBUTE_FIELDS: Set[str] = {
    "name",
    "date_of_birth",
    "birthdate",
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

PROHIBITED_IDENTIFIER_KEYS = {
    "my_number", "individual_number", "kojin_bango", "ssn",
    "social_security_number", "mynumber", "personal_number"
}

MY_NUMBER_REGEX = re.compile(r"^\d{12}$")
EMBEDDED_MY_NUMBER_REGEX = re.compile(r"(?:^|\D)(\d{12}|\d{4}[-\s]\d{4}[-\s]\d{4})(?:$|\D)")

# Maximum permitted string lengths by field type to guard against ReDoS and memory exhaustion
MAX_FIELD_LENGTHS: Dict[str, int] = {
    "name": 255,
    "date_of_birth": 32,
    "birthdate": 32,
    "address": 1024,
    "gender": 32,
    "document_issuer": 255,
    "nationality": 64,
    "challenge_nonce": 128,
    "signature_hex": 4096,
    "certificate_pem": 16384,
    "sod_hex": 65536,
    "document_type": 64,
    "client_jkt": 128,
    "tenant_id": 128,
}
GENERIC_MAX_FIELD_LENGTH = 65536


class RawImageRejectionError(ValueError):
    """Raised when an eKYC payload contains prohibited raw image data or unpermitted fields."""
    pass


class ProhibitedIdentifierError(ValueError):
    """Raised when an eKYC payload contains prohibited Individual Number (My Number) or unpermitted PII identifiers."""
    pass


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to unpadded base64url string per RFC 7515."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(data: str) -> bytes:
    """Decode unpadded base64url string to bytes."""
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def reject_prohibited_identifiers(payload: Any) -> None:
    """Enforces Non-Storage of My Number: Rejects payloads containing 12-digit Individual Numbers or prohibited keys."""
    if isinstance(payload, dict):
        for k, v in payload.items():
            lower_k = str(k).strip().lower()
            if (
                lower_k in PROHIBITED_IDENTIFIER_KEYS
                or "my_number" in lower_k
                or "individual_number" in lower_k
                or "kojin_bango" in lower_k
            ):
                raise ProhibitedIdentifierError(
                    f"Prohibited identifier field detected: '{k}'. Under 2027 eKYC rules, My Number (個人番号) must never be transmitted or stored."
                )

            # Check if value itself is or embeds a 12-digit My Number
            if isinstance(v, (str, int)):
                str_val = str(v).strip()
                # Exclude high-entropy cryptographic signatures from naive embedded substring check
                if lower_k not in {"signature_hex", "certificate_pem", "client_jkt", "challenge_nonce", "sod_hex"}:
                    cleaned = str_val.replace("-", "").replace(" ", "")
                    if MY_NUMBER_REGEX.match(cleaned) or EMBEDDED_MY_NUMBER_REGEX.search(str_val):
                        raise ProhibitedIdentifierError(
                            f"Prohibited 12-digit Individual Number (My Number) detected in field '{k}'. Storage of raw Individual Numbers is prohibited by the My Number Act."
                        )

            if isinstance(v, (dict, list)):
                reject_prohibited_identifiers(v)

    elif isinstance(payload, list):
        for item in payload:
            reject_prohibited_identifiers(item)

    elif isinstance(payload, (str, int)):
        str_val = str(payload).strip()
        cleaned = str_val.replace("-", "").replace(" ", "")
        if MY_NUMBER_REGEX.match(cleaned) or EMBEDDED_MY_NUMBER_REGEX.search(str_val):
            raise ProhibitedIdentifierError(
                "Prohibited 12-digit Individual Number (My Number) detected in payload value."
            )


def reject_raw_images(payload: Any, is_top_level: bool = True) -> None:
    """Enforces Zero-PII Rule: Rejects payloads with unpermitted fields, raw images, or photo streams."""
    # First verify no prohibited Individual Numbers
    if is_top_level:
        reject_prohibited_identifiers(payload)

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

            # Field length limits
            limit = MAX_FIELD_LENGTHS.get(k, GENERIC_MAX_FIELD_LENGTH)
            if isinstance(v, (str, bytes)) and len(v) > limit:
                raise RawImageRejectionError(
                    f"Field '{k}' exceeds maximum permitted length ({len(v)} > {limit})."
                )

            # Check sod_hex for hex-encoded raw image headers (JPEG, PNG, GIF, BMP, WEBP)
            if k == "sod_hex" and isinstance(v, str):
                sod_strip = v.strip().lower()
                if (
                    sod_strip.startswith("ffd8ff")
                    or sod_strip.startswith("89504e47")
                    or sod_strip.startswith("47494638")
                    or sod_strip.startswith("424d")
                    or sod_strip.startswith("52494646")
                ):
                    raise RawImageRejectionError(
                        "Prohibited hex-encoded image data detected in sod_hex."
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

        # Check for data:image anywhere in string or base64 image magic prefixes
        if (
            "data:image/" in lower_stripped
            or lower_stripped.startswith("/9j/")
            or lower_stripped.startswith("ivborw0kggo")
            or lower_stripped.startswith("r0lg")
            or lower_stripped.startswith("qk")
        ):
            raise RawImageRejectionError("Prohibited base64 image data stream detected in payload.")

        # Additional inspection: attempt base64 decode of prefix to detect arbitrary image headers
        if len(stripped) >= 16 and not stripped.startswith("-----BEGIN"):
            try:
                prefix_candidate = stripped[:32]
                padded = prefix_candidate + "=" * (-len(prefix_candidate) % 4)
                decoded_prefix = base64.b64decode(padded.encode("ascii"), validate=False)
                for magic in IMAGE_MAGIC_BYTES:
                    if decoded_prefix.startswith(magic):
                        raise RawImageRejectionError("Prohibited base64 image data stream detected in payload.")
            except Exception:
                pass

    elif isinstance(payload, bytes):
        for magic in IMAGE_MAGIC_BYTES:
            if payload.startswith(magic):
                raise RawImageRejectionError("Prohibited binary image stream detected in payload.")


def _is_running_in_test() -> bool:
    """Return True if running under a test runner or with explicit test opt-in."""
    if "unittest" in sys.modules or "pytest" in sys.modules:
        return True
    if _env("EKYC_ALLOW_EPHEMERAL_KEY") == "1":
        return True
    return False


class ZeroPIITokenizer:
    """Tokenizes verified identity attributes into blind deduplication hashes and tamper-proof OIDC tokens."""

    def __init__(
        self,
        hmac_key: Optional[bytes] = None,
        signing_key: Optional[bytes] = None,
        allow_ephemeral_key: Optional[bool] = None,
    ):
        key = hmac_key or signing_key
        if key:
            self.hmac_key = key
        elif _env("EKYC_HMAC_KEY"):
            self.hmac_key = _env("EKYC_HMAC_KEY").encode("utf-8")
        else:
            is_test = _is_running_in_test() if allow_ephemeral_key is None else allow_ephemeral_key
            if is_test and _env("EKYC_REQUIRE_HMAC_KEY") != "1":
                self.hmac_key = secrets.token_bytes(32)
            else:
                raise RuntimeError(
                    "KOMAGU_EKYC_HMAC_KEY environment variable is required to initialize ZeroPIITokenizer. "
                    "Silent fallback to an ephemeral random key is prohibited outside test environments to prevent "
                    "intermittent token verification failures across restarts and multi-replica deployments."
                )

    def derive_tenant_key(self, tenant_id: str, context: str = "ekyc_dedup") -> bytes:
        """Derive a tenant-isolated cryptographic key to prevent cross-tenant identity correlation."""
        info = f"{tenant_id}:{context}".encode("utf-8")
        return hmac.new(self.hmac_key, info, hashlib.sha256).digest()

    def generate_blind_hash(
        self,
        name: str,
        date_of_birth: str,
        tenant_id: Optional[str] = None,
    ) -> str:
        """Create a one-way blind index hash for deduplication without storing raw identity.

        When tenant_id is provided, keys are derived per tenant to guarantee unlinkability across applications.
        """
        key = self.derive_tenant_key(tenant_id) if tenant_id else self.hmac_key
        normalized = f"{name.strip().lower()}:{date_of_birth.strip()}".encode("utf-8")
        return hmac.new(key, normalized, hashlib.sha256).hexdigest()

    @staticmethod
    def compute_jwk_thumbprint(jwk: Dict[str, Any]) -> str:
        """Calculate RFC 7638 SHA-256 Thumbprint of a JSON Web Key."""
        kty = jwk.get("kty")
        if kty == "RSA":
            canonical = {
                "e": jwk["e"],
                "kty": "RSA",
                "n": jwk["n"],
            }
        elif kty == "EC":
            canonical = {
                "crv": jwk["crv"],
                "kty": "EC",
                "x": jwk["x"],
                "y": jwk["y"],
            }
        else:
            canonical = {k: jwk[k] for k in sorted(jwk.keys())}

        json_bytes = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")
        digest = hashlib.sha256(json_bytes).digest()
        return _base64url_encode(digest)

    def issue_identity_token(
        self,
        verified_attributes: Dict[str, str],
        issuer: str = "Komagu-eKYC-Gateway",
        ttl_minutes: int = 60,
        verified_via: str = "JPKI_NFC_CRYPTO",
    ) -> Dict[str, Any]:
        """Issue an ephemeral, tamper-proof Verified Identity Token without storing raw images.

        `verified_attributes` must come from the verifier, never from the client request.
        """
        # Strictly enforce no images, prohibited fields, or My Number present
        reject_raw_images(verified_attributes, is_top_level=False)

        now = datetime.datetime.now(datetime.timezone.utc)
        exp = now + datetime.timedelta(minutes=ttl_minutes)

        dob = verified_attributes.get("date_of_birth") or verified_attributes.get("birthdate", "")
        blind_hash = self.generate_blind_hash(
            name=verified_attributes.get("name", ""),
            date_of_birth=dob,
        )

        token_id = secrets.token_urlsafe(16)
        claims = {
            "token_id": token_id,
            "iss": issuer,
            "sub_blind_hash": blind_hash,
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "verified_via": verified_via,
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
        """Verify the cryptographic HMAC integrity and expiration of a legacy identity token."""
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

    def issue_oidc_token(
        self,
        verified_attributes: Dict[str, Any],
        tenant_id: str = "default",
        issuer: str = "https://auth.komagu.io",
        audience: str = "komagu-app",
        client_jkt: Optional[str] = None,
        ttl_minutes: int = 60,
        trust_framework: str = "jp_ekyc_2027",
    ) -> Dict[str, Any]:
        """Issue an OpenID Connect for Identity Assurance (OID4IDA) verified_claims JWT.

        Embeds Proof-of-Possession confirmation claim (cnf.jkt) when client_jkt is provided.
        """
        # Strictly reject raw images, unpermitted fields, and My Number
        reject_raw_images(verified_attributes, is_top_level=False)

        now = datetime.datetime.now(datetime.timezone.utc)
        exp = now + datetime.timedelta(minutes=ttl_minutes)
        jti = secrets.token_urlsafe(16)

        dob = verified_attributes.get("date_of_birth") or verified_attributes.get("birthdate", "")
        blind_hash = self.generate_blind_hash(
            name=verified_attributes.get("name", ""),
            date_of_birth=dob,
            tenant_id=tenant_id,
        )

        header = {"alg": "HS256", "typ": "JWT"}

        claims_clean: Dict[str, Any] = {}
        for k in ALLOWED_ATTRIBUTE_FIELDS:
            if k in verified_attributes:
                claims_clean[k] = verified_attributes[k]

        claims: Dict[str, Any] = {
            "iss": issuer,
            "sub": f"urn:komagu:blind:{blind_hash}",
            "aud": audience,
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": jti,
            "tenant_id": tenant_id,
            "verified_claims": {
                "verification": {
                    "trust_framework": trust_framework,
                    "time": now.isoformat(),
                    "verification_process": "jpki_nfc_crypto",
                    "evidence": [
                        {
                            "type": "document",
                            "method": "crypto_ic_chip",
                            "document_details": {
                                "type": "jp_my_number_card"
                            },
                            "verifier": {
                                "organization": "J-LIS",
                                "trust_anchor": "Mock-J-LIS-Root-CA"
                            }
                        }
                    ]
                },
                "claims": claims_clean,
            }
        }

        if client_jkt:
            claims["cnf"] = {"jkt": client_jkt}

        header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_b64 = _base64url_encode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

        tenant_key = self.derive_tenant_key(tenant_id, context="oidc_signing")
        signature_bytes = hmac.new(tenant_key, signing_input, hashlib.sha256).digest()
        signature_b64 = _base64url_encode(signature_bytes)

        jwt_token = f"{header_b64}.{payload_b64}.{signature_b64}"

        return {
            "jwt": jwt_token,
            "blind_hash": blind_hash,
            "expires_at": exp.isoformat(),
            "claims": claims,
        }

    def verify_oidc_token(
        self,
        jwt_str: str,
        expected_audience: Optional[str] = None,
        expected_tenant_id: Optional[str] = None,
        expected_client_jkt: Optional[str] = None,
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """Verify the integrity, signature, expiration, and PoP binding of an OID4IDA JWT."""
        if not jwt_str or "." not in jwt_str:
            return False, None, "Malformed JWT structure: missing dots"

        parts = jwt_str.split(".")
        if len(parts) != 3:
            return False, None, "Malformed JWT: expected 3 dot-separated parts"

        header_b64, payload_b64, sig_b64 = parts[0], parts[1], parts[2]

        try:
            header = json.loads(_base64url_decode(header_b64).decode("utf-8"))
            payload = json.loads(_base64url_decode(payload_b64).decode("utf-8"))
        except Exception as ex:
            return False, None, f"Invalid JWT base64url encoding or JSON: {ex}"

        if header.get("alg") != "HS256":
            return False, None, f"Unsupported algorithm '{header.get('alg')}': expected HS256"

        tenant_id = payload.get("tenant_id", "default")
        if expected_tenant_id and tenant_id != expected_tenant_id:
            return False, None, f"Tenant mismatch: expected '{expected_tenant_id}', got '{tenant_id}'"

        # Verify signature with tenant key
        tenant_key = self.derive_tenant_key(tenant_id, context="oidc_signing")
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected_sig_bytes = hmac.new(tenant_key, signing_input, hashlib.sha256).digest()
        expected_sig_b64 = _base64url_encode(expected_sig_bytes)

        if not hmac.compare_digest(sig_b64, expected_sig_b64):
            return False, None, "Invalid JWT signature: token has been tampered with"

        # Verify expiration
        exp = payload.get("exp")
        if exp is None:
            return False, None, "JWT missing 'exp' claim"
        if time.time() > float(exp):
            return False, None, "JWT has expired"

        # Verify audience
        if expected_audience:
            aud = payload.get("aud")
            if aud != expected_audience:
                return False, None, f"Audience mismatch: expected '{expected_audience}', got '{aud}'"

        # Verify Proof-of-Possession binding (cnf.jkt)
        if expected_client_jkt:
            cnf = payload.get("cnf")
            if not cnf or not isinstance(cnf, dict):
                return False, None, "Proof-of-possession binding required: missing 'cnf' claim"
            actual_jkt = cnf.get("jkt")
            if actual_jkt != expected_client_jkt:
                return False, None, f"Proof-of-possession key thumbprint mismatch: expected '{expected_client_jkt}', got '{actual_jkt}'"

        return True, payload, None


def create_verification_record(
    verification_id: str,
    tenant_id: str,
    tokenized_identity: Dict[str, Any],
    audit_trail: Dict[str, Any],
    oidc_claims: Optional[Dict[str, Any]] = None,
    status: str = "verified",
    verification_method: str = "jpki_nfc",
    trust_framework: str = "jp_ekyc_2027",
) -> Dict[str, Any]:
    """Create a standardized eKYC verification result conforming to contracts/schemas/ekyc-verification.schema.json."""
    # Ensure strict Zero-PII audit trail invariants
    clean_audit = dict(audit_trail)
    clean_audit["raw_images_stored"] = False
    clean_audit["individual_number_stored"] = False

    record: Dict[str, Any] = {
        "verification_id": verification_id,
        "tenant_id": tenant_id,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": status,
        "verification_method": verification_method,
        "trust_framework": trust_framework,
        "tokenized_identity": tokenized_identity,
        "audit_trail": clean_audit,
    }

    if oidc_claims:
        record["oidc_claims"] = oidc_claims

    return record
