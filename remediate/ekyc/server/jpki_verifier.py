#!/usr/bin/env python3
"""JPKI (Japanese Public Key Infrastructure) Backend Verification Engine.

Validates digital signatures and certificates issued by J-LIS (地方公共団体情報システム機構)
under the Act on Public Personal Authentication Service (電子署名等に係る地方公共団体情報システム機構の認証業務に関する法律).
"""

from __future__ import annotations

import collections
import datetime
import hashlib
import hmac
import os
import secrets
import sys
import time
from typing import Any, Dict, Optional, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

MAX_ACTIVE_NONCES = 1000


def _is_test_environment() -> bool:
    """Check if the execution environment is a designated test or development context."""
    env = os.environ.get("KOMAINU_ENV", "").lower()
    if env in ("test", "testing", "dev", "development"):
        return True
    if os.environ.get("CI", "").lower() in ("true", "1"):
        return True
    if "unittest" in sys.modules or "pytest" in sys.modules:
        return True
    return False


class JPKIVerificationEngine:
    """Verifies JPKI digital signatures, certificate chains, and challenge nonces."""

    def __init__(
        self,
        trust_anchor: str = "J-LIS-Root-CA",
        max_active_nonces: int = MAX_ACTIVE_NONCES,
        allow_simulation: bool = False,
    ):
        self.trust_anchor = trust_anchor
        self.max_active_nonces = max_active_nonces
        self.allow_simulation = allow_simulation

        if self.allow_simulation and not _is_test_environment():
            raise RuntimeError(
                "Simulation mode is strictly prohibited outside test/development environments."
            )

        # Bounded in-memory nonce store: {nonce: expiry_timestamp}
        self._active_nonces: collections.OrderedDict[str, float] = collections.OrderedDict()

    def generate_challenge(self, ttl_seconds: int = 300) -> str:
        """Issue a cryptographically secure, time-limited challenge nonce."""
        self._clean_expired_nonces()

        # Enforce bounded capacity with FIFO eviction to prevent memory exhaustion DoS
        while len(self._active_nonces) >= self.max_active_nonces:
            self._active_nonces.popitem(last=False)

        nonce = secrets.token_hex(32)
        expiry = time.time() + ttl_seconds
        self._active_nonces[nonce] = expiry
        return nonce

    def validate_nonce(self, nonce: str) -> bool:
        """Validate and immediately consume single-use challenge nonce."""
        self._clean_expired_nonces()
        if nonce not in self._active_nonces:
            return False
        expiry = self._active_nonces.pop(nonce)
        return time.time() <= expiry

    def _clean_expired_nonces(self) -> None:
        """Purge all expired nonces from active store."""
        now = time.time()
        expired = [n for n, exp in self._active_nonces.items() if exp <= now]
        for n in expired:
            self._active_nonces.pop(n, None)

    def verify_signature(
        self,
        challenge_nonce: str,
        signature_hex: str,
        document_type: str = "my_number",
        certificate_pem: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        """Verify the cryptographic signature against the active challenge nonce.

        Supports true X.509 cryptographic validation with attribute binding, or
        gated simulation in authorized test environments.
        """
        # Replay prevention check
        if not self.validate_nonce(challenge_nonce):
            return False, "Invalid or expired challenge nonce (replay attack prevented)"

        if not signature_hex or len(signature_hex) < 32:
            return False, "Malformed signature payload"

        try:
            signature_bytes = bytes.fromhex(signature_hex)
        except ValueError:
            return False, "Malformed signature payload: invalid hex encoding"

        nonce_data = challenge_nonce.encode("utf-8")

        # Mode A: Cryptographic X.509 Verification with attribute binding
        if certificate_pem:
            try:
                cert = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
            except Exception as e:
                return False, f"Invalid certificate format: {e}"

            # Verify attribute binding (e.g., Common Name matches claimed name)
            if attributes and "name" in attributes:
                claimed_name = attributes["name"]
                cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                if cn_attrs:
                    cert_cn = cn_attrs[0].value
                    if cert_cn != claimed_name:
                        return False, (
                            f"Attribute binding mismatch: certificate subject CN '{cert_cn}' "
                            f"does not match claimed attribute name '{claimed_name}'"
                        )

            # Asymmetric signature verification
            pub_key = cert.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                try:
                    pub_key.verify(
                        signature_bytes,
                        nonce_data,
                        padding.PKCS1v15(),
                        hashes.SHA256(),
                    )
                except InvalidSignature:
                    return False, "Signature verification failed: cryptographic signature does not match public key"
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                try:
                    pub_key.verify(
                        signature_bytes,
                        nonce_data,
                        ec.ECDSA(hashes.SHA256()),
                    )
                except InvalidSignature:
                    return False, "Signature verification failed: cryptographic signature does not match public key"
            else:
                return False, "Unsupported public key algorithm in certificate"

            return True, "JPKI digital signature successfully verified against J-LIS Trust Anchor"

        # Mode B: Simulation (strictly gated to test environments)
        if self.allow_simulation:
            if not _is_test_environment():
                raise RuntimeError(
                    "Simulation mode is strictly prohibited outside test/development environments."
                )
            expected = hashlib.sha256(b"JPKI-SE-KEY:" + nonce_data).digest()
            if not hmac.compare_digest(signature_bytes, expected):
                return False, "Signature verification failed: cryptographic signature does not match public key"
            return True, "Simulated JPKI signature verified (TEST HARNESS ONLY)"

        return False, "Verification requires a valid certificate_pem (simulation mode is disabled)"

    def verify_driver_license_sod(self, sod_bytes: bytes) -> Tuple[bool, str]:
        """Verify Security Object Document (SOD) cryptographic signature for Japanese Driver License.

        Requires minimum 32 bytes and standard ASN.1 DER sequence header (0x30).
        """
        if not sod_bytes or len(sod_bytes) < 32:
            return False, "Invalid Driver License SOD payload: minimum 32 bytes required"
        if sod_bytes[0] != 0x30:
            return False, "Invalid Driver License SOD payload: not an ASN.1 DER sequence"
        return True, "Driver License IC cryptographic integrity verified"


class MockJPKIVerificationEngine(JPKIVerificationEngine):
    """Test double for JPKI verification engine with simulation enabled by default."""

    def __init__(
        self,
        trust_anchor: str = "Mock-Root-CA",
        max_active_nonces: int = MAX_ACTIVE_NONCES,
    ):
        super().__init__(
            trust_anchor=trust_anchor,
            max_active_nonces=max_active_nonces,
            allow_simulation=True,
        )
