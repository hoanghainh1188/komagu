#!/usr/bin/env python3
"""NFC Client Reader Module for Japanese Identification Documents (ISO/IEC 7816-4).

Supports APDU command sequencing and cryptographic extraction for:
1. Japanese My Number Card (個人番号カード - JPKI AP & 券面事項確認AP)
2. Japanese Driver's License IC Chip (運転免許証 IC)
3. Japanese e-Passport (ICAO Doc 9303 Biometric Passport)
"""

from __future__ import annotations

import datetime
import hashlib
import os
from typing import Any, Dict, List, Optional, Tuple

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.x509.oid import NameOID
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# Standard Application Identifiers (AIDs)
AID_MY_NUMBER_JPKI = "D3921000310001010408"          # JPKI (User Auth & Digital Signature)
AID_MY_NUMBER_TEXT_INFO = "D3921000310001010401"     # 券面事項確認AP (4 basic attributes)
AID_DRIVERS_LICENSE_MAIN = "A0000002310100000000000000000000" # 運転免許証 本籍・記載事項AP
AID_EPASSPORT_ICAO = "A0000002471001"                 # ICAO 9303 e-Passport


class APDUCommand:
    """Represents an ISO/IEC 7816-4 Application Protocol Data Unit."""

    def __init__(self, cla: int, ins: int, p1: int, p2: int, data: bytes = b"", le: Optional[int] = None):
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.data = data
        self.le = le

    def to_bytes(self) -> bytes:
        """Encode APDU command to raw byte sequence."""
        buf = bytearray([self.cla, self.ins, self.p1, self.p2])
        if self.data:
            buf.append(len(self.data))
            buf.extend(self.data)
        if self.le is not None:
            buf.append(self.le)
        return bytes(buf)

    @classmethod
    def select_application(cls, aid_hex: str) -> APDUCommand:
        """Construct ISO 7816-4 SELECT FILE by AID command."""
        aid_bytes = bytes.fromhex(aid_hex)
        return cls(cla=0x00, ins=0xA4, p1=0x04, p2=0x0C, data=aid_bytes)

    @classmethod
    def read_binary(cls, offset: int, length: int) -> APDUCommand:
        """Construct ISO 7816-4 READ BINARY command."""
        p1 = (offset >> 8) & 0x7F
        p2 = offset & 0xFF
        return cls(cla=0x00, ins=0xB0, p1=p1, p2=p2, le=length)


class NFCReaderSession:
    """Simulates and coordinates NFC chip reading transactions."""

    def __init__(self, document_type: str = "my_number"):
        self.document_type = document_type
        self.selected_aid: Optional[str] = None
        self.is_authenticated: bool = False

    def select_application(self, aid_hex: str) -> Tuple[bool, str]:
        """Select an on-chip application by AID."""
        cmd = APDUCommand.select_application(aid_hex)
        valid_aids = {AID_MY_NUMBER_JPKI, AID_MY_NUMBER_TEXT_INFO, AID_DRIVERS_LICENSE_MAIN, AID_EPASSPORT_ICAO}
        if aid_hex.upper() in valid_aids:
            self.selected_aid = aid_hex.upper()
            return True, "9000"  # SW1=90, SW2=00 (Normal processing)
        return False, "6A82"  # File or application not found

    def verify_pin(self, pin: str) -> Tuple[bool, str]:
        """Verify 4-digit PIN for My Number User Auth or Driver License PIN1."""
        if not pin or len(pin) < 4:
            return False, "63C0"  # Verification failed
        self.is_authenticated = True
        return True, "9000"

    def sign_challenge(self, challenge_nonce: str, private_key_pem: Optional[str] = None) -> Dict[str, Any]:
        """Sign a server challenge nonce using on-chip JPKI private key."""
        if not self.is_authenticated and self.document_type == "my_number":
            raise PermissionError("NFC session not authenticated with PIN")

        nonce_bytes = challenge_nonce.encode("utf-8")

        if private_key_pem:
            if not HAS_CRYPTOGRAPHY:
                raise RuntimeError("Cryptographic signing requires 'cryptography' library")

            # Cryptographic signing using real key pair
            key = serialization.load_pem_private_key(
                private_key_pem.encode("utf-8"),
                password=None,
            )
            if isinstance(key, rsa.RSAPrivateKey):
                sig_bytes = key.sign(
                    nonce_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
                algorithm = "SHA256withRSA"
            elif isinstance(key, ec.EllipticCurvePrivateKey):
                sig_bytes = key.sign(
                    nonce_bytes,
                    ec.ECDSA(hashes.SHA256()),
                )
                algorithm = "SHA256withECDSA"
            else:
                raise ValueError("Unsupported private key type")

            return {
                "document_type": self.document_type,
                "challenge_nonce": challenge_nonce,
                "signature_hex": sig_bytes.hex(),
                "algorithm": algorithm,
                "cert_type": "JPKI-User-Auth",
            }

        # Simulated fallback for isolated test harnesses
        simulated_signature = hashlib.sha256(b"JPKI-SE-KEY:" + nonce_bytes).hexdigest()

        return {
            "document_type": self.document_type,
            "challenge_nonce": challenge_nonce,
            "signature_hex": simulated_signature,
            "algorithm": "SHA256withRSA",
            "cert_type": "JPKI-User-Auth",
        }

    def read_verified_attributes(self) -> Dict[str, str]:
        """Extract only text attributes without returning any photo/image data (Zero-PII)."""
        if not self.is_authenticated:
            raise PermissionError("Authentication required before reading attributes")

        # In compliance with Zero-PII, no photo binary is returned
        return {
            "name": "山田 太郎",
            "date_of_birth": "1985-04-12",
            "address": "東京都千代田区霞が関１丁目１−１",
            "gender": "male",
            "document_issuer": "J-LIS / Local Authorities Systems",
        }

    @staticmethod
    def generate_test_keypair(common_name: str = "山田 太郎") -> Tuple[str, str]:
        """Generate an RSA-2048 private key and self-signed X.509 cert for testing."""
        if not HAS_CRYPTOGRAPHY:
            raise RuntimeError("Test keypair generation requires 'cryptography' library")

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "J-LIS Test Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256())
        )

        priv_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        return priv_pem, cert_pem
