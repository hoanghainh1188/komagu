"""Mock J-LIS (地方公共団体情報システム機構) Certificate Authority & CRL Engine.

Simulates the Japanese Public Key Infrastructure (JPKI) trust hierarchy:
  Root CA -> Intermediate Sub-CA -> User Authentication & Signature Certificates.
Supports CRL revocation generation and APDU challenge-response nonce signing.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID


class MockJLISCertificateAuthority:
    """Simulates J-LIS Root CA, Intermediate Sub-CA, certificate issuance, and CRL generation."""

    def __init__(self, key_size: int = 2048) -> None:
        self.key_size = key_size
        self._revoked_serials: Dict[int, datetime.datetime] = {}

        # 1. Initialize Root CA
        self.root_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
        )
        self.root_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "J-LIS"),
            x509.NameAttribute(NameOID.COMMON_NAME, "J-LIS Public Authentication Service Root CA"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        self.root_cert = (
            x509.CertificateBuilder()
            .subject_name(self.root_subject)
            .issuer_name(self.root_subject)
            .public_key(self.root_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=2),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.root_private_key, hashes.SHA256())
        )

        # 2. Initialize Intermediate Sub-CA (User Authentication Sub-CA)
        self.sub_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
        )
        self.sub_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "J-LIS"),
            x509.NameAttribute(NameOID.COMMON_NAME, "J-LIS Individual Authentication Sub-CA"),
        ])
        self.sub_cert = (
            x509.CertificateBuilder()
            .subject_name(self.sub_subject)
            .issuer_name(self.root_subject)
            .public_key(self.sub_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1825))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.root_private_key, hashes.SHA256())
        )

    def get_root_ca_pem(self) -> str:
        """Export Root CA certificate as PEM."""
        return self.root_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def get_intermediate_ca_pem(self) -> str:
        """Export Intermediate Sub-CA certificate as PEM."""
        return self.sub_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def issue_user_certificate(
        self,
        subject_cn: str = "TARO YAMADA",
        key_type: str = "rsa",
        validity_days: int = 365,
        expired: bool = False,
        not_before: Optional[datetime.datetime] = None,
        not_after: Optional[datetime.datetime] = None,
    ) -> Tuple[x509.Certificate, Any, str]:
        """Issue a user authentication certificate signed by J-LIS Sub-CA.

        Returns:
            Tuple[x509.Certificate, Any, str]: (Certificate, PrivateKey, PEM_String)
        """
        now = datetime.datetime.now(datetime.timezone.utc)

        if key_type.lower() == "ec" or key_type.lower() == "ecdsa":
            user_key = ec.generate_private_key(ec.SECP256R1())
        else:
            user_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

        user_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "J-LIS User"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
        ])

        if expired:
            nb = now - datetime.timedelta(days=validity_days + 30)
            na = now - datetime.timedelta(days=1)
        elif not_before and not_after:
            nb = not_before
            na = not_after
        else:
            nb = now - datetime.timedelta(days=1)
            na = now + datetime.timedelta(days=validity_days)

        cert = (
            x509.CertificateBuilder()
            .subject_name(user_subject)
            .issuer_name(self.sub_subject)
            .public_key(user_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(nb)
            .not_valid_after(na)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.sub_private_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        return cert, user_key, cert_pem

    def sign_nonce(self, private_key: Any, nonce: str) -> str:
        """Sign challenge nonce with user private key, returning hex signature."""
        data = nonce.encode("utf-8")
        if isinstance(private_key, rsa.RSAPrivateKey):
            sig = private_key.sign(
                data,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            sig = private_key.sign(
                data,
                ec.ECDSA(hashes.SHA256()),
            )
        else:
            raise ValueError("Unsupported key type for signing")
        return sig.hex()

    def revoke_certificate(self, serial_number: int) -> None:
        """Add certificate serial number to revocation list."""
        self._revoked_serials[serial_number] = datetime.datetime.now(datetime.timezone.utc)

    def is_revoked(self, serial_number: int) -> bool:
        """Check if certificate serial number is revoked."""
        return serial_number in self._revoked_serials

    def generate_crl(self) -> x509.CertificateRevocationList:
        """Generate X.509 Certificate Revocation List (CRL) signed by Sub-CA."""
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.sub_subject)
            .last_update(now - datetime.timedelta(minutes=1))
            .next_update(now + datetime.timedelta(days=7))
        )

        for serial, rev_date in self._revoked_serials.items():
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(rev_date)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked_cert)

        return builder.sign(self.sub_private_key, hashes.SHA256())

    def get_crl_pem(self) -> str:
        """Export CRL as PEM string."""
        crl = self.generate_crl()
        return crl.public_bytes(serialization.Encoding.PEM).decode("utf-8")
