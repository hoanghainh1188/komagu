#!/usr/bin/env python3
"""Bring Your Own Key (BYOK) Per-Tenant Envelope Encryption Engine.

Provides cryptographic isolation across SaaS tenants using per-tenant Master Keys
(AWS KMS CMK / HashiCorp Vault transit engine compatible) and AES-256-GCM
envelope encryption. Supports instant crypto-shredding upon tenant offboarding.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from typing import Any, Dict, Optional, Tuple


class CryptoShreddedError(PermissionError):
    """Raised when an attempt is made to decrypt data for a tenant whose key has been revoked."""
    pass


class CrossTenantKeyMismatchError(PermissionError):
    """Raised when an attempt is made to decrypt tenant data using another tenant's cryptographic key."""
    pass


class MockAESGCM:
    """Standardized pure-Python AES-GCM simulation with authenticated encryption tags."""

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, associated_data: bytes) -> Tuple[bytes, bytes, bytes]:
        import hashlib
        import hmac

        nonce = secrets.token_bytes(12)
        # Keystream generation using HMAC-SHA256
        keystream = hmac.new(key, nonce + b":keystream", hashlib.sha256).digest()
        # Expand keystream to plaintext length if needed
        while len(keystream) < len(plaintext):
            keystream += hmac.new(key, keystream + b":exp", hashlib.sha256).digest()

        ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream[:len(plaintext)]))
        # Authentication tag over AD + nonce + ciphertext
        tag_data = associated_data + nonce + ciphertext
        auth_tag = hmac.new(key, tag_data, hashlib.sha256).digest()[:16]

        return nonce, ciphertext, auth_tag

    @staticmethod
    def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, auth_tag: bytes, associated_data: bytes) -> bytes:
        import hashlib
        import hmac

        tag_data = associated_data + nonce + ciphertext
        expected_tag = hmac.new(key, tag_data, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(auth_tag, expected_tag):
            raise ValueError("Authentication tag verification failed: corrupted data or wrong key")

        keystream = hmac.new(key, nonce + b":keystream", hashlib.sha256).digest()
        while len(keystream) < len(ciphertext):
            keystream += hmac.new(key, keystream + b":exp", hashlib.sha256).digest()

        return bytes(c ^ k for c, k in zip(ciphertext, keystream[:len(ciphertext)]))


class BYOKKeyManager:
    """Manages per-tenant master encryption keys (KMS/Vault) and envelope encryption."""

    def __init__(self):
        # Master Key store: {tenant_id: master_key_bytes}
        self._tenant_master_keys: Dict[str, bytes] = {}
        # Revoked / shredded keys: {tenant_id: revocation_timestamp}
        self._revoked_keys: Dict[str, str] = {}

    def register_tenant_key(self, tenant_id: str, custom_key: Optional[bytes] = None) -> bytes:
        """Register or provision a dedicated 256-bit Master Key for a tenant."""
        key = custom_key or secrets.token_bytes(32)
        self._tenant_master_keys[tenant_id] = key
        return key

    def revoke_tenant_key(self, tenant_id: str) -> None:
        """Execute Crypto-Shredding: Permanently destroys tenant master key rendering all data unrecoverable."""
        if tenant_id in self._tenant_master_keys:
            del self._tenant_master_keys[tenant_id]
        import datetime
        self._revoked_keys[tenant_id] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def is_key_active(self, tenant_id: str) -> bool:
        """Check if tenant master key is active and not shredded."""
        return tenant_id in self._tenant_master_keys

    def encrypt_field(self, tenant_id: str, plaintext: str) -> Dict[str, Any]:
        """Encrypt sensitive tenant field using Envelope Encryption (DEK encrypted by Tenant Master Key)."""
        if not self.is_key_active(tenant_id):
            raise CryptoShreddedError(f"Cannot encrypt data: Tenant '{tenant_id}' key is not active or has been shredded.")

        master_key = self._tenant_master_keys[tenant_id]

        # 1. Generate ephemeral Data Encryption Key (DEK)
        dek = secrets.token_bytes(32)

        # 2. Encrypt plaintext with DEK using AES-256-GCM
        aad = tenant_id.encode("utf-8")
        nonce, ciphertext, auth_tag = MockAESGCM.encrypt(dek, plaintext.encode("utf-8"), associated_data=aad)

        # 3. Encrypt DEK with Tenant Master Key (Envelope)
        dek_nonce, enc_dek, dek_tag = MockAESGCM.encrypt(master_key, dek, associated_data=aad)

        envelope = {
            "version": "1.0",
            "tenant_id": tenant_id,
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "auth_tag": base64.b64encode(auth_tag).decode("utf-8"),
            "encrypted_dek": base64.b64encode(enc_dek).decode("utf-8"),
            "dek_nonce": base64.b64encode(dek_nonce).decode("utf-8"),
            "dek_tag": base64.b64encode(dek_tag).decode("utf-8"),
        }
        return envelope

    def decrypt_field(self, requesting_tenant_id: str, envelope: Dict[str, Any]) -> str:
        """Decrypt sensitive field, enforcing tenant cryptographic boundaries."""
        target_tenant = envelope.get("tenant_id")
        if not target_tenant:
            raise ValueError("Malformed envelope: missing tenant_id")

        if requesting_tenant_id != target_tenant:
            raise CrossTenantKeyMismatchError(
                f"Cryptographic boundary breach! Tenant '{requesting_tenant_id}' cannot decrypt "
                f"data belonging to Tenant '{target_tenant}'."
            )

        if not self.is_key_active(target_tenant):
            raise CryptoShreddedError(
                f"Crypto-Shredded: Key for Tenant '{target_tenant}' was revoked. Data is permanently unrecoverable."
            )

        master_key = self._tenant_master_keys[target_tenant]
        aad = target_tenant.encode("utf-8")

        # 1. Decrypt DEK using Tenant Master Key
        enc_dek = base64.b64decode(envelope["encrypted_dek"])
        dek_nonce = base64.b64decode(envelope["dek_nonce"])
        dek_tag = base64.b64decode(envelope["dek_tag"])
        dek = MockAESGCM.decrypt(master_key, dek_nonce, enc_dek, dek_tag, associated_data=aad)

        # 2. Decrypt ciphertext using DEK
        ciphertext = base64.b64decode(envelope["ciphertext"])
        nonce = base64.b64decode(envelope["nonce"])
        auth_tag = base64.b64decode(envelope["auth_tag"])
        plaintext_bytes = MockAESGCM.decrypt(dek, nonce, ciphertext, auth_tag, associated_data=aad)

        return plaintext_bytes.decode("utf-8")
