#!/usr/bin/env python3
"""Unit & Acceptance Tests for Boilerplate 4: Tenant-Isolated SaaS & BYOK Encryption."""

from __future__ import annotations

import os
import unittest

from remediate.tenancy.audit.audit_trail import TenantAuditTrail
from remediate.tenancy.crypto.byok_manager import (
    BYOKKeyManager,
    CrossTenantKeyMismatchError,
    CryptoShreddedError,
)
from remediate.tenancy.middleware.tenant_context import (
    MissingTenantContextError,
    TenantContextResolver,
    get_current_tenant,
    tenant_scope,
)

MODULE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestTenantIsolationAndBYOK(unittest.TestCase):
    def test_01_sql_templates_exist(self) -> None:
        """Verifies PostgreSQL RLS and schema-per-tenant SQL scripts exist."""
        sql_dir = os.path.join(MODULE_ROOT, "sql")
        rls_file = os.path.join(sql_dir, "rls_isolation.sql")
        schema_file = os.path.join(sql_dir, "schema_per_tenant.sql")

        self.assertTrue(os.path.isfile(rls_file), "rls_isolation.sql must exist")
        self.assertTrue(os.path.isfile(schema_file), "schema_per_tenant.sql must exist")

    def test_02_sql_rls_policy_declarations(self) -> None:
        """Verifies RLS script contains FORCE ROW LEVEL SECURITY and session variable."""
        rls_file = os.path.join(MODULE_ROOT, "sql", "rls_isolation.sql")
        with open(rls_file, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("ENABLE ROW LEVEL SECURITY", content)
        self.assertIn("FORCE ROW LEVEL SECURITY", content)
        self.assertIn("tenant_isolation_policy", content)
        self.assertIn("app.current_tenant_id", content)

    def test_03_byok_encryption_and_decryption(self) -> None:
        """Verifies Tenant A can encrypt and decrypt data using their dedicated BYOK master key."""
        byok = BYOKKeyManager()
        byok.register_tenant_key("tenant-acme")

        secret_text = "CONFIDENTIAL_FINANCIAL_LEDGER_2026"
        envelope = byok.encrypt_field("tenant-acme", secret_text)

        self.assertEqual(envelope["tenant_id"], "tenant-acme")
        self.assertIn("encrypted_dek", envelope)
        self.assertIn("ciphertext", envelope)

        decrypted = byok.decrypt_field("tenant-acme", envelope)
        self.assertEqual(decrypted, secret_text)

    def test_04_byok_cross_tenant_isolation_blocked(self) -> None:
        """Verifies Tenant B cannot decrypt Tenant A's ciphertext (cryptographic isolation)."""
        byok = BYOKKeyManager()
        byok.register_tenant_key("tenant-acme")
        byok.register_tenant_key("tenant-beta")

        envelope = byok.encrypt_field("tenant-acme", "Acme Secret Data")

        # Tenant Beta attempts to decrypt Acme's data -> Must raise CrossTenantKeyMismatchError
        with self.assertRaises(CrossTenantKeyMismatchError):
            byok.decrypt_field("tenant-beta", envelope)

    def test_05_byok_crypto_shredding(self) -> None:
        """Verifies Crypto-Shredding: revoking tenant key permanently destroys readability."""
        byok = BYOKKeyManager()
        byok.register_tenant_key("tenant-departing")

        envelope = byok.encrypt_field("tenant-departing", "To be permanently destroyed")

        # Tenant offboards: key is revoked/shredded
        byok.revoke_tenant_key("tenant-departing")
        self.assertFalse(byok.is_key_active("tenant-departing"))

        # Decryption attempt must fail with CryptoShreddedError
        with self.assertRaises(CryptoShreddedError):
            byok.decrypt_field("tenant-departing", envelope)

    def test_06_tamper_evident_audit_trail_integrity(self) -> None:
        """Verifies cryptographic hash chaining and detects tampered audit records."""
        trail = TenantAuditTrail()
        trail.log_event("tenant-1", "user-alice", "ORDER_CREATED", "ord-101")
        trail.log_event("tenant-1", "user-alice", "ORDER_APPROVED", "ord-101")
        rec3 = trail.log_event("tenant-1", "user-bob", "ORDER_PAID", "ord-101")

        valid, msg = trail.verify_chain_integrity("tenant-1")
        self.assertTrue(valid, msg)

        # Tampering simulation: alter the action of record 3
        rec3.action = "ORDER_TAMPERED"
        tampered, tampered_msg = trail.verify_chain_integrity("tenant-1")
        self.assertFalse(tampered)
        self.assertIn("Tampered audit record detected", tampered_msg)

    def test_07_tenant_context_resolution(self) -> None:
        """Verifies tenant resolution from JWT claims, subdomain, and headers."""
        # 1. From verified JWT claims
        tenant_jwt = TenantContextResolver.resolve_from_headers(
            headers={"host": "api.komainu.dev"},
            jwt_claims={"tenant_id": "tenant-from-jwt"},
        )
        self.assertEqual(tenant_jwt, "tenant-from-jwt")

        # 2. From subdomain
        tenant_sub = TenantContextResolver.resolve_from_headers(
            headers={"host": "enterprise-corp.komainu.dev"}
        )
        self.assertEqual(tenant_sub, "enterprise-corp")

        # 3. From header
        tenant_hdr = TenantContextResolver.resolve_from_headers(
            headers={"host": "localhost", "x-tenant-id": "tenant-internal"}
        )
        self.assertEqual(tenant_hdr, "tenant-internal")

        # 4. Missing context raises error
        with self.assertRaises(MissingTenantContextError):
            TenantContextResolver.resolve_from_headers(headers={"host": "localhost"})

    def test_08_tenant_scope_isolation(self) -> None:
        """Verifies tenant_scope binds context variable and resets cleanly."""
        with self.assertRaises(MissingTenantContextError):
            get_current_tenant()

        with tenant_scope("tenant-xyz"):
            self.assertEqual(get_current_tenant(), "tenant-xyz")

        # Must be unbound after context exit
        with self.assertRaises(MissingTenantContextError):
            get_current_tenant()


if __name__ == "__main__":
    unittest.main()
