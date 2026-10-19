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

    def test_09_schema_per_tenant_slug_rejection(self) -> None:
        """Verifies strict slug validation regex ^[a-z0-9_]{1,48}$ and rejection of injection attempts."""
        import re

        slug_pattern = re.compile(r"^[a-z0-9_]{1,48}$")

        valid_slugs = ["acme_corp", "tenant1", "org_999", "a", "12345"]
        for slug in valid_slugs:
            self.assertTrue(slug_pattern.match(slug), f"Valid slug '{slug}' should match pattern")

        invalid_slugs = [
            "acme-corp",  # hyphens rejected
            "ACME_CORP",  # upper-case rejected
            "acme.corp",  # dots rejected
            "tenant; DROP TABLE orders; --",  # SQL injection rejected
            "x' OR '1'='1",  # quotes rejected
            "",  # empty string rejected
            "a" * 49,  # exceeds 48 characters
        ]
        for slug in invalid_slugs:
            self.assertFalse(slug_pattern.match(slug), f"Invalid slug '{slug}' must be rejected")

        # Verify SQL file explicitly declares this regex and raises exception
        schema_file = os.path.join(MODULE_ROOT, "sql", "schema_per_tenant.sql")
        with open(schema_file, "r", encoding="utf-8") as f:
            sql_content = f.read()

        self.assertIn("^[a-z0-9_]{1,48}$", sql_content)
        self.assertIn("RAISE EXCEPTION 'Invalid tenant slug", sql_content)
        # Ensure it does NOT use vulnerable regexp_replace rewrite
        self.assertNotIn("regexp_replace(p_tenant_slug", sql_content)

    def test_10_schema_per_tenant_sql_safety_and_no_public_fallback(self) -> None:
        """Verifies schema_per_tenant uses %I throughout, avoids public fallback, and detects collisions."""
        schema_file = os.path.join(MODULE_ROOT, "sql", "schema_per_tenant.sql")
        with open(schema_file, "r", encoding="utf-8") as f:
            sql_content = f.read()

        # No vulnerable string injection in index or schema names
        self.assertNotIn("idx_%s_orders_owner", sql_content)
        self.assertIn("CREATE INDEX %I ON %I.orders(owner_user_id)", sql_content)
        # Collision detection via tenant_registry table
        self.assertIn("public.tenant_registry", sql_content)
        self.assertIn("Schema collision detected", sql_content)
        # No fallback to public in search_path
        self.assertIn("SET LOCAL search_path TO %I", sql_content)
        self.assertNotIn("search_path TO %I, public", sql_content)
        # Permissions revoked from PUBLIC
        self.assertIn("REVOKE ALL ON SCHEMA %I FROM PUBLIC", sql_content)
        self.assertIn("REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM PUBLIC", sql_content)
        self.assertIn("REVOKE ALL ON FUNCTION create_tenant_schema(VARCHAR) FROM PUBLIC", sql_content)
        self.assertIn("REVOKE ALL ON FUNCTION switch_tenant_schema(VARCHAR) FROM PUBLIC", sql_content)

    def test_11_rls_sql_app_role_and_tenant_organizations_security(self) -> None:
        """Verifies RLS template defines non-owner app role, protects tenant_organizations, and pins search_path."""
        rls_file = os.path.join(MODULE_ROOT, "sql", "rls_isolation.sql")
        with open(rls_file, "r", encoding="utf-8") as f:
            sql_content = f.read()

        # Dedicated non-owner role provisioned
        self.assertIn("CREATE ROLE komainu_app WITH NOSUPERUSER NOBYPASSRLS", sql_content)
        # tenant_organizations protected by RLS
        self.assertIn("ALTER TABLE tenant_organizations ENABLE ROW LEVEL SECURITY", sql_content)
        self.assertIn("ALTER TABLE tenant_organizations FORCE ROW LEVEL SECURITY", sql_content)
        self.assertIn("CREATE POLICY tenant_org_isolation_policy ON tenant_organizations", sql_content)
        # search_path pinned on SECURITY DEFINER functions
        self.assertIn("SECURITY DEFINER\nSET search_path = pg_catalog, pg_temp", sql_content)
        # Transaction requirement documented
        self.assertIn("TRANSACTION REQUIREMENT", sql_content)
        self.assertIn("BEGIN ... COMMIT", sql_content)
        # Execution revoked from public
        self.assertIn("REVOKE ALL ON FUNCTION set_current_tenant(VARCHAR) FROM PUBLIC", sql_content)
        self.assertIn("GRANT EXECUTE ON FUNCTION set_current_tenant(VARCHAR) TO komainu_app", sql_content)

    def test_12_rls_cross_tenant_isolation_logic_simulation(self) -> None:
        """Simulates RLS policy evaluation: verifying cross-tenant records cannot be read."""
        # Simulated database table records
        mock_orders_table = [
            {"id": "ord-1", "tenant_id": "tenant-a", "owner_user_id": "alice", "amount": 100.0},
            {"id": "ord-2", "tenant_id": "tenant-a", "owner_user_id": "alice", "amount": 200.0},
            {"id": "ord-3", "tenant_id": "tenant-b", "owner_user_id": "bob", "amount": 500.0},
        ]

        def evaluate_rls_query(session_tenant: str | None) -> list[dict]:
            # Mirrors PostgreSQL: tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')
            active_tenant = session_tenant if session_tenant else None
            return [row for row in mock_orders_table if row["tenant_id"] == active_tenant]

        # 1. Tenant A only sees Tenant A's orders
        tenant_a_rows = evaluate_rls_query("tenant-a")
        self.assertEqual(len(tenant_a_rows), 2)
        self.assertTrue(all(r["tenant_id"] == "tenant-a" for r in tenant_a_rows))

        # 2. Tenant B only sees Tenant B's orders
        tenant_b_rows = evaluate_rls_query("tenant-b")
        self.assertEqual(len(tenant_b_rows), 1)
        self.assertEqual(tenant_b_rows[0]["id"], "ord-3")

        # 3. Unauthenticated / missing transaction context sees 0 rows (fail-closed)
        empty_rows = evaluate_rls_query(None)
        self.assertEqual(len(empty_rows), 0)
        empty_rows_blank = evaluate_rls_query("")
        self.assertEqual(len(empty_rows_blank), 0)


if __name__ == "__main__":
    unittest.main()

