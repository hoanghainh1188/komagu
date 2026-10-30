#!/usr/bin/env python3
"""Unit & Acceptance Tests for Boilerplate 4: Tenant-Isolated SaaS & BYOK Encryption."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
import unittest

from remediate.tenancy.audit.audit_trail import TenantAuditTrail
from remediate.tenancy.crypto.byok_manager import (
    BYOKKeyManager,
    CrossTenantKeyMismatchError,
    CryptoShreddedError,
    TenantKeyRevokedError,
)
from remediate.tenancy.middleware.tenant_context import (
    CrossTenantAccessDeniedError,
    MissingTenantContextError,
    TenantContextResolver,
    get_current_tenant,
    set_current_tenant,
    tenant_scope,
    validate_tenant_id_format,
)

MODULE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestTenantIsolationAndBYOK(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        os.environ["KOMAGU_ENV"] = "test"
        os.environ["KOMAGU_ALLOW_BYOK_SIMULATION"] = "1"
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
        """Verifies secure tenant resolution prioritizing verified JWT claims and internal auth."""
        # 1. From verified JWT claims
        tenant_jwt = TenantContextResolver.resolve_from_headers(
            headers={"host": "api.komagu.dev"},
            jwt_claims={"tenant_id": "tenant-from-jwt"},
        )
        self.assertEqual(tenant_jwt, "tenant-from-jwt")

        # 2. Subdomain matching verified JWT claims passes
        tenant_sub = TenantContextResolver.resolve_from_headers(
            headers={"host": "enterprise-corp.komagu.dev"},
            jwt_claims={"tenant_id": "enterprise-corp"},
        )
        self.assertEqual(tenant_sub, "enterprise-corp")

        # 3. Direct header accepted ONLY from authenticated internal callers
        tenant_hdr = TenantContextResolver.resolve_from_headers(
            headers={
                "host": "localhost",
                "x-tenant-id": "tenant-internal",
                "x-internal-service-key": "valid-secret-token",
            },
            internal_service_secret="valid-secret-token",
        )
        self.assertEqual(tenant_hdr, "tenant-internal")

        # 4. Unauthenticated X-Tenant-ID header rejected without claims
        with self.assertRaises(CrossTenantAccessDeniedError):
            TenantContextResolver.resolve_from_headers(
                headers={"host": "localhost", "x-tenant-id": "victim-tenant"}
            )

        # 5. Missing context raises error
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

        schema_file = os.path.join(MODULE_ROOT, "sql", "schema_per_tenant.sql")
        with open(schema_file, "r", encoding="utf-8") as f:
            sql_content = f.read()

        self.assertIn("^[a-z0-9_]{1,48}$", sql_content)
        self.assertIn("RAISE EXCEPTION 'Invalid tenant slug", sql_content)
        self.assertNotIn("regexp_replace(p_tenant_slug", sql_content)

    def test_10_schema_per_tenant_sql_safety_and_no_public_fallback(self) -> None:
        """Verifies schema_per_tenant uses %I throughout, avoids public fallback, and detects collisions."""
        schema_file = os.path.join(MODULE_ROOT, "sql", "schema_per_tenant.sql")
        with open(schema_file, "r", encoding="utf-8") as f:
            sql_content = f.read()

        self.assertNotIn("idx_%s_orders_owner", sql_content)
        self.assertIn("CREATE INDEX %I ON %I.orders(owner_user_id)", sql_content)
        self.assertIn("public.tenant_registry", sql_content)
        self.assertIn("Schema collision detected", sql_content)
        # Search path set via set_config without function-level SET to propagate to caller session
        self.assertIn("set_config('search_path'", sql_content)
        self.assertNotIn("search_path TO %I, public", sql_content)
        self.assertIn("REVOKE ALL ON SCHEMA %I FROM PUBLIC", sql_content)
        self.assertIn("REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM PUBLIC", sql_content)
        self.assertIn("REVOKE ALL ON FUNCTION create_tenant_schema(VARCHAR) FROM PUBLIC", sql_content)
        self.assertIn("REVOKE ALL ON FUNCTION switch_tenant_schema(VARCHAR) FROM PUBLIC", sql_content)
        self.assertIn("GRANT USAGE ON SCHEMA %I TO komainu_app", sql_content)
        self.assertIn("GRANT EXECUTE ON FUNCTION switch_tenant_schema(VARCHAR) TO komainu_app", sql_content)

    def test_11_rls_sql_app_role_and_tenant_organizations_security(self) -> None:
        """Verifies RLS template defines non-owner app role, protects tenant_organizations, and pins search_path."""
        rls_file = os.path.join(MODULE_ROOT, "sql", "rls_isolation.sql")
        with open(rls_file, "r", encoding="utf-8") as f:
            sql_content = f.read()

        self.assertIn("CREATE ROLE komainu_app WITH NOSUPERUSER NOBYPASSRLS", sql_content)
        self.assertIn("NOLOGIN", sql_content)
        self.assertNotIn("replace_with_secure_app_password", sql_content)
        self.assertIn("ALTER TABLE tenant_organizations ENABLE ROW LEVEL SECURITY", sql_content)
        self.assertIn("ALTER TABLE tenant_organizations FORCE ROW LEVEL SECURITY", sql_content)
        self.assertIn("CREATE POLICY tenant_org_isolation_policy ON tenant_organizations", sql_content)
        self.assertIn("SECURITY DEFINER\nSET search_path = pg_catalog, pg_temp", sql_content)
        self.assertIn("TRANSACTION REQUIREMENT", sql_content)
        self.assertIn("BEGIN ... COMMIT", sql_content)
        self.assertIn("REVOKE ALL ON FUNCTION set_current_tenant(VARCHAR) FROM PUBLIC", sql_content)
        self.assertIn("GRANT EXECUTE ON FUNCTION set_current_tenant(VARCHAR) TO komainu_app", sql_content)

    def test_12_rls_cross_tenant_isolation_logic_simulation(self) -> None:
        """Simulates RLS policy evaluation: verifying cross-tenant records cannot be read."""
        mock_orders_table = [
            {"id": "ord-1", "tenant_id": "tenant-a", "owner_user_id": "alice", "amount": 100.0},
            {"id": "ord-2", "tenant_id": "tenant-a", "owner_user_id": "alice", "amount": 200.0},
            {"id": "ord-3", "tenant_id": "tenant-b", "owner_user_id": "bob", "amount": 500.0},
        ]

        def evaluate_rls_query(session_tenant: str | None) -> list[dict]:
            active_tenant = session_tenant if session_tenant else None
            return [row for row in mock_orders_table if row["tenant_id"] == active_tenant]

        tenant_a_rows = evaluate_rls_query("tenant-a")
        self.assertEqual(len(tenant_a_rows), 2)
        self.assertTrue(all(r["tenant_id"] == "tenant-a" for r in tenant_a_rows))

        tenant_b_rows = evaluate_rls_query("tenant-b")
        self.assertEqual(len(tenant_b_rows), 1)
        self.assertEqual(tenant_b_rows[0]["id"], "ord-3")

        empty_rows = evaluate_rls_query(None)
        self.assertEqual(len(empty_rows), 0)
        empty_rows_blank = evaluate_rls_query("")
        self.assertEqual(len(empty_rows_blank), 0)

    def test_13_tenant_resolution_header_spoofing_blocked(self) -> None:
        """Verifies that client-supplied X-Tenant-ID header spoofing is strictly rejected."""
        # Spoofed X-Tenant-ID without internal auth and without JWT
        with self.assertRaises(CrossTenantAccessDeniedError):
            TenantContextResolver.resolve_from_headers(
                headers={"X-Tenant-ID": "victim_corp"}
            )

        # Host subdomain alone without JWT cannot establish tenant identity
        with self.assertRaises(MissingTenantContextError):
            TenantContextResolver.resolve_from_headers(
                headers={"Host": "victim-corp.komagu-saas.com"}
            )

    def test_14_tenant_resolution_conflict_fails_closed(self) -> None:
        """Verifies that any conflict between claims, subdomains, and headers fails closed."""
        # 1. JWT claim vs Host subdomain mismatch
        with self.assertRaises(CrossTenantAccessDeniedError):
            TenantContextResolver.resolve_from_headers(
                headers={"Host": "attacker.komagu.dev"},
                jwt_claims={"tenant_id": "victim-tenant"},
            )

        # 2. JWT claim vs unauthenticated header mismatch
        with self.assertRaises(CrossTenantAccessDeniedError):
            TenantContextResolver.resolve_from_headers(
                headers={"X-Tenant-ID": "different-tenant"},
                jwt_claims={"tenant_id": "victim-tenant"},
            )

        # 3. JWT claim vs authenticated internal header mismatch
        with self.assertRaises(CrossTenantAccessDeniedError):
            TenantContextResolver.resolve_from_headers(
                headers={
                    "X-Tenant-ID": "internal-attacker",
                    "X-Internal-Service-Key": "valid-secret",
                },
                jwt_claims={"tenant_id": "victim-tenant"},
                internal_service_secret="valid-secret",
            )

    def test_15_tenant_resolution_invalid_format_blocked(self) -> None:
        """Verifies that invalid or dangerous tenant ID formats are rejected."""
        invalid_formats = [
            "../etc/passwd",
            "victim'; DROP TABLE users; --",
            "VICTIM_UPPERCASE",
            "-leading-hyphen",
            "trailing-hyphen-",
            "space in tenant",
            "a" * 65,  # Exceeds 64 chars
        ]
        for bad_id in invalid_formats:
            with self.assertRaises(ValueError):
                validate_tenant_id_format(bad_id)

            with self.assertRaises(ValueError):
                TenantContextResolver.resolve_from_headers(
                    headers={},
                    jwt_claims={"tenant_id": bad_id},
                )

    def test_16_audit_trail_truncation_detection(self) -> None:
        """Verifies that truncation of the audit trail tail is detected via committed anchor."""
        trail = TenantAuditTrail()
        trail.log_event("tenant-alpha", "actor-1", "LOGIN", "session-1")
        trail.log_event("tenant-alpha", "actor-1", "MUTATION", "record-1")
        trail.log_event("tenant-alpha", "actor-1", "MUTATION", "record-2")
        trail.log_event("tenant-alpha", "actor-1", "LOGOUT", "session-1")

        # Commit anchor of 4 records
        anchor = trail.anchor_head("tenant-alpha")
        self.assertEqual(anchor["count"], 4)

        # Verify valid full chain
        ok, msg = trail.verify_chain_integrity("tenant-alpha")
        self.assertTrue(ok, msg)

        # Truncate the chain: attacker cuts the last record
        trail._chains["tenant-alpha"].pop()
        self.assertEqual(len(trail._chains["tenant-alpha"]), 3)

        # Verification must detect truncation against committed anchor
        ok_trunc, msg_trunc = trail.verify_chain_integrity("tenant-alpha")
        self.assertFalse(ok_trunc)
        self.assertIn("Truncation detected", msg_trunc)

    def test_17_audit_trail_sequence_break_detected(self) -> None:
        """Verifies that non-monotonic sequence or record deletion is detected."""
        trail = TenantAuditTrail()
        trail.log_event("tenant-seq", "u1", "ACT1", "r1")
        trail.log_event("tenant-seq", "u1", "ACT2", "r2")
        trail.log_event("tenant-seq", "u1", "ACT3", "r3")

        # Break sequence: tamper with record 2's sequence number
        trail._chains["tenant-seq"][1].seq = 99
        ok, msg = trail.verify_chain_integrity("tenant-seq")
        self.assertFalse(ok)
        self.assertIn("Sequence break", msg)

    def test_18_audit_trail_thread_safety(self) -> None:
        """Verifies concurrent append operations remain sequential and cryptographically sound."""
        trail = TenantAuditTrail()
        num_threads = 5
        records_per_thread = 10
        total_records = num_threads * records_per_thread

        def append_batch(thread_idx: int) -> None:
            for i in range(records_per_thread):
                trail.log_event(
                    "tenant-concurrent",
                    f"worker-{thread_idx}",
                    f"OP_{i}",
                    f"res-{thread_idx}-{i}",
                )

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(append_batch, t) for t in range(num_threads)]
            for f in futures:
                f.result()

        chain = trail._chains.get("tenant-concurrent", [])
        self.assertEqual(len(chain), total_records)

        # Verify sequential order: 1..total_records
        for idx, rec in enumerate(chain):
            self.assertEqual(rec.seq, idx + 1)

        ok, msg = trail.verify_chain_integrity("tenant-concurrent")
        self.assertTrue(ok, msg)

    def test_19_byok_invalid_key_length_rejected(self) -> None:
        """Verifies that BYOK master keys must be strictly 32 bytes (256 bits)."""
        byok = BYOKKeyManager()

        invalid_keys = [
            b"short-key",          # 9 bytes
            b"0" * 16,             # 16 bytes (AES-128)
            b"0" * 24,             # 24 bytes (AES-192)
            b"0" * 64,             # 64 bytes (512 bits)
        ]
        for bad_key in invalid_keys:
            with self.assertRaises(ValueError):
                byok.register_tenant_key("tenant-len", custom_key=bad_key)

        # Exactly 32 bytes succeeds
        valid_32 = b"01234567890123456789012345678901"
        self.assertEqual(len(valid_32), 32)
        byok.register_tenant_key("tenant-len", custom_key=valid_32)
        self.assertTrue(byok.is_key_active("tenant-len"))

    def test_20_byok_reregister_revoked_tenant_rejected(self) -> None:
        """Verifies that a permanently revoked/crypto-shredded tenant cannot be re-keyed."""
        byok = BYOKKeyManager()
        byok.register_tenant_key("tenant-shredded")
        byok.revoke_tenant_key("tenant-shredded")

        # Re-registering must raise TenantKeyRevokedError
        with self.assertRaises(TenantKeyRevokedError):
            byok.register_tenant_key("tenant-shredded")

        # Even with custom key, must fail
        with self.assertRaises(TenantKeyRevokedError):
            byok.register_tenant_key("tenant-shredded", custom_key=b"1" * 32)

    def test_21_byok_accidental_overwrite_guard(self) -> None:
        """Verifies that active keys cannot be overwritten without explicit overwrite=True."""
        byok = BYOKKeyManager()
        byok.register_tenant_key("tenant-overwrite")

        # Accidental overwrite blocked
        with self.assertRaises(ValueError):
            byok.register_tenant_key("tenant-overwrite")

        # Explicit overwrite allowed
        new_key = byok.register_tenant_key("tenant-overwrite", overwrite=True)
        self.assertIsNotNone(new_key)

    def test_22_tenant_id_trailing_newline_rejected(self) -> None:
        """Verifies that trailing newlines in tenant IDs are rejected (Issue #209)."""
        invalid_trailing_newline = "valid-tenant\n"
        with self.assertRaises(ValueError):
            validate_tenant_id_format(invalid_trailing_newline)

        with self.assertRaises(ValueError):
            validate_tenant_id_format("\nvalid-tenant")

    def test_23_audit_trail_short_key_rejected(self) -> None:
        """Verifies that audit trail HMAC key must be at least 32 bytes."""
        with self.assertRaises(ValueError):
            TenantAuditTrail(hmac_key=b"short-key-16byte")

        # 32-byte key succeeds
        trail = TenantAuditTrail(hmac_key=b"0" * 32)
        self.assertEqual(len(trail.hmac_key), 32)

    def test_24_byok_revocations_export_and_import(self) -> None:
        """Verifies that revoked/shredded tenant records can be synchronized across instances."""
        mgr1 = BYOKKeyManager()
        mgr1.register_tenant_key("tenant-shared")
        mgr1.revoke_tenant_key("tenant-shared")

        revoked_map = mgr1.export_revoked_tenants()
        self.assertIn("tenant-shared", revoked_map)

        # Fresh manager 2 imports revocations
        mgr2 = BYOKKeyManager()
        mgr2.import_revoked_tenants(revoked_map)

        with self.assertRaises(TenantKeyRevokedError):
            mgr2.register_tenant_key("tenant-shared")


if __name__ == "__main__":
    unittest.main()
