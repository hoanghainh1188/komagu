# -*- coding: utf-8 -*-
"""Integration test for tenancy module using a real PostgreSQL instance.

This test validates:
- SQL schema isolation and privilege revocations.
- RLS enforcement across tenant schemas.
- Correct behavior of trigger `trg_inject_current_tenant`.
"""

import os
import time
import unittest
from pathlib import Path

import psycopg2
from psycopg2 import sql

# Paths to the SQL scripts relative to the repository root.
REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_SQL = REPO_ROOT / "remediate" / "tenancy" / "sql" / "schema_per_tenant.sql"
RLS_SQL = REPO_ROOT / "remediate" / "tenancy" / "sql" / "rls_isolation.sql"

# Helper to execute a script file inside a transaction.
def exec_sql_file(conn, file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        script = f.read()
    with conn.cursor() as cur:
        cur.execute(script)
    conn.commit()

class TenancyPostgresIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Wait for PostgreSQL to become ready.
        for _ in range(60):
            try:
                cls.conn = psycopg2.connect(
                    host="localhost",
                    port=5432,
                    user="postgres",
                    password="postgres",
                    dbname="postgres",
                )
                break
            except Exception:
                time.sleep(2)
        else:
            raise RuntimeError("Unable to connect to PostgreSQL service")

        # Apply the tenancy schema scripts.
        exec_sql_file(cls.conn, SCHEMA_SQL)
        exec_sql_file(cls.conn, RLS_SQL)

    @classmethod
    def tearDownClass(cls):
        # Drop all tenant schemas created by the scripts for clean state.
        with cls.conn.cursor() as cur:
            cur.execute("SELECT nspname FROM pg_namespace WHERE nspname LIKE 'tenant_%';")
            schemas = [row[0] for row in cur.fetchall()]
            for schema in schemas:
                cur.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema)))
        cls.conn.commit()
        cls.conn.close()

    def test_slug_validation_and_routing(self):
        """Validate that an invalid slug is rejected and a valid slug routes correctly."""
        with self.conn.cursor() as cur:
            # Attempt to switch to an invalid tenant (should raise an error).
            with self.assertRaises(psycopg2.errors.RaiseException):
                cur.execute("SELECT public.switch_tenant_schema('invalid slug!');")
            self.conn.rollback()
            # Create a valid tenant schema via the helper function.
            cur.execute("SELECT public.create_tenant_schema('validslug');")
            # Switch to the newly created tenant.
            cur.execute("SELECT public.switch_tenant_schema('validslug');")
            # Verify current_schema() matches the tenant schema.
            cur.execute("SELECT current_schema();")
            self.assertEqual(cur.fetchone()[0], 'tenant_validslug')

    def test_rls_enforcement(self):
        """Ensure that rows cannot be read across tenant boundaries."""
        with self.conn.cursor() as cur:
            # Create two tenants and insert a row in each.
            cur.execute("SELECT public.create_tenant_schema('tenanta');")
            cur.execute("SELECT public.switch_tenant_schema('tenanta');")
            cur.execute("SELECT public.set_current_tenant('tenanta');")
            cur.execute("INSERT INTO orders (id, owner_user_id, description, amount, encrypted_data) VALUES ('orderA', 'ownerA', 'desc', 10, 'enc');")
            cur.execute("SELECT public.create_tenant_schema('tenantb');")
            cur.execute("SELECT public.switch_tenant_schema('tenantb');")
            cur.execute("SELECT public.set_current_tenant('tenantb');")
            cur.execute("INSERT INTO orders (id, owner_user_id, description, amount, encrypted_data) VALUES ('orderB', 'ownerB', 'desc', 20, 'enc');")
            # Switch back to tenanta and attempt to read tenantb's row (should be filtered by RLS).
            cur.execute("SELECT public.switch_tenant_schema('tenanta');")
            cur.execute("SELECT public.set_current_tenant('tenanta');")
            cur.execute("SELECT id FROM orders;")
            rows = cur.fetchall()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][0], 'orderA')

    def test_privilege_revocations(self):
        """Check that public privileges are revoked as expected."""
        with self.conn.cursor() as cur:
            # Ensure a clean transaction state
            self.conn.rollback()
            # Verify that PUBLIC does not have SELECT on tenant_registry.
            cur.execute("SELECT has_table_privilege('public', 'public.tenant_registry', 'SELECT');")
            self.assertFalse(cur.fetchone()[0])
            # Verify that PUBLIC cannot execute the trigger function.
            cur.execute("SELECT has_function_privilege('public', 'public.trg_inject_current_tenant()', 'EXECUTE');")
            self.assertFalse(cur.fetchone()[0])

if __name__ == '__main__':
    unittest.main()
