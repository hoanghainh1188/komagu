-- Boilerplate 4: PostgreSQL Row-Level Security (RLS) Tenant Isolation Template
-- Enforces cross-tenant data segregation at the database kernel level
--
-- ARCHITECTURE & SECURITY CONTRACT:
-- 1. TRANSACTION REQUIREMENT: Policies rely on transaction-local session state
--    configured via set_config('app.current_tenant_id', ..., true). All tenant queries
--    and mutations MUST execute inside an explicit transaction block (BEGIN ... COMMIT).
--    In autocommit connection pools, session state expires immediately after set_current_tenant().
-- 2. ROLE RESTRICTION: FORCE ROW LEVEL SECURITY enforces policies on table owners
--    and standard users, but NEVER applies to PostgreSQL superusers or roles with BYPASSRLS.
--    Applications MUST connect using a non-owner, non-BYPASSRLS application role (komainu_app).

-- 0. Provision Dedicated Non-Owner Application Role (without hard-coded password)
-- NOTE: In production environments requiring LOGIN connections, configure passwords
-- exclusively via deployment orchestration or vault parameters (ALTER ROLE komainu_app WITH LOGIN PASSWORD ...),
-- NEVER hard-code credentials in committed migration scripts.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'komainu_app') THEN
        CREATE ROLE komainu_app WITH NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOLOGIN;
    END IF;
END;
$$;

-- 1. Create multi-tenant domain tables with mandatory tenant_id column
CREATE TABLE IF NOT EXISTS tenant_organizations (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    kms_key_arn VARCHAR(512),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenant_organizations(id) ON DELETE CASCADE,
    owner_user_id VARCHAR(64) NOT NULL,
    description TEXT,
    amount NUMERIC(12, 2) DEFAULT 0.00,
    encrypted_sensitive_data TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Index for tenant-scoped query performance
CREATE INDEX IF NOT EXISTS idx_orders_tenant_owner ON orders(tenant_id, owner_user_id);

-- 2. Enable and FORCE Row-Level Security on ALL Tenant Tables (including tenant_organizations)
ALTER TABLE tenant_organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_organizations FORCE ROW LEVEL SECURITY;

ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders FORCE ROW LEVEL SECURITY;

-- 3. Define Strict Tenant Isolation Policies
-- Organization Isolation: Protects tenant metadata and KMS keys from other tenants
DROP POLICY IF EXISTS tenant_org_isolation_policy ON tenant_organizations;
CREATE POLICY tenant_org_isolation_policy ON tenant_organizations
    FOR ALL
    TO komainu_app
    USING (
        id = NULLIF(current_setting('app.current_tenant_id', true), '')
    )
    WITH CHECK (
        id = NULLIF(current_setting('app.current_tenant_id', true), '')
    );

-- Orders Domain Isolation: Prevents cross-tenant reads and writes
DROP POLICY IF EXISTS tenant_isolation_policy ON orders;
CREATE POLICY tenant_isolation_policy ON orders
    FOR ALL
    TO komainu_app
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')
    );

-- 4. Session Context Binding Helper Functions
-- Security Definer functions MUST pin search_path to prevent hijacking
CREATE OR REPLACE FUNCTION set_current_tenant(p_tenant_id VARCHAR(64))
RETURNS void AS $$
BEGIN
    IF p_tenant_id IS NULL OR length(trim(p_tenant_id)) = 0 THEN
        RAISE EXCEPTION 'Tenant context cannot be empty or null';
    END IF;
    -- Set session setting with LOCAL transaction scope (requires active transaction)
    PERFORM set_config('app.current_tenant_id', p_tenant_id, true);
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp;

CREATE OR REPLACE FUNCTION reset_current_tenant()
RETURNS void AS $$
BEGIN
    PERFORM set_config('app.current_tenant_id', '', true);
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp;

-- Revoke public execution rights on tenant injection trigger function to prevent misuse.

CREATE OR REPLACE FUNCTION trg_inject_current_tenant()
RETURNS trigger AS $$
BEGIN
    IF NEW.tenant_id IS NULL OR NEW.tenant_id = '' THEN
        NEW.tenant_id := NULLIF(current_setting('app.current_tenant_id', true), '');
    END IF;

    IF NEW.tenant_id IS NULL THEN
        RAISE EXCEPTION 'Cannot insert record without active app.current_tenant_id session context';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp;

DROP TRIGGER IF EXISTS trg_orders_tenant_injection ON orders;
CREATE TRIGGER trg_orders_tenant_injection
    BEFORE INSERT ON orders
    FOR EACH ROW
    EXECUTE FUNCTION trg_inject_current_tenant();

-- 6. Grant Least-Privilege Access to Application Role & Revoke Public Execution
REVOKE ALL ON FUNCTION trg_inject_current_tenant() FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO komainu_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_organizations TO komainu_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON orders TO komainu_app;

REVOKE ALL ON FUNCTION set_current_tenant(VARCHAR) FROM PUBLIC;
REVOKE ALL ON FUNCTION reset_current_tenant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION set_current_tenant(VARCHAR) TO komainu_app;
GRANT EXECUTE ON FUNCTION reset_current_tenant() TO komainu_app;
