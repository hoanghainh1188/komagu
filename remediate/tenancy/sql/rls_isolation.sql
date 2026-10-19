-- Boilerplate 4: PostgreSQL Row-Level Security (RLS) Tenant Isolation Template
-- Enforces absolute cross-tenant data segregation at the database kernel level

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

-- 2. Enable and FORCE Row-Level Security
-- NOTE: FORCE ensures RLS policies apply even to table owners and application database users
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders FORCE ROW LEVEL SECURITY;

-- 3. Define Strict Tenant Isolation Policy
-- Validates against the connection session variable 'app.current_tenant_id'
DROP POLICY IF EXISTS tenant_isolation_policy ON orders;

CREATE POLICY tenant_isolation_policy ON orders
    FOR ALL
    TO PUBLIC
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')
    );

-- 4. Session Context Binding Helper Functions
CREATE OR REPLACE FUNCTION set_current_tenant(p_tenant_id VARCHAR(64))
RETURNS void AS $$
BEGIN
    IF p_tenant_id IS NULL OR length(trim(p_tenant_id)) = 0 THEN
        RAISE EXCEPTION 'Tenant context cannot be empty or null';
    END IF;
    -- Set session setting with LOCAL transaction scope
    PERFORM set_config('app.current_tenant_id', p_tenant_id, true);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION reset_current_tenant()
RETURNS void AS $$
BEGIN
    PERFORM set_config('app.current_tenant_id', '', true);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 5. Automatic Tenant Injection Trigger
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
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_orders_tenant_injection ON orders;
CREATE TRIGGER trg_orders_tenant_injection
    BEFORE INSERT ON orders
    FOR EACH ROW
    EXECUTE FUNCTION trg_inject_current_tenant();
