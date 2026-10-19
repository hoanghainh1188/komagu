-- Boilerplate 4: Schema-Per-Tenant Isolation Pattern
-- Suitable for enterprise clients requiring complete logical separation per tenant

-- 1. Helper Function to Provision a New Tenant Schema
CREATE OR REPLACE FUNCTION create_tenant_schema(p_tenant_slug VARCHAR(64))
RETURNS void AS $$
DECLARE
    v_schema_name TEXT := 'tenant_' || lower(regexp_replace(p_tenant_slug, '[^a-zA-Z0-9_]', '_', 'g'));
BEGIN
    -- Dynamically create schema
    EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I', v_schema_name);

    -- Create domain tables inside the isolated tenant schema
    EXECUTE format('
        CREATE TABLE IF NOT EXISTS %I.orders (
            id VARCHAR(64) PRIMARY KEY,
            owner_user_id VARCHAR(64) NOT NULL,
            description TEXT,
            amount NUMERIC(12, 2) DEFAULT 0.00,
            encrypted_data TEXT,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_%s_orders_owner ON %I.orders(owner_user_id);
    ', v_schema_name, p_tenant_slug, v_schema_name);

END;
$$ LANGUAGE plpgsql;

-- 2. Session Routing Helper to Bind Tenant Search Path
CREATE OR REPLACE FUNCTION switch_tenant_schema(p_tenant_slug VARCHAR(64))
RETURNS void AS $$
DECLARE
    v_schema_name TEXT := 'tenant_' || lower(regexp_replace(p_tenant_slug, '[^a-zA-Z0-9_]', '_', 'g'));
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = v_schema_name) THEN
        RAISE EXCEPTION 'Tenant schema % does not exist', v_schema_name;
    END IF;

    -- Dynamically route search_path to isolated tenant schema
    EXECUTE format('SET LOCAL search_path TO %I, public', v_schema_name);
END;
$$ LANGUAGE plpgsql;
