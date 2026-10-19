-- Boilerplate 4: Schema-Per-Tenant Isolation Pattern
-- Suitable for enterprise clients requiring complete logical separation per tenant
-- Hardened against SQL Injection, Collision, Search Path Fallbacks, and Privilege Escalation

-- 0. Tenant Registry for Collision Detection and Metadata Tracking
CREATE TABLE IF NOT EXISTS public.tenant_registry (
    tenant_slug VARCHAR(48) PRIMARY KEY,
    schema_name VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 1. Helper Function to Provision a New Tenant Schema
CREATE OR REPLACE FUNCTION create_tenant_schema(p_tenant_slug VARCHAR(64))
RETURNS void AS $$
DECLARE
    v_schema_name TEXT;
    v_index_name TEXT;
BEGIN
    -- Strict Slug Validation: Reject any slug outside ^[a-z0-9_]{1,48}$ (DO NOT rewrite or sanitize)
    IF p_tenant_slug IS NULL OR p_tenant_slug !~ '^[a-z0-9_]{1,48}$' THEN
        RAISE EXCEPTION 'Invalid tenant slug: "%". Tenant slug must strictly match regex ^[a-z0-9_]{1,48}$ (no hyphens, dots, or upper case)', p_tenant_slug;
    END IF;

    v_schema_name := 'tenant_' || p_tenant_slug;
    v_index_name := 'idx_' || p_tenant_slug || '_orders_owner';

    -- Collision Detection: Ensure slug or schema has not already been provisioned
    IF EXISTS (SELECT 1 FROM public.tenant_registry WHERE tenant_slug = p_tenant_slug) THEN
        RAISE EXCEPTION 'Tenant slug "%" already registered in tenant registry', p_tenant_slug;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = v_schema_name) THEN
        RAISE EXCEPTION 'Schema collision detected: schema "%" already exists', v_schema_name;
    END IF;

    -- Dynamically create schema using %I for identifier safety
    EXECUTE format('CREATE SCHEMA %I', v_schema_name);

    -- Register the provisioned tenant
    INSERT INTO public.tenant_registry (tenant_slug, schema_name)
    VALUES (p_tenant_slug, v_schema_name);

    -- Create domain tables inside the isolated tenant schema using %I throughout
    EXECUTE format('
        CREATE TABLE %I.orders (
            id VARCHAR(64) PRIMARY KEY,
            owner_user_id VARCHAR(64) NOT NULL,
            description TEXT,
            amount NUMERIC(12, 2) DEFAULT 0.00,
            encrypted_data TEXT,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX %I ON %I.orders(owner_user_id);
    ', v_schema_name, v_index_name, v_schema_name);

    -- Security Boundaries: Revoke public privileges on tenant schema and tables
    EXECUTE format('REVOKE ALL ON SCHEMA %I FROM PUBLIC', v_schema_name);
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM PUBLIC', v_schema_name);

END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp;

-- 2. Session Routing Helper to Bind Tenant Search Path
-- NOTE: Never falls back to public schema to prevent accidental shared-schema leakage
CREATE OR REPLACE FUNCTION switch_tenant_schema(p_tenant_slug VARCHAR(64))
RETURNS void AS $$
DECLARE
    v_schema_name TEXT;
BEGIN
    -- Strict Slug Validation
    IF p_tenant_slug IS NULL OR p_tenant_slug !~ '^[a-z0-9_]{1,48}$' THEN
        RAISE EXCEPTION 'Invalid tenant slug: "%". Tenant slug must strictly match regex ^[a-z0-9_]{1,48}$', p_tenant_slug;
    END IF;

    v_schema_name := 'tenant_' || p_tenant_slug;

    IF NOT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = v_schema_name) THEN
        RAISE EXCEPTION 'Tenant schema "%" does not exist', v_schema_name;
    END IF;

    -- Dynamically route search_path to isolated tenant schema ONLY (no public fallback)
    EXECUTE format('SET LOCAL search_path TO %I', v_schema_name);
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp;

-- 3. Restrict Execution Privileges
REVOKE ALL ON FUNCTION create_tenant_schema(VARCHAR) FROM PUBLIC;
REVOKE ALL ON FUNCTION switch_tenant_schema(VARCHAR) FROM PUBLIC;
