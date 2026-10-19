"""Tenant-Isolated SaaS Architecture & Bring-Your-Own-Key Encryption (Boilerplate 4)."""

from remediate.tenancy.audit.audit_trail import AuditRecord, TenantAuditTrail
from remediate.tenancy.crypto.byok_manager import (
    BYOKKeyManager,
    CrossTenantKeyMismatchError,
    CryptoShreddedError,
)
from remediate.tenancy.middleware.tenant_context import (
    CrossTenantAccessDeniedError,
    MissingTenantContextError,
    TenantContextResolver,
    get_current_tenant,
    set_current_tenant,
    tenant_scope,
)

__all__ = [
    "BYOKKeyManager",
    "CrossTenantKeyMismatchError",
    "CryptoShreddedError",
    "TenantAuditTrail",
    "AuditRecord",
    "TenantContextResolver",
    "MissingTenantContextError",
    "CrossTenantAccessDeniedError",
    "get_current_tenant",
    "set_current_tenant",
    "tenant_scope",
]
