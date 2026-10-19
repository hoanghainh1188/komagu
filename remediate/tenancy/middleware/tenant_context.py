#!/usr/bin/env python3
"""Multi-Tenant Context Resolver and Request Scoping Middleware.

Resolves tenant identity from incoming HTTP requests (JWT claims, subdomains,
or headers) and binds tenant context to execution scopes.
"""

from __future__ import annotations

import contextvars
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

# Context variable holding the active tenant_id for the current execution thread/coroutine
_active_tenant: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "active_tenant", default=None
)


class MissingTenantContextError(PermissionError):
    """Raised when an operation requires an active tenant context but none is bound."""
    pass


class CrossTenantAccessDeniedError(PermissionError):
    """Raised when a request attempts to access resources outside its bound tenant scope."""
    pass


def get_current_tenant() -> str:
    """Get the active tenant_id for the current execution context."""
    tenant = _active_tenant.get()
    if not tenant:
        raise MissingTenantContextError(
            "Access Denied: No active tenant context is bound to this execution scope."
        )
    return tenant


def set_current_tenant(tenant_id: str) -> contextvars.Token:
    """Set the active tenant context for the current scope."""
    if not tenant_id or not tenant_id.strip():
        raise ValueError("Tenant ID cannot be empty")
    return _active_tenant.set(tenant_id.strip())


def reset_current_tenant(token: contextvars.Token) -> None:
    """Reset the active tenant context."""
    _active_tenant.reset(token)


@contextmanager
def tenant_scope(tenant_id: str) -> Iterator[str]:
    """Context manager for executing operations within an isolated tenant scope."""
    token = set_current_tenant(tenant_id)
    try:
        yield tenant_id
    finally:
        reset_current_tenant(token)


class TenantContextResolver:
    """Resolves tenant ID from request metadata."""

    @staticmethod
    def resolve_from_headers(headers: Dict[str, str], jwt_claims: Optional[Dict[str, Any]] = None) -> str:
        """Resolve tenant ID with priority: 1. Verified JWT claims, 2. Host header / subdomain, 3. X-Tenant-ID."""
        # 1. Highest priority: verified cryptographic JWT claims
        if jwt_claims and "tenant_id" in jwt_claims:
            return str(jwt_claims["tenant_id"])

        # 2. Subdomain check (e.g. acme.komainu-saas.com)
        host = headers.get("host", "").split(":")[0]
        parts = host.split(".")
        if len(parts) >= 3 and parts[0] not in ("www", "api", "app", "localhost"):
            return parts[0]

        # 3. Direct header (for internal service-to-service calls)
        tenant_header = headers.get("x-tenant-id") or headers.get("X-Tenant-ID")
        if tenant_header:
            return tenant_header.strip()

        raise MissingTenantContextError("Unable to resolve tenant identity from request metadata.")
