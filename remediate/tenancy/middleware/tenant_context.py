#!/usr/bin/env python3
"""Multi-Tenant Context Resolver and Request Scoping Middleware.

Resolves tenant identity securely from verified JWT claims or authenticated internal
service headers, validates slug formatting, and binds tenant context to execution scopes.
"""

from __future__ import annotations

import contextvars
from contextlib import contextmanager
import hmac
import os
import re
from typing import Any, Dict, Iterator, Optional

# Context variable holding the active tenant_id for the current execution thread/coroutine
_active_tenant: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "active_tenant", default=None
)

# Strict tenant ID pattern: lowercase alphanumeric, hyphens, and underscores, 1-64 chars
# Uses \A and \Z to prevent accepting trailing newlines
TENANT_ID_PATTERN = re.compile(r"\A(?:[a-z0-9][a-z0-9_-]{0,62}[a-z0-9]|[a-z0-9])\Z")


class MissingTenantContextError(PermissionError):
    """Raised when an operation requires an active tenant context but none is bound."""
    pass


class CrossTenantAccessDeniedError(PermissionError):
    """Raised when a request attempts to access resources outside its bound tenant scope."""
    pass


def validate_tenant_id_format(tenant_id: str) -> None:
    """Validate that tenant ID conforms to strict slug specifications."""
    if not tenant_id or not isinstance(tenant_id, str):
        raise ValueError("Tenant ID must be a non-empty string.")
    if not TENANT_ID_PATTERN.match(tenant_id):
        raise ValueError(
            f"Invalid tenant ID format: '{tenant_id}'. "
            "Must be 1-64 lowercase alphanumeric characters, underscores, or hyphens."
        )


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
    validate_tenant_id_format(tenant_id)
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
    """Resolves tenant ID with cryptographic verification and fail-closed validation."""

    @staticmethod
    def resolve_from_headers(
        headers: Dict[str, str],
        jwt_claims: Optional[Dict[str, Any]] = None,
        internal_service_secret: Optional[str] = None,
    ) -> str:
        """Resolve tenant ID with strict security rules:

        1. Primary: Verified JWT claims ('tenant_id', 'tid', 'tenant').
        2. Direct header ('X-Tenant-ID'): ONLY accepted if the caller provides valid
           internal service authentication ('X-Internal-Service-Key').
        3. Subdomain: Host header alone is NEVER trusted to establish tenant identity.
           If claims exist, subdomain must match claims to prevent host spoofing.
        4. Cross-check: If both token claims and authenticated internal headers are present,
           any disagreement fails closed.
        5. Strict format validation on the resolved tenant ID.
        """
        norm_headers = {k.lower(): v for k, v in headers.items()}

        # 1. Extract verified JWT tenant
        jwt_tenant: Optional[str] = None
        if jwt_claims:
            raw_claim = (
                jwt_claims.get("tenant_id")
                or jwt_claims.get("tid")
                or jwt_claims.get("tenant")
            )
            if raw_claim is not None:
                jwt_tenant = str(raw_claim).strip()

        # 2. Extract internal service authentication
        expected_secret = (
            internal_service_secret
            or os.environ.get("KOMAINU_INTERNAL_SERVICE_SECRET")
        )
        internal_key = (
            norm_headers.get("x-internal-service-key")
            or norm_headers.get("x-internal-secret")
        )
        is_internal_authenticated = False
        if expected_secret and internal_key:
            is_internal_authenticated = hmac.compare_digest(
                internal_key.strip(), expected_secret.strip()
            )

        # 3. Extract header tenant
        header_tenant = norm_headers.get("x-tenant-id")
        if header_tenant:
            header_tenant = header_tenant.strip()

        # Check for unauthenticated header usage
        if header_tenant and not is_internal_authenticated:
            if not jwt_tenant:
                raise CrossTenantAccessDeniedError(
                    "Untrusted X-Tenant-ID header rejected: missing valid internal service authentication."
                )
            if header_tenant != jwt_tenant:
                raise CrossTenantAccessDeniedError(
                    f"Cross-tenant conflict: unauthenticated header '{header_tenant}' "
                    f"does not match verified token claim '{jwt_tenant}'."
                )

        # Cross-check authenticated internal header vs JWT claims
        if is_internal_authenticated and header_tenant and jwt_tenant:
            if header_tenant != jwt_tenant:
                raise CrossTenantAccessDeniedError(
                    f"Cross-tenant conflict: internal service header '{header_tenant}' "
                    f"does not match verified token claim '{jwt_tenant}'."
                )

        # Check Host subdomain consistency if present
        host = norm_headers.get("host", "").split(":")[0]
        parts = host.split(".")
        if len(parts) >= 3 and parts[0] not in ("www", "api", "app", "localhost"):
            subdomain = parts[0]
            if jwt_tenant and subdomain != jwt_tenant:
                raise CrossTenantAccessDeniedError(
                    f"Host subdomain '{subdomain}' conflicts with verified token tenant '{jwt_tenant}'."
                )

        # Resolve tenant candidate
        resolved: Optional[str] = jwt_tenant
        if not resolved and is_internal_authenticated and header_tenant:
            resolved = header_tenant

        if not resolved:
            raise MissingTenantContextError(
                "Unable to securely resolve tenant identity from request metadata."
            )

        validate_tenant_id_format(resolved)
        return resolved
