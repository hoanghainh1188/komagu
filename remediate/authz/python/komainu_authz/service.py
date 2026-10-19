"""Komainu Authorization Service Implementation (Python).

Enforces tenant and user ownership boundaries on domain objects.
Denies access with HTTP 404 (OwnershipException) on BOLA/IDOR violations.
"""

from __future__ import annotations

from typing import Any, Callable, List, Optional

from .models import (
    AuthorizationResult,
    IOwnedResource,
    ISecurityAuditSink,
    LoggingSecurityAuditSink,
    OwnershipException,
    ResourceOperation,
    SecurityAuditEvent,
    UserPrincipal,
)


class KomainuAuthorizationService:
    """Core authorization service enforcing tenant and user boundaries."""

    USER_ID_CLAIMS: List[str] = ["sub", "uid", "userId", "user_id"]
    TENANT_ID_CLAIMS: List[str] = [
        "tenant_id",
        "tid",
        "tenant",
        "org_id",
        "organization_id",
    ]

    def __init__(self, audit_sink: Optional[ISecurityAuditSink] = None) -> None:
        self.audit_sink: ISecurityAuditSink = audit_sink or LoggingSecurityAuditSink()

    def get_current_user_id(self, user: Any) -> str:
        """Extracts verified user subject identifier from security context."""
        if isinstance(user, UserPrincipal):
            if user.user_id:
                return user.user_id
            claims = user.claims
        elif isinstance(user, dict):
            claims = user
        elif hasattr(user, "claims") and isinstance(user.claims, dict):
            claims = user.claims
        else:
            claims = {}

        for claim in self.USER_ID_CLAIMS:
            val = claims.get(claim)
            if val is not None and str(val).strip():
                return str(val).strip()

        # Attribute lookup fallback
        for attr in ["user_id", "sub", "uid", "id"]:
            if hasattr(user, attr):
                val = getattr(user, attr)
                if val is not None and str(val).strip():
                    return str(val).strip()

        raise PermissionError("Verified user subject identifier claim is missing from security context")

    def get_current_tenant_id(self, user: Any) -> str:
        """Extracts verified tenant identifier from security context."""
        if isinstance(user, UserPrincipal):
            if user.tenant_id:
                return user.tenant_id
            claims = user.claims
        elif isinstance(user, dict):
            claims = user
        elif hasattr(user, "claims") and isinstance(user.claims, dict):
            claims = user.claims
        else:
            claims = {}

        for claim in self.TENANT_ID_CLAIMS:
            val = claims.get(claim)
            if val is not None and str(val).strip():
                return str(val).strip()

        # Attribute lookup fallback
        for attr in ["tenant_id", "tid", "org_id", "organization_id"]:
            if hasattr(user, attr):
                val = getattr(user, attr)
                if val is not None and str(val).strip():
                    return str(val).strip()

        raise PermissionError("Verified tenant identifier claim is missing from security context")

    def authorize(
        self,
        user: Any,
        resource: Any,
        operation: ResourceOperation = ResourceOperation.READ,
        owner_id_extractor: Optional[Callable[[Any], str]] = None,
        tenant_id_extractor: Optional[Callable[[Any], str]] = None,
    ) -> AuthorizationResult:
        """Evaluates whether the caller can perform operation on resource."""
        if user is None:
            reason = "Caller is unauthenticated"
            self._emit_denial(None, resource, operation, reason)
            return AuthorizationResult.denied(reason)

        if isinstance(user, UserPrincipal) and not user.is_authenticated:
            reason = "Caller is unauthenticated"
            self._emit_denial(user, resource, operation, reason)
            return AuthorizationResult.denied(reason)

        try:
            current_user_id = self.get_current_user_id(user)
            current_tenant_id = self.get_current_tenant_id(user)
        except PermissionError as ex:
            reason = str(ex)
            self._emit_denial(user, resource, operation, reason)
            return AuthorizationResult.denied(reason)

        if resource is None:
            return AuthorizationResult.denied("Resource is None")

        # Extract resource properties
        res_owner_id: Optional[str] = None
        res_tenant_id: Optional[str] = None
        res_id: Optional[str] = None

        if owner_id_extractor:
            res_owner_id = owner_id_extractor(resource)
        if tenant_id_extractor:
            res_tenant_id = tenant_id_extractor(resource)

        if res_owner_id is None or res_tenant_id is None:
            if isinstance(resource, dict):
                res_owner_id = res_owner_id or resource.get("owner_user_id") or resource.get("ownerUserId")
                res_tenant_id = res_tenant_id or resource.get("tenant_id") or resource.get("tenantId")
                res_id = str(resource.get("id")) if "id" in resource else None
            else:
                res_owner_id = res_owner_id or getattr(resource, "owner_user_id", getattr(resource, "ownerUserId", None))
                res_tenant_id = res_tenant_id or getattr(resource, "tenant_id", getattr(resource, "tenantId", None))
                res_id = str(getattr(resource, "id", None)) if hasattr(resource, "id") else None

        if res_owner_id is None or res_tenant_id is None:
            reason = f"Resource of type {type(resource).__name__} does not expose owner_user_id and tenant_id"
            self._emit_denial(user, resource, operation, reason, res_id)
            return AuthorizationResult.denied(reason)

        # 1. Tenant boundary enforcement
        if str(res_tenant_id) != str(current_tenant_id):
            reason = f"Tenant boundary violation: current tenant '{current_tenant_id}' != resource tenant '{res_tenant_id}'"
            self._emit_denial(user, resource, operation, reason, res_id)
            return AuthorizationResult.denied(reason)

        # 2. User ownership enforcement
        if str(res_owner_id) != str(current_user_id):
            reason = f"User ownership violation: current user '{current_user_id}' != resource owner '{res_owner_id}'"
            self._emit_denial(user, resource, operation, reason, res_id)
            return AuthorizationResult.denied(reason)

        return AuthorizationResult.success()

    def require_ownership(
        self,
        user: Any,
        resource: Any,
        operation: ResourceOperation = ResourceOperation.READ,
        owner_id_extractor: Optional[Callable[[Any], str]] = None,
        tenant_id_extractor: Optional[Callable[[Any], str]] = None,
    ) -> None:
        """Enforces ownership imperatively, raising OwnershipException (HTTP 404) on denial."""
        result = self.authorize(
            user=user,
            resource=resource,
            operation=operation,
            owner_id_extractor=owner_id_extractor,
            tenant_id_extractor=tenant_id_extractor,
        )
        if not result.succeeded:
            # Deny by default with 404 to avoid ID enumeration
            raise OwnershipException(detail="Resource not found", status_code=404)

    def _emit_denial(
        self,
        user: Any,
        resource: Any,
        operation: ResourceOperation,
        reason: str,
        resource_id: Optional[str] = None,
    ) -> None:
        try:
            actor_user_id = None
            actor_tenant_id = None
            if user is not None:
                try:
                    actor_user_id = self.get_current_user_id(user)
                except Exception:
                    pass
                try:
                    actor_tenant_id = self.get_current_tenant_id(user)
                except Exception:
                    pass

            event = SecurityAuditEvent(
                actor_user_id=actor_user_id,
                actor_tenant_id=actor_tenant_id,
                resource_type=type(resource).__name__ if resource is not None else "Unknown",
                resource_id=resource_id,
                operation=operation,
                reason=reason,
            )
            self.audit_sink.emit(event)
        except Exception:
            # Auditing errors must never mask or alter the authorization denial
            pass
