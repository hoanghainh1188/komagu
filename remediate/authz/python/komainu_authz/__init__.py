"""Komainu Object-Level Authorization Library for Python (D1)."""

from .fastapi_adapter import (
    KomainuAuthMiddleware,
    RequireOwnership,
    get_current_user,
    komainu_ownership_exception_handler,
)
from .models import (
    AuthorizationResult,
    InMemorySecurityAuditSink,
    IOwnedResource,
    ISecurityAuditSink,
    LoggingSecurityAuditSink,
    OwnershipException,
    ResourceOperation,
    SecurityAuditEvent,
    UserPrincipal,
)
from .service import KomainuAuthorizationService

__all__ = [
    "AuthorizationResult",
    "InMemorySecurityAuditSink",
    "IOwnedResource",
    "ISecurityAuditSink",
    "KomainuAuthMiddleware",
    "KomainuAuthorizationService",
    "LoggingSecurityAuditSink",
    "OwnershipException",
    "RequireOwnership",
    "ResourceOperation",
    "SecurityAuditEvent",
    "UserPrincipal",
    "get_current_user",
    "komainu_ownership_exception_handler",
]
