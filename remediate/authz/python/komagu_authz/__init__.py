"""Komagu Object-Level Authorization Library for Python (D1)."""

from .fastapi_adapter import (
    KomaguAuthMiddleware,
    RequireOwnership,
    get_current_user,
    komagu_ownership_exception_handler,
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
from .service import KomaguAuthorizationService

__all__ = [
    "AuthorizationResult",
    "InMemorySecurityAuditSink",
    "IOwnedResource",
    "ISecurityAuditSink",
    "KomaguAuthMiddleware",
    "KomaguAuthorizationService",
    "LoggingSecurityAuditSink",
    "OwnershipException",
    "RequireOwnership",
    "ResourceOperation",
    "SecurityAuditEvent",
    "UserPrincipal",
    "get_current_user",
    "komagu_ownership_exception_handler",
]
