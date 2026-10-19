"""Komainu Object-Level Authorization Domain Models & Contracts (Python).

Defines the core abstractions for BOLA defense, ownership enforcement,
and security audit emission.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable


class ResourceOperation(str, Enum):
    """Operations performed on protected domain resources."""
    READ = "Read"
    CREATE = "Create"
    UPDATE = "Update"
    DELETE = "Delete"


@runtime_checkable
class IOwnedResource(Protocol):
    """Protocol for resources with tenant and user ownership attributes."""
    id: Any
    owner_user_id: str
    tenant_id: str


@dataclass
class AuthorizationResult:
    """Outcome of an authorization evaluation."""
    succeeded: bool
    failure_reason: Optional[str] = None

    @classmethod
    def success(cls) -> AuthorizationResult:
        return cls(succeeded=True)

    @classmethod
    def denied(cls, reason: str) -> AuthorizationResult:
        return cls(succeeded=False, failure_reason=reason)


@dataclass
class SecurityAuditEvent:
    """Structured security audit event for authorization failures."""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_name: str = "Komainu.Authorization.Denied"
    actor_user_id: Optional[str] = None
    actor_tenant_id: Optional[str] = None
    resource_type: str = "Unknown"
    resource_id: Optional[str] = None
    operation: ResourceOperation = ResourceOperation.READ
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_name": self.event_name,
            "actor_user_id": self.actor_user_id,
            "actor_tenant_id": self.actor_tenant_id,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "operation": self.operation.value if isinstance(self.operation, ResourceOperation) else str(self.operation),
            "reason": self.reason,
        }


class ISecurityAuditSink(ABC):
    """Abstract sink for publishing security audit events."""

    @abstractmethod
    def emit(self, event: SecurityAuditEvent) -> None:
        """Publishes the given security audit event."""
        raise NotImplementedError


class LoggingSecurityAuditSink(ISecurityAuditSink):
    """Default logger-based audit sink emitting JSON to standard logging."""

    def __init__(self, logger_name: str = "komainu.security.audit") -> None:
        import logging
        self.logger = logging.getLogger(logger_name)

    def emit(self, event: SecurityAuditEvent) -> None:
        import json
        self.logger.warning("SECURITY_AUDIT: %s", json.dumps(event.to_dict()))


class InMemorySecurityAuditSink(ISecurityAuditSink):
    """In-memory sink recording audit events for unit testing and verification."""

    def __init__(self) -> None:
        self.events: List[SecurityAuditEvent] = []

    def emit(self, event: SecurityAuditEvent) -> None:
        self.events.append(event)

    def clear(self) -> None:
        self.events.clear()


class OwnershipException(Exception):
    """Exception raised when object-level authorization fails.

    Invariant: Mapped to HTTP 404 Not Found to prevent ID enumeration.
    """

    def __init__(self, detail: str = "Resource not found", status_code: int = 404) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


@dataclass
class UserPrincipal:
    """Authenticated user identity extracted from verified token claims."""
    user_id: str
    tenant_id: str
    claims: Dict[str, Any] = field(default_factory=dict)
    roles: List[str] = field(default_factory=list)
    is_authenticated: bool = True
