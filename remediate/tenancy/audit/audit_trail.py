#!/usr/bin/env python3
"""Tamper-Evident Tenant Audit Trail Engine.

Maintains cryptographically chained, immutable audit trails per tenant
to satisfy enterprise SOC 2 Type II, ISO 27001, and Japan ISMAP compliance.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import secrets
from typing import Any, Dict, List, Optional, Tuple


class AuditRecord:
    """Represents a single tamper-evident audit event."""

    def __init__(
        self,
        event_id: str,
        tenant_id: str,
        actor_id: str,
        action: str,
        resource_id: str,
        ip_address: str,
        prev_hash: str,
        timestamp: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.event_id = event_id
        self.tenant_id = tenant_id
        self.actor_id = actor_id
        self.action = action
        self.resource_id = resource_id
        self.ip_address = ip_address
        self.prev_hash = prev_hash
        self.timestamp = timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.details = details or {}
        self.record_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Compute cryptographic SHA-256 digest over all audit event fields and predecessor hash."""
        canonical_str = (
            f"{self.event_id}|{self.tenant_id}|{self.actor_id}|{self.action}|"
            f"{self.resource_id}|{self.ip_address}|{self.timestamp}|{self.prev_hash}|"
            f"{json.dumps(self.details, sort_keys=True)}"
        )
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "actor_id": self.actor_id,
            "action": self.action,
            "resource_id": self.resource_id,
            "ip_address": self.ip_address,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
            "record_hash": self.record_hash,
            "details": self.details,
        }


class TenantAuditTrail:
    """Manages independent, cryptographically chained audit trails per tenant."""

    GENESIS_HASH = "0" * 64

    def __init__(self):
        # Audit store: {tenant_id: List[AuditRecord]}
        self._chains: Dict[str, List[AuditRecord]] = {}

    def log_event(
        self,
        tenant_id: str,
        actor_id: str,
        action: str,
        resource_id: str,
        ip_address: str = "127.0.0.1",
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        """Append a new tamper-evident audit event to tenant's chain."""
        chain = self._chains.setdefault(tenant_id, [])
        prev_hash = chain[-1].record_hash if chain else self.GENESIS_HASH

        event_id = f"evt-{secrets.token_hex(8)}"
        record = AuditRecord(
            event_id=event_id,
            tenant_id=tenant_id,
            actor_id=actor_id,
            action=action,
            resource_id=resource_id,
            ip_address=ip_address,
            prev_hash=prev_hash,
            details=details,
        )
        chain.append(record)
        return record

    def verify_chain_integrity(self, tenant_id: str) -> Tuple[bool, str]:
        """Validate cryptographic continuity and immutability of the audit chain."""
        chain = self._chains.get(tenant_id, [])
        if not chain:
            return True, "Audit chain is empty and valid"

        expected_prev_hash = self.GENESIS_HASH
        for i, record in enumerate(chain):
            # 1. Check backward linkage
            if record.prev_hash != expected_prev_hash:
                return False, f"Broken chain at record index {i} (event_id={record.event_id}): prev_hash mismatch!"

            # 2. Recompute record hash to detect tampering
            recomputed = record._compute_hash()
            if recomputed != record.record_hash:
                return False, f"Tampered audit record detected at index {i} (event_id={record.event_id})!"

            expected_prev_hash = record.record_hash

        return True, f"Audit chain verified valid ({len(chain)} tamper-free records)"

    def get_events(self, tenant_id: str) -> List[Dict[str, Any]]:
        """Retrieve audit history for a specific tenant."""
        return [r.to_dict() for r in self._chains.get(tenant_id, [])]
