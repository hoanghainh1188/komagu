#!/usr/bin/env python3
"""Tamper-Evident Tenant Audit Trail Engine.

Maintains cryptographically chained, immutable audit trails per tenant
to satisfy enterprise SOC 2 Type II, ISO 27001, and Japan ISMAP compliance.
Features keyed HMAC-SHA256 integrity, canonical JSON hashing, sequence validation,
and head anchoring to prevent undetected history rewriting or truncation.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
from typing import Any, Dict, List, Optional, Tuple


class AuditRecord:
    """Represents a single tamper-evident audit event."""

    def __init__(
        self,
        seq: int,
        event_id: str,
        tenant_id: str,
        actor_id: str,
        action: str,
        resource_id: str,
        ip_address: str,
        prev_hash: str,
        hmac_key: bytes,
        timestamp: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.seq = seq
        self.event_id = event_id
        self.tenant_id = tenant_id
        self.actor_id = actor_id
        self.action = action
        self.resource_id = resource_id
        self.ip_address = ip_address
        self.prev_hash = prev_hash
        self.timestamp = timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.details = details or {}
        self.record_hash = self._compute_hash(hmac_key)

    def _compute_hash(self, hmac_key: bytes) -> str:
        """Compute cryptographic HMAC-SHA256 digest over canonical JSON representation."""
        canonical_payload = {
            "seq": self.seq,
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "actor_id": self.actor_id,
            "action": self.action,
            "resource_id": self.resource_id,
            "ip_address": self.ip_address,
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
            "details": self.details,
        }
        canonical_bytes = json.dumps(
            canonical_payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hmac.new(hmac_key, canonical_bytes, hashlib.sha256).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
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


def _is_test_environment() -> bool:
    """Detect if running under test execution.
    Returns True only when explicitly opted in via environment variables.
    """
    # Explicit opt‑in for test environments
    if os.getenv("KOMAINU_ENV", "").lower() == "test":
        return True
    if os.getenv("KOMAINU_ALLOW_BYOK_SIMULATION") == "1":
        return True
    return False



class TenantAuditTrail:
    """Manages independent, cryptographically chained, tamper-evident audit trails per tenant."""

    GENESIS_HASH = "0" * 64

    def __init__(self, hmac_key: Optional[bytes] = None):
        if hmac_key:
            if len(hmac_key) < 32:
                raise ValueError(
                    f"Audit trail HMAC key must be at least 32 bytes (got {len(hmac_key)} bytes)"
                )
            self.hmac_key = hmac_key
        elif "KOMAINU_AUDIT_HMAC_KEY" in os.environ and os.environ["KOMAINU_AUDIT_HMAC_KEY"]:
            raw_key = os.environ["KOMAINU_AUDIT_HMAC_KEY"].encode("utf-8")
            if len(raw_key) < 32:
                raise ValueError(
                    f"KOMAINU_AUDIT_HMAC_KEY must be at least 32 bytes (got {len(raw_key)} bytes)"
                )
            self.hmac_key = raw_key
        elif _is_test_environment():
            self.hmac_key = secrets.token_bytes(32)
        else:
            raise ValueError(
                "Audit trail HMAC key must be configured via KOMAINU_AUDIT_HMAC_KEY or constructor in production"
            )

        # Audit store: {tenant_id: List[AuditRecord]}
        self._chains: Dict[str, List[AuditRecord]] = {}
        # Committed external anchors: {tenant_id: (record_count, head_hash)}
        self._head_anchors: Dict[str, Tuple[int, str]] = {}
        self._lock = threading.Lock()

    def log_event(
        self,
        tenant_id: str,
        actor_id: str,
        action: str,
        resource_id: str,
        ip_address: str = "127.0.0.1",
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        """Append a new tamper-evident audit event to the tenant's chain (thread-safe)."""
        with self._lock:
            chain = self._chains.setdefault(tenant_id, [])
            prev_hash = chain[-1].record_hash if chain else self.GENESIS_HASH
            seq = len(chain) + 1

            event_id = f"evt-{secrets.token_hex(8)}"
            record = AuditRecord(
                seq=seq,
                event_id=event_id,
                tenant_id=tenant_id,
                actor_id=actor_id,
                action=action,
                resource_id=resource_id,
                ip_address=ip_address,
                prev_hash=prev_hash,
                hmac_key=self.hmac_key,
                details=details,
            )
            chain.append(record)
            return record

    def anchor_head(self, tenant_id: str) -> Dict[str, Any]:
        """Commit and return the current chain head as an anchor to detect truncation."""
        with self._lock:
            chain = self._chains.get(tenant_id, [])
            count = len(chain)
            head_hash = chain[-1].record_hash if chain else self.GENESIS_HASH
            self._head_anchors[tenant_id] = (count, head_hash)
            return {
                "tenant_id": tenant_id,
                "count": count,
                "head_hash": head_hash,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }

    def register_anchor(self, tenant_id: str, count: int, head_hash: str) -> None:
        """Register an external trusted anchor (e.g. from ledger or WORM storage)."""
        with self._lock:
            self._head_anchors[tenant_id] = (count, head_hash)

    def verify_chain_integrity(
        self,
        tenant_id: str,
        expected_head_hash: Optional[str] = None,
        expected_count: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """Validate cryptographic continuity, authenticity, and completeness of the chain."""
        with self._lock:
            chain = self._chains.get(tenant_id, [])

            # Check against committed anchor if explicit expected values were omitted
            if expected_head_hash is None and expected_count is None:
                if tenant_id in self._head_anchors:
                    expected_count, expected_head_hash = self._head_anchors[tenant_id]

            if not chain:
                if expected_count and expected_count > 0:
                    return False, f"Truncation detected: chain is empty, expected {expected_count} records"
                return True, "Audit chain is empty and valid"

            expected_prev_hash = self.GENESIS_HASH
            for i, record in enumerate(chain):
                # 1. Monotonic sequence check
                if record.seq != i + 1:
                    return False, (
                        f"Sequence break at index {i}: record has seq {record.seq}, "
                        f"expected {i + 1} (event_id={record.event_id})"
                    )

                # 2. Check backward hash linkage
                if record.prev_hash != expected_prev_hash:
                    return False, (
                        f"Broken chain linkage at record index {i} (event_id={record.event_id}): "
                        f"prev_hash mismatch!"
                    )

                # 3. Recompute HMAC digest using key
                recomputed = record._compute_hash(self.hmac_key)
                if not hmac.compare_digest(recomputed, record.record_hash):
                    return False, (
                        f"Tampered audit record detected at index {i} (event_id={record.event_id})! "
                        f"HMAC digest verification failed."
                    )

                expected_prev_hash = record.record_hash

            # 4. Truncation detection
            if expected_count is not None and len(chain) != expected_count:
                return False, (
                    f"Truncation detected: chain length {len(chain)} does not match "
                    f"expected anchor count {expected_count}!"
                )

            if expected_head_hash is not None and not hmac.compare_digest(
                chain[-1].record_hash, expected_head_hash
            ):
                return False, (
                    f"Head hash mismatch: chain head '{chain[-1].record_hash}' does not "
                    f"match expected anchor '{expected_head_hash}'!"
                )

            return True, f"Audit chain verified valid ({len(chain)} tamper-free records)"

    def get_events(self, tenant_id: str) -> List[Dict[str, Any]]:
        """Retrieve audit history for a specific tenant."""
        with self._lock:
            return [r.to_dict() for r in self._chains.get(tenant_id, [])]
