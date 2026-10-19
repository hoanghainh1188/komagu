"""Multi-Region Infrastructure & Immutable Backup Architecture (Boilerplate 3)."""

from remediate.resilience.dr.dr_manager import (
    DRBackupRecord,
    DRManager,
    ImmutableRetentionViolationError,
)

__all__ = [
    "DRManager",
    "DRBackupRecord",
    "ImmutableRetentionViolationError",
]
