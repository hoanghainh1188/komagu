"""Dependency vulnerability (SCA / CVE) manifest patcher and advisory scanner."""

from remediate.deps.patcher import (
    CVEAdvisoryCatalog,
    CVEAdvisoryEntry,
    DependencyManifestPatcher,
    DependencyRewriteResult,
)

__all__ = [
    "CVEAdvisoryCatalog",
    "CVEAdvisoryEntry",
    "DependencyManifestPatcher",
    "DependencyRewriteResult",
]
