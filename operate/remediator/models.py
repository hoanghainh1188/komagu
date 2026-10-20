"""Data models for the Komainu remediation engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class RemediationPlan:
    """Represents a planned or applied code remediation for a single security finding."""

    finding_id: str
    category: str
    title: str
    target_file: str
    absolute_path: str
    start_line: int
    end_line: int
    original_content: str = ""
    patched_content: str = ""
    diff: str = ""
    status: str = "planned"  # "planned", "applied", "skipped", "needs manual fix", "error"
    reason: str = ""
    encoding: str = "utf-8"
    newline: str = "\n"

    def to_dict(self) -> Dict[str, Any]:
        """Convert plan to dictionary for serialization."""
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "title": self.title,
            "target_file": self.target_file,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "status": self.status,
            "reason": self.reason,
            "has_diff": bool(self.diff.strip()),
            "encoding": self.encoding,
        }


@dataclass
class RemediationReport:
    """Represents the complete outcome of a remediation run."""

    target_dir: str
    total_findings: int
    plans: List[RemediationPlan] = field(default_factory=list)
    dry_run: bool = False
    patch_file: Optional[str] = None

    @property
    def planned_count(self) -> int:
        """Count of patches planned but not yet applied (or planned in dry-run mode)."""
        return sum(1 for p in self.plans if p.status == "planned")

    @property
    def applied_count(self) -> int:
        """Count of patches actually written to disk (0 in dry-run mode)."""
        return sum(1 for p in self.plans if p.status == "applied")

    @property
    def manual_fix_count(self) -> int:
        """Count of findings requiring manual remediation because no automated patch applies."""
        return sum(1 for p in self.plans if p.status == "needs manual fix")

    @property
    def skipped_count(self) -> int:
        """Count of skipped findings (e.g. target file missing or no strategy)."""
        return sum(1 for p in self.plans if p.status == "skipped")

    @property
    def error_count(self) -> int:
        """Count of errors encountered during patching."""
        return sum(1 for p in self.plans if p.status == "error")

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary for JSON output."""
        return {
            "target_dir": self.target_dir,
            "dry_run": self.dry_run,
            "total_findings": self.total_findings,
            "planned_count": self.planned_count,
            "applied_count": self.applied_count,
            "manual_fix_count": self.manual_fix_count,
            "skipped_count": self.skipped_count,
            "error_count": self.error_count,
            "patch_file": self.patch_file,
            "plans": [p.to_dict() for p in self.plans],
        }
