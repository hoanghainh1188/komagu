"""Remediation strategies for different vulnerability categories."""

from __future__ import annotations

import difflib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from remediate.authz.patcher import BOLAOwnershipPatcher
from remediate.query.patcher import ParameterizedQueryPatcher


class BaseRemediationStrategy:
    """Abstract base strategy for code remediation."""

    name: str = "base"

    def can_handle(self, finding: Dict[str, Any]) -> bool:
        """Check if this strategy can handle the given finding."""
        raise NotImplementedError

    def generate_patch(
        self,
        target_file: Path,
        content: str,
        finding: Dict[str, Any],
    ) -> Tuple[str, str]:
        """Generate patched file content and an explanation.

        Returns:
            Tuple[str, str]: (patched_content, explanation_of_changes)
        """
        raise NotImplementedError


class SQLInjectionRemediationStrategy(BaseRemediationStrategy):
    """Strategy for remediating SQL and NoSQL dynamic query injections (CWE-89, CWE-943)."""

    name: str = "sql_injection"

    def can_handle(self, finding: Dict[str, Any]) -> bool:
        category = finding.get("category", "")
        cwe = str(finding.get("cwe", ""))
        return category in ("sql_injection", "nosql_injection") or "CWE-89" in cwe or "CWE-943" in cwe

    def generate_patch(
        self,
        target_file: Path,
        content: str,
        finding: Dict[str, Any],
    ) -> Tuple[str, str]:
        lines = content.splitlines(keepends=True)
        loc = finding.get("location", {})
        start_line = loc.get("start_line", 1) - 1

        if start_line < 0 or start_line >= len(lines):
            return content, "Target line number is out of bounds."

        target_line = lines[start_line]

        # Use intelligent parameterized query patcher
        patcher = ParameterizedQueryPatcher()
        lang = patcher.detect_language(target_file)
        rewritten = patcher.patch_code_line(target_line, lang)

        if rewritten.changed:
            lines[start_line] = rewritten.patched_line
            return "".join(lines), rewritten.explanation

        # Do NOT inject comment-only fake fixes. Require genuine code rewrite or manual fix.
        return content, "No automated parameterized query rewrite applicable; requires manual remediation."


class BOLARemediationStrategy(BaseRemediationStrategy):
    """Strategy for remediating Broken Object Level Authorization (OWASP API1:2023, CWE-639)."""

    name: str = "bola"

    def can_handle(self, finding: Dict[str, Any]) -> bool:
        category = finding.get("category", "")
        cwe = str(finding.get("cwe", ""))
        return category == "bola" or "CWE-639" in cwe or "CWE-284" in cwe

    def generate_patch(
        self,
        target_file: Path,
        content: str,
        finding: Dict[str, Any],
    ) -> Tuple[str, str]:
        lines = content.splitlines(keepends=True)
        loc = finding.get("location", {})
        start_line = loc.get("start_line", 1) - 1

        if start_line < 0 or start_line >= len(lines):
            return content, "Target line number is out of bounds."

        # Use intelligent BOLA ownership patcher
        patcher = BOLAOwnershipPatcher()
        patched_content, result = patcher.patch_file(target_file, start_line + 1, finding)
        if result.changed:
            return patched_content, result.explanation

        # Do NOT inject comment-only fake fixes. Require genuine code rewrite or manual fix.
        return content, "No automated BOLA ownership rewrite applicable; requires manual remediation."


class StrategyRegistry:
    """Registry coordinating available remediation strategies."""

    def __init__(self) -> None:
        self._strategies: List[BaseRemediationStrategy] = [
            SQLInjectionRemediationStrategy(),
            BOLARemediationStrategy(),
        ]

    def register(self, strategy: BaseRemediationStrategy) -> None:
        """Register a new custom remediation strategy."""
        self._strategies.insert(0, strategy)

    def find_strategy(self, finding: Dict[str, Any]) -> Optional[BaseRemediationStrategy]:
        """Find the first matching strategy for a given finding."""
        for strategy in self._strategies:
            if strategy.can_handle(finding):
                return strategy
        return None
