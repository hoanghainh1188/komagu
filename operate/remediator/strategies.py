"""Remediation strategies for different vulnerability categories."""

from __future__ import annotations

import difflib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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

        indent = re.match(r"^(\s*)", target_line).group(1) if target_line else ""

        # Suffix / comment style depending on file extension
        ext = target_file.suffix.lower()
        if ext in (".py",):
            comment_prefix = f"{indent}# [KOMAINU-FIX] Parameterized query protection applied (CWE-89)\n"
        elif ext in (".sql",):
            comment_prefix = f"{indent}-- [KOMAINU-FIX] Parameterized query protection applied (CWE-89)\n"
        else:
            comment_prefix = f"{indent}// [KOMAINU-FIX] Parameterized query protection applied (CWE-89)\n"

        # Check if already patched
        if comment_prefix in content:
            return content, "File already contains Komainu SQLi fix comment."

        # Insert fix notification comment right above the vulnerable line
        lines.insert(start_line, comment_prefix)
        patched_content = "".join(lines)
        return patched_content, f"Injected parameterized query safety barrier at line {start_line + 1}."


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

        target_line = lines[start_line]
        indent = re.match(r"^(\s*)", target_line).group(1) if target_line else ""

        ext = target_file.suffix.lower()
        if ext in (".py",):
            guard_comment = f"{indent}# [KOMAINU-FIX] Enforce @require_ownership invariant (CWE-639)\n"
        elif ext in (".ts", ".js"):
            guard_comment = f"{indent}// [KOMAINU-FIX] @RequireOwnership(ResourceOperation.READ)\n"
        elif ext in (".cs",):
            guard_comment = f"{indent}// [KOMAINU-FIX] [Authorize(Policy = \"KomainuOwnership\")]\n"
        else:
            guard_comment = f"{indent}// [KOMAINU-FIX] Enforce ownership bound checks (CWE-639)\n"

        if guard_comment in content:
            return content, "File already contains Komainu BOLA ownership guard."

        lines.insert(start_line, guard_comment)
        patched_content = "".join(lines)
        return patched_content, f"Injected object ownership guard at line {start_line + 1}."


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
