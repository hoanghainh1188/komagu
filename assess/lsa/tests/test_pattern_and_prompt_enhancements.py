#!/usr/bin/env python3
"""Unit tests verifying LSA pattern catalog and multi-agent prompt enhancements (Issue #47)."""

from __future__ import annotations

import unittest
from pathlib import Path

LSA_ROOT = Path(__file__).resolve().parent.parent


class TestPatternAndPromptEnhancements(unittest.TestCase):
    """Verify knowledge catalogs and role prompts contain mandatory high-recall rules."""

    def test_injection_patterns_catalog_contains_dynamic_nuances(self) -> None:
        """injection-patterns.md must cover MyBatis ${}, split construction, and CFML #...#."""
        content = (LSA_ROOT / "knowledge" / "injection-patterns.md").read_text(encoding="utf-8")
        self.assertIn("High-risk multi-stack interpolation nuances", content)
        self.assertIn("MyBatis / iBATIS XML (`${...}` vs. `#{...}`)", content)
        self.assertIn("Multi-line & split construction", content)
        self.assertIn("<choose><when>", content)
        self.assertIn("cfqueryparam", content)

    def test_bola_patterns_catalog_contains_indirect_keys_and_p13(self) -> None:
        """bola-patterns.md must document indirect sub-resource keys and pattern P13."""
        content = (LSA_ROOT / "knowledge" / "bola-patterns.md").read_text(encoding="utf-8")
        self.assertIn("Indirect / sub-resource key", content)
        self.assertIn("cart_id", content)
        self.assertIn("P13 Indirect / session-detached resource key", content)

    def test_bola_auditor_prompt_enforces_two_way_binding(self) -> None:
        """30-bola-auditor.md must require two-way binding and warn on Login != Authorization."""
        content = (LSA_ROOT / "prompts" / "30-bola-auditor.md").read_text(encoding="utf-8")
        self.assertIn("Two-way binding", content)
        self.assertIn("Login ≠ Authorization", content)
        self.assertIn("DELETE FROM carts WHERE cart_id = ?", content)

    def test_injection_auditor_prompt_enforces_split_construction_and_dynamic_sort(self) -> None:
        """40-injection-auditor.md must trace split variables and flag unvalidated ${orderBy}."""
        content = (LSA_ROOT / "prompts" / "40-injection-auditor.md").read_text(encoding="utf-8")
        self.assertIn("Split construction & multiple queries in one handler", content)
        self.assertIn("${orderBy}", content)
        self.assertIn("explicit allow-list", content)

    def test_finding_verifier_prompt_recognizes_allow_lists(self) -> None:
        """50-finding-verifier.md must instruct the Skeptic on allow-list/enum recognition."""
        content = (LSA_ROOT / "prompts" / "50-finding-verifier.md").read_text(encoding="utf-8")
        self.assertIn("explicit allow-lists / enum", content)
        self.assertIn("in_array($sort", content)
        self.assertIn("<choose><when", content)


if __name__ == "__main__":
    unittest.main()
