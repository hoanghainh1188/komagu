#!/usr/bin/env python3
"""KOMAGU_* environment variables with the deprecated KOMAINU_* fallback (#290)."""

from __future__ import annotations

import os
import unittest
import warnings
from unittest.mock import patch

from remediate.resilience.dr import dr_manager

MODULES = (dr_manager,)


class TestLegacyEnvFallback(unittest.TestCase):
    def test_new_name_wins_without_warning(self) -> None:
        env = {"KOMAGU_DR_METADATA_PATH": "new", "KOMAINU_DR_METADATA_PATH": "old"}
        for mod in MODULES:
            with self.subTest(module=mod.__name__), patch.dict(os.environ, env), warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                self.assertEqual(mod._env("DR_METADATA_PATH"), "new")
                self.assertEqual(caught, [])

    def test_legacy_name_is_read_with_deprecation_warning(self) -> None:
        for mod in MODULES:
            with self.subTest(module=mod.__name__), patch.dict(os.environ, {"KOMAINU_DR_METADATA_PATH": "old"}, clear=True):
                with self.assertWarnsRegex(DeprecationWarning, "KOMAINU_DR_METADATA_PATH is deprecated"):
                    self.assertEqual(mod._env("DR_METADATA_PATH"), "old")


if __name__ == "__main__":
    unittest.main()
