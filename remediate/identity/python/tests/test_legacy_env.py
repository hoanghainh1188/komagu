#!/usr/bin/env python3
"""KOMAGU_* environment variables with the deprecated KOMAINU_* fallback (#290)."""

from __future__ import annotations

import os
import unittest
import warnings
from unittest.mock import patch

from remediate.identity.python.komagu_identity import oidc_validator

MODULES = (oidc_validator,)


class TestLegacyEnvFallback(unittest.TestCase):
    def test_new_name_wins_without_warning(self) -> None:
        env = {"KOMAGU_ALLOW_DEV_TOKENS": "new", "KOMAINU_ALLOW_DEV_TOKENS": "old"}
        for mod in MODULES:
            with self.subTest(module=mod.__name__), patch.dict(os.environ, env), warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                self.assertEqual(mod._env("ALLOW_DEV_TOKENS"), "new")
                self.assertEqual(caught, [])

    def test_legacy_name_is_read_with_deprecation_warning(self) -> None:
        for mod in MODULES:
            with self.subTest(module=mod.__name__), patch.dict(os.environ, {"KOMAINU_ALLOW_DEV_TOKENS": "old"}, clear=True):
                with self.assertWarnsRegex(DeprecationWarning, "KOMAINU_ALLOW_DEV_TOKENS is deprecated"):
                    self.assertEqual(mod._env("ALLOW_DEV_TOKENS"), "old")


if __name__ == "__main__":
    unittest.main()
