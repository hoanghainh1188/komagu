#!/usr/bin/env python3
"""KOMAGU_* environment variables with the deprecated KOMAINU_* fallback (#290)."""

from __future__ import annotations

import os
import unittest
import warnings
from unittest.mock import patch

from remediate.tenancy.audit import audit_trail
from remediate.tenancy.crypto import byok_manager
from remediate.tenancy.middleware import tenant_context

# Each drop-in module carries its own copy of _env; other suites test theirs.
MODULES = (audit_trail, byok_manager, tenant_context)


class TestLegacyEnvFallback(unittest.TestCase):
    def test_new_name_wins_without_warning(self) -> None:
        env = {"KOMAGU_AUDIT_HMAC_KEY": "new", "KOMAINU_AUDIT_HMAC_KEY": "old"}
        for mod in MODULES:
            with self.subTest(module=mod.__name__), patch.dict(os.environ, env), warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                self.assertEqual(mod._env("AUDIT_HMAC_KEY"), "new")
                self.assertEqual(caught, [])

    def test_legacy_name_is_read_with_deprecation_warning(self) -> None:
        for mod in MODULES:
            with self.subTest(module=mod.__name__), patch.dict(os.environ, {"KOMAINU_INTERNAL_SERVICE_SECRET": "old"}, clear=True):
                with self.assertWarnsRegex(DeprecationWarning, "KOMAINU_INTERNAL_SERVICE_SECRET is deprecated"):
                    self.assertEqual(mod._env("INTERNAL_SERVICE_SECRET"), "old")

    def test_default_when_unset(self) -> None:
        for mod in MODULES:
            with self.subTest(module=mod.__name__), patch.dict(os.environ, {}, clear=True):
                self.assertEqual(mod._env("ENV", ""), "")
                self.assertIsNone(mod._env("ENV"))

    def test_legacy_audit_key_still_configures_audit_trail(self) -> None:
        key = "k" * 32
        with patch.dict(os.environ, {"KOMAINU_AUDIT_HMAC_KEY": key}, clear=True), warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            trail = audit_trail.TenantAuditTrail()
        self.assertEqual(trail.hmac_key, key.encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
