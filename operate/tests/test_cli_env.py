#!/usr/bin/env python3
"""KOMAGU_* environment variables with the deprecated KOMAINU_* fallback (#290)."""

from __future__ import annotations

import contextlib
import io
import unittest

from operate.cli import env as cli_env


class TestGetenv(unittest.TestCase):
    def setUp(self) -> None:
        cli_env._warned.clear()

    def lookup(self, environ, default=None):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            value = cli_env.getenv("AI_MODEL", default, env=environ)
        return value, stderr.getvalue()

    def test_new_name_wins_without_warning(self) -> None:
        value, err = self.lookup({"KOMAGU_AI_MODEL": "new", "KOMAINU_AI_MODEL": "old"})
        self.assertEqual(value, "new")
        self.assertEqual(err, "")

    def test_legacy_name_is_read_with_warning(self) -> None:
        value, err = self.lookup({"KOMAINU_AI_MODEL": "old"})
        self.assertEqual(value, "old")
        self.assertIn("KOMAINU_AI_MODEL is deprecated, set KOMAGU_AI_MODEL", err)

    def test_legacy_warning_is_printed_once(self) -> None:
        self.lookup({"KOMAINU_AI_MODEL": "old"})
        _, err = self.lookup({"KOMAINU_AI_MODEL": "old"})
        self.assertEqual(err, "")

    def test_default_when_unset(self) -> None:
        value, err = self.lookup({}, default="llama3.1")
        self.assertEqual(value, "llama3.1")
        self.assertEqual(err, "")


if __name__ == "__main__":
    unittest.main()
