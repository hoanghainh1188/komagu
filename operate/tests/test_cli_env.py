#!/usr/bin/env python3
"""KOMAGU_* environment variables; the pre-rename KOMAINU_* names are no longer read (#312)."""

from __future__ import annotations

import unittest

from operate.cli import env as cli_env


class TestGetenv(unittest.TestCase):
    def test_reads_komagu_name(self) -> None:
        self.assertEqual(cli_env.getenv("AI_MODEL", env={"KOMAGU_AI_MODEL": "new"}), "new")

    def test_legacy_name_is_ignored(self) -> None:
        self.assertEqual(cli_env.getenv("AI_MODEL", "llama3.1", env={"KOMAINU_AI_MODEL": "old"}), "llama3.1")

    def test_default_when_unset(self) -> None:
        self.assertEqual(cli_env.getenv("AI_MODEL", "llama3.1", env={}), "llama3.1")
        self.assertIsNone(cli_env.getenv("AI_MODEL", env={}))


if __name__ == "__main__":
    unittest.main()
