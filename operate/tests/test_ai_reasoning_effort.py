#!/usr/bin/env python3
"""`--ai-reasoning-effort` reaches each /chat/completions request and ai-run-stats.json (#382)."""

from __future__ import annotations

import argparse
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from operate.ai.client import LLMClient
from operate.ai.runner import HeadlessAIRunner
from operate.cli.commands.scan import register_subcommand

MESSAGES = [{"role": "user", "content": "audit"}]


class TestReasoningEffortPayload(unittest.TestCase):
    def test_not_sent_by_default(self) -> None:
        payload = LLMClient(model="m").build_payload(MESSAGES)
        self.assertEqual(payload, {"model": "m", "messages": MESSAGES, "temperature": 0.1})

    def test_sent_when_set(self) -> None:
        payload = LLMClient(model="m", reasoning_effort="none").build_payload(MESSAGES, max_tokens=50)
        self.assertEqual(payload["reasoning_effort"], "none")
        self.assertEqual(payload["max_tokens"], 50)

    def test_unknown_value_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            LLMClient(reasoning_effort="off")


class TestReasoningEffortCli(unittest.TestCase):
    def parse(self, *argv: str) -> argparse.Namespace:
        parser = argparse.ArgumentParser()
        register_subcommand(parser.add_subparsers(dest="command"))
        return parser.parse_args(["scan", ".", *argv])

    def test_flag_is_optional(self) -> None:
        self.assertIsNone(self.parse().ai_reasoning_effort)
        self.assertEqual(self.parse("--ai-reasoning-effort", "none").ai_reasoning_effort, "none")

    def test_flag_rejects_unknown_values(self) -> None:
        with self.assertRaises(SystemExit):
            self.parse("--ai-reasoning-effort", "off")


class TestReasoningEffortStats(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="komagu_effort_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_value_is_recorded(self) -> None:
        runner = HeadlessAIRunner(self.tmp, self.tmp / "out", LLMClient(model="m", reasoning_effort="low"))
        (self.tmp / "out").mkdir(parents=True, exist_ok=True)
        stats = json.loads(runner.write_run_stats().read_text(encoding="utf-8"))
        self.assertEqual(stats["reasoning_effort"], "low")


if __name__ == "__main__":
    unittest.main()
