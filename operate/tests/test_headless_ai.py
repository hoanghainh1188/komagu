#!/usr/bin/env python3
"""Comprehensive test suite for Komagu Headless Cognitive AI Runner (Issue #263).

Standard-library only (Python 3.8+ compatible).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from operate.ai.client import LLMClient
from operate.ai.mock_server import start_mock_llm_server
from operate.ai.runner import HeadlessAIRunner
from operate.cli.main import main as cli_main


class TestLLMClient(unittest.TestCase):
    """Tests for zero-dependency OpenAI-compatible LLMClient."""

    def test_url_normalization(self) -> None:
        c1 = LLMClient(endpoint="http://localhost:11434/v1")
        self.assertEqual(c1.endpoint, "http://localhost:11434/v1/chat/completions")

        c2 = LLMClient(endpoint="http://localhost:11434/v1/chat/completions")
        self.assertEqual(c2.endpoint, "http://localhost:11434/v1/chat/completions")

        c3 = LLMClient(endpoint="http://localhost:11434/v1/")
        self.assertEqual(c3.endpoint, "http://localhost:11434/v1/chat/completions")

    def test_extract_json_from_various_formats(self) -> None:
        # 1. Raw JSON
        raw = '{"status": "ok", "count": 42}'
        self.assertEqual(LLMClient.extract_json(raw), {"status": "ok", "count": 42})

        # 2. Markdown fenced json block
        fenced = 'Here is the result:\n```json\n{"findings": [{"id": 1}]}\n```\nHope this helps!'
        self.assertEqual(LLMClient.extract_json(fenced), {"findings": [{"id": 1}]})

        # 3. Code fence without language identifier
        no_lang = '```\n{"result": true}\n```'
        self.assertEqual(LLMClient.extract_json(no_lang), {"result": True})

        # 4. Leading / trailing commentary with braces
        commentary = 'Explanation before...\n{"key": "value"}\nExplanation after.'
        self.assertEqual(LLMClient.extract_json(commentary), {"key": "value"})

    def test_chat_against_mock_server(self) -> None:
        def dynamic_reply(messages, model):
            return f"Echo from {model}: {messages[-1]['content'][:10]}"

        server, thread, base_url = start_mock_llm_server(port=0, response_generator=dynamic_reply)
        try:
            client = LLMClient(endpoint=base_url, model="test-llama", api_key="secret-key")
            response = client.chat([{"role": "user", "content": "Hello World!"}])
            self.assertIn("Echo from test-llama: Hello Worl", response)
        finally:
            server.server_close()

    def test_network_failure_raises_runtime_error(self) -> None:
        # Point to closed port
        client = LLMClient(endpoint="http://127.0.0.1:59999/v1", timeout=2)
        with self.assertRaises(RuntimeError) as ctx:
            client.chat([{"role": "user", "content": "ping"}])
        self.assertIn("Failed to connect to LLM endpoint", str(ctx.exception))


class TestSanitizeFinding(unittest.TestCase):
    """Format repairs for model output that would otherwise fail finding.schema.json (#286)."""

    def test_impact_list_becomes_string(self) -> None:
        f = HeadlessAIRunner._sanitize_finding({"category": "mass_assignment", "subtype": "whole_object_binding",
                                                "impact": ["role escalation", "balance change"]})
        self.assertEqual(f["impact"], "role escalation; balance change")

    def test_verdict_in_subtype_moves_to_status(self) -> None:
        f = HeadlessAIRunner._sanitize_finding({"category": "mass_assignment", "subtype": "needs_review", "status": "unverified"})
        self.assertEqual(f["subtype"], "whole_object_binding")
        self.assertEqual(f["status"], "needs_review")

    def test_unknown_bfla_subtype_falls_back(self) -> None:
        f = HeadlessAIRunner._sanitize_finding({"category": "bfla", "subtype": "admin_only", "status": "unverified"})
        self.assertEqual((f["subtype"], f["status"]), ("missing_role_check", "unverified"))

    def test_valid_subtype_is_kept(self) -> None:
        f = HeadlessAIRunner._sanitize_finding({"category": "bfla", "subtype": "role_from_request"})
        self.assertEqual(f["subtype"], "role_from_request")


class TestHeadlessAIRunner(unittest.TestCase):
    """End-to-end tests for HeadlessAIRunner and multi-agent pipeline."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="komagu_ai_test_")
        self.target_dir = Path(self.temp_dir) / "sample_app"
        self.target_dir.mkdir(parents=True)
        self.out_dir = Path(self.temp_dir) / "out"
        self.out_dir.mkdir(parents=True)

        # Create sample vulnerable Express / Node.js file
        sample_code = """const express = require('express');
const app = express();

// Planted BOLA route
app.get('/api/orders/:id', async (req, res) => {
    const orderId = req.params.id;
    // Missing owner check: directly query order by id without session binding
    const order = await db.query("SELECT * FROM orders WHERE id = " + orderId);
    res.json(order);
});

module.exports = app;
"""
        (self.target_dir / "app.js").write_text(sample_code, encoding="utf-8")
        package_json = {
            "name": "sample-vulnerable-app",
            "version": "1.0.0",
            "dependencies": {"express": "^4.17.1"},
        }
        (self.target_dir / "package.json").write_text(json.dumps(package_json, indent=2), encoding="utf-8")

        # Mock LLM response dispatcher
        def mock_agent_responses(messages, model):
            user_msg = messages[-1]["content"]
            if "Auth Model" in user_msg or "Pre-scan Stack Profile" in user_msg:
                return "# Mock Application Auth Model\n\n- Auth: Express session\n- Ownership: missing on /api/orders/:id\n"
            if "dynamic query string concatenation or interpolation" in user_msg:
                return """```json
{
  "batch_id": "injection-001",
  "findings": [
    {
      "finding_id": "INJ-I-0001",
      "category": "sql_injection",
      "subtype": "string_concatenation",
      "title": "SQL Injection in app.js:7",
      "candidate_id": "I-0001",
      "location": {"file": "app.js", "start_line": 7},
      "evidence": [{"file": "app.js", "line": 7, "code": "SELECT * FROM orders WHERE id = + orderId", "why": "Concatenated request param"}],
      "severity": "critical",
      "confidence": "high",
      "cwe": ["CWE-89"],
      "recommendation": "Use parameterized queries to prevent SQL injection.",
      "status": "unverified"
    }
  ],
  "candidate_verdicts": [{"candidate_id": "I-0001", "verdict": "vulnerable"}]
}
```"""
            if "For each route, decide if an authenticated caller" in user_msg:
                return """```json
{
  "batch_id": "routes-001",
  "findings": [
    {
      "finding_id": "BOLA-R-0001",
      "category": "bola",
      "subtype": "missing_ownership_check",
      "title": "BOLA in GET /api/orders/:id: missing owner check",
      "route_id": "R-0001",
      "endpoint": {"method": "GET", "path": "/api/orders/:id"},
      "location": {"file": "app.js", "start_line": 4},
      "evidence": [{"file": "app.js", "line": 4, "code": "app.get('/api/orders/:id')", "why": "No check against req.user.id"}],
      "severity": "high",
      "confidence": "high",
      "cwe": ["CWE-284", "CWE-639"],
      "recommendation": "Verify resource ownership before returning data.",
      "status": "unverified"
    }
  ],
  "route_verdicts": [{"route_id": "R-0001", "verdict": "vulnerable"}]
}
```"""
            if "Findings to Verify & Challenge" in user_msg:
                return """```json
{
  "batch_id": "verified-1",
  "verifications": [
    {
      "finding_id": "BOLA-R-0001",
      "verdict": "confirmed",
      "reason_code": "traced",
      "confidence": "high",
      "checked": ["Checked app.js route handler and DB access"],
      "notes": "Confirmed BOLA vulnerability: no owner filter found.",
      "consensus": {
        "score": 0.98,
        "agreement_level": "unanimous",
        "voted_models": ["mock-model"],
        "rationale": "Traced data flow without session binding."
      }
    },
    {
      "finding_id": "INJ-I-0001",
      "verdict": "confirmed",
      "reason_code": "traced",
      "confidence": "high",
      "checked": ["Checked query string concatenation"],
      "notes": "Direct string concatenation into SQL command.",
      "consensus": {
        "score": 0.95,
        "agreement_level": "unanimous",
        "voted_models": ["mock-model"],
        "rationale": "Traced dynamic query assembly."
      }
    }
  ]
}
```"""
            return '{"status": "ok"}'

        self.mock_agent_responses = mock_agent_responses
        self.server, self.thread, self.base_url = start_mock_llm_server(
            port=0, response_generator=mock_agent_responses
        )

    def tearDown(self) -> None:
        self.server.server_close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _prescan(self) -> None:
        import subprocess

        prescan_script = PROJECT_ROOT / "assess" / "lsa" / "scripts" / "run_prescan.py"
        res = subprocess.run(
            [sys.executable, str(prescan_script), str(self.target_dir), str(self.out_dir)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"Pre-scan failed: {res.stderr}")

    def test_run_stats_record_tokens_and_phases(self) -> None:
        self._prescan()
        client = LLMClient(endpoint=self.base_url, model="mock-model", api_key="test")
        HeadlessAIRunner(self.target_dir, self.out_dir, client).run()

        stats = json.loads((self.out_dir / "ai-run-stats.json").read_text(encoding="utf-8"))
        self.assertEqual(stats["model"], "mock-model")
        self.assertGreater(stats["totals"]["calls"], 0)
        # the mock server reports 100 prompt / 50 completion tokens per call
        self.assertEqual(stats["totals"]["prompt_tokens"], 100 * stats["totals"]["calls"])
        self.assertEqual(stats["totals"]["completion_tokens"], 50 * stats["totals"]["calls"])
        self.assertEqual(sum(ph["calls"] for ph in stats["phases"].values()), stats["totals"]["calls"])
        self.assertIn("5-finding-verifier", stats["phases"])
        # the mock answers the BOLA prompt with the auth-model markdown, so that batch is a parse failure
        self.assertEqual(stats["parse_failures"], {"4a-bola-auditor": ["routes-001"]})

    def test_unparseable_verifier_reply_leaves_findings_unverified(self) -> None:
        """A broken verifier reply must not confirm findings (#286)."""
        self.server.server_close()

        def broken_verifier(messages, model):
            if "Findings to Verify & Challenge" in messages[-1]["content"]:
                return "I think these all look vulnerable."
            return self.mock_agent_responses(messages, model)

        self.server, self.thread, self.base_url = start_mock_llm_server(port=0, response_generator=broken_verifier)
        self._prescan()
        client = LLMClient(endpoint=self.base_url, model="mock-model", api_key="test")
        logs = []
        HeadlessAIRunner(self.target_dir, self.out_dir, client, step_callback=lambda st, msg: logs.append((st, msg))).run()

        findings = json.loads((self.out_dir / "findings.json").read_text(encoding="utf-8"))["findings"]
        self.assertGreaterEqual(len(findings), 1)
        self.assertNotIn("confirmed", [f.get("status") for f in findings])
        coverage = json.loads((self.out_dir / "coverage.json").read_text(encoding="utf-8"))
        self.assertEqual(sorted(coverage["findings_without_verification"]), sorted(f["finding_id"] for f in findings))
        stats = json.loads((self.out_dir / "ai-run-stats.json").read_text(encoding="utf-8"))
        self.assertEqual(stats["parse_failures"]["5-finding-verifier"], ["verified-1"])
        raw = self.out_dir / "ai-raw" / "5-finding-verifier-verified-1.txt"
        self.assertEqual(raw.read_text(encoding="utf-8"), "I think these all look vulnerable.")
        self.assertTrue(any(st == "warn" and "verified-1" in msg for st, msg in logs))

    def test_failed_batch_call_is_recorded_and_run_continues(self) -> None:
        """A timeout on one batch must not abort the run or lose earlier phases (#286)."""

        class TimeoutOnInjection(LLMClient):
            def chat(self, messages, temperature=0.1, max_tokens=None):  # noqa: ANN001
                if "dynamic query string concatenation or interpolation" in messages[-1]["content"]:
                    raise RuntimeError("timed out")
                return super().chat(messages, temperature=temperature, max_tokens=max_tokens)

        self._prescan()
        client = TimeoutOnInjection(endpoint=self.base_url, model="mock-model", api_key="test")
        result = HeadlessAIRunner(self.target_dir, self.out_dir, client).run()
        self.assertEqual(result["status"], "success")

        stats = json.loads((self.out_dir / "ai-run-stats.json").read_text(encoding="utf-8"))
        self.assertEqual(stats["call_errors"], {"4b-injection-auditor": {"injection-001": "timed out"}})
        self.assertNotIn("4b-injection-auditor", stats["parse_failures"])
        self.assertIn("5-finding-verifier", stats["phases"])
        self.assertTrue((self.out_dir / "findings.json").is_file())

    def test_headless_ai_runner_full_cycle(self) -> None:
        # 1. Run deterministic pre-scan to populate OUT
        prescan_script = PROJECT_ROOT / "assess" / "lsa" / "scripts" / "run_prescan.py"
        import subprocess

        res = subprocess.run(
            [sys.executable, str(prescan_script), str(self.target_dir), str(self.out_dir)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"Pre-scan failed: {res.stderr}")

        # 2. Run HeadlessAIRunner
        client = LLMClient(endpoint=self.base_url, model="mock-model", api_key="test")
        logs = []
        runner = HeadlessAIRunner(
            self.target_dir,
            self.out_dir,
            client,
            step_callback=lambda status, msg: logs.append((status, msg)),
        )
        result = runner.run()
        self.assertEqual(result["status"], "success")

        # 3. Assert artifacts created
        self.assertTrue((self.out_dir / "auth-model.md").is_file())
        self.assertTrue((self.out_dir / "routes").is_dir())
        self.assertTrue((self.out_dir / "findings").is_dir())

        # Check merged findings.json
        findings_file = self.out_dir / "findings.json"
        self.assertTrue(findings_file.is_file())
        findings_data = json.loads(findings_file.read_text(encoding="utf-8"))
        findings_list = findings_data.get("findings", [])
        self.assertGreaterEqual(len(findings_list), 1)

        # Confirm BOLA or SQLi finding got verified
        verified_statuses = [f.get("status") for f in findings_list]
        self.assertIn("confirmed", verified_statuses)

    def test_cli_scan_with_headless_ai_flag(self) -> None:
        cli_out = Path(self.temp_dir) / "cli_out"
        ret = cli_main([
            "scan",
            str(self.target_dir),
            "--headless-ai",
            self.base_url,
            "--model",
            "mock-model",
            "--out",
            str(cli_out),
            "--format",
            "all",
        ])
        self.assertEqual(ret, 0, "komagu scan --headless-ai returned non-zero")

        # Verify output reports
        self.assertTrue((cli_out / "report.html").is_file())
        self.assertTrue((cli_out / "report.md").is_file())
        self.assertTrue((cli_out / "findings.sarif").is_file())
        self.assertTrue((cli_out / "findings.json").is_file())

        findings = json.loads((cli_out / "findings.json").read_text(encoding="utf-8"))
        summary = findings.get("summary", {})
        total_count = summary.get("total_reported", summary.get("active", summary.get("total", 0)))
        self.assertGreaterEqual(total_count, 1)
        self.assertGreaterEqual(len(findings.get("findings", [])), 1)


if __name__ == "__main__":
    unittest.main()
