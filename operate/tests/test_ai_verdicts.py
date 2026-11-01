"""Issue #323: replies with stray quotes in code fields parse, and flagged verdicts without a finding
become low-confidence anchored findings (offline replay of Evaluation Run 5, run A)."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from operate.ai.anchoring import AnchorReport, anchor_findings, load_anchors
from operate.ai.client import LLMClient, repair_json_quotes
from operate.ai.runner import HeadlessAIRunner
from operate.ai.verdicts import verdict_findings
from operate.tests.test_ai_anchoring import _ScriptedClient

REPO_ROOT = Path(__file__).resolve().parents[2]
EVAL_RUN_5 = REPO_ROOT / "assess" / "lsa" / "examples" / "eval-run-5"
SCORER = REPO_ROOT / "assess" / "lsa" / "tests" / "score_findings.py"

# The slip that cost batch routes-001 in Run 4 and Run 5, run B (raw reply was not archived)
SLIPPED_REPLY = """Here is the audit:
```json
{
  "batch_id": "routes-001",
  "findings": [
    {
      "finding_id": "BOLA-R-0001",
      "category": "bola",
      "subtype": "missing_ownership_check",
      "title": "BOLA in GET /orders/{id}",
      "route_id": "R-0001",
      "location": {"file": "app/orders.php", "start_line": 3},
      "evidence": [{"file": "app/orders.php", "start_line": 3, "code": "$id = $_GET["id"];", "why": "id from request"}],
      "severity": "high",
      "confidence": "high",
      "cwe": ["CWE-639"],
      "recommendation": {"summary": "Bind to the session user", "code_before": "SELECT * FROM orders WHERE id = " + id", "code_after": "... AND user_id = ?"},
      "status": "unverified"
    }
  ],
  "route_verdicts": [{"route_id": "R-0001", "verdict": "vulnerable"}]
}
```"""


class TestRepairJsonQuotes(unittest.TestCase):
    def test_run_5_slip_parses_after_repair(self) -> None:
        with self.assertRaises((RuntimeError, ValueError)):
            LLMClient.extract_json(SLIPPED_REPLY)
        parsed = json.loads(repair_json_quotes(SLIPPED_REPLY))
        rec = parsed["findings"][0]["recommendation"]
        self.assertEqual(rec["code_before"], 'SELECT * FROM orders WHERE id = " + id')
        self.assertEqual(parsed["findings"][0]["evidence"][0]["code"], '$id = $_GET["id"];')
        self.assertEqual(parsed["route_verdicts"], [{"route_id": "R-0001", "verdict": "vulnerable"}])

    def test_valid_json_is_unchanged(self) -> None:
        doc = {"a": 'say "hi"', "b": ["x", {"c": "back\\slash"}], "d": 1}
        text = json.dumps(doc, indent=2)
        self.assertEqual(repair_json_quotes(text), text)
        self.assertEqual(json.loads(repair_json_quotes("Answer: " + json.dumps(doc) + " done")), doc)


class TestRunnerParsesRepairedReply(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="komagu_repair_"))
        self.target, self.out = self.tmp / "app", self.tmp / "out"
        (self.target / "app").mkdir(parents=True)
        (self.target / "app" / "orders.php").write_text("<?php\nsession_start();\n$id = $_GET['id'];\n", encoding="utf-8")
        (self.out / "routes").mkdir(parents=True)
        route = {"route_id": "R-0001", "method": ["GET"], "path": "/orders/{id}",
                 "handler": {"file": "app/orders.php", "line": 3}, "needs_bola_audit": True}
        (self.out / "routes" / "routes-001.json").write_text(json.dumps({"routes": [route]}), encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_slipped_bola_reply_keeps_its_findings_without_retry(self) -> None:
        runner = HeadlessAIRunner(self.target, self.out, _ScriptedClient([SLIPPED_REPLY]))
        runner.audit_bola_routes()
        doc = json.loads((self.out / "findings" / "bola-routes-001.json").read_text(encoding="utf-8"))
        self.assertEqual([f["finding_id"] for f in doc["findings"]], ["BOLA-R-0001"])
        self.assertEqual(doc["findings"][0]["recommendation"], "Bind to the session user")
        self.assertEqual((runner.retries, runner.parse_failures), ({}, {}))
        self.assertEqual(runner.repaired, {"4a-bola-auditor": ["routes-001"]})
        self.assertTrue((self.out / "ai-raw" / "4a-bola-auditor-routes-001.txt").is_file())
        stats = json.loads(runner.write_run_stats().read_text(encoding="utf-8"))
        self.assertEqual(stats["repaired"], {"4a-bola-auditor": ["routes-001"]})

    def test_vulnerable_verdict_without_finding_becomes_a_finding(self) -> None:
        reply = json.dumps({"batch_id": "routes-001", "findings": [],
                            "route_verdicts": [{"route_id": "R-0001", "verdict": "vulnerable"}]})
        runner = HeadlessAIRunner(self.target, self.out, _ScriptedClient([reply]))
        runner.audit_bola_routes()
        doc = json.loads((self.out / "findings" / "bola-routes-001.json").read_text(encoding="utf-8"))
        (f,) = doc["findings"]
        self.assertEqual((f["category"], f["subtype"], f["confidence"], f["status"]),
                         ("bola", "missing_ownership_check", "low", "unverified"))
        self.assertEqual(f["location"], {"file": "app/orders.php", "start_line": 3})
        self.assertEqual(f["endpoint"], {"method": "GET", "path": "/orders/{id}"})
        self.assertEqual(runner.findings_from_verdicts, {"4a-bola-auditor": [f["finding_id"]]})

    def test_the_4a_template_no_longer_asks_for_code_fields(self) -> None:
        client = _ScriptedClient(['{"findings": [], "route_verdicts": []}'])
        HeadlessAIRunner(self.target, self.out, client).audit_bola_routes()
        prompt = client.calls[0][-1]["content"]
        self.assertNotIn("code_before", prompt)
        self.assertNotIn("code_after", prompt)


class TestVerdictFindings(unittest.TestCase):
    RECORDS = {
        "M-1": {"candidate_id": "M-1", "file": "a.php", "line": 6, "subtype": "privileged_field_writable"},
        "I-1": {"candidate_id": "I-1", "file": "q.js", "line": 9, "category_hint": "nosql_injection",
                "subtype_hint": "operator_injection|dynamic_identifier"},
    }

    def test_only_flagged_uncovered_known_ids(self) -> None:
        verdicts = [{"candidate_id": "M-1", "verdict": "needs_review"}, {"candidate_id": "I-1", "verdict": "safe"},
                    {"candidate_id": "M-9", "verdict": "vulnerable"}, "noise"]
        (f,) = verdict_findings(verdicts, [], "candidate_id", self.RECORDS, "mass_assignment")
        self.assertEqual((f["finding_id"], f["subtype"], f["cwe"]), ("MASS-M-1-verdict", "privileged_field_writable", ["CWE-915"]))
        self.assertIn("needs_review", f["impact"])
        covered = [{"candidate_id": "M-1"}]
        self.assertEqual(verdict_findings(verdicts, covered, "candidate_id", self.RECORDS, "mass_assignment"), [])

    def test_category_and_subtype_hints_from_the_record(self) -> None:
        (f,) = verdict_findings([{"candidate_id": "I-1", "verdict": "vulnerable"}], [], "candidate_id",
                                self.RECORDS, "sql_injection")
        self.assertEqual((f["category"], f["subtype"], f["cwe"]), ("nosql_injection", "operator_injection", ["CWE-943"]))

    def test_generated_findings_match_the_finding_schema(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "assess" / "lsa" / "scripts"))
        from merge_findings import load_validator
        validate = load_validator("finding.schema.json")
        records = {**self.RECORDS, "R-1": {"route_id": "R-1", "method": ["POST"], "path": "/users/{id}/role",
                                           "handler": {"file": "admin.php", "line": 4}}}
        for key, record_id, category in (("route_id", "R-1", "bola"), ("route_id", "R-1", "bfla"),
                                         ("candidate_id", "M-1", "mass_assignment"), ("candidate_id", "I-1", "sql_injection")):
            with self.subTest(category=category):
                (f,) = verdict_findings([{key: record_id, "verdict": "vulnerable"}], [], key, records, category)
                self.assertEqual(validate(f), [])


class TestReplayRun5RunA(unittest.TestCase):
    """The four flagged mass assignment candidates of run A become located findings; no SAFE marker is hit."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="komagu_replay_"))
        self.out = self.tmp / "gptoss-a"
        shutil.copytree(EVAL_RUN_5 / "gptoss-a", self.out)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def score(self) -> dict:
        proc = subprocess.run([sys.executable, str(SCORER), "--verdicts", str(EVAL_RUN_5 / "ground-truth.json"), str(self.out)],
                              capture_output=True, text=True, check=True)
        return json.loads(proc.stdout)

    def test_replay_recovers_the_four_mass_assignment_items(self) -> None:
        cands = json.loads((self.out / "mass-assignment.candidates.json").read_text(encoding="utf-8"))["candidates"]
        records = {c["candidate_id"]: c for c in cands}
        # the fixtures are not in the archive; anchoring only needs the Tier 1 records
        anchors, report = load_anchors(self.out, self.tmp), AnchorReport()
        generated = []
        for path in sorted((self.out / "findings").glob("priv-*.json")):
            doc = json.loads(path.read_text(encoding="utf-8"))
            extra = verdict_findings(doc["candidate_verdicts"], doc["findings"], "candidate_id", records, "mass_assignment")
            generated += anchor_findings(extra, anchors, self.tmp, report)
            generated += verdict_findings(doc["privilege_route_verdicts"], doc["findings"], "route_id", {}, "bfla")
        self.assertEqual(sorted(f["candidate_id"] for f in generated), ["M-0001", "M-0002", "M-0011", "M-0012"])
        self.assertEqual(report.unanchored, [])

        merged = json.loads((self.out / "findings.json").read_text(encoding="utf-8"))
        merged["findings"] += generated
        (self.out / "findings.json").write_text(json.dumps(merged), encoding="utf-8")
        mass = self.score()["per_category"]["mass_assignment"]
        # before: 10 / 15; register.php:4 stays missed (rejected by the verifier, fixture under review)
        self.assertEqual((mass["found"], mass["missed"]), (14, ["php-plain/register.php:4"]))
        for cat, row in self.score()["per_category"].items():
            self.assertEqual(row["false_positive_on_safe_code"], [], cat)


if __name__ == "__main__":
    unittest.main()
