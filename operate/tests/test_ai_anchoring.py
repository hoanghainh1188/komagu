#!/usr/bin/env python3
"""Finding locations anchored to Tier 1 routes / candidates, and one retry on empty replies (#319)."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from operate.ai.anchoring import AnchorReport, anchor_findings, load_anchors
from operate.ai.runner import HeadlessAIRunner


def _write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data) if not isinstance(data, str) else data, encoding="utf-8")


class TestAnchoring(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="komagu_anchor_"))
        self.target, self.out = self.tmp / "repo", self.tmp / "out"
        _write(self.target / "node-express/routes/admin.js", "\n".join(f"// line {i}" for i in range(1, 21)) + "\n")
        _write(self.target / "python-flask/profile.py", "\n".join(f"# line {i}" for i in range(1, 31)) + "\n")
        _write(self.out / "routes/routes-001.json", {"routes": [
            {"route_id": "R-1", "handler": {"file": "node-express/routes/admin.js", "line": 8}},
            {"route_id": "R-2", "handler": {"file": "node-express/routes/admin.js", "line": 12}},
            {"route_id": "R-3", "handler": {"file": "node-express/routes/admin.js", "line": 16}}]})
        _write(self.out / "mass-assignment.candidates.json", {"candidates": [
            {"candidate_id": "M-14", "file": "python-flask/profile.py", "line": 10}]})
        self.anchors = load_anchors(self.out, self.target)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_one(self, finding: dict) -> tuple:
        report = AnchorReport()
        return anchor_findings([finding], self.anchors, self.target, report)[0], report

    def test_handler_spans_end_before_the_next_route(self) -> None:
        self.assertEqual((self.anchors["R-1"].line, self.anchors["R-1"].end_line), (8, 11))
        self.assertEqual((self.anchors["R-3"].line, self.anchors["R-3"].end_line), (16, 20))

    def test_wrong_path_with_line_in_span_keeps_the_line(self) -> None:
        f, report = self.run_one({"finding_id": "BFLA-R-1-1", "route_id": "R-1",
                                  "location": {"file": "routes.js", "start_line": 9},
                                  "evidence": [{"file": "routes.js", "line": 9, "why": "no role check"}]})
        self.assertEqual(f["location"], {"file": "node-express/routes/admin.js", "start_line": 9})
        self.assertEqual(f["evidence"], [{"file": "node-express/routes/admin.js", "line": 9, "why": "no role check"}])
        self.assertEqual(report.moved, ["BFLA-R-1-1"])

    def test_line_outside_span_falls_back_to_handler(self) -> None:
        f, _ = self.run_one({"finding_id": "BFLA-R-1-1", "route_id": "R-1",
                             "location": {"file": "node-express/routes/admin.js", "start_line": 17}})
        self.assertEqual(f["location"]["start_line"], 8)

    def test_candidate_finding_takes_candidate_site(self) -> None:
        f, _ = self.run_one({"finding_id": "MASS-M-14-1", "candidate_id": "M-14",
                             "location": {"file": "app.py", "start_line": 8, "end_line": 9},
                             "evidence": [{"file": "app.py", "line": 8, "why": "binds request body"}]})
        self.assertEqual(f["location"], {"file": "python-flask/profile.py", "start_line": 10})
        self.assertEqual(f["evidence"][0]["file"], "python-flask/profile.py")

    def test_correct_location_is_not_reported_as_moved(self) -> None:
        f, report = self.run_one({"finding_id": "BFLA-R-2-1", "route_id": "R-2",
                                  "location": {"file": "node-express/routes/admin.js", "start_line": 13}})
        self.assertEqual(f["location"]["start_line"], 13)
        self.assertEqual((report.moved, report.unanchored), ([], []))

    def test_unknown_reference_is_unanchored_and_low_confidence(self) -> None:
        f, report = self.run_one({"finding_id": "BFLA-R-9-1", "route_id": "R-9", "confidence": "high",
                                  "location": {"file": "x.js", "start_line": 1}})
        self.assertEqual(f["location"], {"file": "x.js", "start_line": 1})
        self.assertEqual(f["confidence"], "low")
        self.assertEqual(report.unanchored, ["BFLA-R-9-1"])

    def test_input_is_not_mutated(self) -> None:
        original = {"finding_id": "BFLA-R-1-1", "route_id": "R-1", "location": {"file": "routes.js", "start_line": 9}}
        snapshot = json.dumps(original, sort_keys=True)
        self.run_one(original)
        self.assertEqual(json.dumps(original, sort_keys=True), snapshot)


class _ScriptedClient:
    """Returns the scripted replies in order; an Exception item is raised."""

    model = "scripted"
    endpoint = "test://"

    def __init__(self, replies: list) -> None:
        self.replies = list(replies)
        self.calls: list = []

    def chat(self, messages, temperature=0.1):  # noqa: ANN001
        self.calls.append(messages)
        item = self.replies.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    @staticmethod
    def extract_json(content: str):  # noqa: ANN205
        from operate.ai.client import LLMClient
        return LLMClient.extract_json(content)


class TestRetry(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="komagu_retry_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def runner(self, replies: list) -> HeadlessAIRunner:
        return HeadlessAIRunner(self.tmp, self.tmp / "out", _ScriptedClient(replies))

    def test_empty_reply_is_retried_once(self) -> None:
        r = self.runner(["", '{"findings": []}'])
        self.assertEqual(r._chat("4a-bola-auditor", "routes-001", [{"role": "user", "content": "audit"}]), '{"findings": []}')
        self.assertEqual(r.retries, {"4a-bola-auditor": ["routes-001"]})
        retry = r.client.calls[1]
        self.assertEqual([m["role"] for m in retry], ["user", "user"])  # no empty assistant turn
        self.assertIn("JSON object only", retry[-1]["content"])

    def test_unparseable_reply_is_retried_with_its_text(self) -> None:
        r = self.runner(["looks fine to me", '{"findings": []}'])
        r._chat("4c-privilege-auditor", "privilege-001", [{"role": "user", "content": "audit"}])
        self.assertEqual([m["role"] for m in r.client.calls[1]], ["user", "assistant", "user"])

    def test_second_bad_reply_keeps_the_first_text(self) -> None:
        r = self.runner(["looks fine to me", "still not json"])
        self.assertEqual(r._chat("5-finding-verifier", "verified-1", [{"role": "user", "content": "v"}]), "looks fine to me")

    def test_good_reply_is_not_retried(self) -> None:
        r = self.runner(['{"findings": []}'])
        r._chat("4a-bola-auditor", "routes-001", [{"role": "user", "content": "audit"}])
        self.assertEqual((len(r.client.calls), r.retries), (1, {}))

    def test_failed_call_is_not_retried(self) -> None:
        r = self.runner([RuntimeError("timed out")])
        self.assertIsNone(r._chat("4b-injection-auditor", "injection-001", [{"role": "user", "content": "i"}]))
        self.assertEqual((len(r.client.calls), r.retries), (1, {}))
        self.assertEqual(r.call_errors, {"4b-injection-auditor": {"injection-001": "timed out"}})


if __name__ == "__main__":
    unittest.main()
