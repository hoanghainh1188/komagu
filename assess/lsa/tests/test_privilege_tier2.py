#!/usr/bin/env python3
"""Tests for the Tier 2 privilege auditor wiring (Issue #269, part c).

Validates:
1. make_batches writes privilege-NNN batches from BFLA-hinted routes and mass
   assignment candidates, grouped by file, with the right knowledge files.
2. merge_findings reports BFLA routes and mass candidates without a verdict as
   coverage gaps, kept apart from BOLA and injection coverage.
3. Prompts: the new 35-privilege-auditor role and the updates to the
   orchestrator, route mapper, verifier, stack detector and reporters.
4. Adapters ship the new agent; the verifier loads the new knowledge.
5. The headless AI runner runs phase 4c and writes findings/priv-*.json.
6. score_findings scores bfla and mass_assignment when ground truth has them.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
KIT = HERE.parent
REPO = KIT.parent.parent
sys.path.insert(0, str(KIT / "scripts"))
sys.path.insert(0, str(KIT / "adapters"))
sys.path.insert(0, str(REPO))

from build_adapters import ROLES, build  # noqa: E402
from lsa_common import load_config, write_json  # noqa: E402
from make_batches import make_batches  # noqa: E402
from merge_findings import load_validator  # noqa: E402

PROMPTS = KIT / "prompts"
MERGE = KIT / "scripts" / "merge_findings.py"
SCORE = HERE / "score_findings.py"


def _route(rid: str, rel: str, hint: bool) -> dict:
    return {"route_id": rid, "stack": "php", "kind": "file", "method": ["POST"], "path": "/" + rel,
            "handler": {"file": rel, "line": 1, "symbol": None}, "id_params": [], "guard_hints": [], "data_hints": [],
            "notes": "", "needs_audit_hint": False, "needs_bfla_audit_hint": hint,
            "bfla_signals": [{"signal": "no_role_check", "line": 1, "hint": "path:admin"}] if hint else []}


def _mass(cid: str, rel: str, lang: str = "php") -> dict:
    return {"candidate_id": cid, "file": rel, "line": 3, "language": lang, "rule": "php-extract",
            "subtype": "whole_object_binding", "target": None, "allowlist": "unknown", "priority": "high",
            "sensitive_fields": [], "code": "extract($_POST);"}


class TestPrivilegeBatches(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name)
        write_json(self.out / "injection.candidates.json", {"candidates": []})

    def test_batches_group_routes_and_candidates_by_file(self) -> None:
        write_json(self.out / "routes.candidates.json", {"candidates": [
            _route("R-0001", "admin/a.php", True), _route("R-0002", "orders.php", False), _route("R-0003", "admin/b.php", True)]})
        write_json(self.out / "mass-assignment.candidates.json", {"candidates": [
            _mass("M-0001", "admin/a.php"), _mass("M-0002", "profile.php"), _mass("M-0003", "app.js", "js")]})
        cfg = load_config(None)
        cfg["batch"]["max_privilege_items"] = 3
        idx = make_batches(self.out, cfg)
        self.assertEqual([b["batch_id"] for b in idx["privilege"]], ["privilege-001", "privilege-002"])
        first = json.loads((self.out / "batches" / "privilege-001.json").read_text(encoding="utf-8"))
        self.assertEqual([r["route_id"] for r in first["routes"]], ["R-0001", "R-0003"])
        self.assertEqual([c["candidate_id"] for c in first["mass_candidates"]], ["M-0001"])
        self.assertIn("knowledge/bfla-patterns.md", first["knowledge_files"])
        self.assertIn("knowledge/mass-assignment-patterns.md", first["knowledge_files"])
        second = json.loads((self.out / "batches" / "privilege-002.json").read_text(encoding="utf-8"))
        self.assertEqual(second["routes"], [])
        self.assertEqual([c["candidate_id"] for c in second["mass_candidates"]], ["M-0003", "M-0002"])

    def test_no_privilege_work_and_old_workspaces(self) -> None:
        write_json(self.out / "routes.candidates.json", {"candidates": [_route("R-0001", "orders.php", False)]})
        idx = make_batches(self.out, load_config(None))
        self.assertEqual(idx["privilege"], [])
        self.assertFalse(list((self.out / "batches").glob("privilege-*.json")))


class TestCoverage(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name)
        write_json(self.out / "routes.candidates.json", {"candidates": [_route("R-0001", "admin/a.php", True)]})
        write_json(self.out / "routes" / "routes-001.json", {"batch_id": "routes-001", "routes": [{
            "route_id": "R-0001", "method": ["POST"], "path": "/admin/a.php", "handler": {"file": "admin/a.php", "line": 1},
            "id_inputs": [], "guards": [], "data_ops": [{"op": "delete", "target": "users"}],
            "needs_bola_audit": False, "privilege": "privileged", "needs_bfla_audit": True}]})
        write_json(self.out / "mass-assignment.candidates.json", {"candidates": [_mass("M-0001", "admin/a.php")]})

    def merge(self) -> tuple:
        res = subprocess.run([sys.executable, str(MERGE), str(self.out)], capture_output=True, text=True)
        return res.returncode, json.loads((self.out / "coverage.json").read_text(encoding="utf-8"))

    def test_missing_privilege_verdicts_are_gaps(self) -> None:
        rc, cov = self.merge()
        self.assertEqual(rc, 1)
        self.assertEqual(cov["bfla_routes_to_audit"], 1)
        self.assertEqual(cov["bfla_routes_without_verdict"], ["R-0001"])
        self.assertEqual(cov["mass_candidates"], 1)
        self.assertEqual(cov["mass_candidates_without_verdict"], ["M-0001"])
        self.assertEqual(cov["bola_routes_without_verdict"], [])

    def test_privilege_verdicts_close_gaps_and_findings_merge(self) -> None:
        finding = {
            "finding_id": "BFLA-R-0001-1", "category": "bfla", "subtype": "missing_role_check",
            "title": "User deletion open to any logged-in user", "route_id": "R-0001",
            "endpoint": {"method": "POST", "path": "/admin/a.php"},
            "location": {"file": "admin/a.php", "start_line": 3},
            "evidence": [{"file": "admin/a.php", "line": 3, "code": "delete_user($id);", "why": "no role check"}],
            "severity": "critical", "confidence": "high", "cwe": ["CWE-285"],
            "recommendation": "Require the admin role.", "status": "unverified",
        }
        write_json(self.out / "findings" / "priv-privilege-001.json", {
            "batch_id": "privilege-001",
            "privilege_route_verdicts": [{"route_id": "R-0001", "verdict": "vulnerable", "finding_ids": ["BFLA-R-0001-1"]}],
            "candidate_verdicts": [{"candidate_id": "M-0001", "verdict": "safe", "reason": "only admins reach it"}],
            "findings": [finding],
        })
        rc, cov = self.merge()
        self.assertEqual(cov["bfla_routes_without_verdict"], [])
        self.assertEqual(cov["mass_candidates_without_verdict"], [])
        doc = json.loads((self.out / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual(doc["summary"]["by_category"]["bfla"], 1)
        self.assertEqual(cov["bola_routes_without_verdict"], [])

    def test_route_inventory_schema_accepts_needs_bfla_audit(self) -> None:
        doc = json.loads((self.out / "routes" / "routes-001.json").read_text(encoding="utf-8"))
        self.assertEqual(load_validator("route-inventory.schema.json")(doc), [])


class TestPrompts(unittest.TestCase):
    def read(self, name: str) -> str:
        return (PROMPTS / name).read_text(encoding="utf-8")

    def test_privilege_auditor_prompt(self) -> None:
        text = self.read("35-privilege-auditor.md")
        for needle in ("privilege_route_verdicts", "candidate_verdicts", "BFLA-", "MASS-", "knowledge/bfla-patterns.md",
                       "knowledge/mass-assignment-patterns.md", "not_privileged", "not_a_binding",
                       "missing_role_check", "role_from_request", "client_side_role_check",
                       "whole_object_binding", "privileged_field_writable", "CWE-285", "CWE-915"):
            self.assertIn(needle, text)

    def test_other_prompts_updated(self) -> None:
        orch = self.read("00-orchestrator.md")
        for needle in ("4c", "35-privilege-auditor", "privilege-<n>", "findings/priv-", "mass-assignment.candidates.json"):
            self.assertIn(needle, orch)
        mapper = self.read("20-route-mapper.md")
        for needle in ("needs_bfla_audit", "privilege", "body_bindings"):
            self.assertIn(needle, mapper)
        verifier = self.read("50-finding-verifier.md")
        self.assertIn("knowledge/bfla-patterns.md", verifier)
        self.assertIn("knowledge/mass-assignment-patterns.md", verifier)
        self.assertIn("knowledge/bfla-patterns.md", self.read("10-stack-detector.md"))
        for name in ("60-reporter.md", "60-reporter-ja.md"):
            self.assertIn("BFLA", self.read(name))


class TestAdapters(unittest.TestCase):
    def test_role_registered_and_shipped(self) -> None:
        role = next(r for r in ROLES if r["id"] == "privilege-auditor")
        self.assertEqual(role["file"], "35-privilege-auditor.md")
        self.assertIn("knowledge/bfla-patterns.md", role["knowledge"])
        verifier = next(r for r in ROLES if r["id"] == "finding-verifier")
        self.assertIn("knowledge/mass-assignment-patterns.md", verifier["knowledge"])
        with tempfile.TemporaryDirectory() as tmp:
            build("claude-code", Path(tmp))
            agent = Path(tmp) / ".claude" / "agents" / "lsa-privilege-auditor.md"
            self.assertTrue(agent.is_file())
            self.assertIn("privilege_route_verdicts", agent.read_text(encoding="utf-8"))


class _FakeClient:
    def __init__(self) -> None:
        self.prompts = []

    def chat(self, messages, temperature=0.1):  # noqa: ANN001
        self.prompts.append(messages)
        return json.dumps({
            "privilege_route_verdicts": [{"route_id": "R-0001", "verdict": "vulnerable", "finding_ids": ["BFLA-R-0001-1"]}],
            "candidate_verdicts": [{"candidate_id": "M-0001", "verdict": "vulnerable", "finding_ids": ["MASS-M-0001-1"]}],
            "findings": [
                {"finding_id": "BFLA-R-0001-1", "category": "bfla", "subtype": "missing_role_check", "title": "t",
                 "location": {"file": "admin/a.php", "start_line": 1}, "severity": "high", "confidence": "high",
                 "recommendation": "r", "status": "unverified"},
                {"finding_id": "MASS-M-0001-1", "category": "mass_assignment", "subtype": "whole_object_binding", "title": "t",
                 "location": {"file": "admin/a.php", "start_line": 3}, "severity": "high", "confidence": "high",
                 "recommendation": "r", "status": "unverified"},
            ],
        })

    @staticmethod
    def extract_json(content: str):  # noqa: ANN205
        return json.loads(content)


class TestHeadlessRunner(unittest.TestCase):
    def test_phase_4c_writes_privilege_findings(self) -> None:
        from operate.ai.runner import HeadlessAIRunner

        with tempfile.TemporaryDirectory() as tmp:
            target, out = Path(tmp) / "repo", Path(tmp) / "out"
            (target / "admin").mkdir(parents=True)
            (target / "admin" / "a.php").write_text("<?php\nrequire 'auth.php';\nextract($_POST);\n", encoding="utf-8")
            write_json(out / "batches" / "privilege-001.json", {
                "batch_id": "privilege-001", "files": ["admin/a.php"], "knowledge_files": [],
                "routes": [_route("R-0001", "admin/a.php", True)], "mass_candidates": [_mass("M-0001", "admin/a.php")]})
            client = _FakeClient()
            HeadlessAIRunner(target, out, client).audit_privilege()
            doc = json.loads((out / "findings" / "priv-privilege-001.json").read_text(encoding="utf-8"))
            self.assertEqual([f["cwe"] for f in doc["findings"]], [["CWE-285"], ["CWE-915"]])
            self.assertEqual(doc["privilege_route_verdicts"][0]["route_id"], "R-0001")
            validate = load_validator("finding.schema.json")
            self.assertEqual([validate(f) for f in doc["findings"]], [[], []])
            system = client.prompts[0][0]["content"]
            self.assertIn("Privilege Auditor", system)
            self.assertIn("extract($_POST)", client.prompts[0][1]["content"])


class TestScoring(unittest.TestCase):
    def test_new_categories_scored_when_in_ground_truth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            truth = Path(tmp) / "gt.json"
            write_json(truth, {"items": [
                {"file": "admin/a.php", "line": 3, "category": "bfla", "vulnerable": True, "label": "BFLA"},
                {"file": "p.php", "line": 5, "category": "mass_assignment", "vulnerable": True, "label": "MASS"},
            ]})
            out = Path(tmp) / "out"
            write_json(out / "findings.json", {"findings": [
                {"finding_id": "BFLA-R-1-1", "category": "bfla", "status": "confirmed",
                 "location": {"file": "admin/a.php", "start_line": 3}, "evidence": []}]})
            res = subprocess.run([sys.executable, str(SCORE), str(truth), str(out)], capture_output=True, text=True)
            report = json.loads(res.stdout)
            self.assertEqual(report["per_category"]["bfla"]["recall"], 1.0)
            self.assertEqual(report["per_category"]["mass_assignment"]["recall"], 0.0)
            self.assertNotIn("bola", report["per_category"])


if __name__ == "__main__":
    unittest.main()
