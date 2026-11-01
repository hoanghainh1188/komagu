#!/usr/bin/env python3
"""Privilege work after route mapping, verification of privilege findings, modern BFLA hints (Issue #331)."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

from lsa_common import load_config, read_json, write_json  # noqa: E402
from make_privilege_batches import make_privilege_batches  # noqa: E402
from privilege import annotate_privilege  # noqa: E402


def _mapped(rid: str, rel: str, bfla: bool) -> dict:
    return {"route_id": rid, "method": ["POST"], "path": "/api/" + rid.lower(),
            "handler": {"file": rel, "line": 3, "symbol": "POST"}, "id_inputs": [], "guards": [], "data_ops": [],
            "needs_bola_audit": False, "needs_bfla_audit": bfla, "privilege": "privileged" if bfla else "user", "notes": ""}


def _finding(fid: str, rel: str, category: str) -> dict:
    return {"id": fid, "category": category, "severity": "high", "location": {"file": rel, "start_line": 3}}


class TestMakePrivilegeBatches(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name)
        self.config = load_config(None)
        write_json(self.out / "stack-profile.json", {"stacks": [{"id": "node-nextjs"}],
                                                     "knowledge_files": ["knowledge/stacks/nextjs.md"]})
        write_json(self.out / "routes.json", {"routes": [
            _mapped("R-0001", "src/app/api/a/route.ts", True),
            _mapped("R-0002", "src/app/api/b/route.ts", True),
            _mapped("R-0003", "src/app/api/c/route.ts", True),
            _mapped("R-0004", "src/app/api/d/route.ts", False),
            _mapped("R-0005", "src/app/api/e/route.ts", True),
        ]})
        write_json(self.out / "batches" / "privilege-001.json",
                   {"batch_id": "privilege-001", "files": [], "routes": [{"route_id": "R-0001"}], "mass_candidates": []})
        (self.out / "findings").mkdir()
        write_json(self.out / "findings" / "priv-privilege-001.json",
                   {"batch_id": "privilege-001", "privilege_route_verdicts": [{"route_id": "R-0005", "verdict": "safe"}]})

    def test_new_batch_for_uncovered_routes_only(self) -> None:
        self.assertEqual(make_privilege_batches(self.out, self.config), ["privilege-002"])
        b = read_json(self.out / "batches" / "privilege-002.json")
        self.assertEqual([r["route_id"] for r in b["routes"]], ["R-0002", "R-0003"])
        self.assertEqual(b["files"], ["src/app/api/b/route.ts", "src/app/api/c/route.ts"])
        self.assertIn("knowledge/bfla-patterns.md", b["knowledge_files"])
        self.assertIn("knowledge/stacks/nextjs.md", b["knowledge_files"])
        self.assertEqual(b["mass_candidates"], [])

    def test_second_run_writes_nothing(self) -> None:
        make_privilege_batches(self.out, self.config)
        self.assertEqual(make_privilege_batches(self.out, self.config), [])
        self.assertFalse((self.out / "batches" / "privilege-003.json").exists())

    def test_batch_size_limit(self) -> None:
        cfg = load_config(None)
        cfg["batch"]["max_privilege_items"] = 1
        self.assertEqual(make_privilege_batches(self.out, cfg), ["privilege-002", "privilege-003"])

    def test_no_routes_json(self) -> None:
        (self.out / "routes.json").unlink()
        self.assertEqual(make_privilege_batches(self.out, self.config), [])


class TestVerifyBatchesIncludePrivilege(unittest.TestCase):
    def test_priv_findings_are_batched_with_stack_knowledge(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            write_json(out / "findings" / "bola-routes-001.json",
                       {"findings": [_finding("F-1", "src/app/api/x/route.ts", "bola")]})
            write_json(out / "findings" / "priv-privilege-001.json",
                       {"findings": [_finding("F-2", "src/app/api/users/route.ts", "bfla")]})
            res = subprocess.run([sys.executable, str(SCRIPTS / "make_verify_batches.py"), str(out)],
                                 capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            b = read_json(out / "batches" / "verify-001.json")
            self.assertEqual(sorted(f["id"] for f in b["findings"]), ["F-1", "F-2"])
            self.assertIn("knowledge/stacks/node-python-ruby.md", b["knowledge_files"])


class TestModernRoleChecks(unittest.TestCase):
    def _annotate(self, rel: str, code: str, path: str, line: int = 2) -> dict:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(code, encoding="utf-8")
            route = {"route_id": "R-0001", "path": path, "method": ["GET"],
                     "handler": {"file": rel, "line": line, "symbol": "GET"}}
            return annotate_privilege([route], root, load_config(None))[0]

    def test_permission_option_is_a_role_check(self) -> None:
        r = self._annotate("src/app/api/activity/export/route.ts",
                           'import { withAuth } from "@/lib/auth/guard";\n'
                           "export const GET = withAuth(\n"
                           "  async () => exportCsv(),\n"
                           '  { permission: "activity.view" },\n'
                           ");\n", "/api/activity/export")
        self.assertEqual(r["privilege_hint"], "privileged")
        self.assertTrue(r["role_checks"])
        self.assertFalse(any(s["signal"] == "no_role_check" for s in r["bfla_signals"]))

    def test_can_call_is_a_role_check(self) -> None:
        r = self._annotate("src/app/api/export/route.ts",
                           "export async function GET() {\n"
                           '  if (!can(actor, "activity.view")) return forbidden();\n'
                           "}\n", "/api/export", line=1)
        self.assertTrue(r["role_checks"])

    def test_orm_write_to_users_is_privileged(self) -> None:
        r = self._annotate("src/app/api/x/route.ts",
                           "export async function PATCH(req) {\n"
                           "  await db.update(users).set({ role: body.role }).where(eq(users.id, id));\n"
                           "}\n", "/api/x", line=1)
        self.assertEqual(r["privilege_hint"], "privileged")
        self.assertIn("write:users", r["privilege_reasons"])
        self.assertTrue(any(s["signal"] == "no_role_check" for s in r["bfla_signals"]))

    def test_prisma_write_to_role_is_privileged(self) -> None:
        r = self._annotate("api/role.js",
                           "async function handler(req, res) {\n"
                           "  await prisma.role.update({ where: { id }, data });\n"
                           "}\n", "/api/x", line=1)
        self.assertIn("write:role", r["privilege_reasons"])


if __name__ == "__main__":
    unittest.main()
