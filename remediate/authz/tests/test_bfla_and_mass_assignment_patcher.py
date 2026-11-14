#!/usr/bin/env python3
"""Tests for BFLA & Mass Assignment patchers and remediation strategies (Issue #392)."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from operate.remediator.runner import RemediationRunner
from operate.remediator.strategies import StrategyRegistry
from remediate.authz.bfla_patcher import BFLARolePatcher
from remediate.authz.mass_assignment_patcher import MassAssignmentPatcher


class TestBFLARolePatcher(unittest.TestCase):
    """Verify fail-closed role guard injection across Node.js, Go, C#, and Java."""

    def setUp(self) -> None:
        self.patcher = BFLARolePatcher()
        self.temp_dir = Path(tempfile.mkdtemp(prefix="komagu_bfla_test_")).resolve()

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_nestjs_decorator_and_merge_import(self) -> None:
        ts_file = self.temp_dir / "admin.controller.ts"
        ts_file.write_text(
            "import { OwnershipGuard } from '@hoanghainh/komagu';\n\n"
            "export class AdminController {\n"
            "  @Post('users')\n"
            "  createUser() {\n"
            "    return {};\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )
        finding = {"finding_id": "BFLA-01", "category": "bfla", "endpoint": {"method": "POST", "path": "/admin/users"}}
        patched, res = self.patcher.patch_file(ts_file, 4, finding)
        self.assertTrue(res.changed)
        self.assertIn("import { OwnershipGuard, RequireRole, KomaguRoleGuard } from '@hoanghainh/komagu';", patched)
        self.assertIn("  @UseGuards(KomaguRoleGuard)\n  @RequireRole('admin')\n  @Post('users')", patched)

    def test_express_route_middleware_injection(self) -> None:
        js_file = self.temp_dir / "routes.js"
        js_file.write_text(
            "const express = require('express');\n"
            "app.post('/internal/rebuild', triggerRebuild);\n",
            encoding="utf-8",
        )
        finding = {"finding_id": "BFLA-02", "category": "bfla", "endpoint": {"method": "POST", "path": "/internal/rebuild"}}
        patched, res = self.patcher.patch_file(js_file, 2, finding)
        self.assertTrue(res.changed)
        self.assertIn("import { requireRole } from '@hoanghainh/komagu';", patched)
        self.assertIn("app.post('/internal/rebuild', requireRole('internal'), triggerRebuild);", patched)

    def test_go_mux_handlefunc_wrapping(self) -> None:
        go_file = self.temp_dir / "routes.go"
        go_file.write_text(
            'package main\n\nimport "net/http"\n\n'
            "func register(mux *http.ServeMux) {\n"
            '\tmux.HandleFunc("/admin/audit", handleAudit)\n'
            "}\n",
            encoding="utf-8",
        )
        finding = {"finding_id": "BFLA-03", "category": "bfla", "endpoint": {"method": "GET", "path": "/admin/audit"}}
        patched, res = self.patcher.patch_file(go_file, 6, finding)
        self.assertTrue(res.changed)
        self.assertIn('komaguauthz "github.com/hoanghainh1188/komagu/remediate/authz/golang"', patched)
        self.assertIn('mux.Handle("/admin/audit", komaguauthz.RequireRole([]string{"admin"})(http.HandlerFunc(handleAudit)))', patched)

    def test_csharp_and_spring_annotations(self) -> None:
        cs_file = self.temp_dir / "StaffController.cs"
        cs_file.write_text("public class StaffController {\n    public IActionResult List() => Ok();\n}\n", encoding="utf-8")
        finding = {"finding_id": "BFLA-04", "category": "bfla", "endpoint": {"method": "GET", "path": "/staff/list"}}
        patched_cs, res_cs = self.patcher.patch_file(cs_file, 2, finding)
        self.assertTrue(res_cs.changed)
        self.assertIn("using Komagu.Security.Authorization;", patched_cs)
        self.assertIn('    [RequireRole("staff")]\n    public IActionResult List()', patched_cs)

        java_file = self.temp_dir / "AdminController.java"
        java_file.write_text(
            "package com.example;\n\n@RestController\npublic class AdminController {\n"
            "    @GetMapping(\"/admin/metrics\")\n"
            "    public String metrics() { return \"ok\"; }\n"
            "}\n",
            encoding="utf-8",
        )
        patched_java, res_java = self.patcher.patch_file(java_file, 5, finding)
        self.assertTrue(res_java.changed)
        self.assertIn("import io.komagu.security.spring.RequireRole;", patched_java)
        self.assertIn('    @RequireRole("staff")\n    @GetMapping("/admin/metrics")', patched_java)

    def test_idempotent_when_guard_already_present(self) -> None:
        cs_file = self.temp_dir / "AdminController.cs"
        cs_file.write_text(
            'using Komagu.Security.Authorization;\n[RequireRole("admin")]\npublic IActionResult Delete() => Ok();\n',
            encoding="utf-8",
        )
        _, res = self.patcher.patch_file(cs_file, 3, {"category": "bfla"})
        self.assertFalse(res.changed)


class TestMassAssignmentPatcher(unittest.TestCase):
    """Verify allow-list rewrites for Mass Assignment findings."""

    def setUp(self) -> None:
        self.patcher = MassAssignmentPatcher()
        self.temp_dir = Path(tempfile.mkdtemp(prefix="komagu_mass_test_")).resolve()

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_refuses_without_explicit_allowed_fields(self) -> None:
        ts_file = self.temp_dir / "user.ts"
        ts_file.write_text("Object.assign(user, req.body);\n", encoding="utf-8")
        _, res = self.patcher.patch_file(ts_file, 1, {"category": "mass_assignment"})
        self.assertFalse(res.changed)
        self.assertIn("No allowed_fields", res.explanation)

    def test_typescript_req_body_wrapped_with_allow_fields(self) -> None:
        ts_file = self.temp_dir / "user.ts"
        ts_file.write_text("Object.assign(user, req.body);\n", encoding="utf-8")
        finding = {"category": "mass_assignment", "allowed_fields": ["name", "email"]}
        patched, res = self.patcher.patch_file(ts_file, 1, finding)
        self.assertTrue(res.changed)
        self.assertIn("import { allowFields } from '@hoanghainh/komagu';", patched)
        self.assertIn("Object.assign(user, allowFields(req.body, ['name', 'email']));", patched)

    def test_python_pydantic_model_dump_include(self) -> None:
        py_file = self.temp_dir / "routes.py"
        py_file.write_text("user.update(**payload.model_dump())\n", encoding="utf-8")
        finding = {"category": "mass_assignment", "allowed_fields": ["display_name", "bio"]}
        patched, res = self.patcher.patch_file(py_file, 1, finding)
        self.assertTrue(res.changed)
        self.assertEqual(patched, 'user.update(**payload.model_dump(include={"display_name", "bio"}))\n')

    def test_go_allow_fields_wrapping(self) -> None:
        go_file = self.temp_dir / "handler.go"
        go_file.write_text(
            'package main\n\nfunc update(repo Repo, id string, body map[string]any) {\n'
            "\trepo.Update(id, body)\n"
            "}\n",
            encoding="utf-8",
        )
        finding = {"category": "mass_assignment", "allowed_fields": ["name", "email"]}
        patched, res = self.patcher.patch_file(go_file, 4, finding)
        self.assertTrue(res.changed)
        self.assertIn('komaguauthz "github.com/hoanghainh1188/komagu/remediate/authz/golang"', patched)
        self.assertIn('repo.Update(id, komaguauthz.AllowFields(body, "name", "email"))', patched)


class TestStrategyRegistryAndRunner(unittest.TestCase):
    """Verify BFLA and Mass Assignment strategies integrate end-to-end with RemediationRunner."""

    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="komagu_strat_test_")).resolve()

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_registry_resolves_bfla_and_mass_assignment(self) -> None:
        registry = StrategyRegistry()
        self.assertEqual(registry.find_strategy({"category": "bfla"}).name, "bfla")
        self.assertEqual(registry.find_strategy({"category": "mass_assignment"}).name, "mass_assignment")

    def test_runner_dry_run_generates_diff_for_bfla_and_mass_assignment(self) -> None:
        app_file = self.temp_dir / "routes.js"
        app_file.write_text(
            "app.delete('/admin/users/:id', deleteUser);\n"
            "Object.assign(profile, req.body);\n",
            encoding="utf-8",
        )
        findings_path = self.temp_dir / "findings.json"
        findings_path.write_text(
            json.dumps(
                {
                    "findings": [
                        {
                            "finding_id": "BFLA-01",
                            "category": "bfla",
                            "cwe": "CWE-285",
                            "endpoint": {"method": "DELETE", "path": "/admin/users/{id}"},
                            "location": {"file": "routes.js", "start_line": 1},
                        },
                        {
                            "finding_id": "MASS-01",
                            "category": "mass_assignment",
                            "cwe": "CWE-915",
                            "allowed_fields": ["bio"],
                            "location": {"file": "routes.js", "start_line": 2},
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        runner = RemediationRunner(target_dir=self.temp_dir, findings_path=findings_path, dry_run=True)
        report = runner.run()
        self.assertEqual(report.planned_count, 2)
        combined_diff = "\n".join(p.diff for p in report.plans)
        self.assertIn("requireRole('admin')", combined_diff)
        self.assertIn("allowFields(req.body, ['bio'])", combined_diff)


if __name__ == "__main__":
    unittest.main()
