#!/usr/bin/env python3
"""Automated verification tests for BOLA Ownership Guard Patcher (Issue #188)."""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from remediate.authz.patcher import BOLAOwnershipPatcher, BOLARewriteResult


class TestBOLAOwnershipPatcher(unittest.TestCase):
    """Test suite verifying automated BOLA ownership guard injection across languages."""

    def setUp(self) -> None:
        self.patcher = BOLAOwnershipPatcher()
        self.temp_dir = tempfile.mkdtemp(prefix="komainu_bola_patch_test_")
        self.test_dir = Path(self.temp_dir).resolve()

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_detect_language(self) -> None:
        """Languages must be correctly identified from file extensions."""
        self.assertEqual(self.patcher.detect_language("controller.ts"), "typescript")
        self.assertEqual(self.patcher.detect_language("OrderController.cs"), "csharp")
        self.assertEqual(self.patcher.detect_language("OrderResource.java"), "java")
        self.assertEqual(self.patcher.detect_language("api.py"), "python")
        self.assertEqual(self.patcher.detect_language("routes.php"), "php")
        self.assertEqual(self.patcher.detect_language("unknown.foo"), "generic")

    def test_infer_operation_and_resource(self) -> None:
        """HTTP method and path must accurately infer operation and resource domain name."""
        finding_get = {
            "endpoint": {"method": "GET", "path": "/api/v1/orders/{id}"},
        }
        self.assertEqual(self.patcher.infer_operation(finding_get), "READ")
        self.assertEqual(self.patcher.infer_resource_name("order_controller.ts", finding_get), "Order")

        finding_del = {
            "endpoint": {"method": "DELETE", "path": "/api/v1/users/{id}"},
        }
        self.assertEqual(self.patcher.infer_operation(finding_del), "DELETE")
        self.assertEqual(self.patcher.infer_resource_name("user_service.py", finding_del), "User")

        finding_put = {
            "endpoint": {"method": "PUT", "path": "/api/v1/invoices/{id}"},
        }
        self.assertEqual(self.patcher.infer_operation(finding_put), "UPDATE")

    def test_patch_typescript_nestjs_controller(self) -> None:
        """TypeScript NestJS controller method must receive @UseGuards and @RequireOwnership."""
        controller_file = self.test_dir / "order.controller.ts"
        controller_file.write_text(
            "export class OrderController {\n"
            "    @Get(':id')\n"
            "    async getOrder(@Param('id') id: string) {\n"
            "        return this.orderService.find(id);\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )

        finding = {
            "finding_id": "BOLA-ORD-01",
            "category": "bola",
            "endpoint": {"method": "GET", "path": "/orders/{id}"},
        }

        patched_content, res = self.patcher.patch_file(controller_file, 2, finding)
        self.assertTrue(res.changed)
        self.assertIn("import { RequireOwnership, OwnershipGuard, ResourceOperation } from 'komainu-guard';", patched_content)
        self.assertIn("@UseGuards(OwnershipGuard)", patched_content)
        self.assertIn("@RequireOwnership(ResourceOperation.READ, { idParamName: 'id' })", patched_content)

    def test_patch_csharp_controller(self) -> None:
        """C# ASP.NET Core controller action must receive [RequireOwnership] attribute and using import."""
        controller_file = self.test_dir / "OrderController.cs"
        controller_file.write_text(
            "namespace Web.Controllers;\n\n"
            "public class OrderController : ControllerBase {\n"
            "    [HttpGet(\"{id}\")]\n"
            "    public async Task<IActionResult> GetOrder(Guid id) {\n"
            "        return Ok(await _orders.Find(id));\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )

        finding = {
            "finding_id": "BOLA-CS-01",
            "category": "bola",
            "endpoint": {"method": "GET", "path": "/api/orders/{id}"},
        }

        patched_content, res = self.patcher.patch_file(controller_file, 4, finding)
        self.assertTrue(res.changed)
        self.assertIn("using Komagu.Security.Authorization;", patched_content)
        self.assertIn("[RequireOwnership(typeof(Order), idRouteParameter: \"id\", operation: ResourceOperation.Read)]", patched_content)

    def test_patch_spring_boot_controller(self) -> None:
        """Spring Boot controller method must receive @RequireOwnership annotation and import."""
        controller_file = self.test_dir / "OrderController.java"
        controller_file.write_text(
            "package com.example.demo;\n\n"
            "@RestController\n"
            "public class OrderController {\n"
            "    @GetMapping(\"/{id}\")\n"
            "    public Order getOrder(@PathVariable UUID id) {\n"
            "        return repository.findById(id).orElseThrow();\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )

        finding = {
            "finding_id": "BOLA-JAVA-01",
            "category": "bola",
            "endpoint": {"method": "GET", "path": "/api/orders/{id}"},
        }

        patched_content, res = self.patcher.patch_file(controller_file, 5, finding)
        self.assertTrue(res.changed)
        self.assertIn("import io.komainu.security.authorization.RequireOwnership;", patched_content)
        self.assertIn("@RequireOwnership(entityClass = Order.class, operation = ResourceOperation.READ)", patched_content)

    def test_patch_python_fastapi(self) -> None:
        """FastAPI route handler must receive @RequireOwnership decorator and import."""
        py_file = self.test_dir / "order_api.py"
        py_file.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n\n"
            "@app.get('/api/orders/{id}')\n"
            "def get_order(id: str):\n"
            "    return db.find(id)\n",
            encoding="utf-8",
        )

        finding = {
            "finding_id": "BOLA-PY-01",
            "category": "bola",
            "endpoint": {"method": "GET", "path": "/api/orders/{id}"},
        }

        patched_content, res = self.patcher.patch_file(py_file, 4, finding)
        self.assertTrue(res.changed)
        self.assertIn("from remediate.authz.python.komainu_authz import RequireOwnership, ResourceOperation", patched_content)
        self.assertIn("@RequireOwnership(operation=ResourceOperation.READ, id_param=\"id\")", patched_content)

    def test_skip_already_patched_file(self) -> None:
        """If file already contains ownership guards, patcher must skip to prevent duplicates."""
        controller_file = self.test_dir / "protected_order.ts"
        controller_file.write_text(
            "import { RequireOwnership } from 'komainu-guard';\n"
            "export class OrderController {\n"
            "    @UseGuards(OwnershipGuard)\n"
            "    @RequireOwnership(ResourceOperation.READ)\n"
            "    @Get(':id')\n"
            "    async getOrder(@Param('id') id: string) {}\n"
            "}\n",
            encoding="utf-8",
        )

        finding = {"finding_id": "BOLA-02", "category": "bola"}
        _, res = self.patcher.patch_file(controller_file, 5, finding)
        self.assertFalse(res.changed)
        self.assertIn("already present", res.explanation)


    def test_express_route_is_manual_not_comment(self) -> None:
        """Express routes used to get only a `// [KOMAINU-FIX]` comment reported as a fix (#216)."""
        route_file = self.test_dir / "routes.js"
        original = (
            "const express = require('express');\n"
            "router.get('/orders/:id', async (req, res) => {\n"
            "    res.json(await Order.findById(req.params.id));\n"
            "});\n"
        )
        route_file.write_text(original, encoding="utf-8")
        finding = {"finding_id": "BOLA-EXP-01", "category": "bola", "endpoint": {"method": "GET", "path": "/orders/:id"}}

        patched_content, res = self.patcher.patch_file(route_file, 2, finding)
        self.assertFalse(res.changed)
        self.assertEqual(patched_content, original)
        self.assertNotIn("KOMAINU-FIX", patched_content)

if __name__ == "__main__":
    unittest.main()
