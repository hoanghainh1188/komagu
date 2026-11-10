#!/usr/bin/env python3
"""Regression tests for #372: `komagu fix` on Java legacy code and non-UTF-8 sources."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from operate.remediator.models import RemediationPlan
from operate.remediator.runner import RemediationRunner
from remediate.authz.patcher import BOLAOwnershipPatcher

SHIM = "remediate/legacy_shims/java/OwnershipEnforcer.java"
GUARD_IMPORT = "import io.komagu.security.spring.RequireOwnership;"
BOOT3_POM = """<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.1</version>
  </parent>
</project>
"""
BOOT2_POM = BOOT3_POM.replace("3.2.1", "2.7.18")
MVC_POM = """<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-webmvc</artifactId>
      <version>4.3.30.RELEASE</version>
    </dependency>
  </dependencies>
</project>
"""
STRUTS_ACTION = (
    "package com.acme.web;\n"
    "\n"
    "public class ViewAction extends Action {\n"
    "    public ActionForward execute(ActionMapping m, ActionForm f, HttpServletRequest req, HttpServletResponse res) {\n"
    '        req.setAttribute("order", dao.find(req.getParameter("id")));\n'
    '        return m.findForward("ok");\n'
    "    }\n"
    "}\n"
)
SERVLET = (
    "public class OrderServlet extends HttpServlet {\n"
    "    protected void doGet(HttpServletRequest req, HttpServletResponse res) {\n"
    '        write(res, dao.find(req.getParameter("id")));\n'
    "    }\n"
    "}\n"
)
SPRING_CONTROLLER = (
    "package com.acme.web;\n"
    "\n"
    "@RestController\n"
    "public class OrderController {\n"
    '    @GetMapping("/orders/{id}")\n'
    "    public Order getOrder(@PathVariable Long id) {\n"
    "        return repository.findById(id).orElseThrow();\n"
    "    }\n"
    "\n"
    '    @DeleteMapping("/orders/{id}")\n'
    "    public Order deleteOrder(@PathVariable Long id) {\n"
    "        return repository.deleteById(id);\n"
    "    }\n"
    "}\n"
)
ORDER_ENDPOINT = {"method": "GET", "path": "/orders/{id}"}


def _finding(fid: str, file: str, line: int, endpoint: Optional[Dict[str, str]] = None) -> dict:
    return {
        "finding_id": fid,
        "category": "bola",
        "title": fid,
        "severity": "high",
        "location": {"file": file, "start_line": line, "end_line": line},
        "endpoint": endpoint or ORDER_ENDPOINT,
    }


class JavaFixTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="komagu_java_fix_")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def write(self, rel: str, data: bytes) -> Path:
        path = self.tmp / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def run_fix(self, findings: List[dict], dry_run: bool = False) -> List[RemediationPlan]:
        findings_file = self.tmp / "findings.json"
        findings_file.write_text(json.dumps({"findings": findings}), encoding="utf-8")
        return RemediationRunner(self.tmp, findings_file, dry_run=dry_run).run().plans

    def assert_manual_with_shim(self, plan: RemediationPlan) -> None:
        self.assertEqual(plan.status, "needs manual fix", plan.reason)
        self.assertIn(SHIM, plan.reason)
        self.assertEqual(plan.diff, "")


class TestNotSpringBoot3GoesToManualFix(JavaFixTestCase):
    def assert_untouched_manual(self, source: str, line: int, endpoint: Optional[Dict[str, str]] = None) -> None:
        data = source.encode("utf-8")
        path = self.write("src/Target.java", data)
        plans = self.run_fix([_finding("BOLA-1", "src/Target.java", line, endpoint)])
        self.assert_manual_with_shim(plans[0])
        self.assertEqual(path.read_bytes(), data)

    def test_struts_action(self) -> None:
        self.assert_untouched_manual(STRUTS_ACTION, 4, {"method": "GET", "path": "/order/View.do"})

    def test_struts_action_inside_a_spring_boot_3_build(self) -> None:
        self.write("pom.xml", BOOT3_POM.encode("utf-8"))
        self.assert_untouched_manual(STRUTS_ACTION, 4, {"method": "GET", "path": "/order/View.do"})

    def test_servlet(self) -> None:
        self.assert_untouched_manual(SERVLET, 2)

    def test_controller_without_a_build_file(self) -> None:
        self.assert_untouched_manual(SPRING_CONTROLLER, 5)

    def test_controller_on_spring_boot_2(self) -> None:
        self.write("pom.xml", BOOT2_POM.encode("utf-8"))
        self.assert_untouched_manual(SPRING_CONTROLLER, 5)

    def test_controller_on_plain_spring_mvc(self) -> None:
        self.write("pom.xml", MVC_POM.encode("utf-8"))
        self.assert_untouched_manual(SPRING_CONTROLLER, 5)

    def test_spring_boot_3_commented_out_in_pom_does_not_count(self) -> None:
        self.write("pom.xml", f"<!-- migration attempt: {BOOT3_POM} -->\n{MVC_POM}".encode("utf-8"))
        self.assert_untouched_manual(SPRING_CONTROLLER, 5)


class TestSpringBoot3ControllerStillPatched(JavaFixTestCase):
    def assert_planned_on_handler(self) -> RemediationPlan:
        self.write("src/OrderController.java", SPRING_CONTROLLER.encode("utf-8"))
        plan = self.run_fix([_finding("BOLA-1", "src/OrderController.java", 5)], dry_run=True)[0]
        self.assertEqual(plan.status, "planned", plan.reason)
        return plan

    def test_guard_uses_the_real_annotation_package(self) -> None:
        self.write("pom.xml", BOOT3_POM.encode("utf-8"))
        plan = self.assert_planned_on_handler()
        self.assertIn(GUARD_IMPORT, plan.patched_content)
        self.assertIn("import io.komagu.security.authorization.ResourceOperation;", plan.patched_content)
        self.assertIn("@RequireOwnership(entityClass = Order.class, operation = ResourceOperation.READ)", plan.patched_content)

    def test_version_from_parent_pom_of_a_multi_module_build(self) -> None:
        self.write("pom.xml", BOOT3_POM.encode("utf-8"))
        self.write("web/pom.xml", b"<project><artifactId>web</artifactId></project>\n")
        self.write("web/src/OrderController.java", SPRING_CONTROLLER.encode("utf-8"))
        plan = self.run_fix([_finding("BOLA-1", "web/src/OrderController.java", 5)], dry_run=True)[0]
        self.assertEqual(plan.status, "planned", plan.reason)

    def test_version_from_gradle_plugin(self) -> None:
        self.write("build.gradle.kts", b'plugins {\n    id("org.springframework.boot") version "3.3.0"\n}\n')
        self.assert_planned_on_handler()

    def test_version_from_gradle_properties(self) -> None:
        self.write("build.gradle", b"plugins { id 'org.springframework.boot' version \"$springBootVersion\" }\n")
        self.write("gradle.properties", b"springBootVersion=3.1.5\n")
        self.assert_planned_on_handler()

    def test_version_from_maven_property(self) -> None:
        self.write("pom.xml", b"<project><properties><spring-boot.version>3.4.0</spring-boot.version></properties></project>\n")
        self.assert_planned_on_handler()

    def test_finding_on_the_method_declaration(self) -> None:
        self.write("pom.xml", BOOT3_POM.encode("utf-8"))
        self.write("src/OrderController.java", SPRING_CONTROLLER.encode("utf-8"))
        plan = self.run_fix([_finding("BOLA-1", "src/OrderController.java", 6)], dry_run=True)[0]
        self.assertEqual(plan.status, "planned", plan.reason)

    def test_finding_inside_the_method_body_is_manual(self) -> None:
        self.write("pom.xml", BOOT3_POM.encode("utf-8"))
        self.write("src/OrderController.java", SPRING_CONTROLLER.encode("utf-8"))
        plan = self.run_fix([_finding("BOLA-1", "src/OrderController.java", 7)], dry_run=True)[0]
        self.assert_manual_with_shim(plan)

    def test_class_level_mapping_is_manual(self) -> None:
        self.write("pom.xml", BOOT3_POM.encode("utf-8"))
        source = (
            "@RestController\n"
            '@RequestMapping("/orders")\n'
            "public class OrderController {\n"
            '    @GetMapping("/{id}")\n'
            "    public Order get(@PathVariable Long id) { return repository.find(id); }\n"
            "}\n"
        )
        self.write("src/OrderController.java", source.encode("utf-8"))
        plan = self.run_fix([_finding("BOLA-1", "src/OrderController.java", 2)], dry_run=True)[0]
        self.assert_manual_with_shim(plan)

    def test_entity_that_would_not_compile_is_manual(self) -> None:
        self.write("pom.xml", BOOT3_POM.encode("utf-8"))
        self.write("src/OrderController.java", SPRING_CONTROLLER.encode("utf-8"))
        plan = self.run_fix(
            [_finding("BOLA-1", "src/OrderController.java", 5, {"method": "GET", "path": "/order/View.do"})],
            dry_run=True,
        )[0]
        self.assert_manual_with_shim(plan)
        self.assertNotIn("View.do.class", plan.patched_content)

    def test_entity_not_referenced_in_the_file_is_manual(self) -> None:
        self.write("pom.xml", BOOT3_POM.encode("utf-8"))
        self.write("src/OrderController.java", SPRING_CONTROLLER.encode("utf-8"))
        plan = self.run_fix(
            [_finding("BOLA-1", "src/OrderController.java", 5, {"method": "GET", "path": "/invoices/{id}"})],
            dry_run=True,
        )[0]
        self.assert_manual_with_shim(plan)

    def assert_entity_rejected(self, source: str, line: int, path: str) -> None:
        self.write("pom.xml", BOOT3_POM.encode("utf-8"))
        self.write("src/Thing.java", source.encode("utf-8"))
        plan = self.run_fix([_finding("BOLA-1", "src/Thing.java", line, {"method": "GET", "path": path})], dry_run=True)[0]
        self.assert_manual_with_shim(plan)

    def test_controller_class_is_not_accepted_as_the_entity(self) -> None:
        source = '@RestController\npublic class Thing {\n    @GetMapping("/{id}")\n    public Object get(@PathVariable Long id) {\n        return null;\n    }\n}\n'
        self.assert_entity_rejected(source, 3, "/{id}")

    def test_entity_mentioned_only_in_a_string_or_comment_is_rejected(self) -> None:
        source = '// Order lookup\n@RestController\npublic class Thing {\n    @GetMapping("/orders/{id}")\n    public Object get(@PathVariable Long id) {\n        throw new RuntimeException("Order not found");\n    }\n}\n'
        self.assert_entity_rejected(source, 4, "/orders/{id}")

    def test_two_findings_in_one_file_are_both_applied_on_their_own_handlers(self) -> None:
        self.write("pom.xml", BOOT3_POM.encode("utf-8"))
        path = self.write("src/OrderController.java", SPRING_CONTROLLER.encode("utf-8"))
        plans = self.run_fix(
            [
                _finding("BOLA-1", "src/OrderController.java", 5),
                _finding("BOLA-2", "src/OrderController.java", 10, {"method": "DELETE", "path": "/orders/{id}"}),
            ]
        )
        self.assertEqual([p.status for p in plans], ["applied", "applied"], [p.reason for p in plans])
        lines = path.read_text(encoding="utf-8").splitlines()
        read_guard = lines.index('    @GetMapping("/orders/{id}")') - 1
        delete_guard = lines.index('    @DeleteMapping("/orders/{id}")') - 1
        self.assertIn("ResourceOperation.READ", lines[read_guard])
        self.assertIn("ResourceOperation.DELETE", lines[delete_guard])
        self.assertEqual(sum(line == GUARD_IMPORT for line in lines), 1)


class TestEncodingAndNewlinesPreserved(JavaFixTestCase):
    COMMENT = "    // 注文を取得する\r\n"

    def sjis_controller(self) -> bytes:
        source = SPRING_CONTROLLER.replace("\n", "\r\n").replace(
            '    @GetMapping("/orders/{id}")', self.COMMENT + '    @GetMapping("/orders/{id}")'
        )
        return source.encode("cp932")

    def test_shift_jis_crlf_file_keeps_every_original_byte(self) -> None:
        self.write("pom.xml", BOOT3_POM.encode("utf-8"))
        original = self.sjis_controller()
        path = self.write("src/OrderController.java", original)

        plan = self.run_fix([_finding("BOLA-1", "src/OrderController.java", 6)])[0]

        self.assertEqual(plan.status, "applied", plan.reason)
        patched = path.read_bytes()
        self.assertIn(self.COMMENT.encode("cp932"), patched)
        self.assertNotIn(b"\xef\xbf\xbd", patched)
        self.assertEqual(patched.count(b"\n"), patched.count(b"\r\n"))
        remaining = patched.split(b"\r\n")
        for line in (
            b"import io.komagu.security.spring.RequireOwnership;",
            b"import io.komagu.security.authorization.ResourceOperation;",
            b"",
            b"    @RequireOwnership(entityClass = Order.class, operation = ResourceOperation.READ)",
        ):
            remaining.remove(line)
        self.assertEqual(remaining, original.split(b"\r\n"))

    def test_diff_only_adds_lines(self) -> None:
        self.write("pom.xml", BOOT3_POM.encode("utf-8"))
        self.write("src/OrderController.java", self.sjis_controller())

        plan = self.run_fix([_finding("BOLA-1", "src/OrderController.java", 6)], dry_run=True)[0]

        self.assertEqual(plan.status, "planned", plan.reason)
        body = plan.diff.split("\n")[2:]
        self.assertEqual([line for line in body if line.startswith("-")], [])
        self.assertIn("注文を取得する", plan.patched_content)
        self.assertEqual(plan.patched_content.count("\n"), plan.patched_content.count("\r\n"))

    def test_shift_jis_struts_action_is_manual_and_untouched(self) -> None:
        original = STRUTS_ACTION.replace("\n", "\r\n").replace("public class", "// 注文\r\npublic class", 1).encode("cp932")
        path = self.write("src/ViewAction.java", original)
        plan = self.run_fix([_finding("BOLA-1", "src/ViewAction.java", 5)])[0]
        self.assert_manual_with_shim(plan)
        self.assertEqual(path.read_bytes(), original)

    def test_crlf_csharp_patch_stays_crlf(self) -> None:
        source = "namespace Web;\r\npublic class C {\r\n    [HttpGet]\r\n    public Order Get(Guid id) { return null; }\r\n}\r\n"
        path = self.write("C.cs", source.encode("utf-8"))
        plan = self.run_fix([_finding("BOLA-1", "C.cs", 3)])[0]
        self.assertEqual(plan.status, "applied", plan.reason)
        patched = path.read_bytes()
        self.assertEqual(patched.count(b"\n"), patched.count(b"\r\n"))

    def test_import_goes_after_the_package_statement_not_into_a_license_comment(self) -> None:
        self.write("pom.xml", BOOT3_POM.encode("utf-8"))
        source = "/* Terms: see LICENSE;\n * package names are ours;\n */\n" + SPRING_CONTROLLER
        self.write("src/OrderController.java", source.encode("utf-8"))
        plan = self.run_fix([_finding("BOLA-1", "src/OrderController.java", 8)], dry_run=True)[0]
        self.assertEqual(plan.status, "planned", plan.reason)
        self.assertLess(plan.patched_content.index("package com.acme.web;"), plan.patched_content.index(GUARD_IMPORT))
        self.assertLess(plan.patched_content.index("*/"), plan.patched_content.index(GUARD_IMPORT))

    def test_direct_call_refuses_to_replace_undecodable_bytes(self) -> None:
        path = self.write("Dao.java", self.sjis_controller())
        with self.assertRaises(UnicodeDecodeError):
            BOLAOwnershipPatcher().patch_file(path, 6, _finding("BOLA-1", "Dao.java", 6))


if __name__ == "__main__":
    unittest.main()
