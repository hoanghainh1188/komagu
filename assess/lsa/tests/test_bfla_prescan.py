#!/usr/bin/env python3
"""Tests for Tier 1 BFLA hints (Issue #269, part a).

Validates privilege.py, which annotates route candidates with:
  privilege_hint, privilege_reasons, role_checks, bfla_signals, needs_bfla_audit_hint
Covers privileged-route detection (path, handler, sensitive writes), server-side
role checks per stack, method annotations above the handler, applied vs merely
defined file-level checks, role read from request input, and UI-only checks.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
KIT = HERE.parent
sys.path.insert(0, str(KIT / "scripts"))

from lsa_common import load_config  # noqa: E402
from privilege import annotate_privilege, is_privileged  # noqa: E402


def _route(rel: str, line: int, path: str, symbol: str = None, rid: str = "R-0001") -> dict:
    return {"route_id": rid, "stack": "x", "kind": "declared_route", "method": ["POST"], "path": path,
            "handler": {"file": rel, "line": line, "symbol": symbol}, "id_params": [], "guard_hints": [],
            "data_hints": [], "notes": ""}


class TestIsPrivileged(unittest.TestCase):
    def test_path_handler_and_symbol_tokens(self) -> None:
        cases = [
            ("/admin/users", "routes/x.js", None, True),
            ("/AdminPanel/Index", "Controllers/HomeController.cs", None, True),
            ("/users/{id}/roles", "UserController.java", None, True),
            ("/reports/export", "routes/r.js", None, True),
            ("/backoffice/orders", "a.php", None, True),
            ("/orders/{id}", "admin/orders.php", None, True),
            ("/orders/{id}", "OrderController.java", "impersonateUser", True),
            ("/orders/{id}", "OrderController.java", "show", False),
            ("/administrative-fees", "fees.php", None, True),
            ("/badminton/club", "club.php", None, False),
            ("/configurator/car", "car.php", None, False),
        ]
        for path, rel, symbol, want in cases:
            with self.subTest(path=path, rel=rel, symbol=symbol):
                ok, _ = is_privileged(path, rel, symbol, "")
                self.assertEqual(ok, want)

    def test_sensitive_write_makes_route_privileged(self) -> None:
        ok, reasons = is_privileged("/profile/save", "profile.php", None, "UPDATE users SET role = ? WHERE id = ?")
        self.assertTrue(ok)
        self.assertIn("write:users", reasons)
        self.assertFalse(is_privileged("/profile/view", "profile.php", None, "SELECT * FROM users WHERE id = ?")[0])


class _Annotate(unittest.TestCase):
    def annotate(self, rel: str, text: str, routes: list) -> list:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
        return annotate_privilege(routes, root, load_config(None))

    def signals(self, route: dict) -> list:
        return [s["signal"] for s in route["bfla_signals"]]


class TestAnnotate(_Annotate):
    def test_non_privileged_route_is_not_flagged(self) -> None:
        r = self.annotate("orders.php", "<?php\n$o = get_order((int)$_GET['id']);\n", [_route("orders.php", 1, "/orders.php")])[0]
        self.assertEqual(r["privilege_hint"], "unknown")
        self.assertFalse(r["needs_bfla_audit_hint"])
        self.assertEqual(r["bfla_signals"], [])

    def test_does_not_mutate_input(self) -> None:
        routes = [_route("admin/x.php", 1, "/admin/x.php")]
        self.annotate("admin/x.php", "<?php\nexit;\n", routes)
        self.assertNotIn("privilege_hint", routes[0])

    def test_server_side_role_checks_per_stack(self) -> None:
        cases = {
            "admin/a.php": "<?php\nif (!is_admin()) { exit; }\ndelete_all();\n",
            "admin/b.php": "<?php\nrequire_once '../inc/admin_check.php';\ndelete_all();\n",
            "Admin.java": "class A {\n  @RolesAllowed(\"ADMIN\")\n  @POST\n  public void purge() {}\n}\n",
            "AdminController.cs": "class A {\n  public void Purge() {\n    if (!User.IsInRole(\"Admin\")) return;\n  }\n}\n",
            "admin.py": "@app.route('/admin/purge')\n@roles_required('admin')\ndef purge():\n    pass\n",
            "admin_controller.rb": "class AdminController\n  def purge\n    authorize! :manage, User\n  end\nend\n",
        }
        for rel, text in cases.items():
            with self.subTest(rel=rel):
                line = next(i for i, ln in enumerate(text.splitlines(), 1) if "purge" in ln.lower() or "delete_all" in ln or "<?php" in ln)
                if rel.endswith(".php"):
                    line = 1
                r = self.annotate(rel, text, [_route(rel, line, "/admin/purge")])[0]
                self.assertTrue(r["role_checks"], r)
                self.assertFalse(r["needs_bfla_audit_hint"], r)

    def test_missing_role_check_on_privileged_route(self) -> None:
        r = self.annotate("admin/x.php", "<?php\nrequire 'auth.php';\ndelete_user((int)$_POST['id']);\n",
                          [_route("admin/x.php", 1, "/admin/x.php")])[0]
        self.assertEqual(r["privilege_hint"], "privileged")
        self.assertEqual(self.signals(r), ["no_role_check"])
        self.assertTrue(r["needs_bfla_audit_hint"])

    def test_annotation_above_handler_belongs_to_that_route(self) -> None:
        text = (
            "@RequestMapping(\"/admin\")\nclass A {\n"
            "  @RequestMapping(\"/a\")\n  public void a() { dao.delete(); }\n"
            "  @PreAuthorize(\"hasRole('ADMIN')\")\n  @RequestMapping(\"/b\")\n  public void b() { dao.delete(); }\n}\n"
        )
        routes = [_route("A.java", 3, "/admin/a", "a", "R-1"), _route("A.java", 6, "/admin/b", "b", "R-2")]
        a, b = self.annotate("A.java", text, routes)
        self.assertTrue(a["needs_bfla_audit_hint"])
        self.assertFalse(b["needs_bfla_audit_hint"])
        self.assertEqual(b["role_checks"][0]["line"], 5)

    def test_class_level_annotation_applies_to_all_routes(self) -> None:
        text = "[Authorize(Roles = \"Admin\")]\npublic class AdminController {\n  [HttpPost]\n  public void Purge() {}\n}\n"
        r = self.annotate("AdminController.cs", text, [_route("AdminController.cs", 4, "/Admin/Purge")])[0]
        self.assertFalse(r["needs_bfla_audit_hint"])
        self.assertEqual(r["role_checks"][0]["scope"], "file")

    def test_defined_but_unused_guard_does_not_protect(self) -> None:
        text = ("function requireAdmin(req, res, next) { if (req.user.role !== 'admin') return res.sendStatus(404); next(); }\n"
                "router.post('/admin/purge', function (req, res) { purge(); });\n")
        r = self.annotate("admin.js", text, [_route("admin.js", 2, "/admin/purge")])[0]
        self.assertTrue(r["needs_bfla_audit_hint"])

    def test_router_level_guard_applies(self) -> None:
        text = "router.use(requireAdmin);\nrouter.post('/admin/purge', function (req, res) { purge(); });\n"
        r = self.annotate("admin.js", text, [_route("admin.js", 2, "/admin/purge")])[0]
        self.assertFalse(r["needs_bfla_audit_hint"])

    def test_role_from_request_is_flagged_even_when_not_privileged(self) -> None:
        text = "<?php\nif ($_POST['is_admin'] == '1') { grant(); }\n"
        r = self.annotate("profile.php", text, [_route("profile.php", 1, "/profile.php")])[0]
        self.assertIn("role_from_request", self.signals(r))
        self.assertEqual(r["role_checks"], [])
        self.assertTrue(r["needs_bfla_audit_hint"])

    def test_role_from_request_per_stack(self) -> None:
        lines = [
            "if (req.body.role === 'admin') {}",
            "String r = request.getParameter(\"role\");",
            "if (Request.Form[\"isAdmin\"] == \"1\") {}",
            "if request.args.get('is_admin'):",
            "if params[:admin]",
            "<cfif form.isAdmin>",
        ]
        for ln in lines:
            with self.subTest(line=ln):
                r = self.annotate("h.txt", ln + "\n", [_route("h.txt", 1, "/x")])[0]
                self.assertIn("role_from_request", self.signals(r))

    def test_ui_only_role_check(self) -> None:
        text = ("<?php\nif ($_SERVER['REQUEST_METHOD'] === 'POST') { delete_user((int)$_POST['id']); }\n?>\n"
                "<?php if ($_SESSION['role'] == 'admin'): ?><a href=\"/x\">Delete</a><?php endif; ?>\n")
        r = self.annotate("manage_users.php", text, [_route("manage_users.php", 1, "/manage_users.php")])[0]
        self.assertEqual(self.signals(r), ["client_side_role_check"])
        self.assertTrue(r["needs_bfla_audit_hint"])

    def test_unreadable_handler_file_is_tolerated(self) -> None:
        r = self.annotate("x.php", "<?php\n", [_route("missing.php", 1, "/admin/x")])[0]
        self.assertEqual(r["privilege_hint"], "privileged")
        self.assertTrue(r["needs_bfla_audit_hint"])


if __name__ == "__main__":
    unittest.main()
