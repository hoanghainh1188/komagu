#!/usr/bin/env python3
"""Tests for PR diff mode (Issue #270, part c).

Validates:
1. git_changed_files: committed, uncommitted and untracked changes since the
   merge base, relative to the target; clear errors for bad refs / non-git dirs.
2. select_files: changed in-scope files plus files that reference them
   (include/require by file name, class names, module imports), deleted files.
3. iter_source_files honors scope.only_files without touching the cache hash.
4. run_prescan.py --diff limits candidates to the selected files, writes
   diff-scope.json and reuses the content-hash cache.
5. Baseline comparison never marks entries outside the diff scope as fixed.
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
sys.path.insert(0, str(KIT / "scripts"))

from baseline import compare, update_baseline  # noqa: E402
from changed_files import ChangedFilesError, git_changed_files, select_files  # noqa: E402
from lsa_common import iter_source_files, load_config  # noqa: E402
from scan_cache import compute_config_hash  # noqa: E402

RUN_PRESCAN = KIT / "scripts" / "run_prescan.py"
GIT = ["git", "-c", "user.name=komagu-test", "-c", "user.email=test@komagu.invalid", "-c", "init.defaultBranch=main"]

FILES = {
    "orders.php": "<?php\ninclude 'inc/db.php';\n$id = $_GET['id'];\n$r = mysql_query(\"SELECT * FROM orders WHERE id=\" . $id);\n",
    "profile.php": "<?php\n$uid = $_GET['user_id'];\n$r = mysql_query(\"SELECT * FROM users WHERE id=\" . $uid);\n",
    "inc/db.php": "<?php\nfunction db() { return 1; }\n",
    "search.php": "<?php\n$q = $_GET['q'];\n$r = mysql_query(\"SELECT * FROM items WHERE name LIKE '%\" . $q . \"%'\");\n",
    "vendor/lib.php": "<?php\ninclude 'inc/db.php';\n",
    "web/WEB-INF/web.xml": "<web-app><servlet><servlet-class>com.acme.OrderServlet</servlet-class></servlet></web-app>\n",
    "src/com/acme/OrderServlet.java": "package com.acme;\npublic class OrderServlet {}\n",
    "src/com/acme/Billing.java": "package com.acme;\npublic class Billing { OrderServlet s; }\n",
    "app/orders.js": "module.exports = {};\n",
    "app/server.js": "const orders = require('./orders');\n",
    "app/ordersHelper.js": "const x = 'not an import of orders';\n",
    "py/models.py": "class Order: pass\n",
    "py/views.py": "from app.models import Order\n",
}


def git(repo: Path, *args: str) -> str:
    return subprocess.run([*GIT, "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


class _RepoMixin:
    def make_repo(self) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)  # type: ignore[attr-defined]
        repo = Path(tmp.name) / "repo"
        for rel, text in FILES.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(text, encoding="utf-8")
        git(repo, "init", "-q")
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "base")
        git(repo, "switch", "-q", "-c", "feature")
        return repo


class TestGitChangedFiles(_RepoMixin, unittest.TestCase):
    def test_committed_uncommitted_and_untracked(self) -> None:
        repo = self.make_repo()
        (repo / "orders.php").write_text(FILES["orders.php"] + "// changed\n", encoding="utf-8")
        git(repo, "commit", "-q", "-am", "change orders")
        (repo / "profile.php").write_text(FILES["profile.php"] + "// wip\n", encoding="utf-8")
        (repo / "new.php").write_text("<?php\n", encoding="utf-8")
        self.assertEqual(git_changed_files(repo, "main"), ["new.php", "orders.php", "profile.php"])

    def test_paths_are_relative_to_target_subdirectory(self) -> None:
        repo = self.make_repo()
        (repo / "app" / "orders.js").write_text("module.exports = {a: 1};\n", encoding="utf-8")
        (repo / "orders.php").write_text("<?php\n", encoding="utf-8")
        self.assertEqual(git_changed_files(repo / "app", "main"), ["orders.js"])

    def test_deleted_files_are_reported(self) -> None:
        repo = self.make_repo()
        git(repo, "rm", "-q", "inc/db.php")
        self.assertEqual(git_changed_files(repo, "main"), ["inc/db.php"])

    def test_errors(self) -> None:
        repo = self.make_repo()
        with self.assertRaises(ChangedFilesError):
            git_changed_files(repo, "no-such-ref")
        with tempfile.TemporaryDirectory() as plain:
            with self.assertRaises(ChangedFilesError):
                git_changed_files(Path(plain), "main")


class TestSelectFiles(_RepoMixin, unittest.TestCase):
    def setUp(self) -> None:
        self.repo = self.make_repo()
        self.cfg = load_config(None)

    def test_php_include_by_file_name(self) -> None:
        self.assertEqual(select_files(self.repo, ["inc/db.php"], self.cfg), ["inc/db.php", "orders.php"])

    def test_java_class_referenced_by_xml_and_other_classes(self) -> None:
        self.assertEqual(
            select_files(self.repo, ["src/com/acme/OrderServlet.java"], self.cfg),
            ["src/com/acme/Billing.java", "src/com/acme/OrderServlet.java", "web/WEB-INF/web.xml"],
        )

    def test_module_imports(self) -> None:
        self.assertEqual(select_files(self.repo, ["app/orders.js"], self.cfg), ["app/orders.js", "app/server.js"])
        self.assertEqual(select_files(self.repo, ["py/models.py"], self.cfg), ["py/models.py", "py/views.py"])

    def test_deleted_file_keeps_its_referrers(self) -> None:
        (self.repo / "inc" / "db.php").unlink()
        self.assertEqual(select_files(self.repo, ["inc/db.php"], self.cfg), ["orders.php"])

    def test_out_of_scope_and_non_source_changes_are_dropped(self) -> None:
        (self.repo / "README.md").write_text("docs\n", encoding="utf-8")
        self.assertEqual(select_files(self.repo, ["vendor/lib.php", "README.md"], self.cfg), [])


class TestOnlyFilesScope(_RepoMixin, unittest.TestCase):
    def test_only_files_filters_and_empty_list_yields_nothing(self) -> None:
        repo = self.make_repo()
        cfg = load_config(None)
        cfg["scope"]["only_files"] = ["search.php"]
        self.assertEqual([rel for _, rel in iter_source_files(repo, cfg)], ["search.php"])
        cfg["scope"]["only_files"] = []
        self.assertEqual(list(iter_source_files(repo, cfg)), [])

    def test_only_files_does_not_change_cache_hash(self) -> None:
        cfg = load_config(None)
        scoped = load_config(None)
        scoped["scope"]["only_files"] = ["search.php"]
        self.assertEqual(compute_config_hash(cfg, {"php-plain"}), compute_config_hash(scoped, {"php-plain"}))


class TestPrescanDiff(_RepoMixin, unittest.TestCase):
    def setUp(self) -> None:
        self.repo = self.make_repo()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name) / "out"

    def prescan(self, *extra: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(RUN_PRESCAN), str(self.repo), str(self.out), *extra],
                              capture_output=True, text=True)

    def candidate_files(self, name: str) -> set:
        doc = json.loads((self.out / name).read_text(encoding="utf-8"))
        return {c.get("file") or c["handler"]["file"] for c in doc["candidates"]}

    def test_diff_limits_candidates_and_reuses_cache(self) -> None:
        full = self.prescan()
        self.assertEqual(full.returncode, 0, full.stderr)
        self.assertIn("search.php", self.candidate_files("injection.candidates.json"))

        # db.php changes; orders.php includes it and is unchanged, so it comes from the cache
        (self.repo / "inc" / "db.php").write_text(FILES["inc/db.php"] + "function db2() { return 2; }\n", encoding="utf-8")
        res = self.prescan("--diff", "main")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(self.candidate_files("injection.candidates.json"), {"orders.php"})
        self.assertTrue(self.candidate_files("routes.candidates.json") <= {"orders.php", "inc/db.php"})

        scope = json.loads((self.out / "diff-scope.json").read_text(encoding="utf-8"))
        self.assertEqual(scope["base_ref"], "main")
        self.assertEqual(scope["changed"], ["inc/db.php"])
        self.assertEqual(scope["selected"], ["inc/db.php", "orders.php"])
        self.assertIn("Diff scope: 2 file(s)", res.stdout)
        self.assertNotIn("Cache: 0 hits", res.stdout)

        # a later full scan must not keep the stale diff scope
        self.assertEqual(self.prescan().returncode, 0)
        self.assertFalse((self.out / "diff-scope.json").exists())

        stack = json.loads((self.out / "stack-profile.json").read_text(encoding="utf-8"))
        self.assertIn("java-servlet", {s["id"] for s in stack["stacks"]})

    def test_no_relevant_changes_scans_nothing(self) -> None:
        res = self.prescan("--diff", "main")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(self.candidate_files("injection.candidates.json"), set())
        self.assertIn("Diff scope: 0 file(s)", res.stdout)

    def test_bad_ref_is_usage_error(self) -> None:
        res = self.prescan("--diff", "no-such-ref")
        self.assertEqual(res.returncode, 2)
        self.assertIn("no-such-ref", res.stderr)


class TestBaselineScope(unittest.TestCase):
    def test_entries_outside_scope_are_not_fixed(self) -> None:
        def finding(fid: str, fp: str, rel: str) -> dict:
            return {"finding_id": fid, "category": "bola", "severity": "high", "status": "confirmed",
                    "title": fid, "location": {"file": rel, "start_line": 1}, "fingerprint": fp}

        a = finding("BOLA-A", "kfp1:" + "a" * 64, "orders.php")
        b = finding("BOLA-B", "kfp1:" + "b" * 64, "profile.php")
        doc = update_baseline({}, compare([a, b], {}), "2026-11-01")
        entries = {e["fingerprint"]: e for e in doc["entries"]}
        self.assertEqual(entries[a["fingerprint"]]["file"], "orders.php")

        scoped = compare([], entries, scope={"orders.php"})
        self.assertEqual([e["fingerprint"] for e in scoped.fixed], [a["fingerprint"]])
        self.assertEqual(compare([], entries).counts["fixed"], 2)


if __name__ == "__main__":
    unittest.main()
