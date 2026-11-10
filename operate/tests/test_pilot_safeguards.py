#!/usr/bin/env python3
"""Pilot safeguards: source copy exclude list, deletion record, guard against committing real pilot data (#367)."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from typing import Dict, Set

REPO_ROOT = Path(__file__).resolve().parents[2]
PILOT = REPO_ROOT / "delivery" / "pilot"
EXCLUDE_FILE = PILOT / "ams-exclude.sample.txt"
GUARD_FILE = REPO_ROOT / ".githooks" / "pilot_data_guard.py"
HAS_GIT_CHECKOUT = (REPO_ROOT / ".git").exists() and shutil.which("git") is not None


def load_guard() -> ModuleType:
    spec = importlib.util.spec_from_file_location("komagu_pilot_data_guard", GUARD_FILE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def clean_env() -> Dict[str, str]:
    """A run started from inside a git hook must not act on the outer repository."""
    return {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}


@unittest.skipUnless(shutil.which("rsync"), "rsync is not installed")
class TestExcludeList(unittest.TestCase):
    EXCLUDED = (
        "keystore.jks",
        "conf/ssl/app.keystore",
        "conf/ssl/client.p12",
        "src/main/resources/server.key",
        "src/main/resources/application-prod.properties",
        "src/main/resources/application-prod.yml",
        "src/main/resources/application-production.yml",
        "context.xml",
        "conf/context.xml",
        "src/main/webapp/META-INF/context.xml",
        "server.xml",
        "conf/tomcat-users.xml",
        ".env",
        "src/test/java/FooTest.java",
        "modules/billing/src/test/resources/seed.sql",
        "test-data/users.csv",
    )
    KEPT = (
        "pom.xml",
        "src/main/java/com/acme/OrderAction.java",
        "src/main/resources/application.properties",
        "src/main/webapp/WEB-INF/web.xml",
        "src/main/webapp/WEB-INF/struts-config.xml",
        "src/testing/Keep.java",
    )

    def test_patterns_filter_a_real_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source, target = Path(tmp) / "repo", Path(tmp) / "copy"
            for relative in self.EXCLUDED + self.KEPT:
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("x", encoding="utf-8")
            subprocess.run(
                ["rsync", "-a", f"--exclude-from={EXCLUDE_FILE}", f"{source}/", f"{target}/"],
                check=True,
                capture_output=True,
            )
            copied: Set[str] = {str(p.relative_to(target)) for p in target.rglob("*") if p.is_file()}
        self.assertEqual(copied, set(self.KEPT))


class TestDocuments(unittest.TestCase):
    def test_runbook_uses_the_tracked_exclude_list(self) -> None:
        runbook = (REPO_ROOT / "docs" / "pilot-execution-runbook.md").read_text(encoding="utf-8")
        self.assertIn("ams-exclude.sample.txt", runbook)
        self.assertNotIn("**/context.xml", runbook)
        self.assertIn("komagu leak-check", runbook)
        self.assertIn("data-deletion-report.template.md", runbook)

    def test_deletion_report_covers_the_commitment_in_both_languages(self) -> None:
        template = (PILOT / "data-deletion-report.template.md").read_text(encoding="utf-8")
        for term in ("削除日時", "Deleted at", "実施者", "Operator", "確認者", "Verifier", "モデルサーバーログ",
                     "Model server logs", "一時ディレクトリ", "Temporary directories", "~/pilot/src", "~/pilot/out*"):
            self.assertIn(term, template)


class TestGuardRules(unittest.TestCase):
    guard = load_guard()

    def test_real_output_paths_are_rejected(self) -> None:
        for path in (
            "delivery/pilot/ai-raw/4a.txt",
            "out/ai-raw/4a.txt",
            "delivery/pilot/client-a-config.json",
            "delivery/pilot/out/findings.json",
            "ams-exclude.txt",
            "delivery/pilot/src-file-list.txt",
            "canaries.txt",
            "notes/canaries-prod.txt",
            "delivery/pilot/data-deletion-report.md",
            "notes/Canaries.txt",
            "out/AI-RAW/4a.txt",
        ):
            self.assertIsNotNone(self.guard.path_violation(path), path)

    def test_known_files_are_accepted(self) -> None:
        for path in (
            "delivery/pilot/pilot-config.json",
            "delivery/pilot/ams-exclude.sample.txt",
            "delivery/pilot/data-deletion-report.template.md",
            "delivery/pilot/audit-out/report.md",
            "operate/ai/runner.py",
        ):
            self.assertIsNone(self.guard.path_violation(path), path)

    def test_fallback_config_passes_and_real_config_fails(self) -> None:
        fallback = (PILOT / "pilot-config.json").read_bytes()
        sample = (PILOT / "pilot-config.sample.json").read_bytes()
        check = self.guard.CONTENT_CHECKS[self.guard.CONFIG]
        self.assertIsNone(check(fallback))
        self.assertIsNotNone(check(sample), "a copy of the sample over the fallback is the likely accident")
        self.assertIsNotNone(check(b"not json"))

    def test_filled_sample_fails(self) -> None:
        sample = json.loads((PILOT / "pilot-config.sample.json").read_text(encoding="utf-8"))
        check = self.guard.CONTENT_CHECKS[self.guard.SAMPLE_CONFIG]
        self.assertIsNone(check(json.dumps(sample).encode()))
        filled = {**sample, "system": {**sample["system"], "name": "Real system"}}
        self.assertIsNotNone(check(json.dumps(filled).encode()))

    @unittest.skipUnless(HAS_GIT_CHECKOUT, "needs a git checkout")
    def test_tracked_tree_is_clean(self) -> None:
        completed = subprocess.run(
            ["python3", str(GUARD_FILE), "--tree"], cwd=REPO_ROOT, env=clean_env(), capture_output=True, text=True
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


@unittest.skipUnless(shutil.which("git"), "git is not installed")
class TestPrePushHook(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.repo, self.remote = root / "repo", root / "remote.git"
        self.git_at(root, "init", "--bare", str(self.remote))
        self.git_at(root, "init", str(self.repo))
        shutil.copytree(REPO_ROOT / ".githooks", self.repo / ".githooks")
        self.git("remote", "add", "origin", str(self.remote))
        self.write("delivery/pilot/pilot-config.json", (PILOT / "pilot-config.json").read_text(encoding="utf-8"))
        self.write("delivery/pilot/audit-out/report.md", "fallback\n")
        self.write("README.md", "hello\n")
        self.commit("base")
        self.git("push", "-q", "origin", "HEAD:refs/heads/seed")
        self.git("fetch", "-q", "origin")
        self.git("config", "core.hooksPath", ".githooks")
        self.git("switch", "-q", "-c", "work")

    def git_at(self, cwd: Path, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", *args],
            cwd=cwd, env=clean_env(), check=True, capture_output=True, text=True,
        )

    def git(self, *args: str) -> subprocess.CompletedProcess:
        return self.git_at(self.repo, *args)

    def write(self, relative: str, content: str) -> None:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def commit(self, message: str) -> None:
        self.git("add", "-A", "-f")
        self.git("commit", "-q", "-m", message)

    def push(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", "push", "origin", "work"], cwd=self.repo, env=clean_env(), capture_output=True, text=True
        )

    def assert_blocked(self, expected: str) -> None:
        completed = self.push()
        self.assertNotEqual(completed.returncode, 0, completed.stdout)
        self.assertIn(expected, completed.stderr)
        refs = subprocess.run(["git", "ls-remote", str(self.remote)], capture_output=True, text=True, env=clean_env())
        self.assertNotIn("refs/heads/work", refs.stdout)

    def test_ordinary_change_is_pushed(self) -> None:
        self.write("README.md", "changed\n")
        self.commit("docs")
        completed = self.push()
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_real_config_over_the_tracked_file_is_blocked(self) -> None:
        self.write("delivery/pilot/pilot-config.json", (PILOT / "pilot-config.sample.json").read_text(encoding="utf-8"))
        self.commit("config")
        self.assert_blocked("delivery/pilot/pilot-config.json")

    def test_output_removed_in_a_later_commit_is_still_blocked(self) -> None:
        self.write("delivery/pilot/ai-raw/4a.txt", "reply\n")
        self.commit("oops")
        self.git("rm", "-q", "delivery/pilot/ai-raw/4a.txt")
        self.commit("undo")
        self.assert_blocked("ai-raw")

    def test_change_to_frozen_fallback_output_is_blocked(self) -> None:
        self.write("delivery/pilot/audit-out/report.md", "real client report\n")
        self.commit("report")
        self.assert_blocked("frozen fallback")

    def test_intended_fallback_edit_needs_the_named_override_only(self) -> None:
        self.write("delivery/pilot/audit-out/report.md", "corrected fallback report\n")
        self.write("delivery/pilot/ai-raw/4a.txt", "reply\n")
        self.commit("edit")
        env = {**clean_env(), "KOMAGU_ALLOW_FALLBACK_EDIT": "1"}
        blocked = subprocess.run(["git", "push", "origin", "work"], cwd=self.repo, env=env, capture_output=True, text=True)
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("ai-raw", blocked.stderr)
        self.assertNotIn("frozen fallback", blocked.stderr)
        self.git("rm", "-q", "--cached", "delivery/pilot/ai-raw/4a.txt")
        self.git("commit", "-q", "--amend", "--no-edit")
        allowed = subprocess.run(["git", "push", "origin", "work"], cwd=self.repo, env=env, capture_output=True, text=True)
        self.assertEqual(allowed.returncode, 0, allowed.stderr)

    def test_push_to_main_is_still_blocked(self) -> None:
        completed = subprocess.run(
            ["git", "push", "origin", "work:main"], cwd=self.repo, env=clean_env(), capture_output=True, text=True
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("direct push to main", completed.stderr)


if __name__ == "__main__":
    unittest.main()
