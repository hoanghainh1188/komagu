#!/usr/bin/env python3
"""Tests for the runtime adapter generators (Issue #244).

Validates:
1. Codex adapter: repo-scoped skill, .codex/agents/*.toml custom agents, managed AGENTS.md block.
2. Claude Code, Cursor and generic adapters keep producing their files.
3. Generic adapter never overwrites a contract.json, kit/ or system-prompts/ it did not generate (Issue #246).
4. build() API: runtime aliases, unknown runtimes, script exit codes.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
KIT = HERE.parent
sys.path.insert(0, str(KIT / "adapters"))

import build_adapters  # noqa: E402
from build_adapters import AGENTS_MD_BEGIN, AGENTS_MD_END, ROLES, build, toml_multiline  # noqa: E402

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover - Python 3.8-3.10
    tomllib = None

SKILL_REF = ".agents/skills/legacy-security-audit"


def frontmatter(text: str) -> str:
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    return m.group(1) if m else ""


class TestCodexAdapter(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dest = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_skill_is_repo_scoped_with_kit(self) -> None:
        build("codex", self.dest)
        skill = self.dest / SKILL_REF
        text = (skill / "SKILL.md").read_text(encoding="utf-8")
        fm = frontmatter(text)
        self.assertIn("name: legacy-security-audit", fm)
        self.assertIn("description:", fm)
        self.assertNotIn("KIT/", text, "orchestrator KIT/ paths must be rewritten to the skill folder")
        self.assertIn(f"{SKILL_REF}/scripts/", text)
        for d in ("prompts", "knowledge", "schemas", "scripts", "templates", "governance"):
            self.assertTrue((skill / d).is_dir(), f"missing kit folder {d}")
        self.assertTrue((skill / "scripts" / "run_prescan.py").is_file())

    def test_one_custom_agent_per_role(self) -> None:
        build("codex", self.dest)
        agents = sorted((self.dest / ".codex" / "agents").glob("*.toml"))
        self.assertEqual([p.name for p in agents], sorted(f"lsa-{r['id']}.toml" for r in ROLES))
        for path in agents:
            text = path.read_text(encoding="utf-8")
            if tomllib is None:
                self.assertRegex(text, r'(?m)^name = "lsa-[a-z-]+"$')
                self.assertIn('developer_instructions = """', text)
                continue
            data = tomllib.loads(text)
            self.assertEqual(data["name"], path.stem)
            self.assertTrue(data["description"])
            body = data["developer_instructions"]
            self.assertIn("Never write into TARGET", body)
            self.assertIn(SKILL_REF, body)

    def test_agents_md_created_with_managed_block(self) -> None:
        build("codex", self.dest)
        text = (self.dest / "AGENTS.md").read_text(encoding="utf-8")
        self.assertEqual(text.count(AGENTS_MD_BEGIN), 1)
        self.assertEqual(text.count(AGENTS_MD_END), 1)
        self.assertIn("legacy-security-audit", text)
        self.assertIn("Never write into TARGET", text)

    def test_agents_md_preserves_user_content_and_is_idempotent(self) -> None:
        user = "# My workspace\n\nAlways answer in Japanese.\n"
        (self.dest / "AGENTS.md").write_text(user, encoding="utf-8")
        build("codex", self.dest)
        build("codex", self.dest)
        text = (self.dest / "AGENTS.md").read_text(encoding="utf-8")
        self.assertTrue(text.startswith(user))
        self.assertEqual(text.count(AGENTS_MD_BEGIN), 1)
        self.assertEqual(text.count(AGENTS_MD_END), 1)

    def test_pre_2_0_markers_are_replaced_in_place(self) -> None:
        old = (f"# Notes\n\n{build_adapters.LEGACY_AGENTS_MD_BEGIN}\nold block\n"
               f"{build_adapters.LEGACY_AGENTS_MD_END}\n\n# Footer\n")
        (self.dest / "AGENTS.md").write_text(old, encoding="utf-8")
        build("codex", self.dest)
        text = (self.dest / "AGENTS.md").read_text(encoding="utf-8")
        self.assertNotIn("komainu-lsa", text)
        self.assertNotIn("old block", text)
        self.assertEqual(text.count(AGENTS_MD_BEGIN), 1)
        self.assertTrue(text.startswith("# Notes\n\n") and text.endswith("# Footer\n"))

    def test_unbalanced_markers_fail_before_touching_workspace(self) -> None:
        user = f"# Notes\n{AGENTS_MD_BEGIN}\nimportant user text\n"
        (self.dest / "AGENTS.md").write_text(user, encoding="utf-8")
        with self.assertRaises(ValueError):
            build("codex", self.dest)
        self.assertEqual((self.dest / "AGENTS.md").read_text(encoding="utf-8"), user)
        self.assertFalse((self.dest / ".agents").exists())
        self.assertFalse((self.dest / ".codex").exists())

    def test_end_marker_before_begin_fails(self) -> None:
        (self.dest / "AGENTS.md").write_text(f"{AGENTS_MD_END}\nmine\n{AGENTS_MD_BEGIN}\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            build("codex", self.dest)

    def test_non_utf8_agents_md_fails_before_touching_workspace(self) -> None:
        (self.dest / "AGENTS.md").write_bytes(b"# caf\xe9 notes\n")
        with self.assertRaises(ValueError):
            build("codex", self.dest)
        self.assertFalse((self.dest / ".agents").exists())

    def test_crlf_agents_md_keeps_line_endings(self) -> None:
        (self.dest / "AGENTS.md").write_bytes(b"# mine\r\nline\r\n")
        build("codex", self.dest)
        build("codex", self.dest)
        raw = (self.dest / "AGENTS.md").read_bytes()
        self.assertTrue(raw.startswith(b"# mine\r\nline\r\n"))
        self.assertNotIn(b"\n", raw.replace(b"\r\n", b""), "every newline must stay CRLF")
        self.assertEqual(raw.count(AGENTS_MD_BEGIN.encode()), 1)

    def test_empty_agents_md_gets_block_without_leading_blank_lines(self) -> None:
        (self.dest / "AGENTS.md").write_text("\n\n", encoding="utf-8")
        build("codex", self.dest)
        self.assertTrue((self.dest / "AGENTS.md").read_text(encoding="utf-8").startswith(AGENTS_MD_BEGIN))

    def test_rebuild_refreshes_kit_without_leftovers(self) -> None:
        build("codex", self.dest)
        stale = self.dest / SKILL_REF / "scripts" / "stale.py"
        stale.write_text("# old", encoding="utf-8")
        build("codex", self.dest)
        self.assertFalse(stale.exists())


class TestTomlMultiline(unittest.TestCase):
    @unittest.skipIf(tomllib is None, "tomllib requires Python 3.11+")
    def test_round_trips_quotes_and_backslashes(self) -> None:
        tricky = 'regex \\d+ and "quoted" and """triple""" and trailing quote"'
        doc = "x = " + toml_multiline(tricky) + "\n"
        self.assertEqual(tomllib.loads(doc)["x"], tricky)

    @unittest.skipIf(tomllib is None, "tomllib requires Python 3.11+")
    def test_round_trips_control_characters(self) -> None:
        tricky = "tab\there\r\nwindows line\x07bell"
        doc = "x = " + toml_multiline(tricky) + "\n"
        self.assertEqual(tomllib.loads(doc)["x"], tricky)


class TestOtherAdapters(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dest = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_claude_code(self) -> None:
        build("claude-code", self.dest)
        self.assertTrue((self.dest / ".claude" / "skills" / "legacy-security-audit" / "SKILL.md").is_file())
        self.assertEqual(len(list((self.dest / ".claude" / "agents").glob("lsa-*.md"))), len(ROLES))

    def test_cursor(self) -> None:
        build("cursor", self.dest)
        self.assertTrue((self.dest / ".lsa-kit" / "VERSION").is_file())
        self.assertEqual(len(list((self.dest / ".cursor" / "rules").glob("lsa-*.mdc"))), len(ROLES) + 1)

    def test_generic(self) -> None:
        build("generic", self.dest)
        self.assertTrue((self.dest / "contract.json").is_file())
        self.assertEqual(len(list((self.dest / "system-prompts").glob("*.md"))), len(ROLES) + 1)


class TestGenericAdapterGuard(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dest = Path(self._tmp.name)
        self.contract = self.dest / "contract.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def assert_untouched(self, *names: str) -> None:
        self.assertEqual(sorted(p.name for p in self.dest.iterdir()), sorted(names))

    def test_contract_carries_generator_marker(self) -> None:
        build("generic", self.dest)
        self.assertEqual(json.loads(self.contract.read_text(encoding="utf-8"))["generator"], "komagu-lsa")

    def test_rebuild_refreshes_generated_contract(self) -> None:
        build("generic", self.dest)
        data = json.loads(self.contract.read_text(encoding="utf-8"))
        data["kit_version"] = "0.0.0"
        self.contract.write_text(json.dumps(data), encoding="utf-8")
        build("generic", self.dest)
        self.assertEqual(json.loads(self.contract.read_text(encoding="utf-8"))["kit_version"], build_adapters.VERSION)

    def test_rebuild_accepts_pre_2_0_generator(self) -> None:
        build("generic", self.dest)
        data = json.loads(self.contract.read_text(encoding="utf-8"))
        data["generator"] = "komainu-lsa"
        self.contract.write_text(json.dumps(data), encoding="utf-8")
        build("generic", self.dest)
        self.assertEqual(json.loads(self.contract.read_text(encoding="utf-8"))["generator"], "komagu-lsa")

    def test_foreign_contract_fails_before_touching_workspace(self) -> None:
        self.contract.write_text('{"name": "my-project-contract"}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "contract.json"):
            build("generic", self.dest)
        self.assertEqual(self.contract.read_text(encoding="utf-8"), '{"name": "my-project-contract"}')
        self.assert_untouched("contract.json")

    def test_non_json_contract_fails(self) -> None:
        self.contract.write_bytes(b"\xff not json")
        with self.assertRaises(ValueError):
            build("generic", self.dest)
        self.assert_untouched("contract.json")

    def test_non_object_contract_fails(self) -> None:
        self.contract.write_text('["komagu-lsa"]', encoding="utf-8")
        with self.assertRaises(ValueError):
            build("generic", self.dest)

    def test_foreign_kit_dir_without_contract_fails(self) -> None:
        (self.dest / "kit" / "scripts").mkdir(parents=True)
        (self.dest / "kit" / "scripts" / "mine.sh").write_text("echo hi\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "kit"):
            build("generic", self.dest)
        self.assertTrue((self.dest / "kit" / "scripts" / "mine.sh").is_file())
        self.assert_untouched("kit")

    def test_foreign_system_prompts_dir_without_contract_fails(self) -> None:
        (self.dest / "system-prompts").mkdir()
        with self.assertRaisesRegex(ValueError, "system-prompts"):
            build("generic", self.dest)

    def test_script_reports_foreign_contract(self) -> None:
        self.contract.write_text("{}", encoding="utf-8")
        res = subprocess.run([sys.executable, str(KIT / "adapters" / "build_adapters.py"), "generic", str(self.dest)],
                             capture_output=True, text=True)
        self.assertEqual(res.returncode, 2)
        self.assertIn("contract.json", res.stdout)
        self.assertEqual(self.contract.read_text(encoding="utf-8"), "{}")


class TestBuildApi(unittest.TestCase):
    def test_claude_alias(self) -> None:
        self.assertEqual(build_adapters.resolve_runtime("claude"), "claude-code")
        self.assertEqual(build_adapters.resolve_runtime("Codex"), "codex")

    def test_unknown_runtime_raises(self) -> None:
        with self.assertRaises(ValueError):
            build_adapters.resolve_runtime("copilot")

    def test_script_rejects_unknown_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            res = subprocess.run([sys.executable, str(KIT / "adapters" / "build_adapters.py"), "copilot", tmp],
                                 capture_output=True, text=True)
        self.assertEqual(res.returncode, 2)
        self.assertIn("codex", res.stdout)

    def test_script_builds_codex(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            res = subprocess.run([sys.executable, str(KIT / "adapters" / "build_adapters.py"), "codex", tmp],
                                 capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertTrue((Path(tmp) / ".codex" / "agents" / "lsa-bola-auditor.toml").is_file())


if __name__ == "__main__":
    unittest.main()
