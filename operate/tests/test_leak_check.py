#!/usr/bin/env python3
"""komagu leak-check: planted secrets are found and masked, clean output passes (runbook §9, #367)."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import List

from operate.cli.main import main
from operate.devsecops.leak_check import load_canaries, CanaryFileError, scan_paths, scan_text, shannon_entropy

REPO_ROOT = Path(__file__).resolve().parents[2]
# Assembled at run time so repository secret scanners do not flag the test itself
AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
SLACK_TOKEN = "xoxb-" + "1234567890-abcdefghijklmnop"
JWT = "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0" + ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9P"
RANDOM_TOKEN = "kX9mQ2vL7pR4" + "tZ8wB3nY6cF1"


def detectors(text: str) -> List[str]:
    return [hit.detector for hit in scan_text("f", text)]


class TestDetection(unittest.TestCase):
    def test_redaction_pattern_catches_unmasked_password(self) -> None:
        self.assertIn("redaction-pattern", detectors('String password = "hunter2hunter2";'))

    def test_token_patterns_beyond_the_redaction_list(self) -> None:
        for planted in (SLACK_TOKEN, JWT):
            self.assertIn("token-pattern", detectors(f"seen in reply: {planted}"), planted)

    def test_aws_key_is_found(self) -> None:
        self.assertTrue(detectors(f"key {AWS_KEY}"))

    def test_entropy_finds_a_bare_token_no_pattern_knows(self) -> None:
        self.assertEqual(detectors(f"the upstream expects {RANDOM_TOKEN} here"), ["entropy"])

    def test_japanese_label_is_found(self) -> None:
        self.assertIn("token-pattern", detectors("初期パスワード：Abcd1234"))

    def test_secret_inside_json_string_is_found(self) -> None:
        raw = json.dumps({"snippet": 'db.setPassword("hunter2hunter2");'})
        self.assertIn("redaction-pattern", detectors(raw))

    def test_secret_inside_double_encoded_json_is_found(self) -> None:
        raw = json.dumps(json.dumps({"snippet": 'password = "hunter2hunter2"'}))
        self.assertIn("redaction-pattern", detectors(raw))

    def test_secret_inside_html_is_found(self) -> None:
        self.assertIn("redaction-pattern", detectors("<code>password = &quot;hunter2hunter2&quot;</code>"))

    def test_unmasked_multiline_private_key_is_found(self) -> None:
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7\n-----END RSA PRIVATE KEY-----"
        self.assertIn("token-pattern", detectors(text))

    def test_secret_at_end_of_very_long_line_is_found(self) -> None:
        text = "x " * 5000 + 'password = "hunter2hunter2"'
        self.assertIn("redaction-pattern", detectors(text))

    def test_value_split_over_lines_is_found(self) -> None:
        self.assertIn("redaction-pattern", detectors('<property name="password"\n  value="hunter2hunter2"/>'))


class TestCleanOutput(unittest.TestCase):
    def test_masked_values_are_clean(self) -> None:
        for line in (
            'password = "[REDACTED]"',
            "jdbc:mysql://h/db?user=a&password=[REDACTED]",
            "-----BEGIN PRIVATE KEY-----[REDACTED]-----END PRIVATE KEY-----",
            "パスワード: [REDACTED]",
        ):
            self.assertEqual(detectors(line), [], line)

    def test_multiline_masked_key_is_clean(self) -> None:
        text = "-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----"
        self.assertEqual(detectors(text), [])

    def test_ordinary_audit_content_is_clean(self) -> None:
        for line in (
            '"fingerprint": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"',
            '"sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709"',
            '"id": "123e4567-e89b-12d3-a456-426614174000"',
            '"file": "src/main/java/com/acme/order/OrderManagementController.java"',
            "org.springframework.web.servlet.DispatcherServlet",
            "commons-collections4-4.4.jar and struts2-core-2.5.33.jar",
            "パスワードはハードコードされています",
        ):
            self.assertEqual(detectors(line), [], line)

    def test_tracked_fallback_audit_output_is_clean(self) -> None:
        result = scan_paths([str(REPO_ROOT / "delivery" / "pilot" / "audit-out")])
        self.assertEqual([(h.path, h.line, h.rule) for h in result.hits], [])
        self.assertEqual(result.exit_code, 0)


class TestCanaries(unittest.TestCase):
    CANARY = "orange-falcon-db"

    def run_with(self, text: str) -> int:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "reply.txt").write_text(text, encoding="utf-8")
            return len(scan_paths([tmp], [self.CANARY]).hits)

    def test_canary_forms(self) -> None:
        encoded = base64.b64encode(self.CANARY.encode()).decode()
        for text in (
            f"host {self.CANARY} found",
            f"host {self.CANARY.upper()} found",
            f"host {encoded} found",
            json.dumps({"host": self.CANARY}),
        ):
            self.assertGreaterEqual(self.run_with(text), 1, text)

    def test_japanese_canary_in_ascii_escaped_json(self) -> None:
        canary = "社内基幹システム"
        hits = scan_text("f", json.dumps({"name": canary}), [])
        self.assertEqual(hits, [])
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "r.json").write_text(json.dumps({"name": canary}), encoding="utf-8")
            self.assertEqual([h.detector for h in scan_paths([tmp], [canary]).hits], ["canary"])

    def test_canary_in_shift_jis_file(self) -> None:
        canary = "社内基幹システム"
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "note.txt").write_bytes(f"対象: {canary}\n".encode("cp932"))
            self.assertEqual(len(scan_paths([tmp], [canary]).hits), 1)

    def test_canary_inside_encoded_payloads(self) -> None:
        canary = "p@ss/w0rd-Zq9"
        with tempfile.TemporaryDirectory() as tmp:
            for offset in range(3):
                payload = base64.b64encode(b"xy"[:offset] + canary.encode() + b"tail").decode()
                (Path(tmp) / f"b{offset}.txt").write_text(payload, encoding="utf-8")
            (Path(tmp) / "url.txt").write_text("p%40ss%2fw0rd-Zq9", encoding="utf-8")
            (Path(tmp) / "wide.txt").write_text("ｐ＠ｓｓ／ｗ０ｒｄ－Ｚｑ９", encoding="utf-8")
            (Path(tmp) / "zw.txt").write_text("p@ss/\u200bw0rd-Zq9", encoding="utf-8")
            hit_files = {Path(h.path).name for h in scan_paths([tmp], [canary]).hits}
        self.assertEqual(hit_files, {"b0.txt", "b1.txt", "b2.txt", "url.txt", "wide.txt", "zw.txt"})

    def test_no_canary_no_hit(self) -> None:
        self.assertEqual(self.run_with("nothing to see"), 0)

    def _load(self, content: str) -> tuple:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.txt"
            path.write_text(content, encoding="utf-8")
            return load_canaries(str(path))

    def test_every_nonblank_line_is_a_canary(self) -> None:
        self.assertEqual(self._load("#hash-start\n\n  spaced-value \n"), ("#hash-start", "spaced-value"))

    def test_empty_or_short_canary_file_is_rejected(self) -> None:
        for content in ("\n\n", "abc\n"):
            with self.assertRaises(CanaryFileError):
                self._load(content)


class TestCommand(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out = self.root / "out"
        (self.out / "ai-raw").mkdir(parents=True)

    def invoke(self, *args: str) -> "tuple[int, str]":
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(["--no-banner", "leak-check", *args])
        return code, stdout.getvalue()

    def test_clean_output_exits_zero(self) -> None:
        (self.out / "report.md").write_text('password = "[REDACTED]"\n', encoding="utf-8")
        self.assertEqual(self.invoke(str(self.out))[0], 0)

    def test_hit_exits_one_with_file_line_and_masked_value(self) -> None:
        secret = "hunter2hunter2"
        (self.out / "ai-raw" / "4a.txt").write_text(f'ok\npassword = "{secret}"\n', encoding="utf-8")
        canaries = self.root / "canaries.txt"
        canaries.write_text("orange-falcon-db\n", encoding="utf-8")
        (self.out / "report.md").write_text("connects to orange-falcon-db\n", encoding="utf-8")
        for fmt in ("text", "json"):
            code, output = self.invoke(str(self.out), "--canary-file", str(canaries), "--format", fmt)
            self.assertEqual(code, 1)
            self.assertIn("4a.txt", output)
            self.assertNotIn(secret, output)
            self.assertNotIn("orange-falcon-db", output)
        self.assertIn("4a.txt:2:", self.invoke(str(self.out))[1])

    def test_hidden_cache_and_test_named_paths_are_scanned(self) -> None:
        cache = self.out / ".cache" / "test-example"
        cache.mkdir(parents=True)
        (cache / "excerpt.txt").write_text(f"{RANDOM_TOKEN}\n", encoding="utf-8")
        self.assertEqual(self.invoke(str(self.out))[0], 1)

    def test_binary_file_makes_the_scan_incomplete(self) -> None:
        (self.out / "report.md").write_text("fine\n", encoding="utf-8")
        (self.out / "bundle.zip").write_bytes(b"PK\0\0payload")
        code, output = self.invoke(str(self.out))
        self.assertEqual(code, 2)
        self.assertIn("NOT SCANNED", output)

    def test_missing_or_empty_target_is_not_clean(self) -> None:
        self.assertEqual(self.invoke(str(self.root / "absent"))[0], 2)
        self.assertEqual(self.invoke(str(self.out))[0], 2)

    def test_unusable_canary_file_is_not_clean(self) -> None:
        (self.out / "report.md").write_text("fine\n", encoding="utf-8")
        for value in (str(self.root / "absent.txt"), ""):
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code, _ = self.invoke(str(self.out), "--canary-file", value)
            self.assertEqual(code, 2, value)

    def test_symlinked_directory_makes_the_scan_incomplete(self) -> None:
        (self.out / "report.md").write_text("fine\n", encoding="utf-8")
        real = self.root / "real"
        real.mkdir()
        (self.out / "linked").symlink_to(real, target_is_directory=True)
        self.assertEqual(self.invoke(str(self.out))[0], 2)

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0, "needs enforced directory permissions")
    def test_unreadable_directory_makes_the_scan_incomplete(self) -> None:
        (self.out / "report.md").write_text("fine\n", encoding="utf-8")
        locked = self.out / "locked"
        locked.mkdir()
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o700)
        self.assertEqual(self.invoke(str(self.out))[0], 2)

    def test_utf32_file_is_not_treated_as_clean_text(self) -> None:
        (self.out / "report.txt").write_bytes('password = "hunter2hunter2"'.encode("utf-32"))
        self.assertEqual(self.invoke(str(self.out))[0], 2)


class TestEntropy(unittest.TestCase):
    def test_entropy_ordering(self) -> None:
        self.assertEqual(shannon_entropy("aaaa"), 0)
        self.assertGreater(shannon_entropy(RANDOM_TOKEN), shannon_entropy("passwordpasswordpassword"))


if __name__ == "__main__":
    unittest.main()
