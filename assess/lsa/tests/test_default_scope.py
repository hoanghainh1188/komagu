#!/usr/bin/env python3
"""Default scan scope skips framework build output, caches and source maps (Issue #325)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
LSA_SCRIPTS = REPO_ROOT / "assess" / "lsa" / "scripts"
sys.path.insert(0, str(LSA_SCRIPTS))

from find_injection import find_injection  # noqa: E402
from lsa_common import DEFAULT_CONFIG, deep_merge, iter_source_files, load_config  # noqa: E402

TEMPLATE = REPO_ROOT / "assess" / "lsa" / "templates" / "audit-config.json"

VULN_JS = (
    "const id = req.query.id;\n"
    "db.query(`SELECT * FROM orders WHERE id = ${id}`);\n"
)

GENERATED = [
    ".next/server/chunks/x.js",
    ".next/dev/server/chunks/y.js",
    ".nuxt/dist/server/a.js",
    ".output/server/index.mjs",
    ".svelte-kit/output/server/b.js",
    ".vercel/output/functions/c.js",
    ".turbo/cache/d.js",
    "out/_next/e.js",
    "coverage/lcov-report/f.js",
    "test-results/g.js",
    "playwright-report/h.js",
    "storybook-static/i.js",
    ".venv/lib/site.py",
    "__pycache__/m.py",
    "src/app/page.js.map",
]


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


class TestDefaultScope(unittest.TestCase):
    def _repo(self, td: str) -> Path:
        root = Path(td)
        for rel in GENERATED:
            _write(root, rel, VULN_JS)
        _write(root, "src/lib/orders.js", VULN_JS)
        return root

    def test_generated_output_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = self._repo(td)
            rels = {rel for _, rel in iter_source_files(root, load_config(None))}
            self.assertEqual(rels, {"src/lib/orders.js"})

    def test_injection_candidates_only_from_source(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = self._repo(td)
            res = find_injection(root, load_config(None))
            files = {c["file"] for c in res["candidates"]}
            self.assertEqual(files, {"src/lib/orders.js"})

    def test_user_exclude_override_brings_folder_back(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = self._repo(td)
            excludes = [e for e in DEFAULT_CONFIG["scope"]["exclude"] if e != ".next/"]
            cfg = deep_merge(DEFAULT_CONFIG, {"scope": {"exclude": excludes}})
            rels = {rel for _, rel in iter_source_files(root, cfg)}
            self.assertIn(".next/server/chunks/x.js", rels)

    def test_template_matches_default(self) -> None:
        template = json.loads(TEMPLATE.read_text(encoding="utf-8"))
        self.assertEqual(template["scope"]["exclude"], DEFAULT_CONFIG["scope"]["exclude"])


if __name__ == "__main__":
    unittest.main()
