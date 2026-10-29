#!/usr/bin/env python3
"""Build a clean evaluation repository from the fixtures, for testing the AI agents end to end.

Usage: python3 tests/build_eval_repo.py DEST

- Copies tests/fixtures/* to DEST/repo/ with all LSA-EXPECT markers removed
  (agents must not see the answers).
- Writes DEST/ground-truth.json with the expected results.
Then run the full pipeline on DEST/repo and score with tests/score_findings.py.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from lsa_markers import iter_files, read_markers, strip_markers  # noqa: E402

LABEL_MAP = {"SQLI": ("sql_injection", True), "NOSQL": ("nosql_injection", True), "BOLA": ("bola", True),
             "SAFE-SQL": ("sql_injection", False), "SAFE-SQL-NOFLAG": ("sql_injection", False), "SAFE-BOLA": ("bola", False),
             "BFLA": ("bfla", True), "SAFE-BFLA": ("bfla", False),
             "MASS": ("mass_assignment", True), "SAFE-MASS": ("mass_assignment", False)}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    dest = Path(sys.argv[1]).resolve()
    repo = dest / "repo"
    if repo.exists():
        shutil.rmtree(repo)
    src = HERE / "fixtures"
    truth = []
    for m in read_markers(src):
        cat, vuln = LABEL_MAP[m["label"]]
        if m["label"] == "NOSQL":
            cat = "nosql_injection"
        truth.append({"file": m["file"], "line": m["line"], "category": cat, "vulnerable": vuln, "label": m["label"]})
    for p, rel in iter_files(src):
        out = repo / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            out.write_text(strip_markers(p.read_text(encoding="utf-8")), encoding="utf-8")
        except UnicodeDecodeError:
            shutil.copy2(p, out)
    (dest / "ground-truth.json").write_text(json.dumps({"items": truth}, indent=2), encoding="utf-8")
    print(f"eval repo: {repo}\nground truth: {dest / 'ground-truth.json'} ({len(truth)} items)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
