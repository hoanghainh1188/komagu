#!/usr/bin/env python3
"""Group auditor findings into verifier batches (default 10 findings each).

Usage: make_verify_batches.py OUT [--size 10]
Reads  OUT/findings/bola-*.json, OUT/findings/inj-*.json
Writes OUT/batches/verify-NNN.json  (give each one to a FRESH finding-verifier agent;
       its output goes to OUT/findings/verified-NNN.json)
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lsa_common import write_json  # noqa: E402
from make_batches import LANG_KNOWLEDGE  # noqa: E402
from merge_findings import extract_json  # noqa: E402


EXT_LANG = {".php": "php", ".inc": "php", ".java": "java", ".jsp": "java", ".xml": "java", ".cs": "cs", ".vb": "vb",
            ".aspx": "aspx", ".ashx": "cs", ".asmx": "cs", ".asp": "vb", ".pl": "perl", ".cgi": "perl", ".pm": "perl",
            ".cfm": "cfml", ".cfc": "cfml", ".js": "js", ".py": "python", ".rb": "ruby", ".kt": "java"}


def ext_lang(path: str) -> str:
    return EXT_LANG.get(Path(path).suffix.lower(), "")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out")
    ap.add_argument("--size", type=int, default=10)
    a = ap.parse_args()
    out = Path(a.out)
    findings = []
    for p in sorted((out / "findings").glob("*.json")):
        if p.name.startswith(("bola-", "inj-")):
            findings += extract_json(p).get("findings", [])
    # keep findings on the same file together, highest severity first
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (f["location"]["file"], order.get(f.get("severity"), 9)))
    n = 0
    for i in range(0, len(findings), a.size):
        n += 1
        chunk = findings[i:i + a.size]
        write_json(out / "batches" / f"verify-{n:03d}.json",
                   {"batch_id": f"verify-{n:03d}", "files": sorted({f["location"]["file"] for f in chunk}),
                    "knowledge_files": sorted({"knowledge/stacks/" + LANG_KNOWLEDGE[ext_lang(f["location"]["file"])]
                                               for f in chunk if ext_lang(f["location"]["file"]) in LANG_KNOWLEDGE}),
                    "findings": chunk})
    print(f"{len(findings)} findings -> {n} verifier batches")
    return 0


if __name__ == "__main__":
    sys.exit(main())
