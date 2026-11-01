#!/usr/bin/env python3
"""Add privilege batches for routes the route mapper flagged for a BFLA audit.

Usage: make_privilege_batches.py OUT [--config audit-config.json]
Run after phase 3, once merge_findings.py has written OUT/routes.json.
Reads  OUT/routes.json, OUT/batches/privilege-*.json, OUT/findings/priv-*.json, OUT/stack-profile.json
Writes OUT/batches/privilege-NNN.json for routes with needs_bfla_audit: true that are in no
       privilege batch yet and have no privilege verdict (numbering continues after the existing
       batches). Running it again writes nothing new. Give each new batch to the privilege auditor.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, List, Set

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lsa_common import load_config, read_json, write_json  # noqa: E402
from make_batches import PRIVILEGE_KNOWLEDGE, group_by_file, pack  # noqa: E402
from merge_findings import extract_json  # noqa: E402

BATCH_RE = re.compile(r"^privilege-(\d+)\.json$")


def _covered(out: Path) -> Set[str]:
    """Route ids already in a privilege batch or with a privilege verdict."""
    ids: Set[str] = set()
    for p in (out / "batches").glob("privilege-*.json"):
        ids |= {r.get("route_id") for r in read_json(p).get("routes", []) if isinstance(r, dict)}
    for p in (out / "findings").glob("priv-*.json"):
        doc = extract_json(p)
        verdicts = doc.get("privilege_route_verdicts", []) if isinstance(doc, dict) else []
        ids |= {v.get("route_id") for v in verdicts if isinstance(v, dict)}
    return ids


def _stack_knowledge(out: Path) -> List[str]:
    prof = out / "stack-profile.json"
    files = read_json(prof).get("knowledge_files", []) if prof.is_file() else []
    return [f for f in files if isinstance(f, str) and f.startswith("knowledge/stacks/")]


def make_privilege_batches(out: Path, config: Dict) -> List[str]:
    """Write privilege batches for uncovered BFLA routes; return the new batch ids."""
    if not (out / "routes.json").is_file():
        return []
    covered = _covered(out)
    todo = [r for r in read_json(out / "routes.json").get("routes", [])
            if isinstance(r, dict) and r.get("needs_bfla_audit") and r.get("route_id") not in covered]
    if not todo:
        return []
    bdir = out / "batches"
    numbers = [int(m.group(1)) for p in bdir.glob("privilege-*.json") for m in [BATCH_RE.match(p.name)] if m]
    n = max(numbers, default=0)
    knowledge = PRIVILEGE_KNOWLEDGE + _stack_knowledge(out)
    limit = int(config["batch"].get("max_privilege_items", 20))
    written = []
    for chunk in pack(group_by_file(todo, lambda r: r["handler"]["file"]), limit):
        n += 1
        bid = f"privilege-{n:03d}"
        write_json(bdir / f"{bid}.json", {"batch_id": bid, "files": sorted({r["handler"]["file"] for r in chunk}),
                                          "knowledge_files": knowledge, "routes": chunk, "mass_candidates": [],
                                          "source": "routes.json (needs_bfla_audit set by the route mapper)"})
        written.append(bid)
    return written


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out")
    ap.add_argument("--config")
    a = ap.parse_args()
    written = make_privilege_batches(Path(a.out), load_config(a.config))
    print(f"new privilege batches: {len(written)}" + (f" ({', '.join(written)})" if written else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
