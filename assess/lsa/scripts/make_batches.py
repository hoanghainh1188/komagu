#!/usr/bin/env python3
"""Split route, injection and privilege candidates into agent-sized batches, grouped by file.

Usage: make_batches.py OUT [--config audit-config.json]
Reads  OUT/routes.candidates.json, OUT/injection.candidates.json,
       OUT/mass-assignment.candidates.json (optional)
Writes OUT/batches/routes-NNN.json, OUT/batches/injection-NNN.json,
       OUT/batches/privilege-NNN.json, OUT/batches/index.json

A privilege batch holds the BFLA-hinted routes and the mass assignment
candidates of the same files, for the 35-privilege-auditor agent.
"""
from __future__ import annotations

import argparse
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lsa_common import load_config, read_json, write_json  # noqa: E402

STACK_KNOWLEDGE = [("php", "php.md"), ("java", "java.md"), ("dotnet", "dotnet.md"), ("classic-asp", "classic-asp.md"),
                   ("perl", "perl-cgi.md"), ("coldfusion", "coldfusion.md"), ("node", "node-python-ruby.md"),
                   ("python", "node-python-ruby.md"), ("ruby", "node-python-ruby.md")]
LANG_KNOWLEDGE = {"php": "php.md", "java": "java.md", "xml": "java.md", "cs": "dotnet.md", "vb": "dotnet.md",
                  "aspx": "dotnet.md", "perl": "perl-cgi.md", "cfml": "coldfusion.md", "js": "node-python-ruby.md",
                  "python": "node-python-ruby.md", "ruby": "node-python-ruby.md"}


def knowledge_for(items, key) -> List[str]:
    out = []
    for it in items:
        k = key(it)
        if k and "knowledge/stacks/" + k not in out:
            out.append("knowledge/stacks/" + k)
    return out


def stack_file(stack: str):
    for prefix, f in STACK_KNOWLEDGE:
        if stack.startswith(prefix):
            return f
    return None


PRIORITY_DIRS = ("admin", "api", "ajax", "download", "export", "upload", "account", "user", "member", "order", "invoice", "report")


def group_by_file(items: List[Dict], key) -> "OrderedDict[str, List[Dict]]":
    groups: "OrderedDict[str, List[Dict]]" = OrderedDict()
    for it in items:
        groups.setdefault(key(it), []).append(it)
    return groups


def pack(groups: "OrderedDict[str, List[Dict]]", limit: int) -> List[List[Dict]]:
    batches, cur = [], []
    for _f, its in groups.items():
        if cur and len(cur) + len(its) > limit:
            batches.append(cur)
            cur = []
        # a single huge file is split, but stays contiguous
        while len(its) > limit:
            batches.append(its[:limit])
            its = its[limit:]
        cur.extend(its)
    if cur:
        batches.append(cur)
    return batches


def route_rank(r: Dict) -> tuple:
    p = r["path"].lower()
    return (0 if r.get("needs_audit_hint") or r.get("needs_bfla_audit_hint") else 1, 0 if any(d in p for d in PRIORITY_DIRS) else 1, r["handler"]["file"])


PRIVILEGE_KNOWLEDGE = ["knowledge/bfla-patterns.md", "knowledge/mass-assignment-patterns.md"]


def privilege_batches(routes: List[Dict], mass: List[Dict], limit: int) -> List[Dict]:
    """Group hinted routes and mass candidates per file; files with route hints first."""
    by_file: "OrderedDict[str, Dict[str, List[Dict]]]" = OrderedDict()
    for r in routes:
        if r.get("needs_bfla_audit_hint"):
            by_file.setdefault(r["handler"]["file"], {"routes": [], "mass": []})["routes"].append(r)
    for c in sorted(mass, key=lambda c: (0 if c.get("priority") == "high" else 1, c["file"], c["line"])):
        by_file.setdefault(c["file"], {"routes": [], "mass": []})["mass"].append(c)
    order = sorted(by_file, key=lambda f: (0 if by_file[f]["routes"] else 1, f))
    groups: "OrderedDict[str, List[Dict]]" = OrderedDict(
        (f, [("route", r) for r in by_file[f]["routes"]] + [("mass", c) for c in by_file[f]["mass"]]) for f in order)
    batches = []
    for chunk in pack(groups, limit):
        rs = [x for kind, x in chunk if kind == "route"]
        ms = [x for kind, x in chunk if kind == "mass"]
        stacks = knowledge_for(rs, lambda r: stack_file(r["stack"]))
        stacks += [k for k in knowledge_for(ms, lambda c: LANG_KNOWLEDGE.get(c["language"])) if k not in stacks]
        files = sorted({r["handler"]["file"] for r in rs} | {c["file"] for c in ms})
        batches.append({"files": files, "knowledge_files": PRIVILEGE_KNOWLEDGE + stacks, "routes": rs, "mass_candidates": ms})
    return batches


def make_batches(out: Path, config: Dict) -> Dict:
    routes = read_json(out / "routes.candidates.json")["candidates"]
    inj = read_json(out / "injection.candidates.json")["candidates"]
    routes_sorted = sorted(routes, key=route_rank)
    inj_sorted = sorted(inj, key=lambda c: (0 if c["priority"] == "high" else 1, c["file"], c["line"]))
    rb = pack(group_by_file(routes_sorted, lambda r: r["handler"]["file"]), int(config["batch"]["max_endpoints"]))
    ib = pack(group_by_file(inj_sorted, lambda c: c["file"]), int(config["batch"]["max_injection_candidates"]))
    bdir = out / "batches"
    index = {"routes": [], "injection": [], "privilege": []}
    for n, b in enumerate(rb, 1):
        bid = f"routes-{n:03d}"
        files = sorted({r["handler"]["file"] for r in b})
        write_json(bdir / f"{bid}.json", {"batch_id": bid, "files": files,
                                          "knowledge_files": knowledge_for(b, lambda r: stack_file(r["stack"])), "candidates": b})
        index["routes"].append({"batch_id": bid, "count": len(b), "files": len(files)})
    for n, b in enumerate(ib, 1):
        bid = f"injection-{n:03d}"
        files = sorted({c["file"] for c in b})
        write_json(bdir / f"{bid}.json", {"batch_id": bid, "files": files,
                                          "knowledge_files": knowledge_for(b, lambda c: LANG_KNOWLEDGE.get(c["language"])), "candidates": b})
        index["injection"].append({"batch_id": bid, "count": len(b), "files": len(files)})
    mass_file = out / "mass-assignment.candidates.json"
    mass = read_json(mass_file)["candidates"] if mass_file.is_file() else []
    for stale in bdir.glob("privilege-*.json"):
        stale.unlink()
    limit = int(config["batch"].get("max_privilege_items", 20))
    for n, b in enumerate(privilege_batches(routes, mass, limit), 1):
        bid = f"privilege-{n:03d}"
        write_json(bdir / f"{bid}.json", {"batch_id": bid, **b})
        index["privilege"].append({"batch_id": bid, "routes": len(b["routes"]),
                                   "mass_candidates": len(b["mass_candidates"]), "files": len(b["files"])})
    write_json(bdir / "index.json", index)
    return index


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out")
    ap.add_argument("--config")
    a = ap.parse_args()
    idx = make_batches(Path(a.out), load_config(a.config))
    print(f"route batches: {len(idx['routes'])}, injection batches: {len(idx['injection'])}, "
          f"privilege batches: {len(idx['privilege'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
