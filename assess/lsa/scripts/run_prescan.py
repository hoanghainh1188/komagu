#!/usr/bin/env python3
"""Phase 1 of the LSA pipeline: deterministic pre-scan.

Usage: run_prescan.py TARGET OUT [--config audit-config.json]

Writes into OUT:
  stack-profile.json, routes.candidates.json, injection.candidates.json,
  batches/*.json, prescan-summary.md
OUT must not be inside TARGET (audit output never goes into the audited repo).
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from detect_stack import detect  # noqa: E402
from find_injection import find_injection  # noqa: E402
from lsa_common import KIT_VERSION, load_config, write_json  # noqa: E402
from make_batches import make_batches  # noqa: E402
from map_routes import map_routes  # noqa: E402
from scan_cache import ScanCache, compute_config_hash  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target")
    ap.add_argument("out")
    ap.add_argument("--config")
    ap.add_argument("--workers", "-j", type=int, default=0,
                    help="Number of worker processes for parallel scan (default: 0 = auto/cpu_count)")
    ap.add_argument("--no-cache", action="store_true", help="Disable content-hash candidate caching")
    ap.add_argument("--clean-cache", action="store_true", help="Clear existing candidate cache before scan")
    ap.add_argument("--cache-dir", help="Path to cache directory (default: OUT/.cache)")
    a = ap.parse_args()
    target, out = Path(a.target).resolve(), Path(a.out).resolve()
    if not target.is_dir():
        print(f"error: target {target} is not a directory", file=sys.stderr)
        return 2
    if out == target or target in out.parents:
        print("error: OUT must be outside TARGET", file=sys.stderr)
        return 2
    cfg = load_config(a.config)
    out.mkdir(parents=True, exist_ok=True)
    effective_workers = a.workers if a.workers > 0 else (os.cpu_count() or 1)

    # Initialize content-hash caching
    cache_dir = Path(a.cache_dir).resolve() if a.cache_dir else (out / ".cache")
    cache = ScanCache(cache_dir=cache_dir, enabled=(not a.no_cache))
    if a.clean_cache:
        cache.clean()

    t0 = time.time()
    prof = detect(target, cfg)
    write_json(out / "stack-profile.json", prof)

    stack_ids = {s["id"] for s in prof["stacks"]}
    cfg_hash = compute_config_hash(cfg, stack_ids)
    cache.load(cfg_hash)

    routes = map_routes(target, cfg, stack_ids, workers=a.workers, cache=cache)
    write_json(out / "routes.candidates.json", routes)
    inj = find_injection(target, cfg, workers=a.workers, cache=cache)
    write_json(out / "injection.candidates.json", inj)

    if cache.enabled:
        cache.save()

    idx = make_batches(out, cfg)
    write_json(out / "audit-config.effective.json", cfg)
    dt = time.time() - t0

    cache_summary = "disabled"
    if cache.enabled:
        tot = cache.total_hits + cache.total_misses
        pct = (cache.total_hits / tot * 100) if tot > 0 else 0
        cache_summary = f"{cache.total_hits} hits, {cache.total_misses} misses ({pct:.1f}% hit rate)"

    lines = [
        f"# Pre-scan summary — {target.name}", "",
        f"- Kit version: {KIT_VERSION}", f"- Duration: {dt:.1f}s",
        f"- Workers: {effective_workers}",
        f"- Cache: {cache_summary}",
        f"- Stacks: {', '.join(s['id'] for s in prof['stacks']) or 'none detected'}",
        f"- Data access: {', '.join(prof['data_access']) or 'unknown'}",
        f"- Route candidates: {routes['summary']['total']} (with id-like params: {routes['summary']['with_id_like_params']})",
        f"- Injection candidates: {inj['summary']['total']} (high priority: {inj['summary']['high_priority']})",
        f"- Batches: {len(idx['routes'])} route, {len(idx['injection'])} injection",
        f"- Knowledge files to load: {', '.join(prof['knowledge_files'])}", "",
        "Next: run the stack-detector agent (prompts/10-stack-detector.md).",
    ]
    (out / "prescan-summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
