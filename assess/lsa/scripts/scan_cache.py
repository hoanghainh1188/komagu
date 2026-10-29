#!/usr/bin/env python3
"""Content-hash based scan caching engine for LSA (Issue #197).

Provides SHA-256 file-level candidate caching for map_routes and find_injection.
Skips untouched files across repeated scans, achieving orders-of-magnitude speedups.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lsa_common import KIT_VERSION  # noqa: E402


def compute_file_sha256(path: Path) -> str:
    """Compute SHA-256 checksum of a file in 64KB blocks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def compute_config_hash(config: Dict, stack_ids: Optional[Set[str]] = None) -> str:
    """Compute a deterministic hash of scan configuration and detected stacks."""
    h = hashlib.sha256()
    h.update(f"KIT:{KIT_VERSION}".encode("utf-8"))
    if stack_ids:
        h.update(f"STACKS:{sorted(stack_ids)}".encode("utf-8"))
    # The diff-mode file list only narrows which files are read; per-file results are unchanged
    scope = {k: v for k, v in (config.get("scope") or {}).items() if k != "only_files"}
    canonical_cfg = json.dumps({**config, "scope": scope}, sort_keys=True, separators=(",", ":"))
    h.update(canonical_cfg.encode("utf-8"))
    return h.hexdigest()


class ScanCache:
    """Manages persistent SHA-256 content-hash caching for LSA security candidates."""

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        enabled: bool = True,
    ) -> None:
        self.enabled = enabled
        self.cache_dir = cache_dir
        self.cache_file = (cache_dir / "lsa-cache.json") if cache_dir else None
        self.config_hash: str = ""
        self.entries: Dict[str, Dict[str, Any]] = {}
        self.stats = {
            "routes_hits": 0,
            "routes_misses": 0,
            "injection_hits": 0,
            "injection_misses": 0,
            "mass_hits": 0,
            "mass_misses": 0,
        }

    @property
    def total_hits(self) -> int:
        return self.stats["routes_hits"] + self.stats["injection_hits"] + self.stats["mass_hits"]

    @property
    def total_misses(self) -> int:
        return self.stats["routes_misses"] + self.stats["injection_misses"] + self.stats["mass_misses"]

    def load(self, config_hash: str) -> bool:
        """Load cache from disk. Invalidate if config_hash or kit_version mismatch."""
        self.config_hash = config_hash
        self.entries.clear()
        self.stats = {
            "routes_hits": 0,
            "routes_misses": 0,
            "injection_hits": 0,
            "injection_misses": 0,
            "mass_hits": 0,
            "mass_misses": 0,
        }

        if not self.enabled or not self.cache_file or not self.cache_file.is_file():
            return False

        try:
            data = json.loads(self.cache_file.read_text(encoding="utf-8"))
            if data.get("kit_version") != KIT_VERSION or data.get("config_hash") != config_hash:
                return False
            self.entries = data.get("files", {})
            return True
        except Exception:
            self.entries.clear()
            return False

    def _is_file_fresh(self, rel: str, path: Path) -> Optional[Dict[str, Any]]:
        """Validate whether the file is unchanged in size, mtime, or sha256."""
        entry = self.entries.get(rel)
        if not entry:
            return None

        try:
            stat = path.stat()
            if entry.get("mtime") == stat.st_mtime and entry.get("size") == stat.st_size:
                return entry

            curr_sha = compute_file_sha256(path)
            if curr_sha == entry.get("sha256"):
                entry["mtime"] = stat.st_mtime
                entry["size"] = stat.st_size
                return entry
        except Exception:
            pass

        return None

    def get_routes(self, rel: str, path: Path) -> Optional[Tuple[List[Dict], Optional[str]]]:
        """Retrieve cached route candidate items and optional Java source text."""
        if not self.enabled:
            return None

        entry = self._is_file_fresh(rel, path)
        if entry and entry.get("routes_cached"):
            self.stats["routes_hits"] += 1
            return entry.get("route_items", []), entry.get("java_text")

        self.stats["routes_misses"] += 1
        return None

    def put_routes(
        self,
        rel: str,
        path: Path,
        route_items: List[Dict],
        java_text: Optional[str] = None,
    ) -> None:
        """Store route candidates for a file."""
        if not self.enabled:
            return

        try:
            stat = path.stat()
            sha = compute_file_sha256(path)
            entry = self.entries.setdefault(rel, {})
            entry.update({
                "sha256": sha,
                "mtime": stat.st_mtime,
                "size": stat.st_size,
                "route_items": route_items,
                "java_text": java_text,
                "routes_cached": True,
            })
        except Exception:
            pass

    def get_injection(self, rel: str, path: Path) -> Optional[Tuple[List[Dict], List[Dict]]]:
        """Retrieve cached injection candidates and suppressed items."""
        if not self.enabled:
            return None

        entry = self._is_file_fresh(rel, path)
        if entry and entry.get("injection_cached"):
            self.stats["injection_hits"] += 1
            return entry.get("injection_items", []), entry.get("injection_suppressed", [])

        self.stats["injection_misses"] += 1
        return None

    def put_injection(
        self,
        rel: str,
        path: Path,
        injection_items: List[Dict],
        injection_suppressed: List[Dict],
    ) -> None:
        """Store injection candidates for a file."""
        if not self.enabled:
            return

        try:
            stat = path.stat()
            sha = compute_file_sha256(path)
            entry = self.entries.setdefault(rel, {})
            entry.update({
                "sha256": sha,
                "mtime": stat.st_mtime,
                "size": stat.st_size,
                "injection_items": injection_items,
                "injection_suppressed": injection_suppressed,
                "injection_cached": True,
            })
        except Exception:
            pass

    def get_mass(self, rel: str, path: Path) -> Optional[Tuple[List[Dict], Dict[str, Any]]]:
        """Retrieve cached mass assignment candidates and model facts for a file."""
        if not self.enabled:
            return None

        entry = self._is_file_fresh(rel, path)
        if entry and entry.get("mass_cached"):
            self.stats["mass_hits"] += 1
            return entry.get("mass_items", []), entry.get("mass_meta", {})

        self.stats["mass_misses"] += 1
        return None

    def put_mass(self, rel: str, path: Path, mass_items: List[Dict], mass_meta: Dict[str, Any]) -> None:
        """Store mass assignment candidates and model facts for a file."""
        if not self.enabled:
            return

        try:
            stat = path.stat()
            entry = self.entries.setdefault(rel, {})
            entry.update({
                "sha256": compute_file_sha256(path),
                "mtime": stat.st_mtime,
                "size": stat.st_size,
                "mass_items": mass_items,
                "mass_meta": mass_meta,
                "mass_cached": True,
            })
        except Exception:
            pass

    def save(self) -> None:
        """Atomically persist cache entries to disk."""
        if not self.enabled or not self.cache_file or not self.cache_dir:
            return

        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            payload = {
                "kit_version": KIT_VERSION,
                "config_hash": self.config_hash,
                "files": self.entries,
            }
            tmp = self.cache_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self.cache_file)
        except Exception:
            pass

    def clean(self) -> None:
        """Remove cached files from disk."""
        if self.cache_file and self.cache_file.is_file():
            try:
                self.cache_file.unlink()
            except Exception:
                pass
        self.entries.clear()
