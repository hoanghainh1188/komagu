#!/usr/bin/env python3
"""Deterministic Tier 1 pre-scanner for Path Traversal (CWE-22) and SSRF (CWE-918).

Usage: find_path_ssrf.py TARGET [--config audit-config.json] [--out path-ssrf.candidates.json]

Standard-library-only (Python 3.8+).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lsa_common import KIT_VERSION, iter_source_files, load_config, write_json  # noqa: E402
from redaction import redact  # noqa: E402

_PATH_SINKS: Tuple[Tuple[str, Pattern[str]], ...] = (
    ("fs_read_node", re.compile(r"\b(?:fs\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync)|res\.(?:sendFile|download))\s*\(")),
    ("path_open_py", re.compile(r"\b(?:open|send_file|send_from_directory)\s*\(")),
    ("file_java", re.compile(r"\b(?:new\s+File|Paths\.get|Files\.(?:readAllBytes|readString|newInputStream|copy))\s*\(")),
    ("file_php", re.compile(r"\b(?:file_get_contents|fopen|readfile|include_once|require_once|include|require)\s*(?:\(| )")),
    ("file_dotnet", re.compile(r"\bFile\.(?:ReadAllText|ReadAllBytes|OpenRead|OpenWrite)\s*\(")),
    ("file_go", re.compile(r"\b(?:os\.(?:Open|ReadFile|Create)|ioutil\.ReadFile)\s*\(")),
)

_SSRF_SINKS: Tuple[Tuple[str, Pattern[str]], ...] = (
    ("http_py", re.compile(r"\b(?:requests\.(?:get|post|put|delete|head|request)|urllib\.request\.urlopen|httpx\.(?:get|post|request))\s*\(")),
    ("http_node", re.compile(r"\b(?:fetch|axios(?:\.(?:get|post|put|request))?|https?\.(?:get|request))\s*\(")),
    ("http_java", re.compile(r"\b(?:new\s+URL\s*\(|HttpURLConnection|RestTemplate\.(?:getFor|postFor|exchange)|WebClient\.)")),
    ("http_php", re.compile(r"\b(?:curl_init|file_get_contents)\s*\(")),
    ("http_dotnet", re.compile(r"\b(?:HttpClient|WebRequest\.Create)\b")),
    ("http_go", re.compile(r"\bhttp\.(?:Get|Post|NewRequest)\s*\(")),
)

_REQUEST_INPUT_HINT = re.compile(
    r"(?:\$_(?:GET|POST|REQUEST)|"
    r"\breq(?:uest)?\.(?:query|params|body|args|form|GET|POST|URL)|"
    r"\b(?:getParameter|@RequestParam|@PathVariable|r\.URL\.Query|QueryRow|Request\.QueryString)\b|"
    r"\b(?:file_?name|file_?path|target_?url|webhook_?url|callback_?url|redirect_?url|endpoint_?url|avatar_?url)\b)",
    re.IGNORECASE,
)

_LITERAL_ONLY_CALL = re.compile(
    r"\(\s*(?:['\"][^'\"]+['\"]\s*(?:,|\))|`https?://[^`$]+`)"
)

_PATH_SANITIZER_HINT = re.compile(
    r"(?:\brealpath\b|\bcanonical(?:Path)?\b|\bGetFullPath\b|\bPath\.basename\b|\bos\.path\.basename\b|\bfilepath\.Clean\b|\bstartsWith\s*\()",
    re.IGNORECASE,
)

_SSRF_SANITIZER_HINT = re.compile(
    r"(?:\ballowlist\b|\bwhitelist\b|\ballowed_?hosts?\b|\bis_safe_url\b|\bvalidate_url\b)",
    re.IGNORECASE,
)


def _has_nearby_input(lines: List[str], idx: int, window: int = 5) -> bool:
    """True when request-controlled input appears on the sink line or within +-window lines."""
    start = max(0, idx - window)
    end = min(len(lines), idx + 2)
    snippet = "\n".join(lines[start:end])
    return _REQUEST_INPUT_HINT.search(snippet) is not None


def _has_nearby_guard(lines: List[str], idx: int, guard_rx: Pattern[str], window: int = 4) -> bool:
    """True when a sanitizer/allow-list guard is visible near the sink."""
    start = max(0, idx - window)
    end = min(len(lines), idx + 2)
    return guard_rx.search("\n".join(lines[start:end])) is not None


def scan_file_path_ssrf(path: Path, rel: str) -> List[Dict[str, Any]]:
    """Scan a single source file for Path Traversal (CWE-22) and SSRF (CWE-918) candidates."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    lines = text.splitlines()
    candidates: List[Dict[str, Any]] = []

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "#", "/*", "*")):
            continue
        if _LITERAL_ONLY_CALL.search(stripped):
            continue

        # Check SSRF first when PHP file_get_contents is used with URL hints
        matched_ssrf = False
        for sink_id, rx in _SSRF_SINKS:
            if rx.search(stripped):
                if sink_id == "http_php" and "file_get_contents" in stripped and not re.search(r"url|http", stripped, re.IGNORECASE):
                    continue
                if _has_nearby_input(lines, idx) and not _has_nearby_guard(lines, idx, _SSRF_SANITIZER_HINT):
                    candidates.append(
                        {
                            "category": "ssrf",
                            "cwe": "CWE-918",
                            "sink": sink_id,
                            "file": rel,
                            "line": idx + 1,
                            "snippet": redact(stripped[:240]),
                            "priority": "high",
                        }
                    )
                    matched_ssrf = True
                break

        if matched_ssrf:
            continue

        for sink_id, rx in _PATH_SINKS:
            if rx.search(stripped):
                if _has_nearby_input(lines, idx) and not _has_nearby_guard(lines, idx, _PATH_SANITIZER_HINT):
                    candidates.append(
                        {
                            "category": "path_traversal",
                            "cwe": "CWE-22",
                            "sink": sink_id,
                            "file": rel,
                            "line": idx + 1,
                            "snippet": redact(stripped[:240]),
                            "priority": "high",
                        }
                    )
                break

    return candidates


def find_path_ssrf(target: Path, config: Dict[str, Any], cache: Optional[Any] = None) -> Dict[str, Any]:
    """Scan target directory for Path Traversal and SSRF candidates."""
    all_candidates: List[Dict[str, Any]] = []
    files_scanned = 0

    for path, rel in iter_source_files(target, config):
        files_scanned += 1
        found = scan_file_path_ssrf(path, rel)
        all_candidates.extend(found)

    path_count = sum(1 for c in all_candidates if c["category"] == "path_traversal")
    ssrf_count = sum(1 for c in all_candidates if c["category"] == "ssrf")

    return {
        "generated_by": f"lsa find_path_ssrf.py {KIT_VERSION}",
        "files_scanned": files_scanned,
        "summary": {
            "total": len(all_candidates),
            "path_traversal": path_count,
            "ssrf": ssrf_count,
        },
        "candidates": all_candidates,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target")
    ap.add_argument("--config")
    ap.add_argument("--out")
    a = ap.parse_args()
    res = find_path_ssrf(Path(a.target).resolve(), load_config(a.config))
    if a.out:
        write_json(Path(a.out), res)
    else:
        print(f"path_traversal={res['summary']['path_traversal']} ssrf={res['summary']['ssrf']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
