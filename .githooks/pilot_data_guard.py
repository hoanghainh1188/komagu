#!/usr/bin/env python3
"""Stop real pilot configuration and outputs from reaching this public repository (runbook W9-1).

The pre-push hook passes its ref lines on stdin and every commit about to leave this clone is checked, so data added
and then removed in a later commit is still caught. `--tree` checks the tracked tree only (used by the test suite as
a backstop for clones without the hook). Standard-library only (Python 3.8+).

The fallback pilot (Deliverable D6) keeps its tracked files. To push a deliberate edit of a frozen fallback record,
set KOMAGU_ALLOW_FALLBACK_EDIT=1 for that push: every other rule still applies.
"""

from __future__ import annotations

import fnmatch
import json
import os
import subprocess
import sys
from typing import Callable, Iterable, List, Optional, Sequence

PILOT_DIR = "delivery/pilot/"
AUDIT_OUT = PILOT_DIR + "audit-out/"
CONFIG = PILOT_DIR + "pilot-config.json"
SAMPLE_CONFIG = PILOT_DIR + "pilot-config.sample.json"
FROZEN_FILES = frozenset({PILOT_DIR + "timesheet-pilot.csv"})
ALLOWED_PILOT_FILES = FROZEN_FILES | frozenset(
    PILOT_DIR + name
    for name in (
        "ams-exclude.sample.txt",
        "data-deletion-report.template.md",
        "pilot-config.json",
        "pilot-config.sample.json",
        "pilot-final-report.md",
        "remediation-verification.md",
        "timesheet-template.csv",
        "verify_pilot_edge.py",
    )
)
FORBIDDEN_DIRECTORIES = frozenset({"ai-raw"})
FORBIDDEN_NAMES = ("ams-exclude.txt", "src-file-list.txt", "data-deletion-report.md", "leak-check.json", "canaries*.txt")
FALLBACK_PILOT_PREFIX = "PILOT-D6-FALLBACK"


def path_violation(path: str) -> Optional[str]:
    """Why this path must not be in the repository, whatever the commit."""
    # Lower-cased: macOS and Windows treat Canaries.txt and canaries.txt as the same working file
    directories, name = path.lower().split("/")[:-1], path.lower().rsplit("/", 1)[-1]
    if FORBIDDEN_DIRECTORIES.intersection(directories):
        return "raw model output belongs in the secure pilot directory"
    if any(fnmatch.fnmatch(name, pattern) for pattern in FORBIDDEN_NAMES):
        return "real pilot working file belongs in the secure pilot directory"
    if path.startswith(PILOT_DIR) and not path.startswith(AUDIT_OUT) and path not in ALLOWED_PILOT_FILES:
        return f"not a known tracked file of {PILOT_DIR} (a real pilot file? otherwise add it to ALLOWED_PILOT_FILES)"
    return None


def frozen_violation(path: str) -> Optional[str]:
    """Fallback records that keep their name: a real output copied over them would look like a normal edit."""
    if os.environ.get("KOMAGU_ALLOW_FALLBACK_EDIT") == "1":
        return None
    if path.startswith(AUDIT_OUT) or path in FROZEN_FILES:
        return "frozen fallback pilot record (if this edit is intended, push with KOMAGU_ALLOW_FALLBACK_EDIT=1)"
    return None


def _parse(blob: bytes) -> Optional[dict]:
    try:
        parsed = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _config_violation(blob: bytes) -> Optional[str]:
    config = _parse(blob)
    if config is None:
        return "not valid JSON, so it cannot be confirmed as the fallback configuration"
    governance = config.get("governance") or {}
    is_fallback = (
        str(config.get("pilotId", "")).startswith(FALLBACK_PILOT_PREFIX)
        and governance.get("fallbackActive") is True
        and governance.get("writtenConsentApproved") is False
    )
    return None if is_fallback else "real pilot configuration: keep it in the secure pilot directory (runbook W9-1)"


def _sample_violation(blob: bytes) -> Optional[str]:
    config = _parse(blob)
    if config is None:
        return "not valid JSON, so it cannot be confirmed as a sample"
    name = str((config.get("system") or {}).get("name", ""))
    is_blank = (
        name.startswith("<")
        and (config.get("governance") or {}).get("approvalDate") is None
        and (config.get("hosting") or {}).get("selected") is None
    )
    return None if is_blank else "the sample has been filled in: copy it to the secure pilot directory instead"


CONTENT_CHECKS = {CONFIG: _config_violation, SAMPLE_CONFIG: _sample_violation}


def _git(*args: str) -> bytes:
    return subprocess.run(["git", *args], check=True, stdout=subprocess.PIPE).stdout


def _names(output: bytes) -> List[str]:
    return [name.decode("utf-8", "surrogateescape") for name in output.split(b"\0") if name]


def _content_violations(paths: Iterable[str], read: Callable[[str], bytes]) -> List[str]:
    return [f"{path}: {reason}" for path in paths if path in CONTENT_CHECKS for reason in [CONTENT_CHECKS[path](read(path))] if reason]


def check_commit(commit: str) -> List[str]:
    """Violations introduced by one commit; merges report only what differs from every parent."""
    paths = _names(_git("diff-tree", "--root", "--no-commit-id", "--name-only", "-r", "-c", "-z", "--diff-filter=ACMRT", commit))
    problems = [
        f"{commit[:12]} {path}: {reason}"
        for path in paths
        for reason in (path_violation(path), frozen_violation(path))
        if reason
    ]
    problems.extend(f"{commit[:12]} {item}" for item in _content_violations(paths, lambda path: _git("show", f"{commit}:{path}")))
    return problems


def check_tree() -> List[str]:
    """Violations in the tracked tree. Frozen files are not checked here: they are expected to exist."""
    paths = _names(_git("ls-files", "-z"))
    problems = [f"{path}: {reason}" for path in paths for reason in [path_violation(path)] if reason]
    problems.extend(_content_violations(paths, lambda path: _git("show", f":{path}")))
    return problems


def outgoing_commits(local_sha: str, remote_sha: str) -> List[str]:
    """Commits that no remote-tracking branch already has; a stale clone only means extra checking."""
    args = ["rev-list", local_sha, "--not", "--remotes"]
    if set(remote_sha) != {"0"}:
        known = subprocess.run(["git", "cat-file", "-e", remote_sha], stderr=subprocess.DEVNULL).returncode == 0
        if known:
            args.append(remote_sha)
    return [line for line in _git(*args).decode().splitlines() if line]


def check_push(ref_lines: Sequence[str]) -> List[str]:
    problems: List[str] = []
    for line in ref_lines:
        fields = line.split()
        if len(fields) != 4 or set(fields[1]) == {"0"}:
            continue  # a branch deletion carries no content
        for commit in outgoing_commits(fields[1], fields[3]):
            problems.extend(check_commit(commit))
    return problems


def main(argv: Sequence[str]) -> int:
    problems = check_tree() if "--tree" in argv else check_push(sys.stdin.read().splitlines())
    if not problems:
        return 0
    print("pilot data guard: blocked. This repository is public.", file=sys.stderr)
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
