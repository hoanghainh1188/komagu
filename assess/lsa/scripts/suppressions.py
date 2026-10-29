#!/usr/bin/env python3
"""Approved, expiring suppressions for accepted-risk findings.

File format (JSON, because Tier 1 is stdlib-only and Python has no YAML parser):

  {
    "version": 1,
    "suppressions": [
      {"fingerprint": "kfp1:<64 hex>", "reason": "...", "approved_by": "...", "expires": "2027-03-31"}
    ]
  }

A suppression hides a finding from the CI gate and marks it as accepted in
SARIF. It is valid up to and including its expiry date; after that the finding
counts again. `expires` may be null, but every entry needs a reason and an
approver (see governance/ human-in-the-loop sign-off).

Standard-library-only (Python 3.8+).
"""
from __future__ import annotations

import datetime
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lsa_common import read_json  # noqa: E402

FINGERPRINT_RE = re.compile(r"^kfp1:[0-9a-f]{64}$")
DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


class SuppressionError(Exception):
    """The suppressions file is missing, unreadable or invalid."""


@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    reason: str
    approved_by: str
    expires: Optional[str] = None

    def is_expired(self, today: str) -> bool:
        return self.expires is not None and self.expires < today

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass(frozen=True)
class SuppressionResult:
    findings: List[Dict]
    expired: List[Suppression]
    unused: List[Suppression]


def _valid_date(value: str) -> bool:
    if not DATE_RE.match(value):
        return False
    try:
        datetime.date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _parse_entry(entry: object, idx: int) -> Suppression:
    where = f"suppressions[{idx}]"
    if not isinstance(entry, dict):
        raise SuppressionError(f"{where}: expected an object")
    fp = entry.get("fingerprint")
    if not isinstance(fp, str) or not FINGERPRINT_RE.match(fp):
        raise SuppressionError(f"{where}: fingerprint must look like kfp1:<64 lowercase hex>")
    for field in ("reason", "approved_by"):
        value = entry.get(field)
        if not isinstance(value, str) or not value.strip():
            raise SuppressionError(f"{where}: '{field}' is required")
    expires = entry.get("expires")
    if expires is not None and (not isinstance(expires, str) or not _valid_date(expires)):
        raise SuppressionError(f"{where}: expires must be a YYYY-MM-DD date or null")
    return Suppression(fp, entry["reason"].strip(), entry["approved_by"].strip(), expires)


def load_suppressions(path: Path) -> List[Suppression]:
    """Load and validate a suppressions file."""
    try:
        doc = read_json(path)
    except FileNotFoundError as exc:
        raise SuppressionError(f"suppressions file not found: {path}") from exc
    except (OSError, ValueError) as exc:
        raise SuppressionError(f"cannot read suppressions {path}: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("version") != 1 or not isinstance(doc.get("suppressions"), list):
        raise SuppressionError(f"{path}: expected {{\"version\": 1, \"suppressions\": [...]}}")
    parsed = [_parse_entry(e, i) for i, e in enumerate(doc["suppressions"])]
    seen = set()
    for s in parsed:
        if s.fingerprint in seen:
            raise SuppressionError(f"{path}: duplicate fingerprint {s.fingerprint}")
        seen.add(s.fingerprint)
    return parsed


def apply_suppressions(findings: List[Dict], suppressions: List[Suppression], today: str) -> SuppressionResult:
    """Return copies of the findings with active suppressions attached."""
    active = {s.fingerprint: s for s in suppressions if not s.is_expired(today)}
    matched = set()
    annotated: List[Dict] = []
    for f in findings:
        copy = {k: v for k, v in f.items() if k != "suppression"}
        rule = active.get(f.get("fingerprint", "")) if f.get("status") != "rejected" else None
        if rule:
            copy["suppression"] = {"reason": rule.reason, "approved_by": rule.approved_by, "expires": rule.expires}
            matched.add(rule.fingerprint)
        annotated.append(copy)
    return SuppressionResult(
        findings=annotated,
        expired=[s for s in suppressions if s.is_expired(today)],
        unused=[s for s in suppressions if not s.is_expired(today) and s.fingerprint not in matched],
    )
