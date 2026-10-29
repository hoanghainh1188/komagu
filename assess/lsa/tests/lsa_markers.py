"""Read LSA-EXPECT markers from fixture files.

Marker syntax (at the end of a code line, inside that language's comment):
    LSA-EXPECT:SQLI             query built from input; pre-scan MUST flag; agents MUST report
    LSA-EXPECT:NOSQL            NoSQL injection; pre-scan MUST flag; agents MUST report
    LSA-EXPECT:SAFE-SQL         pre-scan may flag; agents MUST judge safe (cast / escaped string context)
    LSA-EXPECT:SAFE-SQL-NOFLAG  parameterized; pre-scan must NOT flag
    LSA-EXPECT:BOLA             object access without ownership binding; route must be found; agents MUST report
    LSA-EXPECT:SAFE-BOLA        ownership is bound; agents must NOT report
    LSA-EXPECT:BFLA             privileged function without a server-side role check; pre-scan MUST set
                                needs_bfla_audit_hint on the covering route; agents MUST report
    LSA-EXPECT:SAFE-BFLA        role is enforced server-side; pre-scan must NOT set the hint
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List

MARK_RE = re.compile(r"LSA-EXPECT:([A-Z-]+)")
STRIP_RE = re.compile(r"\s*(?://|#|'|--|<!---|<!--)\s*(?:LSA-EXPECT:[A-Z-]+\s*)+(?:--->|-->)?\s*$")


def iter_files(root: Path):
    for dp, _dn, fns in os.walk(root):
        for fn in sorted(fns):
            p = Path(dp) / fn
            yield p, p.relative_to(root).as_posix()


def read_markers(root: Path) -> List[Dict]:
    out = []
    for p, rel in iter_files(root):
        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for m in MARK_RE.finditer(line):
                out.append({"file": rel, "line": i, "label": m.group(1)})
    return out


def strip_markers(text: str) -> str:
    return "\n".join(STRIP_RE.sub("", ln) for ln in text.splitlines()) + ("\n" if text.endswith("\n") else "")
