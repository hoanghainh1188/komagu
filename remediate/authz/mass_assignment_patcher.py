"""Automated Mass Assignment Allow-List Patcher (OWASP API3:2023, CWE-915).

Rewrites whole-object request body bindings into explicit allow-list calls
using Komagu's allowFields / AllowFields helpers or framework-native include
filters when explicit allowed_fields are provided in the finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from remediate.authz.bfla_patcher import _ensure_go_import, _ensure_js_named_imports
from remediate.authz.patcher import _newline_of

_JS_REQ_BODY = re.compile(r"\breq\.body\b")
_PY_MODEL_DUMP = re.compile(r"\b(?P<var>[A-Za-z_][A-Za-z0-9_]*)\.(?P<method>model_dump|dict)\s*\(\s*\)")
_GO_MAP_ARG = re.compile(r"(?P<call>[A-Za-z_][A-Za-z0-9_.]*\([^)]*\b)(?P<arg>body|payload|input|updates|fields)\b")


@dataclass
class MassAssignmentRewriteResult:
    """Represents the outcome of rewriting a mass-assignment binding."""

    original_line: str
    patched_line: str
    allowed_fields: Tuple[str, ...] = ()
    imported: bool = False
    changed: bool = False
    explanation: str = ""


def _extract_allowed_fields(finding: Dict[str, Any]) -> List[str]:
    """Extract validated allowed field names from finding metadata, if explicitly supplied."""
    candidates: Any = finding.get("allowed_fields")
    if candidates is None:
        evidence = finding.get("evidence")
        if isinstance(evidence, dict):
            candidates = evidence.get("allowed_fields")
    if not isinstance(candidates, list):
        return []
    cleaned: List[str] = []
    for item in candidates:
        if isinstance(item, str):
            name = item.strip()
            if name and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                cleaned.append(name)
    return cleaned


class MassAssignmentPatcher:
    """Rewrites unsafe whole-object bindings into explicit allow-list bindings."""

    EXT_TO_LANG: Dict[str, str] = {
        ".ts": "typescript",
        ".js": "javascript",
        ".py": "python",
        ".go": "golang",
    }

    def detect_language(self, file_path: Path | str) -> str:
        """Infer language from file extension."""
        return self.EXT_TO_LANG.get(Path(file_path).suffix.lower(), "generic")

    def patch_file(
        self,
        target_file: Path,
        line_number: int,
        finding: Dict[str, Any],
        content: Optional[str] = None,
    ) -> Tuple[str, MassAssignmentRewriteResult]:
        """Rewrite an unsafe mass-assignment line using explicit allowed_fields from finding."""
        if content is None:
            content = Path(target_file).read_bytes().decode("utf-8")
        lines = content.splitlines(keepends=True)
        idx = line_number - 1

        if idx < 0 or idx >= len(lines):
            return content, MassAssignmentRewriteResult("", "", changed=False, explanation="Line number out of bounds.")

        target_line = lines[idx]
        allowed = _extract_allowed_fields(finding)
        if not allowed:
            return content, MassAssignmentRewriteResult(
                original_line=target_line,
                patched_line=target_line,
                changed=False,
                explanation="No allowed_fields provided in finding; requires manual allow-list definition.",
            )

        lang = self.detect_language(target_file)

        if lang in ("typescript", "javascript"):
            if "allowFields(" in target_line:
                return content, MassAssignmentRewriteResult(
                    original_line=target_line,
                    patched_line=target_line,
                    allowed_fields=tuple(allowed),
                    changed=False,
                    explanation="allowFields() guard already applied on target line.",
                )
            if not _JS_REQ_BODY.search(target_line):
                return content, MassAssignmentRewriteResult(
                    original_line=target_line,
                    patched_line=target_line,
                    allowed_fields=tuple(allowed),
                    changed=False,
                    explanation="No direct req.body binding found on target line; requires manual remediation.",
                )
            fields_js = ", ".join(f"'{f}'" for f in allowed)
            rewritten = _JS_REQ_BODY.sub(f"allowFields(req.body, [{fields_js}])", target_line, count=1)
            lines[idx] = rewritten
            final_content, imported = _ensure_js_named_imports("".join(lines), ["allowFields"])
            return final_content, MassAssignmentRewriteResult(
                original_line=target_line,
                patched_line=rewritten,
                allowed_fields=tuple(allowed),
                imported=imported,
                changed=True,
                explanation=f"Wrapped req.body with allowFields(..., [{fields_js}]).",
            )

        if lang == "python":
            match = _PY_MODEL_DUMP.search(target_line)
            if not match:
                return content, MassAssignmentRewriteResult(
                    original_line=target_line,
                    patched_line=target_line,
                    allowed_fields=tuple(allowed),
                    changed=False,
                    explanation="No unguarded Pydantic .dict()/.model_dump() call on target line; requires manual remediation.",
                )
            fields_py = ", ".join(f'"{f}"' for f in allowed)
            replacement = f"{match.group('var')}.{match.group('method')}(include={{{fields_py}}})"
            rewritten = target_line[: match.start()] + replacement + target_line[match.end():]
            lines[idx] = rewritten
            return "".join(lines), MassAssignmentRewriteResult(
                original_line=target_line,
                patched_line=rewritten,
                allowed_fields=tuple(allowed),
                imported=False,
                changed=True,
                explanation=f"Restricted {match.group('method')}() with include={{{fields_py}}}.",
            )

        if lang == "golang":
            if "AllowFields(" in target_line:
                return content, MassAssignmentRewriteResult(
                    original_line=target_line,
                    patched_line=target_line,
                    allowed_fields=tuple(allowed),
                    changed=False,
                    explanation="AllowFields() guard already applied on target line.",
                )
            match = _GO_MAP_ARG.search(target_line)
            if not match:
                return content, MassAssignmentRewriteResult(
                    original_line=target_line,
                    patched_line=target_line,
                    allowed_fields=tuple(allowed),
                    changed=False,
                    explanation="No direct map payload binding found on target line; requires manual remediation.",
                )
            fields_go = ", ".join(f'"{f}"' for f in allowed)
            replacement = f"{match.group('call')}komaguauthz.AllowFields({match.group('arg')}, {fields_go})"
            rewritten = target_line[: match.start()] + replacement + target_line[match.end():]
            lines[idx] = rewritten
            final_content, imported = _ensure_go_import(
                "".join(lines), "komaguauthz", "github.com/hoanghainh1188/komagu/remediate/authz/golang"
            )
            return final_content, MassAssignmentRewriteResult(
                original_line=target_line,
                patched_line=rewritten,
                allowed_fields=tuple(allowed),
                imported=imported,
                changed=True,
                explanation=f"Wrapped {match.group('arg')} with komaguauthz.AllowFields(..., {fields_go}).",
            )

        return content, MassAssignmentRewriteResult(
            original_line=target_line,
            patched_line=target_line,
            allowed_fields=tuple(allowed),
            changed=False,
            explanation=f"Automated mass-assignment rewrite not supported for language '{lang}'; requires manual remediation.",
        )
