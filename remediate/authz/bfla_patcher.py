"""Automated BFLA Role Guard Patcher (OWASP API5:2023, CWE-285 / CWE-862).

Injects fail-closed role authorization guards (@RequireRole, requireRole,
[RequireRole], komaguauthz.RequireRole) above or around privileged endpoints
across TypeScript/JavaScript (NestJS & Express), C#, Java (Spring), and Go.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from remediate.authz.patcher import (
    _JAVA_PACKAGE_STATEMENT,
    _SPRING_CONTROLLER,
    _is_java_handler_line,
    _newline_of,
)

_EXPRESS_ROUTE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<router>[A-Za-z_][A-Za-z0-9_$.]*)\."
    r"(?P<method>get|post|put|patch|delete)\s*\(\s*"
    r"(?P<path>['\"`][^'\"`]+['\"`])\s*,\s*"
    r"(?P<handler>[A-Za-z_][A-Za-z0-9_$.]*)\s*\)(?P<tail>[ \t]*;?)[ \t]*(?P<eol>\r?\n?)$"
)

_GO_HANDLE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<router>[A-Za-z_][A-Za-z0-9_.]*)\."
    r"(?P<fn>Handle|HandleFunc)\s*\(\s*"
    r"(?P<path>\"[^\"]+\")\s*,\s*"
    r"(?P<handler>[A-Za-z_][A-Za-z0-9_.]*)\s*\)[ \t]*(?P<eol>\r?\n?)$"
)

_GO_IMPORT_SINGLE = re.compile(r'^(?P<indent>[ \t]*)import\s+"(?P<pkg>[^"]+)"[ \t]*(?P<eol>\r?\n?)$', re.MULTILINE)
_GO_IMPORT_BLOCK = re.compile(r"^(?P<indent>[ \t]*)import\s*\((?P<body>.*?)\)", re.MULTILINE | re.DOTALL)
_GO_PACKAGE = re.compile(r"^[ \t]*package\s+\w+[ \t]*(?:\r\n|\r|\n)", re.MULTILINE)

_ROLE_GUARD_MARKERS = (
    "RequireRole",
    "KomaguRoleGuard",
    "requireRole",
    "@RolesAllowed",
    "@PreAuthorize",
    "[Authorize(Roles",
)

_ROLE_PATH_HINTS: Tuple[Tuple[str, str], ...] = (
    ("/admin", "admin"),
    ("/staff", "staff"),
    ("/internal", "internal"),
    ("/operator", "operator"),
    ("/moderator", "moderator"),
)


@dataclass
class BFLARewriteResult:
    """Represents the outcome of injecting a BFLA role guard."""

    original_line: str
    patched_line: str
    role: str = "admin"
    guard_type: str = "annotation"
    imported: bool = False
    changed: bool = False
    explanation: str = ""


def _ensure_go_import(content: str, alias: str, pkg_path: str) -> Tuple[str, bool]:
    """Ensure a Go import with alias is present in content."""
    if pkg_path in content:
        return content, False
    newline = _newline_of(content)
    import_line = f'\t{alias} "{pkg_path}"{newline}'

    block = _GO_IMPORT_BLOCK.search(content)
    if block:
        body = block.group("body")
        insert_at = block.end("body")
        prefix = "" if body.endswith(("\n", "\r")) else newline
        return content[:insert_at] + prefix + import_line + content[insert_at:], True

    single = _GO_IMPORT_SINGLE.search(content)
    if single:
        existing = f'\t"{single.group("pkg")}"{newline}'
        replacement = f"import ({newline}{existing}{import_line}){newline}"
        return content[: single.start()] + replacement + content[single.end():], True

    pkg = _GO_PACKAGE.search(content)
    if pkg:
        stmt = f'{newline}import {alias} "{pkg_path}"{newline}'
        return content[: pkg.end()] + stmt + content[pkg.end():], True

    return f'import {alias} "{pkg_path}"{newline}' + content, True


def _ensure_js_named_imports(content: str, names: List[str]) -> Tuple[str, bool]:
    """Ensure named imports from '@hoanghainh/komagu' are present in JS/TS content."""
    newline = _newline_of(content)
    match = re.search(
        r"""import\s*\{(?P<names>[^}]*)\}\s*from\s*(['"])@hoanghainh/komagu\2\s*;?""",
        content,
    )
    if match:
        existing = [n.strip() for n in match.group("names").split(",") if n.strip()]
        missing = [n for n in names if n not in existing]
        if not missing:
            return content, False
        merged = ", ".join(existing + missing)
        updated = f"import {{ {merged} }} from '@hoanghainh/komagu';"
        return content[: match.start()] + updated + content[match.end():], True

    stmt = f"import {{ {', '.join(names)} }} from '@hoanghainh/komagu';{newline}"
    return stmt + content, True


class BFLARolePatcher:
    """Detects unprotected privileged endpoints and injects fail-closed role guards."""

    EXT_TO_LANG: Dict[str, str] = {
        ".ts": "typescript",
        ".js": "javascript",
        ".cs": "csharp",
        ".java": "java",
        ".kt": "java",
        ".go": "golang",
        ".py": "python",
    }

    def detect_language(self, file_path: Path | str) -> str:
        """Infer language from file extension."""
        return self.EXT_TO_LANG.get(Path(file_path).suffix.lower(), "generic")

    def infer_role(self, finding: Dict[str, Any]) -> str:
        """Infer required role from finding metadata or endpoint path (defaults to 'admin')."""
        explicit = finding.get("required_role") or (finding.get("endpoint") or {}).get("required_role")
        if isinstance(explicit, str) and explicit.strip():
            return explicit.strip()

        path = str((finding.get("endpoint") or {}).get("path", "")).lower()
        for prefix, role in _ROLE_PATH_HINTS:
            if prefix in path:
                return role
        return "admin"

    def ensure_imports(self, content: str, lang: str, names: Optional[List[str]] = None) -> Tuple[str, bool]:
        """Ensure required Komagu role-guard imports exist for the target language."""
        newline = _newline_of(content)
        if lang in ("typescript", "javascript"):
            return _ensure_js_named_imports(content, names or ["RequireRole", "KomaguRoleGuard"])
        if lang == "csharp":
            if "using Komagu.Security.Authorization;" in content:
                return content, False
            return f"using Komagu.Security.Authorization;{newline}" + content, True
        if lang == "java":
            if "import io.komagu.security.spring.RequireRole;" in content:
                return content, False
            stmt = f"import io.komagu.security.spring.RequireRole;{newline}"
            pkg = _JAVA_PACKAGE_STATEMENT.search(content)
            if pkg:
                return content[: pkg.end()] + newline + stmt + content[pkg.end():], True
            return stmt + content, True
        if lang == "golang":
            return _ensure_go_import(content, "komaguauthz", "github.com/hoanghainh1188/komagu/remediate/authz/golang")
        return content, False

    def patch_file(
        self,
        target_file: Path,
        line_number: int,
        finding: Dict[str, Any],
        content: Optional[str] = None,
    ) -> Tuple[str, BFLARewriteResult]:
        """Inject a role guard at line_number for a BFLA finding."""
        if content is None:
            content = Path(target_file).read_bytes().decode("utf-8")
        lines = content.splitlines(keepends=True)
        idx = line_number - 1

        if idx < 0 or idx >= len(lines):
            return content, BFLARewriteResult("", "", changed=False, explanation="Line number out of bounds.")

        lang = self.detect_language(target_file)
        role = self.infer_role(finding)
        target_line = lines[idx]
        indent = re.match(r"^(\s*)", target_line).group(1) if target_line else ""
        newline = _newline_of(content)

        surrounding = "".join(lines[max(0, idx - 3):min(len(lines), idx + 3)])
        if any(marker in surrounding for marker in _ROLE_GUARD_MARKERS):
            return content, BFLARewriteResult(
                original_line=target_line,
                patched_line=target_line,
                role=role,
                changed=False,
                explanation="Role guard already present at target line.",
            )

        if lang in ("typescript", "javascript"):
            express_match = _EXPRESS_ROUTE.match(target_line)
            if express_match:
                eol = express_match.group("eol") or newline
                rewritten = (
                    f"{express_match.group('indent')}{express_match.group('router')}."
                    f"{express_match.group('method')}({express_match.group('path')}, "
                    f"requireRole('{role}'), {express_match.group('handler')}){express_match.group('tail')}{eol}"
                )
                lines[idx] = rewritten
                final_content, imported = self.ensure_imports("".join(lines), lang, ["requireRole"])
                return final_content, BFLARewriteResult(
                    original_line=target_line,
                    patched_line=rewritten,
                    role=role,
                    guard_type="express_middleware",
                    imported=imported,
                    changed=True,
                    explanation=f"Injected Express requireRole('{role}') middleware on route.",
                )

            if re.search(r"\b(app|router)\.(get|post|put|delete|patch)\s*\(", target_line):
                return content, BFLARewriteResult(
                    original_line=target_line,
                    patched_line=target_line,
                    role=role,
                    changed=False,
                    explanation="Complex Express route needs requireRole middleware wired manually; requires manual remediation.",
                )

            guard_snippet = (
                f"{indent}@UseGuards(KomaguRoleGuard){newline}"
                f"{indent}@RequireRole('{role}'){newline}"
            )
            lines.insert(idx, guard_snippet)
            final_content, imported = self.ensure_imports("".join(lines), lang, ["RequireRole", "KomaguRoleGuard"])
            return final_content, BFLARewriteResult(
                original_line=target_line,
                patched_line=guard_snippet + target_line,
                role=role,
                guard_type="nestjs_decorator",
                imported=imported,
                changed=True,
                explanation=f"Injected NestJS @UseGuards(KomaguRoleGuard) and @RequireRole('{role}').",
            )

        if lang == "csharp":
            guard_snippet = f'{indent}[RequireRole("{role}")]{newline}'
            lines.insert(idx, guard_snippet)
            final_content, imported = self.ensure_imports("".join(lines), lang)
            return final_content, BFLARewriteResult(
                original_line=target_line,
                patched_line=guard_snippet + target_line,
                role=role,
                guard_type="csharp_attribute",
                imported=imported,
                changed=True,
                explanation=f'Injected ASP.NET Core [RequireRole("{role}")] attribute.',
            )

        if lang == "java":
            if not (_SPRING_CONTROLLER.search(content) and _is_java_handler_line(lines, idx)):
                return content, BFLARewriteResult(
                    original_line=target_line,
                    patched_line=target_line,
                    role=role,
                    changed=False,
                    explanation="@RequireRole requires a Spring controller handler method; requires manual remediation.",
                )
            guard_snippet = f'{indent}@RequireRole("{role}"){newline}'
            lines.insert(idx, guard_snippet)
            final_content, imported = self.ensure_imports("".join(lines), lang)
            return final_content, BFLARewriteResult(
                original_line=target_line,
                patched_line=guard_snippet + target_line,
                role=role,
                guard_type="spring_annotation",
                imported=imported,
                changed=True,
                explanation=f'Injected Spring @RequireRole("{role}") annotation.',
            )

        if lang == "golang":
            go_match = _GO_HANDLE.match(target_line)
            if not go_match:
                return content, BFLARewriteResult(
                    original_line=target_line,
                    patched_line=target_line,
                    role=role,
                    changed=False,
                    explanation="Go BFLA guard requires a standard mux.Handle/HandleFunc registration; requires manual remediation.",
                )
            eol = go_match.group("eol") or newline
            handler = go_match.group("handler")
            wrapped = f"http.HandlerFunc({handler})" if go_match.group("fn") == "HandleFunc" else handler
            rewritten = (
                f"{go_match.group('indent')}{go_match.group('router')}.Handle("
                f"{go_match.group('path')}, "
                f'komaguauthz.RequireRole([]string{{"{role}"}})({wrapped})){eol}'
            )
            lines[idx] = rewritten
            final_content, imported = self.ensure_imports("".join(lines), lang)
            return final_content, BFLARewriteResult(
                original_line=target_line,
                patched_line=rewritten,
                role=role,
                guard_type="go_middleware",
                imported=imported,
                changed=True,
                explanation=f'Wrapped Go handler with komaguauthz.RequireRole([]string{{"{role}"}}).',
            )

        return content, BFLARewriteResult(
            original_line=target_line,
            patched_line=target_line,
            role=role,
            changed=False,
            explanation=f"Automated BFLA role guard not supported for language '{lang}'; requires manual remediation.",
        )
