"""Automated BOLA / IDOR Ownership Guard Patcher (OWASP API1:2023, CWE-639).

Automatically inspects controller/route definitions and injects standard Komagu
@RequireOwnership decorators, action filters, or middleware across TypeScript,
C#, Java, Python, and PHP.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

JAVA_LEGACY_SHIM = "remediate/legacy_shims/java/OwnershipEnforcer.java"

_SPRING_BUILD_FILES = ("pom.xml", "build.gradle", "build.gradle.kts", "gradle.properties")
_SPRING_BOOT_VERSION_PATTERNS = (
    re.compile(r"spring-boot-(?:starter-parent|dependencies)</artifactId>\s*<version>\s*(\d+)\."),
    re.compile(r"<spring-boot\.version>\s*(\d+)\."),
    re.compile(r"org\.springframework\.boot['\"]\)?\s+version\s+['\"](\d+)\."),
    re.compile(r"org\.springframework\.boot:spring-boot[\w-]*:(\d+)\."),
    re.compile(r"springBootVersion\s*=\s*['\"]?(\d+)\."),
)
_XML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_SPRING_CONTROLLER = re.compile(r"^\s*@(?:Rest)?Controller\b", re.MULTILINE)
_SPRING_MAPPING_LINE = re.compile(r"^\s*@(?:Get|Post|Put|Patch|Delete|Request)Mapping\b")
_JAVA_METHOD_LINE = re.compile(r"^\s*(?:public|protected)\b[^;=]*\(")
_JAVA_DECLARATION_LINE = re.compile(r"^\s*(?:public|protected|private|abstract|final|class)\b")
_JAVA_TYPE_NAME = re.compile(r"[A-Z][A-Za-z0-9_]*")
_JAVA_LITERALS_AND_COMMENTS = re.compile(
    r""""(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])'|//[^\n]*|/\*.*?\*/""", re.DOTALL
)
_JAVA_PACKAGE_STATEMENT = re.compile(r"^[ \t]*package\s+[\w.]+\s*;[ \t]*(?:\r\n|\r|\n)", re.MULTILINE)


def _newline_of(content: str) -> str:
    """Return the line ending a generated line must use to match the surrounding file."""
    if "\r\n" in content:
        return "\r\n"
    return "\r" if "\r" in content else "\n"


def _declared_spring_boot_major(build_file: Path) -> Optional[int]:
    """Return the Spring Boot major version a build file declares, if it declares one."""
    try:
        text = _XML_COMMENT.sub("", build_file.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None
    for pattern in _SPRING_BOOT_VERSION_PATTERNS:
        match = pattern.search(text)
        if match:
            return int(match.group(1))
    return None


def _spring_boot_major(source_file: Path) -> Optional[int]:
    """Find the Spring Boot major version from the nearest build file that declares one."""
    for directory in Path(source_file).resolve().parents:
        for name in _SPRING_BUILD_FILES:
            major = _declared_spring_boot_major(directory / name)
            if major is not None:
                return major
        if (directory / ".git").exists():
            break
    return None


def _is_java_handler_line(lines: List[str], idx: int) -> bool:
    """True when an annotation inserted above lines[idx] would land on a controller method."""
    if not (_SPRING_MAPPING_LINE.match(lines[idx]) or _JAVA_METHOD_LINE.match(lines[idx])):
        return False
    declaration = next((line for line in lines[idx:] if _JAVA_DECLARATION_LINE.match(line)), "")
    return "(" in declaration and not re.search(r"\bclass\b", declaration)


def _java_uses_type(content: str, type_name: str) -> bool:
    """True when code outside strings and comments references type_name, other than declaring it."""
    if not _JAVA_TYPE_NAME.fullmatch(type_name):
        return False
    code = _JAVA_LITERALS_AND_COMMENTS.sub(" ", content)
    code = re.sub(rf"\b(?:class|interface|enum)\s+{type_name}\b", " ", code)
    return re.search(rf"\b{type_name}\b", code) is not None


@dataclass
class BOLARewriteResult:
    """Represents the outcome of injecting an ownership guard into a vulnerable endpoint."""

    original_line: str
    patched_line: str
    guard_type: str = "annotation"
    resource_name: str = "Resource"
    operation: str = "READ"
    imported: bool = False
    changed: bool = False
    explanation: str = ""


class BOLAOwnershipPatcher:
    """Detects vulnerable endpoints and injects framework-native ownership guards."""

    EXT_TO_LANG: Dict[str, str] = {
        ".ts": "typescript",
        ".js": "javascript",
        ".cs": "csharp",
        ".java": "java",
        ".kt": "java",
        ".py": "python",
        ".php": "php",
        ".go": "golang",
    }

    METHOD_TO_OPERATION: Dict[str, str] = {
        "GET": "READ",
        "POST": "CREATE",
        "PUT": "UPDATE",
        "PATCH": "UPDATE",
        "DELETE": "DELETE",
    }

    def detect_language(self, file_path: Path | str) -> str:
        """Infer language from file extension."""
        ext = Path(file_path).suffix.lower()
        return self.EXT_TO_LANG.get(ext, "generic")

    def infer_operation(self, finding: Dict[str, Any]) -> str:
        """Infer resource operation (READ, UPDATE, DELETE) from endpoint metadata."""
        endpoint = finding.get("endpoint") or {}
        method = endpoint.get("method", "GET").upper()
        # Handle multiple methods like "GET|POST" -> take the first
        first_method = method.split("|")[0].strip()
        return self.METHOD_TO_OPERATION.get(first_method, "READ")

    def infer_resource_name(self, file_path: Path | str, finding: Dict[str, Any]) -> str:
        """Infer domain resource name from route path or file name."""
        endpoint = finding.get("endpoint") or {}
        path_str = endpoint.get("path", "")

        # Try to infer from path e.g. /api/v1/orders/{id} -> Order
        path_segments = [s for s in path_str.split("/") if s and not s.startswith(("{", ":", "["))]
        if path_segments:
            candidate = path_segments[-1].rstrip("s")
            if candidate:
                return candidate.capitalize()

        # Fallback to filename e.g. order_controller.ts -> Order
        stem = Path(file_path).stem
        cleaned = re.sub(r"(?i)(controller|handler|service|routes?|api|_)+", "", stem)
        if cleaned:
            return cleaned.capitalize()

        return "Resource"

    def ensure_imports(self, content: str, lang: str) -> Tuple[str, bool]:
        """Ensure necessary Komagu authorization import is present at the top of the file."""
        newline = _newline_of(content)
        if lang in ("typescript", "javascript"):
            if "from '@hoanghainh/komagu'" in content or 'from "@hoanghainh/komagu"' in content:
                return content, False
            import_stmt = "import { RequireOwnership, OwnershipGuard, ResourceOperation } from '@hoanghainh/komagu';" + newline
            return import_stmt + content, True

        elif lang == "csharp":
            if "using Komagu.Security.Authorization;" in content:
                return content, False
            import_stmt = "using Komagu.Security.Authorization;" + newline
            return import_stmt + content, True

        elif lang == "java":
            if "import io.komagu.security.spring.RequireOwnership;" in content:
                return content, False
            import_stmt = (
                "import io.komagu.security.spring.RequireOwnership;" + newline
                + "import io.komagu.security.authorization.ResourceOperation;" + newline
            )
            package = _JAVA_PACKAGE_STATEMENT.search(content)
            if package:
                return content[: package.end()] + newline + import_stmt + content[package.end():], True
            return import_stmt + content, True

        elif lang == "python":
            if "from remediate.authz.python.komagu_authz" in content:
                return content, False
            import_stmt = "from remediate.authz.python.komagu_authz import RequireOwnership, ResourceOperation" + newline
            return import_stmt + content, True

        return content, False

    def _java_manual_reason(
        self, target_file: Path, content: str, lines: List[str], idx: int, resource: str
    ) -> Optional[str]:
        """Say why @RequireOwnership cannot be inserted here, or None when it can."""
        if not _SPRING_CONTROLLER.search(content):
            problem = "this file is not a Spring controller"
        elif _spring_boot_major(target_file) != 3:
            problem = "no Spring Boot 3 version was found in the build files"
        elif not _is_java_handler_line(lines, idx):
            problem = "the finding does not point at a controller method"
        elif not _java_uses_type(content, resource):
            problem = f"the entity class could not be confirmed from the route (inferred {resource!r})"
        else:
            return None
        return (
            f"@RequireOwnership needs a Spring Boot 3 controller method, but {problem}; requires manual "
            f"remediation: call OwnershipEnforcer.requireOwnership(...) before the object is read or "
            f"written (see {JAVA_LEGACY_SHIM})."
        )

    def patch_file(
        self,
        target_file: Path,
        line_number: int,
        finding: Dict[str, Any],
        content: Optional[str] = None,
    ) -> Tuple[str, BOLARewriteResult]:
        """Inject appropriate ownership guard above the method or route at line_number.

        Pass the already-decoded `content` to keep the caller's encoding and pending edits.
        Without it the file must be valid UTF-8: replacing bytes would corrupt the source.
        """
        if content is None:
            content = Path(target_file).read_bytes().decode("utf-8")
        lines = content.splitlines(keepends=True)
        idx = line_number - 1

        if idx < 0 or idx >= len(lines):
            return content, BOLARewriteResult(
                original_line="",
                patched_line="",
                changed=False,
                explanation="Line number out of bounds.",
            )

        lang = self.detect_language(target_file)
        operation = self.infer_operation(finding)
        resource = self.infer_resource_name(target_file, finding)

        target_line = lines[idx]
        indent = re.match(r"^(\s*)", target_line).group(1) if target_line else ""

        # Check if guard is already present on or adjacent to this line
        surrounding = "".join(lines[max(0, idx - 3):min(len(lines), idx + 3)])
        # [KOMAINU-FIX] is only read: nothing writes it since #216, but files patched before that still carry it (#312)
        if "RequireOwnership" in surrounding or "OwnershipGuard" in surrounding or "[KOMAINU-FIX]" in surrounding:
            return content, BOLARewriteResult(
                original_line=target_line,
                patched_line=target_line,
                changed=False,
                explanation="Ownership guard already present at target line.",
            )

        newline = _newline_of(content)
        guard_lines: List[str] = []

        if lang in ("typescript", "javascript"):
            # Check if this is an Express app.get / router.get line
            if re.search(r"\b(app|router)\.(get|post|put|delete|patch)\s*\(", target_line):
                # Express handlers need the ownership middleware wired into the route call;
                # a comment would be reported as a fix without changing behaviour.
                return content, BOLARewriteResult(
                    original_line=target_line,
                    patched_line=target_line,
                    changed=False,
                    explanation="Express route needs requireOwnership middleware added manually; requires manual remediation.",
                )
            else:
                # NestJS / Declarative Controller
                guard_lines.append(f"{indent}@UseGuards(OwnershipGuard)\n")
                guard_lines.append(f"{indent}@RequireOwnership(ResourceOperation.{operation}, {{ idParamName: 'id' }})\n")

        elif lang == "csharp":
            cs_op = "Read" if operation == "READ" else "Update" if operation == "UPDATE" else "Delete" if operation == "DELETE" else "Read"
            guard_lines.append(f"{indent}[RequireOwnership(typeof({resource}), idRouteParameter: \"id\", operation: ResourceOperation.{cs_op})]\n")

        elif lang == "java":
            manual_reason = self._java_manual_reason(target_file, content, lines, idx, resource)
            if manual_reason:
                return content, BOLARewriteResult(
                    original_line=target_line,
                    patched_line=target_line,
                    changed=False,
                    explanation=manual_reason,
                )
            guard_lines.append(f"{indent}@RequireOwnership(entityClass = {resource}.class, operation = ResourceOperation.{operation})\n")

        elif lang == "python":
            guard_lines.append(f"{indent}@RequireOwnership(operation=ResourceOperation.{operation}, id_param=\"id\")\n")

        elif lang == "golang":
            return content, BOLARewriteResult(
                original_line=target_line,
                patched_line=target_line,
                changed=False,
                explanation="Go BOLA guard requires Authorizer.Middleware(resourceLoader, ...) with a domain resourceLoader; requires manual remediation.",
            )

        else:
            return content, BOLARewriteResult(
                original_line=target_line,
                patched_line=target_line,
                changed=False,
                explanation=f"Automated BOLA ownership guard not supported for language '{lang}'; requires manual remediation.",
            )

        guard_snippet = "".join(guard_lines).replace("\n", newline)
        lines.insert(idx, guard_snippet)
        patched_body = "".join(lines)

        # Ensure imports
        final_content, imported = self.ensure_imports(patched_body, lang)

        return final_content, BOLARewriteResult(
            original_line=target_line,
            patched_line=guard_snippet + target_line,
            guard_type=lang,
            resource_name=resource,
            operation=operation,
            imported=imported,
            changed=True,
            explanation=f"Injected {lang} ownership guard enforcing {operation} on {resource}.",
        )
