"""Automated BOLA / IDOR Ownership Guard Patcher (OWASP API1:2023, CWE-639).

Automatically inspects controller/route definitions and injects standard Komainu
@RequireOwnership decorators, action filters, or middleware across TypeScript,
C#, Java, Python, and PHP.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


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
        """Ensure necessary Komainu authorization import is present at the top of the file."""
        if lang in ("typescript", "javascript"):
            if "from 'komainu-guard'" in content or 'from "komainu-guard"' in content:
                return content, False
            import_stmt = "import { RequireOwnership, OwnershipGuard, ResourceOperation } from 'komainu-guard';\n"
            return import_stmt + content, True

        elif lang == "csharp":
            if "using Komainu.Security.Authorization;" in content:
                return content, False
            import_stmt = "using Komainu.Security.Authorization;\n"
            return import_stmt + content, True

        elif lang == "java":
            if "import io.komagu.security.authorization.RequireOwnership;" in content:
                return content, False
            import_stmt = "import io.komagu.security.authorization.RequireOwnership;\nimport io.komagu.security.authorization.ResourceOperation;\n"
            if "package " in content:
                parts = content.split(";\n", 1)
                return parts[0] + ";\n\n" + import_stmt + parts[1], True
            return import_stmt + content, True

        elif lang == "python":
            if "from remediate.authz.python.komainu_authz" in content:
                return content, False
            import_stmt = "from remediate.authz.python.komainu_authz import RequireOwnership, ResourceOperation\n"
            return import_stmt + content, True

        return content, False

    def patch_file(
        self,
        target_file: Path,
        line_number: int,
        finding: Dict[str, Any],
    ) -> Tuple[str, BOLARewriteResult]:
        """Inject appropriate ownership guard above the method or route at line_number."""
        content = target_file.read_text(encoding="utf-8", errors="replace")
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
        if "RequireOwnership" in surrounding or "OwnershipGuard" in surrounding or "[KOMAINU-FIX]" in surrounding:
            return content, BOLARewriteResult(
                original_line=target_line,
                patched_line=target_line,
                changed=False,
                explanation="Ownership guard already present at target line.",
            )

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
            guard_lines.append(f"{indent}@RequireOwnership(entityClass = {resource}.class, operation = ResourceOperation.{operation})\n")

        elif lang == "python":
            guard_lines.append(f"{indent}@RequireOwnership(operation=ResourceOperation.{operation}, id_param=\"id\")\n")

        else:
            return content, BOLARewriteResult(
                original_line=target_line,
                patched_line=target_line,
                changed=False,
                explanation=f"Automated BOLA ownership guard not supported for language '{lang}'; requires manual remediation.",
            )

        guard_snippet = "".join(guard_lines)
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
