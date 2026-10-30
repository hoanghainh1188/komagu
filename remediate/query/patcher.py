"""Automated Parameterized Query Patcher for SQL and NoSQL Injection (CWE-89, CWE-943).

Transforms string-concatenated, interpolated, and template-based dynamic SQL queries
into safe parameterized queries conforming to language-specific standard APIs.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class RewrittenQuery:
    """Represents the result of transforming a vulnerable dynamic query line."""

    original_line: str
    patched_line: str
    placeholders: List[str] = field(default_factory=list)
    params: List[str] = field(default_factory=list)
    pattern_type: str = "unknown"
    changed: bool = False
    explanation: str = ""


class ParameterizedQueryPatcher:
    """Detects and rewrites string-built SQL queries into parameterized forms."""

    EXT_TO_LANG: Dict[str, str] = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "javascript",
        ".jsx": "javascript",
        ".tsx": "javascript",
        ".php": "php",
        ".cs": "csharp",
        ".java": "java",
    }

    SQL_KEYWORDS = re.compile(
        r"(?i)\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|WHERE|JOIN|GROUP\s+BY|ORDER\s+BY)\b"
    )

    def detect_language(self, file_path: Path | str) -> str:
        """Infer target programming language from file extension."""
        ext = Path(file_path).suffix.lower()
        return self.EXT_TO_LANG.get(ext, "generic")

    def patch_code_line(self, line: str, lang: str) -> RewrittenQuery:
        """Analyze and rewrite a single line of code containing a dynamic query."""
        if not self.SQL_KEYWORDS.search(line):
            return RewrittenQuery(
                original_line=line,
                patched_line=line,
                changed=False,
                explanation="No SQL keywords detected on line.",
            )

        if lang == "python":
            return self._rewrite_python(line)
        elif lang == "javascript":
            return self._rewrite_javascript(line)
        elif lang == "php":
            return self._rewrite_php(line)
        elif lang == "csharp":
            return self._rewrite_csharp(line)
        elif lang == "java":
            return self._rewrite_java(line)
        else:
            return self._rewrite_generic(line, lang=lang)

    def _rewrite_python(self, line: str) -> RewrittenQuery:
        """Rewrite Python f-strings, concatenation, or format calls into parameterized queries."""
        # Case A: cur.execute(f"SELECT ... {var} ...") or execute(f'...')
        fstring_exec_match = re.search(
            r"""(?P<prefix>.*?\bexecute\s*\(\s*)f(?P<quote>["'])(?P<query>.*?)(?P=quote)(?P<suffix>.*)""",
            line,
            re.DOTALL,
        )
        if fstring_exec_match:
            prefix = fstring_exec_match.group("prefix")
            quote = fstring_exec_match.group("quote")
            query_str = fstring_exec_match.group("query")
            suffix = fstring_exec_match.group("suffix")

            # Extract interpolated expressions inside {expression}
            exprs: List[str] = []

            # Handle LIKE '%{var}%' pattern so that placeholder is '?' without literal quotes
            def repl_like(m: re.Match[str]) -> str:
                expr = m.group(1).strip()
                exprs.append(expr)
                return "?"

            cleaned_query = re.sub(r"""['"]?%\{([^}]+)\}%['"]?""", repl_like, query_str)

            def repl_fstring(m: re.Match[str]) -> str:
                expr = m.group(1).strip()
                exprs.append(expr)
                return "?"

            # Handle standard quoted string interpolation like '{id}' -> ?
            cleaned_query = re.sub(r"""['"]?\{([^}]+)\}['"]?""", repl_fstring, cleaned_query)

            # Build tuple string
            if len(exprs) == 1:
                params_tuple = f"({exprs[0]},)"
            else:
                params_tuple = f"({', '.join(exprs)})"

            # Check if suffix ends with closing parenthesis
            if suffix.strip().startswith(")"):
                patched_line = f"{prefix}{quote}{cleaned_query}{quote}, {params_tuple}{suffix}"
            else:
                patched_line = f"{prefix}{quote}{cleaned_query}{quote}, {params_tuple})"

            return RewrittenQuery(
                original_line=line,
                patched_line=patched_line,
                placeholders=["?"] * len(exprs),
                params=exprs,
                pattern_type="python_fstring_execute",
                changed=True,
                explanation="Converted Python f-string execute() to parameterized query with '?' placeholder tuple.",
            )

        # Case B: Python concatenation with +
        concat_match = re.search(
            r"""(?P<prefix>.*?["'])(?P<query>(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[\s\S]*?)(?:['"]\s*\+\s*)(?P<var>[A-Za-z0-9_().]+)(?P<suffix>.*)""",
            line,
            re.IGNORECASE,
        )
        if concat_match:
            prefix = concat_match.group("prefix")
            var_name = concat_match.group("var")
            suffix = concat_match.group("suffix")

            # The var pattern also eats the call's closing ")": hand unbalanced ones back.
            while var_name.endswith(")") and var_name.count(")") > var_name.count("("):
                var_name, suffix = var_name[:-1], ")" + suffix

            # cur.execute("SELECT ... = " + x): only when x is the last operand of the call
            exec_match = re.fullmatch(r"""(?P<call>.*?\bexecute\s*\(\s*)["']""", prefix, re.DOTALL)
            eol = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
            tail_match = re.fullmatch(r"""\s*\)(?P<after>[ \t]*(?:#.*)?)""", suffix.rstrip("\r\n"))
            base_query = concat_match.group("query")
            if exec_match and tail_match and not base_query.rstrip().endswith(("'", '"', "%")):
                patched_line = (
                    f'{exec_match.group("call")}"{base_query}?", ({var_name},)){tail_match.group("after")}{eol}'
                )
                return RewrittenQuery(
                    original_line=line,
                    patched_line=patched_line,
                    placeholders=["?"],
                    params=[var_name],
                    pattern_type="python_concat_execute",
                    changed=True,
                    explanation="Converted Python string concatenation in execute() to a parameterized query.",
                )

            # `q = "..." + x` is left for manual remediation: turning q into a tuple would
            # break the later execute(q) call, which is outside this line.

        return self._rewrite_generic(line, lang="python")

    def _rewrite_javascript(self, line: str) -> RewrittenQuery:
        """Rewrite JavaScript / TypeScript db.query concatenation or template literals."""
        # Case A: Template literal: db.query(`SELECT ... ${var} ...`, ...)
        tmpl_match = re.search(
            r"""(?P<prefix>.*?\bquery\s*\(\s*)`(?P<query>.*?)`(?P<rest>.*)""",
            line,
            re.DOTALL,
        )
        if tmpl_match:
            prefix = tmpl_match.group("prefix")
            query_str = tmpl_match.group("query")
            rest = tmpl_match.group("rest")

            exprs: List[str] = []

            def repl_tmpl(m: re.Match[str]) -> str:
                expr = m.group(1).strip()
                exprs.append(expr)
                return "?"

            cleaned_query = re.sub(r"""\$\{([^}]+)\}""", repl_tmpl, query_str)
            params_arr = f"[{', '.join(exprs)}]"

            # Insert params array into query call arguments
            if rest.strip().startswith(","):
                patched_line = f'{prefix}"{cleaned_query}", {params_arr}{rest}'
            elif rest.strip().startswith(")"):
                patched_line = f'{prefix}"{cleaned_query}", {params_arr}{rest}'
            else:
                patched_line = f'{prefix}"{cleaned_query}", {params_arr})'

            return RewrittenQuery(
                original_line=line,
                patched_line=patched_line,
                placeholders=["?"] * len(exprs),
                params=exprs,
                pattern_type="js_template_literal",
                changed=True,
                explanation="Converted JavaScript template literal to parameterized query array.",
            )

        # Case B: Binary concatenation in db.query("SELECT ... WHERE col = '" + req.query.var + "'", callback)
        concat_match = re.search(
            r"""(?P<prefix>.*?\bquery\s*\(\s*)(?P<quote>["'])(?P<query>(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[\s\S]*?)(?:['"]\s*\+\s*)(?P<var>[A-Za-z0-9_.\[\]'"$]+)(?:\s*\+\s*["'][^"']*["'])?(?P<rest>.*)""",
            line,
            re.IGNORECASE,
        )
        if concat_match:
            prefix = concat_match.group("prefix")
            query_start = concat_match.group("query")
            var_name = concat_match.group("var")
            rest = concat_match.group("rest")

            # Clean trailing quotes or equal signs
            cleaned_query = re.sub(r"""['"= ]+$""", "", query_start).strip() + " = ?"
            params_arr = f"[{var_name}]"

            if rest.strip().startswith(","):
                patched_line = f'{prefix}"{cleaned_query}", {params_arr}{rest}'
            elif rest.strip().startswith(")"):
                patched_line = f'{prefix}"{cleaned_query}", {params_arr}{rest}'
            else:
                patched_line = f'{prefix}"{cleaned_query}", {params_arr})'

            return RewrittenQuery(
                original_line=line,
                patched_line=patched_line,
                placeholders=["?"],
                params=[var_name],
                pattern_type="js_string_concat",
                changed=True,
                explanation="Converted JavaScript string concatenation to parameterized query array.",
            )

        return self._rewrite_generic(line)

    def _rewrite_php(self, line: str) -> RewrittenQuery:
        """PHP: no automated rewrite.

        mysql_query() takes no parameter array (and was removed in PHP 7); a safe fix moves
        to PDO/mysqli prepared statements, which spans several lines.
        """
        return self._rewrite_generic(line, lang="php")

    _CS_IDENT = r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
    _CS_SQLCOMMAND = re.compile(
        r"^(?P<indent>[ \t]*)"
        r"(?P<decl>(?:using\s+)?(?:var|SqlCommand)\s+(?P<cmd>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+SqlCommand\s*\(\s*)"
        r"(?P<sql>.+?)\s*,\s*(?P<conn>[A-Za-z_][A-Za-z0-9_.]*)\s*\)\s*;[ \t]*(?P<eol>\r?\n?)$"
    )

    def _rewrite_csharp(self, line: str) -> RewrittenQuery:
        """Rewrite `var cmd = new SqlCommand(<dynamic sql>, conn);` with one interpolated or
        concatenated value into a placeholder plus a real `cmd.Parameters.AddWithValue` statement.

        Anything else (a bare SQL string, several values, `using (...)` headers, LIKE patterns)
        has no command object on the line to bind to and is left for manual remediation.
        """
        decl = self._CS_SQLCOMMAND.match(line)
        if not decl:
            return self._rewrite_generic(line, lang="csharp")

        ident = self._CS_IDENT
        sql = decl.group("sql")
        parts = re.fullmatch(r'\$"(?P<head>[^"{}]*)\{\s*(?P<var>' + ident + r')\s*\}(?P<tail>[^"{}]*)"', sql)
        if parts is None:
            parts = re.fullmatch(
                r'"(?P<head>[^"]*)"\s*\+\s*(?P<var>' + ident + r')(?:\s*\+\s*"(?P<tail>[^"]*)")?', sql
            )
        if parts is None:
            return self._rewrite_generic(line, lang="csharp")

        head, var_name, tail = parts.group("head"), parts.group("var"), parts.group("tail") or ""
        if head.endswith("'") != tail.startswith("'"):
            return self._rewrite_generic(line, lang="csharp")
        if head.endswith("'"):
            head, tail = head[:-1], tail[1:]
        if head.endswith("%") or tail.startswith("%"):
            # LIKE '%x%' needs the wildcard moved into the parameter value.
            return self._rewrite_generic(line, lang="csharp")

        param_name = "@" + var_name.replace(".", "_")
        indent, eol = decl.group("indent"), decl.group("eol")
        patched_line = (
            f'{indent}{decl.group("decl")}"{head}{param_name}{tail}", {decl.group("conn")});{eol or chr(10)}'
            f'{indent}{decl.group("cmd")}.Parameters.AddWithValue("{param_name}", {var_name});{eol}'
        )
        return RewrittenQuery(
            original_line=line,
            patched_line=patched_line,
            placeholders=[param_name],
            params=[var_name],
            pattern_type="csharp_sqlcommand",
            changed=True,
            explanation=f"Bound '{var_name}' to SqlCommand parameter '{param_name}' via Parameters.AddWithValue.",
        )

    def _rewrite_java(self, line: str) -> RewrittenQuery:
        """Java: no automated rewrite.

        A safe fix replaces the Statement with a PreparedStatement and adds setX() calls,
        which spans several lines; a placeholder alone leaves nothing bound.
        """
        return self._rewrite_generic(line, lang="java")

    def _rewrite_generic(self, line: str, lang: str = "generic") -> RewrittenQuery:
        """Generic fallback when no automated AST/regex rewrite applies."""
        return RewrittenQuery(
            original_line=line,
            patched_line=line,
            placeholders=[],
            params=[],
            pattern_type="unsupported",
            changed=False,
            explanation="No automated parameterized query rewrite applicable; requires manual remediation.",
        )

    def patch_file(self, target_file: Path, line_number: int) -> Tuple[str, RewrittenQuery]:
        """Apply patch to a specific line in target_file, returning (patched_content, RewrittenQuery)."""
        content = target_file.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines(keepends=True)
        idx = line_number - 1

        if idx < 0 or idx >= len(lines):
            return content, RewrittenQuery(
                original_line="",
                patched_line="",
                changed=False,
                explanation="Line number out of range.",
            )

        lang = self.detect_language(target_file)
        rewrite_res = self.patch_code_line(lines[idx], lang)

        if rewrite_res.changed:
            lines[idx] = rewrite_res.patched_line
            return "".join(lines), rewrite_res

        return content, rewrite_res

    def verify_fix(self, target_file: Path, line_number: int) -> bool:
        """Return True only when LSA find_injection.py no longer flags `line_number` of `target_file`.

        The file is scanned on its own (copied into a temporary directory) so project-level
        excludes cannot hide it. Any failure to run the scan counts as not verified.
        """
        repo_root = Path(__file__).resolve().parents[2]
        script_path = repo_root / "assess" / "lsa" / "scripts" / "find_injection.py"
        if not script_path.is_file():
            return False

        scan_dir = Path(tempfile.mkdtemp(prefix="komagu_verify_"))
        try:
            shutil.copy2(target_file, scan_dir / target_file.name)
            res = subprocess.run(
                [sys.executable, str(script_path), str(scan_dir)],
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
            if res.returncode != 0:
                return False
            data = json.loads(res.stdout)
            for c in data.get("candidates", []):
                if c.get("file") == target_file.name and c.get("line") == line_number:
                    return False
            return True
        except (OSError, ValueError, subprocess.SubprocessError):
            return False
        finally:
            shutil.rmtree(scan_dir, ignore_errors=True)
