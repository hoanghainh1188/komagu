"""Tier 2 AI-assisted multi-line remediation with mandatory verification gate (#394).

Used as an opt-in fallback (--ai) when Tier 1 deterministic patchers cannot
rewrite a vulnerability (e.g., Java legacy Statement -> PreparedStatement,
PHP mysql_query -> PDO, or multi-line authorization checks).

Every candidate patch produced by the LLM is:
1. Redacted on input via assess/lsa/scripts/redaction.py before leaving the host.
2. Constrained to a bounded line window around the finding.
3. Verified via syntax/compiler checks (when available) and Tier 1 sink re-scan.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from operate.ai.client import LLMClient, repair_json_quotes

_LSA_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "assess" / "lsa" / "scripts"
if str(_LSA_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_LSA_SCRIPTS_DIR))

from find_injection import find_injection  # noqa: E402
from lsa_common import load_config  # noqa: E402
from redaction import redact_lines  # noqa: E402

_SYSTEM_PROMPT = (
    "You are a senior application security engineer fixing a verified vulnerability in legacy code.\n"
    "Rules:\n"
    "1. Fix ONLY the security vulnerability at the indicated lines without changing unrelated behavior.\n"
    "2. Never emit comment-only fixes or TODO placeholders.\n"
    "3. Use standard, idiomatic APIs for the file's language and existing imports/stack.\n"
    "4. Return STRICT JSON only with keys: start_line (int), end_line (int), "
    "patched_snippet (string), explanation (string).\n"
    "5. start_line and end_line are 1-based inclusive line numbers in the original file."
)

_COMMENT_ONLY_LINE = re.compile(r"^\s*(?://|#|--|/\*|\*|\*/|$)")


@dataclass
class AIFixResult:
    """Outcome of Tier 2 AI-assisted patch generation and verification."""

    changed: bool
    patched_content: str
    explanation: str
    verified: bool = False
    syntax_status: str = "not_run"


def _strip_comments_and_blank(lines: List[str]) -> List[str]:
    """Return non-empty, non-comment lines to detect comment-only fake fixes."""
    return [ln.strip() for ln in lines if not _COMMENT_ONLY_LINE.match(ln)]


def _check_syntax(file_path: Path, patched_content: str) -> Tuple[bool, str]:
    """Run language-appropriate syntax/compile verification on patched_content."""
    ext = file_path.suffix.lower()

    if ext == ".py":
        try:
            compile(patched_content, str(file_path), "exec")
            return True, "py_compile:ok"
        except SyntaxError as exc:
            return False, f"py_compile failed: {exc.msg} (line {exc.lineno})"

    tool_commands: Dict[str, List[str]] = {
        ".js": ["node", "--check"],
        ".mjs": ["node", "--check"],
        ".php": ["php", "-l"],
        ".go": ["gofmt", "-e"],
    }

    cmd_prefix = tool_commands.get(ext)
    if cmd_prefix is None:
        return True, f"skipped (no syntax checker configured for {ext or 'unknown'})"

    tool_bin = shutil.which(cmd_prefix[0])
    if not tool_bin:
        return True, f"skipped ({cmd_prefix[0]} not installed)"

    with tempfile.TemporaryDirectory(prefix="komagu_ai_syntax_") as tmpdir:
        tmp_file = Path(tmpdir) / file_path.name
        tmp_file.write_text(patched_content, encoding="utf-8")
        proc = subprocess.run(
            [tool_bin, *cmd_prefix[1:], str(tmp_file)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout).strip().splitlines()[:3]
            return False, f"{cmd_prefix[0]} failed: {' | '.join(err)}"
        return True, f"{cmd_prefix[0]}:ok"


def _check_injection_sink_removed(
    file_path: Path,
    patched_content: str,
    start_line: int,
    new_end_line: int,
) -> Tuple[bool, str]:
    """Re-run Tier 1 injection detector on patched lines to confirm sink removal."""
    with tempfile.TemporaryDirectory(prefix="komagu_ai_rescan_") as tmpdir:
        tmp_dir = Path(tmpdir)
        tmp_file = tmp_dir / file_path.name
        tmp_file.write_text(patched_content, encoding="utf-8")
        result = find_injection(tmp_dir, load_config(None))
        candidates = result.get("candidates", [])
        for cand in candidates:
            line_no = int(cand.get("line", 0))
            if start_line <= line_no <= new_end_line:
                return False, (
                    f"Tier 1 re-scan still flags injection sink at line {line_no}: "
                    f"{cand.get('sink', cand.get('pattern', 'dynamic query'))}"
                )
    return True, "tier1_rescan:clean"


class AITier2Fixer:
    """Generates and verifies multi-line security patches using a BYO-LLM endpoint."""

    def __init__(
        self,
        endpoint: str = "http://localhost:11434/v1",
        model: str = "llama3.1",
        api_key: Optional[str] = None,
        timeout: int = 120,
        reasoning_effort: Optional[str] = None,
        context_radius: int = 30,
        max_changed_lines: int = 40,
        client: Optional[LLMClient] = None,
    ) -> None:
        self.client = client or LLMClient(
            endpoint=endpoint,
            model=model,
            api_key=api_key,
            timeout=timeout,
            reasoning_effort=reasoning_effort,
        )
        self.context_radius = context_radius
        self.max_changed_lines = max_changed_lines

    def _build_prompt(
        self,
        target_file: Path,
        content: str,
        finding: Dict[str, Any],
        target_line: int,
    ) -> str:
        """Build a redacted, bounded code context prompt for the LLM."""
        lines = content.splitlines()
        total = len(lines)

        header_end = min(20, total)
        ctx_start = max(1, target_line - self.context_radius)
        ctx_end = min(total, target_line + self.context_radius)

        header_lines = redact_lines(lines[:header_end])
        window_lines = redact_lines(lines[ctx_start - 1 : ctx_end])

        numbered_header = "\n".join(f"{i + 1}: {ln}" for i, ln in enumerate(header_lines))
        numbered_window = "\n".join(f"{ctx_start + i}: {ln}" for i, ln in enumerate(window_lines))

        category = finding.get("category", "vulnerability")
        cwe = finding.get("cwe", "")
        title = finding.get("title", "")

        return (
            f"File: {target_file.name}\n"
            f"Category: {category} ({cwe})\n"
            f"Finding: {title}\n"
            f"Target line: {target_line}\n\n"
            f"--- File Header (lines 1..{header_end}) ---\n{numbered_header}\n\n"
            f"--- Vulnerable Context (lines {ctx_start}..{ctx_end}) ---\n{numbered_window}\n\n"
            "Provide a minimal, secure multi-line replacement in strict JSON."
        )

    def _parse_response(self, raw_reply: str) -> Dict[str, Any]:
        """Parse and repair JSON returned by the LLM."""
        repaired = repair_json_quotes(raw_reply)
        data = json.loads(repaired)
        if not isinstance(data, dict):
            raise ValueError("LLM reply must be a JSON object")
        return data

    def generate_verified_patch(
        self,
        target_file: Path,
        content: str,
        finding: Dict[str, Any],
    ) -> AIFixResult:
        """Generate a multi-line patch with the LLM and run all verification gates."""
        lines = content.splitlines(keepends=True)
        total_lines = len(lines)
        loc = finding.get("location") or {}
        finding_line = int(loc.get("start_line", 1))

        if finding_line < 1 or finding_line > total_lines:
            return AIFixResult(False, content, "AI fix skipped: target line out of bounds.")

        prompt = self._build_prompt(target_file, content, finding, finding_line)
        try:
            raw_reply = self.client.chat(
                [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
            )
            payload = self._parse_response(raw_reply)
        except Exception as exc:
            return AIFixResult(False, content, f"AI fix failed: {exc}")

        try:
            start_line = int(payload["start_line"])
            end_line = int(payload["end_line"])
            patched_snippet = str(payload["patched_snippet"])
            explanation = str(payload.get("explanation", "Applied AI-assisted security fix.")).strip()
        except (KeyError, TypeError, ValueError) as exc:
            return AIFixResult(False, content, f"AI fix rejected: invalid JSON schema ({exc}).")

        if start_line < 1 or end_line < start_line or end_line > total_lines:
            return AIFixResult(False, content, f"AI fix rejected: invalid line span {start_line}..{end_line}.")

        if abs(start_line - finding_line) > 15 and not (start_line <= finding_line <= end_line):
            return AIFixResult(
                False,
                content,
                f"AI fix rejected: span {start_line}..{end_line} is too far from finding line {finding_line}.",
            )

        if not patched_snippet.strip():
            return AIFixResult(False, content, "AI fix rejected: empty patched_snippet.")

        new_snippet_lines = patched_snippet.splitlines(keepends=True)
        if not patched_snippet.endswith(("\n", "\r")):
            newline = "\r\n" if "\r\n" in content else "\n"
            new_snippet_lines[-1] += newline

        if (end_line - start_line + 1) > self.max_changed_lines or len(new_snippet_lines) > self.max_changed_lines:
            return AIFixResult(
                False,
                content,
                f"AI fix rejected: patch exceeds bounded limit of {self.max_changed_lines} lines.",
            )

        old_slice = lines[start_line - 1 : end_line]
        if _strip_comments_and_blank(old_slice) == _strip_comments_and_blank(new_snippet_lines):
            return AIFixResult(False, content, "AI fix rejected: comment-only or no-op change.")

        patched_lines = lines[: start_line - 1] + new_snippet_lines + lines[end_line:]
        patched_content = "".join(patched_lines)
        if patched_content == content:
            return AIFixResult(False, content, "AI fix rejected: produced identical content.")

        syntax_ok, syntax_status = _check_syntax(target_file, patched_content)
        if not syntax_ok:
            return AIFixResult(False, content, f"AI fix rejected ({syntax_status}).", syntax_status=syntax_status)

        category = str(finding.get("category", "")).lower()
        new_end_line = start_line + len(new_snippet_lines) - 1
        if category in ("sql_injection", "nosql_injection"):
            rescan_ok, rescan_msg = _check_injection_sink_removed(
                target_file, patched_content, start_line, new_end_line
            )
            if not rescan_ok:
                return AIFixResult(False, content, f"AI fix rejected: {rescan_msg}", syntax_status=syntax_status)

        return AIFixResult(
            changed=True,
            patched_content=patched_content,
            explanation=f"[AI-GENERATED — REQUIRES PERSON B REVIEW] {explanation} (verified: {syntax_status})",
            verified=True,
            syntax_status=syntax_status,
        )
