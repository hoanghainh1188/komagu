"""Orchestrator runner for Komainu automated code remediation."""

from __future__ import annotations

import difflib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from operate.remediator.models import RemediationPlan, RemediationReport
from operate.remediator.strategies import BaseRemediationStrategy, StrategyRegistry


def safe_resolve_target_file(target_dir: Path, rel_file: str) -> Tuple[Optional[Path], str, Optional[str]]:
    """Safely resolve target file path within target_dir, rejecting path traversal and symlinks.

    Returns:
        (resolved_abs_path, clean_relative_path, error_message)
    """
    if not rel_file:
        return None, "", "Empty file path in finding location"

    # Normalize slashes and strip leading path separators
    norm = rel_file.strip().replace("\\", "/")
    while norm.startswith("/"):
        norm = norm[1:]

    # Strip leading ./ but preserve dotfiles (.env, .github/etc.)
    while norm.startswith("./"):
        norm = norm[2:]

    if not norm:
        return None, "", "Empty relative path after normalization"

    target_resolved = target_dir.resolve()
    candidate = target_resolved / norm

    # Containment check: prevent directory traversal outside target_dir
    try:
        resolved_candidate = candidate.resolve()
        resolved_candidate.relative_to(target_resolved)
    except (ValueError, RuntimeError):
        return None, norm, f"Path traversal detected: '{rel_file}' resolves outside target directory"

    # Symlink defense: reject any symlinks in path
    curr = candidate
    while curr != target_resolved and curr != curr.parent:
        if curr.is_symlink():
            return None, norm, f"Symlinks are not allowed for remediation: '{rel_file}'"
        curr = curr.parent

    if not candidate.is_file():
        return None, norm, f"Target file not found: {norm}"

    try:
        clean_rel = str(candidate.relative_to(target_resolved))
    except ValueError:
        clean_rel = norm

    return candidate, clean_rel, None


def read_source_file_safe(file_path: Path) -> Tuple[str, str, str]:
    """Read source file while detecting encoding and preserving line endings.

    Returns:
        (content_str, detected_encoding, newline_sequence)
    """
    raw_bytes = file_path.read_bytes()

    # Detect line endings
    if b"\r\n" in raw_bytes:
        newline = "\r\n"
    elif b"\r" in raw_bytes:
        newline = "\r"
    else:
        newline = "\n"

    # Try encodings in order: UTF-8 with BOM, standard UTF-8, Japanese legacy encodings, then latin-1 fallback
    encodings_to_try = ["utf-8-sig", "utf-8", "cp932", "euc_jp", "iso2022_jp", "latin-1"]
    detected_encoding = "utf-8"
    content: Optional[str] = None

    for enc in encodings_to_try:
        try:
            content = raw_bytes.decode(enc)
            detected_encoding = enc
            break
        except (UnicodeDecodeError, LookupError):
            continue

    if content is None:
        content = raw_bytes.decode("utf-8", errors="replace")
        detected_encoding = "utf-8"

    return content, detected_encoding, newline


def write_source_file_safe(file_path: Path, content: str, encoding: str, newline: str) -> None:
    """Write patched source file preserving original encoding and line endings."""
    normalized_content = content.replace("\r\n", "\n").replace("\r", "\n")
    if newline != "\n":
        normalized_content = normalized_content.replace("\n", newline)

    encoded_bytes = normalized_content.encode(encoding)
    file_path.write_bytes(encoded_bytes)


class RemediationRunner:
    """Coordinates automated code patching based on security audit findings."""

    def __init__(
        self,
        target_dir: str | Path,
        findings_path: Optional[str | Path] = None,
        dry_run: bool = False,
        output_patch: Optional[str | Path] = None,
        branch_prefix: str = "fix-sec-",
    ) -> None:
        self.target_dir = Path(target_dir).resolve()
        self.findings_path = Path(findings_path).resolve() if findings_path else None
        self.dry_run = dry_run
        self.output_patch = Path(output_patch).resolve() if output_patch else None
        self.branch_prefix = branch_prefix
        self.registry = StrategyRegistry()

    def discover_findings_file(self) -> Path:
        """Locate findings.json in default known output paths if not explicitly provided."""
        if self.findings_path and self.findings_path.is_file():
            return self.findings_path

        candidates = [
            self.target_dir / "komainu-out" / "findings.json",
            self.target_dir / "findings.json",
            self.target_dir / "audit-results" / "findings.json",
            self.target_dir / "out" / "findings.json",
        ]
        for candidate in candidates:
            if candidate.is_file():
                return candidate

        raise FileNotFoundError(
            f"Findings file not found. Checked default locations under {self.target_dir}. "
            "Please specify --findings <path/to/findings.json>."
        )

    def load_findings(self) -> List[Dict[str, Any]]:
        """Load and parse findings from JSON or SARIF report."""
        findings_file = self.discover_findings_file()
        with open(findings_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        # 1. Format: { "findings": [...] }
        if isinstance(data, dict) and "findings" in data and isinstance(data["findings"], list):
            return data["findings"]

        # 2. Format: [...]
        if isinstance(data, list):
            return data

        # 3. Format: SARIF v2.1.0 { "runs": [{ "results": [...] }] }
        if isinstance(data, dict) and "runs" in data:
            findings = []
            for run in data.get("runs", []):
                for res in run.get("results", []):
                    rule_id = res.get("ruleId", "UNKNOWN")
                    category = "bola" if "BOLA" in rule_id else "sql_injection"
                    msg = res.get("message", {}).get("text", rule_id)
                    locs = res.get("locations", [])
                    file_uri = ""
                    start_line = 1
                    if locs:
                        phys = locs[0].get("physicalLocation", {})
                        file_uri = phys.get("artifactLocation", {}).get("uri", "")
                        start_line = phys.get("region", {}).get("startLine", 1)

                    findings.append({
                        "finding_id": rule_id,
                        "category": category,
                        "title": msg,
                        "location": {
                            "file": file_uri,
                            "start_line": start_line,
                        },
                        "status": "confirmed",
                    })
            return findings

        return []

    def create_plan(self, finding: Dict[str, Any]) -> RemediationPlan:
        """Create a planned remediation diff for a single finding."""
        finding_id = finding.get("finding_id", "UNKNOWN")
        category = finding.get("category", "unknown")
        title = finding.get("title", finding_id)
        loc = finding.get("location", {})
        rel_file = loc.get("file", "")
        start_line = loc.get("start_line", 1)
        end_line = loc.get("end_line", start_line)

        abs_file, clean_rel, err = safe_resolve_target_file(self.target_dir, rel_file)
        if err or abs_file is None:
            # Traversal attempt or symlink is flagged as error, missing file as skipped
            is_security_err = "traversal" in (err or "").lower() or "symlink" in (err or "").lower()
            return RemediationPlan(
                finding_id=finding_id,
                category=category,
                title=title,
                target_file=clean_rel or rel_file,
                absolute_path=str(abs_file) if abs_file else "",
                start_line=start_line,
                end_line=end_line,
                status="error" if is_security_err else "skipped",
                reason=err or "Target file resolution failed",
            )

        strategy = self.registry.find_strategy(finding)
        if not strategy:
            return RemediationPlan(
                finding_id=finding_id,
                category=category,
                title=title,
                target_file=clean_rel,
                absolute_path=str(abs_file),
                start_line=start_line,
                end_line=end_line,
                status="skipped",
                reason=f"No matching remediation strategy for category '{category}'",
            )

        try:
            original_content, encoding, newline = read_source_file_safe(abs_file)
            patched_content, explanation = strategy.generate_patch(abs_file, original_content, finding)

            if patched_content == original_content:
                return RemediationPlan(
                    finding_id=finding_id,
                    category=category,
                    title=title,
                    target_file=clean_rel,
                    absolute_path=str(abs_file),
                    start_line=start_line,
                    end_line=end_line,
                    original_content=original_content,
                    patched_content=original_content,
                    encoding=encoding,
                    newline=newline,
                    status="needs manual fix",
                    reason=explanation or "No automated rewrite applicable; requires manual remediation",
                )

            # Generate unified diff
            orig_lines = original_content.splitlines(keepends=True)
            patch_lines = patched_content.splitlines(keepends=True)
            diff_lines = list(
                difflib.unified_diff(
                    orig_lines,
                    patch_lines,
                    fromfile=f"a/{clean_rel}",
                    tofile=f"b/{clean_rel}",
                )
            )
            diff_text = "".join(diff_lines)

            return RemediationPlan(
                finding_id=finding_id,
                category=category,
                title=title,
                target_file=clean_rel,
                absolute_path=str(abs_file),
                start_line=start_line,
                end_line=end_line,
                original_content=original_content,
                patched_content=patched_content,
                diff=diff_text,
                encoding=encoding,
                newline=newline,
                status="planned",
                reason=explanation,
            )
        except Exception as e:
            return RemediationPlan(
                finding_id=finding_id,
                category=category,
                title=title,
                target_file=clean_rel,
                absolute_path=str(abs_file),
                start_line=start_line,
                end_line=end_line,
                status="error",
                reason=f"Failed to generate patch: {str(e)}",
            )

    def apply_plan(self, plan: RemediationPlan) -> bool:
        """Apply a remediation plan to disk preserving original encoding and line endings."""
        if plan.status != "planned" or not plan.patched_content or plan.patched_content == plan.original_content:
            return False

        if self.dry_run:
            # In dry-run mode, leave original file completely untouched and preserve 'planned' status
            return True

        try:
            target_path = Path(plan.absolute_path)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            write_source_file_safe(target_path, plan.patched_content, plan.encoding, plan.newline)
            plan.status = "applied"
            return True
        except Exception as e:
            plan.status = "error"
            plan.reason = f"Write error: {str(e)}"
            return False

    def run(self) -> RemediationReport:
        """Execute the remediation workflow."""
        findings = self.load_findings()
        report = RemediationReport(
            target_dir=str(self.target_dir),
            total_findings=len(findings),
            dry_run=self.dry_run,
        )

        all_diffs: List[str] = []

        for finding in findings:
            plan = self.create_plan(finding)
            if plan.status == "planned":
                self.apply_plan(plan)
                if plan.diff:
                    all_diffs.append(plan.diff)
            report.plans.append(plan)

        if self.output_patch and all_diffs:
            self.output_patch.parent.mkdir(parents=True, exist_ok=True)
            with open(self.output_patch, "w", encoding="utf-8") as f:
                f.write("".join(all_diffs))
            report.patch_file = str(self.output_patch)

        return report
