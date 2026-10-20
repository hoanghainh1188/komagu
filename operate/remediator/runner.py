"""Orchestrator runner for Komainu automated code remediation."""

from __future__ import annotations

import difflib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from operate.remediator.models import RemediationPlan, RemediationReport
from operate.remediator.strategies import BaseRemediationStrategy, StrategyRegistry


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

        # Normalize relative path (strip leading slashes or ./)
        clean_rel = rel_file.lstrip("/").lstrip("./") if rel_file else ""
        abs_file = self.target_dir / clean_rel

        if not clean_rel or not abs_file.is_file():
            return RemediationPlan(
                finding_id=finding_id,
                category=category,
                title=title,
                target_file=clean_rel,
                absolute_path=str(abs_file),
                start_line=start_line,
                end_line=end_line,
                status="skipped",
                reason=f"Target file not found: {clean_rel}",
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
            with open(abs_file, "r", encoding="utf-8", errors="replace") as f:
                original_content = f.read()

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
                    patched_content=patched_content,
                    status="skipped",
                    reason=f"No changes required: {explanation}",
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
        """Apply a remediation plan to disk."""
        if plan.status != "planned" or not plan.patched_content:
            return False

        if self.dry_run:
            return True

        try:
            target_path = Path(plan.absolute_path)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            with open(target_path, "w", encoding="utf-8") as f:
                f.write(plan.patched_content)
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
