#!/usr/bin/env python3
"""METI SCS Evidence Pack Bundler and Gap Report Generator (#271).

Assembles technical audit artifacts into a timestamped, cryptographically
hashed ZIP archive with evidence-manifest.json and bilingual gap reports.

Standard library only (Python 3.8+) per ADR-0006.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from governance.scs.mapping import (
    LEGAL_DISCLAIMER_EN,
    LEGAL_DISCLAIMER_JA,
    SCS_CONTROLS,
)


def compute_file_sha256(path: Path) -> str:
    """Compute standard SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class EvidencePackBuilder:
    """Evaluates audit directories and packages METI SCS evidence."""

    def __init__(
        self,
        audit_dirs: List[Union[str, Path]],
        project_name: str = "Komagu-Protected-Project",
        target_system: str = "Production-Environment",
    ) -> None:
        self.audit_dirs = [Path(d).resolve() for d in audit_dirs]
        self.project_name = project_name
        self.target_system = target_system

    def discover_artifacts(self) -> Dict[str, Path]:
        """Discover available technical evidence artifacts across provided directories."""
        discovered: Dict[str, Path] = {}
        for d in self.audit_dirs:
            if not d.is_dir():
                continue
            for root, _, files in os.walk(d):
                for f in files:
                    fp = Path(root) / f
                    # Key by filename for mapping match
                    if f not in discovered:
                        discovered[f] = fp
        return discovered

    def evaluate_controls(self, artifacts: Dict[str, Path]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Map discovered artifacts against METI SCS controls and compute readiness rating."""
        evaluated_controls: List[Dict[str, Any]] = []
        covered_count = 0
        partial_count = 0

        for ctrl in SCS_CONTROLS:
            matched_files: List[str] = []
            for exp in ctrl["expected_artifacts"]:
                if exp in artifacts:
                    matched_files.append(exp)

            if ctrl["control_id"] == "SCS-OG-01":
                # Organizational governance requires manual policy attachment
                status = "partially_covered" if matched_files else "out_of_scope_organizational"
            elif matched_files:
                status = "covered"
            else:
                status = "missing_evidence"

            if status == "covered":
                covered_count += 1
            elif status == "partially_covered":
                partial_count += 1

            entry = dict(ctrl)
            entry["status"] = status
            entry["evidence_files"] = matched_files
            evaluated_controls.append(entry)

        total = len(SCS_CONTROLS)
        compliance_pct = round(((covered_count + (0.5 * partial_count)) / total) * 100.0, 1)

        if compliance_pct >= 85.0 and any(c["tier"] == "★4" and c["status"] == "covered" for c in evaluated_controls):
            rating = "SCS-★4-READY"
        elif compliance_pct >= 60.0:
            rating = "SCS-★3-READY"
        elif compliance_pct > 0:
            rating = "GAP-IDENTIFIED"
        else:
            rating = "INSUFFICIENT-EVIDENCE"

        readiness = {
            "rating": rating,
            "total_controls": total,
            "covered_controls": covered_count,
            "partial_controls": partial_count,
            "compliance_percentage": compliance_pct,
        }

        return evaluated_controls, readiness

    def generate_manifest(
        self,
        evaluated_controls: List[Dict[str, Any]],
        readiness: Dict[str, Any],
        artifacts: Dict[str, Path],
    ) -> Dict[str, Any]:
        """Generate evidence-manifest.json conforming to evidence-manifest.schema.json."""
        bundled_records: List[Dict[str, Any]] = []

        # Collect artifacts referenced in controls
        used_files = set()
        for ctrl in evaluated_controls:
            for ef in ctrl["evidence_files"]:
                used_files.add(ef)

        for fname in sorted(used_files):
            fp = artifacts.get(fname)
            if fp and fp.is_file():
                bundled_records.append({
                    "filename": fname,
                    "artifact_type": fp.suffix.lstrip(".") or "txt",
                    "sha256": compute_file_sha256(fp),
                    "size_bytes": fp.stat().st_size,
                    "description": f"Audit artifact: {fname}",
                })

        manifest = {
            "$schema": "https://raw.githubusercontent.com/hoanghainh1188/komagu/main/contracts/schemas/evidence-manifest.schema.json",
            "manifest_version": "1.0.0",
            "project_name": self.project_name,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "target_system": self.target_system,
            "frameworks": [
                "METI Supply Chain Security Evaluation Scheme (SCS ★3/★4)",
                "NIST Cybersecurity Framework (NIST CSF 2.0)",
                "Japan Active Cyber Defense Act (能動的サイバー防御 2025)",
            ],
            "overall_readiness": readiness,
            "controls": evaluated_controls,
            "bundled_artifacts": bundled_records,
            "disclaimer": LEGAL_DISCLAIMER_JA + " " + LEGAL_DISCLAIMER_EN,
        }

        return manifest

    def render_gap_report_ja(self, manifest: Dict[str, Any]) -> str:
        """Render Japanese METI SCS Gap Analysis Report (gap-report.ja.md)."""
        r = manifest["overall_readiness"]
        lines = [
            "# 経済産業省 サプライチェーン・サイバーセキュリティ (SCS ★3/★4) 適合性ギャップ分析レポート",
            "",
            "> **対象プロジェクト / システム:** `" + manifest["project_name"] + " (" + manifest["target_system"] + ")`  ",
            "> **評価実施日時:** `" + manifest["generated_at"] + "`  ",
            "> **総合適合性ステータス:** **`" + r["rating"] + "`** (適合率: **" + str(r["compliance_percentage"]) + "%**)  ",
            "",
            "## 1. 概要及び評価結果サマリー",
            "",
            "本レポートは、2026年10月施行の**能動的サイバー防御法**および経済産業省**サプライチェーン・サイバーセキュリティ評価制度（SCS ★3/★4、NIST CSF 2.0準拠）**に基づき、"
            "Komaguが検出・収集したセキュリティ監査成果物を自動照合した結果です。",
            "",
            "| 評価項目 | 結果 / 指標 |",
            "|---|---|",
            f"| **評価対象統制数** | {r['total_controls']} 項目 |",
            f"| **技術的エビデンス充足 (Covered)** | {r['covered_controls']} 項目 |",
            f"| **部分的充足 / 組織的対応要 (Partial)** | {r['partial_controls']} 項目 |",
            f"| **総合適合率** | **{r['compliance_percentage']}%** |",
            f"| **判定ランク** | **{r['rating']}** |",
            "",
            "## 2. METI SCS / NIST CSF 2.0 統制項目別 照合結果マトリクス",
            "",
            "| 統制ID | 統制名 / カテゴリ | 要求水準 | NIST CSF 2.0 | ステータス | 添付エビデンス |",
            "|---|---|---|---|---|---|",
        ]

        status_ja = {
            "covered": "✅ 適合 (Covered)",
            "partially_covered": "⚠️ 部分的充足 (Partial)",
            "out_of_scope_organizational": "ℹ️ 組織的対応 (Organizational)",
            "missing_evidence": "❌ 証跡不足 (Missing)",
        }

        for c in manifest["controls"]:
            st = status_ja.get(c["status"], c["status"])
            ev_str = ", ".join(f"`{f}`" for f in c["evidence_files"]) if c["evidence_files"] else "*(なし)*"
            csf = ", ".join(c["nist_csf_v2"])
            lines.append(f"| **{c['control_id']}** | {c['name_ja']} | `{c['tier']}` | `{csf}` | {st} | {ev_str} |")

        lines.extend([
            "",
            "## 3. 残存ギャップおよび是正アクション (Action Items)",
            "",
        ])

        gap_found = False
        for c in manifest["controls"]:
            if c["status"] != "covered":
                gap_found = True
                lines.append(f"### 【{c['control_id']}】{c['name_ja']} ({c['tier']})")
                lines.append(f"- **NIST CSF 2.0 カテゴリ:** `{', '.join(c['nist_csf_v2'])}`")
                lines.append(f"- **現在の状態:** {status_ja.get(c['status'], c['status'])}")
                lines.append(f"- **推奨是正アクション:** {c.get('action_required_ja', '社内規程の整備')}")
                lines.append("")

        if not gap_found:
            lines.append("🎉 すべての統制項目に対して技術的エビデンスが充足しています。元請企業への提出が可能です。\n")

        lines.extend([
            "## 4. 添付エビデンスファイル一覧 (SHA-256 チェックサム)",
            "",
            "| ファイル名 | 種別 | SHA-256 チェックサム | サイズ |",
            "|---|---|---|---|",
        ])

        for a in manifest["bundled_artifacts"]:
            lines.append(f"| `{a['filename']}` | `{a['artifact_type']}` | `{a['sha256'][:16]}...` | {a['size_bytes']} bytes |")

        lines.extend([
            "",
            "---",
            "### 法的免責事項 (Legal Disclaimer)",
            LEGAL_DISCLAIMER_JA,
            "",
            "*Report generated autonomously by Komagu Security-First Modernization Platform.*",
        ])

        return "\n".join(lines) + "\n"

    def render_gap_report_en(self, manifest: Dict[str, Any]) -> str:
        """Render English METI SCS Gap Analysis Report (gap-report.md)."""
        r = manifest["overall_readiness"]
        lines = [
            "# METI Supply Chain Security (SCS ★3/★4) & NIST CSF 2.0 Gap Analysis Report",
            "",
            "> **Target Project / System:** `" + manifest["project_name"] + " (" + manifest["target_system"] + ")`  ",
            "> **Evaluation Timestamp:** `" + manifest["generated_at"] + "`  ",
            "> **Readiness Verdict:** **`" + r["rating"] + "`** (Compliance Score: **" + str(r["compliance_percentage"]) + "%**)  ",
            "",
            "## 1. Executive Summary",
            "",
            "This report maps automated Komagu technical security audit artifacts against the Japanese Ministry of Economy, "
            "Trade and Industry (METI) Supply Chain Security Evaluation Scheme (SCS ★3/★4) and NIST Cybersecurity Framework (CSF 2.0).",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| **Total Controls Evaluated** | {r['total_controls']} |",
            f"| **Technically Covered** | {r['covered_controls']} |",
            f"| **Partially Covered / Organizational** | {r['partial_controls']} |",
            f"| **Overall Compliance Score** | **{r['compliance_percentage']}%** |",
            f"| **Readiness Status** | **{r['rating']}** |",
            "",
            "## 2. Control Evaluation Matrix",
            "",
            "| Control ID | Name | Tier | NIST CSF 2.0 | Status | Evidence Artifacts |",
            "|---|---|---|---|---|---|",
        ]

        status_en = {
            "covered": "PASSED (Covered)",
            "partially_covered": "PARTIAL (Action Req)",
            "out_of_scope_organizational": "ORGANIZATIONAL",
            "missing_evidence": "MISSING",
        }

        for c in manifest["controls"]:
            st = status_en.get(c["status"], c["status"])
            ev_str = ", ".join(f"`{f}`" for f in c["evidence_files"]) if c["evidence_files"] else "*(none)*"
            csf = ", ".join(c["nist_csf_v2"])
            lines.append(f"| **{c['control_id']}** | {c['name_en']} | `{c['tier']}` | `{csf}` | `{st}` | {ev_str} |")

        lines.extend([
            "",
            "## 3. Gap Analysis & Remediation Action Plan",
            "",
        ])

        for c in manifest["controls"]:
            if c["status"] != "covered":
                lines.append(f"### [{c['control_id']}] {c['name_en']} ({c['tier']})")
                lines.append(f"- **NIST CSF 2.0 Category:** `{', '.join(c['nist_csf_v2'])}`")
                lines.append(f"- **Current Status:** `{status_en.get(c['status'], c['status'])}`")
                lines.append(f"- **Recommended Action:** {c.get('action_required_en', 'Document internal policy.')}")
                lines.append("")

        lines.extend([
            "## 4. Bundled Artifact Manifest & Cryptographic Hashes",
            "",
            "| Filename | Type | SHA-256 Digest | Size (Bytes) |",
            "|---|---|---|---|",
        ])

        for a in manifest["bundled_artifacts"]:
            lines.append(f"| `{a['filename']}` | `{a['artifact_type']}` | `{a['sha256']}` | {a['size_bytes']} |")

        lines.extend([
            "",
            "---",
            "### Disclaimer",
            LEGAL_DISCLAIMER_EN,
            "",
            "*Report generated autonomously by Komagu Security-First Modernization Platform.*",
        ])

        return "\n".join(lines) + "\n"

    def build_pack(self, output_dir: Union[str, Path]) -> Tuple[Path, Path, Path, Path]:
        """Build evidence pack ZIP, manifest JSON, and bilingual reports.
        
        Returns:
            (zip_path, manifest_path, gap_report_ja_path, gap_report_en_path)
        """
        out_p = Path(output_dir).resolve()
        out_p.mkdir(parents=True, exist_ok=True)

        artifacts = self.discover_artifacts()
        evaluated_controls, readiness = self.evaluate_controls(artifacts)
        manifest = self.generate_manifest(evaluated_controls, readiness, artifacts)

        manifest_path = out_p / "evidence-manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

        gap_report_ja_path = out_p / "gap-report.ja.md"
        gap_report_ja_path.write_text(self.render_gap_report_ja(manifest), encoding="utf-8")

        gap_report_en_path = out_p / "gap-report.md"
        gap_report_en_path.write_text(self.render_gap_report_en(manifest), encoding="utf-8")

        # Create evidence-pack.zip
        zip_path = out_p / "evidence-pack.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(manifest_path, arcname="evidence-manifest.json")
            zf.write(gap_report_ja_path, arcname="gap-report.ja.md")
            zf.write(gap_report_en_path, arcname="gap-report.md")

            for item in manifest["bundled_artifacts"]:
                fname = item["filename"]
                if fname in artifacts and artifacts[fname].is_file():
                    zf.write(artifacts[fname], arcname=f"artifacts/{fname}")

        return zip_path, manifest_path, gap_report_ja_path, gap_report_en_path
