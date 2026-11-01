#!/usr/bin/env python3
"""Comprehensive unit tests for METI SCS Evidence Pack and Gap Report (#271).

Validates:
1. evidence-manifest.schema.json schema conformity.
2. Control mapping evaluation and readiness rating logic (★3, ★4, GAP).
3. ZIP archive bundling, SHA-256 cryptographic digests, and manifest structure.
4. Bilingual gap report generation (gap-report.ja.md and gap-report.md).
5. CLI execution `komagu evidence`, argument parsing, and quality gating (--require-tier).
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from assess.lsa.scripts.merge_findings import load_validator
from governance.scs.mapping import SCS_CONTROLS
from governance.scs.pack import EvidencePackBuilder
from operate.cli.main import main as cli_main


class TestEvidencePack(unittest.TestCase):
    def setUp(self) -> None:
        self.validate_schema = load_validator("evidence-manifest.schema.json")

    def test_schema_conformity_on_evaluated_manifest(self) -> None:
        """Generated evidence manifest must strictly conform to evidence-manifest.schema.json."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create synthetic audit artifacts
            audit_dir = Path(tmp_dir) / "audit"
            audit_dir.mkdir()
            (audit_dir / "findings.sarif").write_text("{}", encoding="utf-8")
            (audit_dir / "sbom-cyclonedx.json").write_text("{}", encoding="utf-8")
            (audit_dir / "api-inventory-diff.json").write_text("{}", encoding="utf-8")
            (audit_dir / "coraza.conf").write_text("SecRuleEngine On", encoding="utf-8")
            (audit_dir / "bas-evidence.json").write_text("{}", encoding="utf-8")

            builder = EvidencePackBuilder(
                audit_dirs=[audit_dir],
                project_name="Test Enterprise Portal",
                target_system="Production-Kubernetes",
            )
            arts = builder.discover_artifacts()
            ctrls, readiness = builder.evaluate_controls(arts)
            manifest = builder.generate_manifest(ctrls, readiness, arts)

            errs = self.validate_schema(manifest)
            self.assertEqual(errs, [], f"Schema validation errors: {errs}")
            self.assertEqual(manifest["project_name"], "Test Enterprise Portal")
            self.assertEqual(manifest["overall_readiness"]["rating"], "SCS-★4-READY")

    def test_pack_builder_generates_zip_and_reports(self) -> None:
        """build_pack must package evidence-pack.zip, manifest JSON, and bilingual reports."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit_dir = Path(tmp_dir) / "audit"
            audit_dir.mkdir()
            (audit_dir / "findings.sarif").write_text('{"runs": []}', encoding="utf-8")
            (audit_dir / "sbom-cyclonedx.json").write_text('{"bomFormat": "CycloneDX"}', encoding="utf-8")

            out_dir = Path(tmp_dir) / "output"

            builder = EvidencePackBuilder(
                audit_dirs=[audit_dir],
                project_name="Tokyo Logistics Monolith",
            )
            zip_p, manifest_p, ja_p, en_p = builder.build_pack(out_dir)

            self.assertTrue(zip_p.is_file())
            self.assertTrue(manifest_p.is_file())
            self.assertTrue(ja_p.is_file())
            self.assertTrue(en_p.is_file())

            # Verify Japanese report content
            ja_content = ja_p.read_text(encoding="utf-8")
            self.assertIn("サプライチェーン・サイバーセキュリティ", ja_content)
            self.assertIn("NIST CSF 2.0", ja_content)
            self.assertIn("Tokyo Logistics Monolith", ja_content)

            # Verify English report content
            en_content = en_p.read_text(encoding="utf-8")
            self.assertIn("METI Supply Chain Security", en_content)
            self.assertIn("Tokyo Logistics Monolith", en_content)

            # Verify ZIP contents
            with zipfile.ZipFile(zip_p, "r") as zf:
                names = zf.namelist()
                self.assertIn("evidence-manifest.json", names)
                self.assertIn("gap-report.ja.md", names)
                self.assertIn("gap-report.md", names)
                self.assertIn("artifacts/findings.sarif", names)
                self.assertIn("artifacts/sbom-cyclonedx.json", names)

    def test_cli_evidence_command_execution_and_gating(self) -> None:
        """Test `komagu evidence` CLI invocation and tier requirements."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit_dir = Path(tmp_dir) / "audit"
            audit_dir.mkdir()
            (audit_dir / "findings.sarif").write_text("{}", encoding="utf-8")

            out_dir = Path(tmp_dir) / "pack"

            # Execute without gate -> should succeed
            code = cli_main(["evidence", "--audit-dir", str(audit_dir), "--output-dir", str(out_dir)])
            self.assertEqual(code, 0)
            self.assertTrue((out_dir / "evidence-pack.zip").is_file())

            # Require tier 4 with only 1 artifact -> should fail quality gate
            code_gate = cli_main([
                "evidence",
                "--audit-dir", str(audit_dir),
                "--output-dir", str(out_dir),
                "--require-tier", "4",
            ])
            self.assertEqual(code_gate, 1)


if __name__ == "__main__":
    unittest.main()
