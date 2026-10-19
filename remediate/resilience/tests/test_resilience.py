#!/usr/bin/env python3
"""Unit & Acceptance Tests for Boilerplate 3: Multi-Region Resilience & WORM Backup."""

from __future__ import annotations

import os
import unittest

from remediate.resilience.dr.dr_manager import (
    DRManager,
    ImmutableRetentionViolationError,
)

MODULE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestMultiRegionResilience(unittest.TestCase):
    def test_01_terraform_configuration_files_exist(self) -> None:
        """Verifies all required Terraform / OpenTofu files exist."""
        tf_dir = os.path.join(MODULE_ROOT, "terraform")
        required_files = ["main.tf", "backup_worm.tf", "variables.tf", "outputs.tf"]
        for f in required_files:
            p = os.path.join(tf_dir, f)
            self.assertTrue(os.path.isfile(p), f"Terraform file {f} must exist")

    def test_02_terraform_worm_compliance_declarations(self) -> None:
        """Verifies S3 Object Lock in COMPLIANCE mode is declared in Terraform."""
        worm_tf = os.path.join(MODULE_ROOT, "terraform", "backup_worm.tf")
        with open(worm_tf, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("object_lock_enabled = true", content)
        self.assertIn('mode = "COMPLIANCE"', content)
        self.assertIn("aws_kms_key", content)
        self.assertIn("s3:DeleteObject", content)
        self.assertIn('Effect    = "Deny"', content)

    def test_03_dr_snapshot_creation_and_integrity(self) -> None:
        """Verifies immutable snapshot creation and cryptographic integrity check."""
        mgr = DRManager(secondary_region="ap-northeast-3")
        payload = b'{"database": "production", "records_count": 105420, "tenant": "all"}'
        record = mgr.create_snapshot("snap-2026-10-19-001", payload, retention_days=365)

        self.assertEqual(record.snapshot_id, "snap-2026-10-19-001")
        self.assertEqual(record.compliance_mode, "COMPLIANCE")
        self.assertEqual(record.secondary_region, "ap-northeast-3")

        valid, msg = mgr.verify_integrity("snap-2026-10-19-001")
        self.assertTrue(valid)
        self.assertIn("Cryptographic integrity verified", msg)

    def test_04_worm_immutability_blocks_deletion(self) -> None:
        """Verifies that attempting to delete a WORM compliant snapshot raises error."""
        mgr = DRManager()
        mgr.create_snapshot("snap-locked", b"critical-ledger-data", retention_days=365)

        # Must raise ImmutableRetentionViolationError
        with self.assertRaises(ImmutableRetentionViolationError):
            mgr.delete_snapshot("snap-locked")

    def test_05_dr_failover_restore_execution(self) -> None:
        """Verifies disaster recovery failover rehydration to secondary Osaka cluster."""
        mgr = DRManager(secondary_region="ap-northeast-3")
        mgr.create_snapshot("snap-dr-test", b"backup_state_bytes", retention_days=30)

        restore_res = mgr.execute_failover_restore("snap-dr-test", target_cluster="standby-osaka-ecs")
        self.assertEqual(restore_res["status"], "RESTORE_SUCCESSFUL")
        self.assertEqual(restore_res["target_cluster"], "standby-osaka-ecs")
        self.assertEqual(restore_res["region"], "ap-northeast-3")
        self.assertEqual(restore_res["integrity_status"], "VERIFIED_VALID")
        self.assertGreater(restore_res["recovery_time_objective_actual_seconds"], 0)

    def test_06_dr_runbook_content(self) -> None:
        """Verifies the DR runbook defines RTO, RPO, and failover triggers."""
        runbook = os.path.join(MODULE_ROOT, "dr", "runbook.md")
        self.assertTrue(os.path.isfile(runbook))
        with open(runbook, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("Recovery Time Objective", content)
        self.assertIn("Recovery Point Objective", content)
        self.assertIn("ap-northeast-1", content)
        self.assertIn("ap-northeast-3", content)
        self.assertIn("S3 Object Lock", content)


if __name__ == "__main__":
    unittest.main()
