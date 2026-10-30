#!/usr/bin/env python3
"""Unit & Acceptance Tests for Boilerplate 3: Multi-Region Resilience & WORM Backup (Issue #113 & #210)."""

from __future__ import annotations

import datetime
import json
import os
import subprocess
import sys
import tempfile
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
        """Verifies S3 Object Lock, versioning, logging, and KMS key policy with role separation."""
        worm_tf = os.path.join(MODULE_ROOT, "terraform", "backup_worm.tf")
        with open(worm_tf, "r", encoding="utf-8") as f:
            content = f.read()

        # Invariant 1: S3 Object Lock & Versioning
        self.assertIn("object_lock_enabled = true", content)
        self.assertIn('mode = "COMPLIANCE"', content)
        self.assertIn("aws_s3_bucket_versioning", content)

        # Invariant 2: S3 Server Access Logging
        self.assertIn("aws_s3_bucket_logging", content)
        self.assertIn("worm_access_logs", content)

        # Invariant 3: KMS Key with strict role separation
        self.assertIn("aws_kms_key", content)
        self.assertIn("AllowBackupWriterKeyUsage", content)
        self.assertIn("DenyDirectKeyDeletionProtectionNote", content)

        # Invariant 4: No invalid s3:x-amz-object-lock-mode on delete
        self.assertNotIn("s3:x-amz-object-lock-mode", content)

        # Invariant 5: Cross-region replication infrastructure
        self.assertIn("aws_s3_bucket_replication_configuration", content)
        self.assertIn("replication_role", content)

    def test_03_terraform_networking_infrastructure(self) -> None:
        """Verifies primary VPC has IGW, route tables, and security groups."""
        main_tf = os.path.join(MODULE_ROOT, "terraform", "main.tf")
        with open(main_tf, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("aws_internet_gateway", content)
        self.assertIn("aws_route_table", content)
        self.assertIn("aws_route_table_association", content)
        self.assertIn("aws_security_group", content)

    def test_04_dr_snapshot_creation_and_integrity(self) -> None:
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

    def test_05_dr_snapshot_rejects_duplicate_id(self) -> None:
        """Verifies that attempting to overwrite an existing snapshot ID is rejected."""
        mgr = DRManager()
        mgr.create_snapshot("snap-unique-100", b"original-data", retention_days=365)

        with self.assertRaises(ValueError) as ctx:
            mgr.create_snapshot("snap-unique-100", b"tampered-data", retention_days=365)

        self.assertIn("already exists and is immutable", str(ctx.exception))

    def test_06_worm_immutability_blocks_deletion(self) -> None:
        """Verifies that attempting to delete a WORM compliant snapshot raises error."""
        mgr = DRManager()
        mgr.create_snapshot("snap-locked", b"critical-ledger-data", retention_days=365)

        # Must raise ImmutableRetentionViolationError
        with self.assertRaises(ImmutableRetentionViolationError):
            mgr.delete_snapshot("snap-locked")

    def test_07_dr_failover_restore_execution(self) -> None:
        """Verifies disaster recovery failover rehydration to secondary Osaka cluster."""
        mgr = DRManager(secondary_region="ap-northeast-3")
        mgr.create_snapshot("snap-dr-test", b"backup_state_bytes", retention_days=30)

        restore_res = mgr.execute_failover_restore("snap-dr-test", target_cluster="standby-osaka-ecs")
        self.assertEqual(restore_res["status"], "RESTORE_SUCCESSFUL")
        self.assertEqual(restore_res["target_cluster"], "standby-osaka-ecs")
        self.assertEqual(restore_res["region"], "ap-northeast-3")
        self.assertEqual(restore_res["integrity_status"], "VERIFIED_VALID")
        self.assertTrue(restore_res["is_simulated"])
        self.assertIn("synthetic benchmark", restore_res["simulation_note"].lower())
        self.assertGreater(restore_res["recovery_time_objective_actual_seconds"], 0)

    def test_08_dr_runbook_content(self) -> None:
        """Verifies the DR runbook defines RTO, RPO, and notes simulated benchmarks."""
        runbook = os.path.join(MODULE_ROOT, "dr", "runbook.md")
        self.assertTrue(os.path.isfile(runbook))
        with open(runbook, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("Recovery Time Objective", content)
        self.assertIn("Recovery Point Objective", content)
        self.assertIn("simulated synthetic benchmarks", content)
        self.assertIn("ap-northeast-1", content)
        self.assertIn("ap-northeast-3", content)
        self.assertIn("S3 Object Lock", content)

    def test_09_terraform_iam_roles_and_kms_hardening(self) -> None:
        """Verifies managed IAM roles, conditional replication handling, and KMS policy hardening (Issue #210)."""
        worm_tf = os.path.join(MODULE_ROOT, "terraform", "backup_worm.tf")
        outputs_tf = os.path.join(MODULE_ROOT, "terraform", "outputs.tf")
        with open(worm_tf, "r", encoding="utf-8") as f:
            content = f.read()
        with open(outputs_tf, "r", encoding="utf-8") as f:
            outputs = f.read()

        # Invariant 1: Dedicated IAM roles exist
        self.assertIn('resource "aws_iam_role" "backup_writer"', content)
        self.assertIn('resource "aws_iam_role" "backup_restore"', content)
        self.assertIn('resource "aws_iam_role" "security_officer"', content)

        # Invariant 2: KMS Key policy grants explicit Decrypt to restore role
        self.assertIn("AllowBackupRestoreKeyUsage", content)
        self.assertIn("aws_iam_role.backup_restore.arn", content)

        # Invariant 3: KMS key deletion deny statement uses managed security officer role
        self.assertIn("aws_iam_role.security_officer.arn", content)
        self.assertNotIn("role/KomaguSecurityOfficer", content)

        # Invariant 4: No unguarded direct index on replication_role[0]
        # Must be conditionally guarded when enable_cross_region_replication = false
        self.assertIn("var.enable_cross_region_replication", content)

        # Invariant 5: Outputs export new roles and log bucket
        self.assertIn("backup_writer_role_arn", outputs)
        self.assertIn("backup_restore_role_arn", outputs)
        self.assertIn("security_officer_role_arn", outputs)
        self.assertIn("worm_access_logs_bucket_arn", outputs)

    def test_10_terraform_bucket_hardening_and_logging_policy(self) -> None:
        """Verifies S3 access log delivery policy, bucket encryption, and public access blocks (Issue #210)."""
        worm_tf = os.path.join(MODULE_ROOT, "terraform", "backup_worm.tf")
        with open(worm_tf, "r", encoding="utf-8") as f:
            content = f.read()

        # Invariant 1: Access log bucket policy allows logging.s3.amazonaws.com
        self.assertIn("logging.s3.amazonaws.com", content)
        self.assertIn("aws_s3_bucket_policy", content)
        self.assertIn("worm_access_logs", content)

        # Invariant 2: Primary backup bucket hardened with public access block and SSE
        self.assertIn("aws_s3_bucket_public_access_block", content)
        self.assertIn("aws_s3_bucket_server_side_encryption_configuration", content)
        self.assertIn("primary_backup", content)

    def test_11_dr_manager_retention_validation_and_immutability(self) -> None:
        """Verifies DRManager rejects non-positive retention and prevents retention_until modification (Issue #210)."""
        mgr = DRManager()

        # Reject non-positive retention periods
        with self.assertRaises(ValueError) as ctx:
            mgr.create_snapshot("snap-invalid-1", b"data", retention_days=0)
        self.assertIn("at least 1", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            mgr.create_snapshot("snap-invalid-2", b"data", retention_days=-5)
        self.assertIn("at least 1", str(ctx.exception))

        # Retention deadline is read-only property
        record = mgr.create_snapshot("snap-valid-1", b"data", retention_days=30)
        with self.assertRaises(AttributeError):
            record.retention_until = datetime.datetime.now(datetime.timezone.utc)

    def test_12_dr_manager_cli_and_runbook_command(self) -> None:
        """Verifies DRManager CLI commands, including the exact runbook restore command (Issue #210)."""
        env = dict(os.environ)

        with tempfile.NamedTemporaryFile(suffix=".json") as tmp:
            env["KOMAGU_DR_METADATA_PATH"] = tmp.name

            # CLI --create
            create_cmd = [
                sys.executable,
                "-m",
                "remediate.resilience.dr.dr_manager",
                "--create",
                "--snapshot-id",
                "cli-test-01",
                "--payload",
                "test-data-cli",
                "--retention-days",
                "10",
                "--storage-path",
                tmp.name,
            ]
            res = subprocess.run(create_cmd, capture_output=True, text=True, check=True)
            self.assertIn("cli-test-01", res.stdout)

            # CLI --verify
            verify_cmd = [
                sys.executable,
                "-m",
                "remediate.resilience.dr.dr_manager",
                "--verify",
                "--snapshot-id",
                "cli-test-01",
                "--storage-path",
                tmp.name,
            ]
            res = subprocess.run(verify_cmd, capture_output=True, text=True, check=True)
            self.assertIn("OK: Cryptographic integrity verified", res.stdout)

            # CLI --list
            list_cmd = [
                sys.executable,
                "-m",
                "remediate.resilience.dr.dr_manager",
                "--list",
                "--storage-path",
                tmp.name,
            ]
            res = subprocess.run(list_cmd, capture_output=True, text=True, check=True)
            self.assertIn("cli-test-01", res.stdout)

            # CLI --restore from specific snapshot
            restore_cmd = [
                sys.executable,
                "-m",
                "remediate.resilience.dr.dr_manager",
                "--restore",
                "--snapshot-id",
                "cli-test-01",
                "--storage-path",
                tmp.name,
            ]
            res = subprocess.run(restore_cmd, capture_output=True, text=True, check=True)
            self.assertIn("RESTORE_SUCCESSFUL", res.stdout)

        # Exact runbook command: python3 -m remediate.resilience.dr.dr_manager --restore --snapshot-id "latest-verified"
        runbook_cmd = [
            sys.executable,
            "-m",
            "remediate.resilience.dr.dr_manager",
            "--restore",
            "--snapshot-id",
            "latest-verified",
        ]
        res = subprocess.run(runbook_cmd, capture_output=True, text=True, check=True)
        self.assertIn("RESTORE_SUCCESSFUL", res.stdout)
        self.assertIn("latest-verified", res.stdout)

    def test_13_dr_manager_persistence(self) -> None:
        """Verifies DRManager persists snapshot records to disk and reloads them."""
        with tempfile.NamedTemporaryFile(suffix=".json") as tmp:
            mgr1 = DRManager(storage_path=tmp.name)
            mgr1.create_snapshot("persisted-01", b"state-12345", retention_days=50)

            # Re-instantiate in a new instance
            mgr2 = DRManager(storage_path=tmp.name)
            self.assertIn("persisted-01", mgr2.storage)
            valid, msg = mgr2.verify_integrity("persisted-01")
            self.assertTrue(valid)
            self.assertEqual(mgr2.storage["persisted-01"].size_bytes, len(b"state-12345"))


if __name__ == "__main__":
    unittest.main()
