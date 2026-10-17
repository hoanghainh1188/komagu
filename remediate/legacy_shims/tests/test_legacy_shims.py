#!/usr/bin/env python3
"""Unit and security verification tests for Komainu Legacy Remediation Shims (Issue #48)."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SHIMS_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = SHIMS_ROOT.parent.parent


class TestLegacyRemediationShims(unittest.TestCase):
    """Verify PHP, Java, ColdFusion, and Classic ASP legacy remediation shims."""

    def test_php_shim_enforces_pdo_allowlist_and_404_exit(self) -> None:
        """PHP shim must validate identifiers, use PDO prepare/execute, and exit with 404."""
        php_file = SHIMS_ROOT / "php" / "komainu_authz_shim.php"
        self.assertTrue(php_file.is_file())
        content = php_file.read_text(encoding="utf-8")

        self.assertIn("function komainu_validate_identifier", content)
        self.assertIn("in_array($identifier, $allowList, true)", content)
        self.assertIn("$pdo->prepare($sql)", content)
        self.assertIn("':resource_id' => $resourceId", content)
        self.assertIn("':owner_id' => $sessionUserId", content)
        self.assertIn("http_response_code(404)", content)
        self.assertIn("exit;", content)
        self.assertIn("function komainu_safe_order_by", content)

    def test_java_shim_enforces_prepared_statement_and_allowlist(self) -> None:
        """Java OwnershipEnforcer must use PreparedStatement, regex + allow-list, and 404 exception."""
        java_file = SHIMS_ROOT / "java" / "OwnershipEnforcer.java"
        self.assertTrue(java_file.is_file())
        content = java_file.read_text(encoding="utf-8")

        self.assertIn("class OwnershipEnforcer", content)
        self.assertIn("PreparedStatement ps = conn.prepareStatement(sql)", content)
        self.assertIn("ps.setObject(1, resourceId)", content)
        self.assertIn("ps.setObject(2, sessionUserId)", content)
        self.assertIn("ResourceNotFoundOrForbiddenException", content)
        self.assertIn("public static String safeOrderBy", content)

    @unittest.skipUnless(shutil.which("javac"), "javac not installed")
    def test_java_shim_compiles_cleanly(self) -> None:
        """Java OwnershipEnforcer.java must compile with zero errors via javac."""
        java_file = SHIMS_ROOT / "java" / "OwnershipEnforcer.java"
        with tempfile.TemporaryDirectory() as tmp_dir:
            proc = subprocess.run(
                ["javac", "-d", tmp_dir, str(java_file)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, f"javac failed: {proc.stderr}")

    def test_mybatis_xml_uses_safe_binding_and_choose_when(self) -> None:
        """MyBatis example XML must use #{...} binding and <choose><when> without ${...}."""
        xml_file = SHIMS_ROOT / "java" / "mybatis-safe-sort-example.xml"
        self.assertTrue(xml_file.is_file())
        content = xml_file.read_text(encoding="utf-8")

        self.assertIn("#{orderId}", content)
        self.assertIn("#{sessionUserId}", content)
        self.assertIn("<choose>", content)
        self.assertIn("<when test=\"sortBy == 'amount_asc'\">", content)
        # Ensure no raw ${...} interpolation exists in executable XML tags
        non_comment = content.split("-->")[-1]
        self.assertNotIn("${", non_comment)

    def test_coldfusion_shim_forbids_remote_and_enforces_cfqueryparam(self) -> None:
        """ColdFusion CFC shim must use access='public', <cfqueryparam>, and 404 + <cfabort>."""
        cfc_file = SHIMS_ROOT / "coldfusion" / "KomainuSecurityShim.cfc"
        self.assertTrue(cfc_file.is_file())
        content = cfc_file.read_text(encoding="utf-8")

        self.assertIn('access="public"', content)
        self.assertIn("<cfqueryparam", content)
        self.assertIn('statuscode="404"', content)
        self.assertIn("<cfabort>", content)
        # Ensure no method is exposed as access="remote"
        self.assertNotIn('<cffunction name="enforceOwnership" access="remote"', content)

    def test_classic_asp_shim_uses_adodb_command_parameters_and_response_end(self) -> None:
        """Classic ASP shim must use ADODB.Command CreateParameter and Response.End on 404."""
        asp_file = SHIMS_ROOT / "classic_asp" / "check_owner.asp"
        self.assertTrue(asp_file.is_file())
        content = asp_file.read_text(encoding="utf-8")

        self.assertIn('Server.CreateObject("ADODB.Command")', content)
        self.assertIn("cmd.CreateParameter", content)
        self.assertIn('Response.Status = "404 Not Found"', content)
        self.assertIn("Response.End", content)
        self.assertIn("Function KomainuSafeOrderBy", content)

    def test_lsa_prescan_flags_zero_high_confidence_injections_on_shims(self) -> None:
        """Running LSA find_injection on remediate/legacy_shims must produce zero high-confidence SQLi."""
        lsa_scripts = REPO_ROOT / "assess" / "lsa" / "scripts"
        if str(lsa_scripts) not in sys.path:
            sys.path.insert(0, str(lsa_scripts))
        from find_injection import find_injection  # type: ignore
        from lsa_common import load_config  # type: ignore

        cfg = load_config(None)
        result = find_injection(SHIMS_ROOT, cfg)
        candidates = result.get("candidates", [])
        high_candidates = [c for c in candidates if c.get("confidence") == "high"]
        self.assertEqual(
            len(high_candidates),
            0,
            f"Expected 0 high-confidence injection candidates in shims, got: {high_candidates}",
        )


if __name__ == "__main__":
    unittest.main()
