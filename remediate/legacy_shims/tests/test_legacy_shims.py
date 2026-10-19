#!/usr/bin/env python3
"""Unit and security verification tests for Komainu Legacy Remediation Shims (Issue #48 & #111)."""

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

    def test_php_shim_enforces_pdo_allowlist_portable_sql_and_404_exit(self) -> None:
        """PHP shim must validate identifiers, normalize IDs, use portable SQL, and exit with 404."""
        php_file = SHIMS_ROOT / "php" / "komainu_authz_shim.php"
        self.assertTrue(php_file.is_file())
        content = php_file.read_text(encoding="utf-8")

        self.assertIn("function komainu_validate_identifier", content)
        self.assertIn("in_array($identifier, $allowList, true)", content)
        self.assertIn("function komainu_normalize_id", content)
        self.assertIn("$pdo->prepare($sql)", content)
        self.assertIn("':resource_id' => $normResourceId", content)
        self.assertIn("':owner_id' => $normSessionUserId", content)
        self.assertIn("http_response_code(404)", content)
        self.assertIn("exit;", content)
        self.assertIn("function komainu_safe_order_by", content)
        # Ensure non-portable LIMIT 1 is eliminated in query
        self.assertNotIn("LIMIT 1", content)

    def test_java_shim_enforces_prepared_statement_and_allowlist(self) -> None:
        """Java OwnershipEnforcer must use PreparedStatement, normalize IDs, and throw 404 exception."""
        java_file = SHIMS_ROOT / "java" / "OwnershipEnforcer.java"
        self.assertTrue(java_file.is_file())
        content = java_file.read_text(encoding="utf-8")

        self.assertIn("class OwnershipEnforcer", content)
        self.assertIn("public static long normalizeId", content)
        self.assertIn("PreparedStatement ps = conn.prepareStatement(sql)", content)
        self.assertIn("ps.setLong(1, validResourceId)", content)
        self.assertIn("ps.setLong(2, validSessionUserId)", content)
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

    @unittest.skipUnless(shutil.which("javac") and shutil.which("java"), "JDK (javac/java) not available")
    def test_java_shim_behavioural_execution(self) -> None:
        """Verify Java OwnershipEnforcer behavioral execution with dynamic mock JDBC proxy."""
        java_source = SHIMS_ROOT / "java" / "OwnershipEnforcer.java"
        test_harness_src = """package dev.komainu.legacy.shim;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

public class OwnershipEnforcerBehaviouralTest {

    public static void main(String[] args) throws Exception {
        testNormalizeId();
        testCheckOwnershipFalsyIds();
        testRequireOwnershipBehavior();
        System.out.println("ALL_JAVA_BEHAVIOURAL_TESTS_PASSED");
    }

    private static void assertTrue(boolean cond, String msg) {
        if (!cond) throw new AssertionError(msg);
    }

    private static void testNormalizeId() {
        // Valid canonical positive integer IDs
        assertTrue(OwnershipEnforcer.normalizeId(1) == 1L, "int 1");
        assertTrue(OwnershipEnforcer.normalizeId("42") == 42L, "string 42");
        assertTrue(OwnershipEnforcer.normalizeId(9223372036854775807L) == Long.MAX_VALUE, "max long");

        // Falsy, empty, 0, negative, non-canonical, decimals, overflow
        Object[] invalid = new Object[] {
            null, "", "   ", 0, "0", -1, "-1", "007", "1e2", "&H5", "1.5", "abc", "99999999999999999999999"
        };
        for (Object inv : invalid) {
            try {
                OwnershipEnforcer.normalizeId(inv);
                throw new AssertionError("Expected IllegalArgumentException for: " + inv);
            } catch (IllegalArgumentException expected) {
                // Expected
            }
        }
    }

    private static void testCheckOwnershipFalsyIds() throws Exception {
        Map<String, OwnershipEnforcer.TableOwnershipSchema> registry = new HashMap<>();
        registry.put("orders", new OwnershipEnforcer.TableOwnershipSchema("orders", "id", "user_id"));

        // Connection should never be queried if candidate IDs are invalid
        Connection dummyConn = (Connection) Proxy.newProxyInstance(
            Connection.class.getClassLoader(),
            new Class<?>[] { Connection.class },
            (proxy, method, mArgs) -> {
                throw new AssertionError("Connection method should not be called for falsy IDs: " + method.getName());
            }
        );

        assertTrue(!OwnershipEnforcer.checkOwnership(dummyConn, "orders", "", 100, registry), "empty resourceId");
        assertTrue(!OwnershipEnforcer.checkOwnership(dummyConn, "orders", 0, 100, registry), "zero resourceId");
        assertTrue(!OwnershipEnforcer.checkOwnership(dummyConn, "orders", -5, 100, registry), "negative resourceId");
        assertTrue(!OwnershipEnforcer.checkOwnership(dummyConn, "orders", 100, "0", registry), "zero sessionUserId");
        assertTrue(!OwnershipEnforcer.checkOwnership(dummyConn, "orders", 100, "", registry), "empty sessionUserId");
        assertTrue(!OwnershipEnforcer.checkOwnership(dummyConn, "orders", 100, null, registry), "null sessionUserId");
    }

    private static void testRequireOwnershipBehavior() throws Exception {
        Map<String, OwnershipEnforcer.TableOwnershipSchema> registry = new HashMap<>();
        registry.put("orders", new OwnershipEnforcer.TableOwnershipSchema("orders", "id", "user_id"));

        AtomicBoolean resultSetNext = new AtomicBoolean(false);

        ResultSet mockRs = (ResultSet) Proxy.newProxyInstance(
            ResultSet.class.getClassLoader(),
            new Class<?>[] { ResultSet.class },
            (proxy, method, mArgs) -> {
                if ("next".equals(method.getName())) {
                    return resultSetNext.get();
                }
                return null;
            }
        );

        PreparedStatement mockPs = (PreparedStatement) Proxy.newProxyInstance(
            PreparedStatement.class.getClassLoader(),
            new Class<?>[] { PreparedStatement.class },
            (proxy, method, mArgs) -> {
                if ("executeQuery".equals(method.getName())) {
                    return mockRs;
                }
                return null;
            }
        );

        Connection mockConn = (Connection) Proxy.newProxyInstance(
            Connection.class.getClassLoader(),
            new Class<?>[] { Connection.class },
            (proxy, method, mArgs) -> {
                if ("prepareStatement".equals(method.getName())) {
                    return mockPs;
                }
                return null;
            }
        );

        // When DB finds matching row -> returns normalized resourceId
        resultSetNext.set(true);
        long normId = OwnershipEnforcer.requireOwnership(mockConn, "orders", "123", "456", registry);
        assertTrue(normId == 123L, "requireOwnership returned normalized ID");

        // When DB does NOT find row -> throws ResourceNotFoundOrForbiddenException
        resultSetNext.set(false);
        try {
            OwnershipEnforcer.requireOwnership(mockConn, "orders", "123", "456", registry);
            throw new AssertionError("Expected ResourceNotFoundOrForbiddenException on ownership mismatch");
        } catch (OwnershipEnforcer.ResourceNotFoundOrForbiddenException expected) {
            // Expected
        }

        // When table not registered -> throws ResourceNotFoundOrForbiddenException
        try {
            OwnershipEnforcer.requireOwnership(mockConn, "unregistered_table", "123", "456", registry);
            throw new AssertionError("Expected ResourceNotFoundOrForbiddenException on unregistered table");
        } catch (OwnershipEnforcer.ResourceNotFoundOrForbiddenException expected) {
            // Expected
        }
    }
}
"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            pkg_dir = Path(tmp_dir) / "dev" / "komainu" / "legacy" / "shim"
            pkg_dir.mkdir(parents=True)
            shutil.copy(java_source, pkg_dir / "OwnershipEnforcer.java")
            (pkg_dir / "OwnershipEnforcerBehaviouralTest.java").write_text(test_harness_src, encoding="utf-8")

            compile_proc = subprocess.run(
                ["javac", "-d", tmp_dir, str(pkg_dir / "OwnershipEnforcer.java"), str(pkg_dir / "OwnershipEnforcerBehaviouralTest.java")],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(compile_proc.returncode, 0, f"Compilation failed: {compile_proc.stderr}")

            run_proc = subprocess.run(
                ["java", "-cp", tmp_dir, "dev.komainu.legacy.shim.OwnershipEnforcerBehaviouralTest"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(run_proc.returncode, 0, f"Execution failed: {run_proc.stderr}")
            self.assertIn("ALL_JAVA_BEHAVIOURAL_TESTS_PASSED", run_proc.stdout)

    @unittest.skipUnless(shutil.which("php"), "php runtime not available")
    def test_php_shim_behavioural_execution(self) -> None:
        """Verify PHP shim behavioral normalization and denial with SQLite in-memory PDO."""
        php_file = SHIMS_ROOT / "php" / "komainu_authz_shim.php"
        php_test_script = f"""
        require_once '{php_file}';

        // 1. Test komainu_normalize_id
        assert(komainu_normalize_id(1) === 1);
        assert(komainu_normalize_id('42') === 42);
        
        $invalidIds = [null, '', false, true, 0, '0', -1, '-5', '007', '1e2', '0x5', '1.5'];
        foreach ($invalidIds as $inv) {{
            try {{
                komainu_normalize_id($inv);
                echo "FAIL: Expected exception for " . var_export($inv, true) . "\\n";
                exit(1);
            }} catch (InvalidArgumentException $e) {{
                // Expected
            }}
        }}

        // 2. Test komainu_check_ownership with SQLite in-memory PDO
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->exec('CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER)');
        $pdo->exec('INSERT INTO orders (id, user_id) VALUES (1, 100), (2, 0)');

        $allowed = ['orders' => ['pk' => 'id', 'owner' => 'user_id']];

        // Matching owner
        assert(komainu_check_ownership($pdo, 'orders', 'id', 1, 'user_id', 100, $allowed) === true);
        // Non-matching owner
        assert(komainu_check_ownership($pdo, 'orders', 'id', 1, 'user_id', 101, $allowed) === false);
        // Falsy or 0 ID never matches unowned row (id=2, user_id=0)
        assert(komainu_check_ownership($pdo, 'orders', 'id', 2, 'user_id', 0, $allowed) === false);
        assert(komainu_check_ownership($pdo, 'orders', 'id', 2, 'user_id', '0', $allowed) === false);
        assert(komainu_check_ownership($pdo, 'orders', 'id', '', 'user_id', 100, $allowed) === false);

        echo "ALL_PHP_BEHAVIOURAL_TESTS_PASSED\\n";
        """
        proc = subprocess.run(
            ["php", "-r", php_test_script],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"PHP execution failed: {proc.stderr}")
        self.assertIn("ALL_PHP_BEHAVIOURAL_TESTS_PASSED", proc.stdout)

    def test_mybatis_xml_uses_safe_binding_and_choose_when(self) -> None:
        """MyBatis example XML must use #{...} binding and <choose><when> without ${...}."""
        xml_file = SHIMS_ROOT / "java" / "mybatis-safe-sort-example.xml"
        self.assertTrue(xml_file.is_file())
        content = xml_file.read_text(encoding="utf-8")

        self.assertIn("#{orderId}", content)
        self.assertIn("#{sessionUserId}", content)
        self.assertIn("<choose>", content)
        self.assertIn("<when test=\"sortBy == 'amount_asc'\">", content)
        non_comment = content.split("-->")[-1]
        self.assertNotIn("${", non_comment)

    def test_coldfusion_shim_forbids_remote_and_enforces_cfqueryparam(self) -> None:
        """ColdFusion CFC shim must use access='public', <cfqueryparam>, normalizeId, and 404 + <cfabort>."""
        cfc_file = SHIMS_ROOT / "coldfusion" / "KomainuSecurityShim.cfc"
        self.assertTrue(cfc_file.is_file())
        content = cfc_file.read_text(encoding="utf-8")

        self.assertIn('access="public"', content)
        self.assertIn("<cfqueryparam", content)
        self.assertIn('statuscode="404"', content)
        self.assertIn("<cfabort>", content)
        self.assertIn('name="normalizeId"', content)
        self.assertIn("^[1-9][0-9]{0,18}$", content)
        self.assertIn("<cftry>", content)
        self.assertIn("<cfcatch", content)
        self.assertNotIn('<cffunction name="enforceOwnership" access="remote"', content)

    def test_classic_asp_shim_traps_errors_and_normalizes_ids(self) -> None:
        """Classic ASP shim must trap errors locally, normalize IDs, avoid Err.Raise, and emit 404 on failure."""
        asp_file = SHIMS_ROOT / "classic_asp" / "check_owner.asp"
        self.assertTrue(asp_file.is_file())
        content = asp_file.read_text(encoding="utf-8")

        self.assertIn('Server.CreateObject("ADODB.Command")', content)
        self.assertIn("cmd.CreateParameter", content)
        self.assertIn('Response.Status = "404 Not Found"', content)
        self.assertIn("Response.End", content)
        self.assertIn("Function KomainuNormalizeId", content)
        self.assertIn("Function KomainuSafeOrderBy", content)
        self.assertIn("On Error Resume Next", content)
        # Ensure no Err.Raise exists that could be swallowed by caller's On Error Resume Next
        self.assertNotIn("Err.Raise", content)

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
