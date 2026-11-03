#!/usr/bin/env python3
"""Secrets are masked in every code snippet the headless agents send to the model (#350)."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

import time

from operate.ai.context import _model_source, _read_snippet, _redact_lines, _verification_context

JAVA_DAO = '''package com.acme.dao;
public class AccountDao {
    private static final String URL = "jdbc:sqlserver://db01;databaseName=ams;user=sa;password=Ams#2019!";
    private static final String MONGO = "mongodb://svc:Mongo2020pw@mongo01:27017/ams";
    private static final String ORA = "jdbc:oracle:thin:scott/Tiger2018@db02:1521/AMS";
    // db.password=CommentPw7 (old config, kept for reference)
    private String apiKey = "sk-live-abcdef123456";
    public Account find(HttpServletRequest req) {
        String password = req.getParameter("password");
        String sql = "SELECT * FROM account WHERE id = " + req.getParameter("id");
        return jdbc.query(sql);
    }
}
'''

PROPERTIES = '''spring.datasource.url=jdbc:oracle:thin:@db02:1521/AMS
spring.datasource.username=ams_app
spring.datasource.password=Oracle#Pw2021
mail.smtp.password: smtpPw99
app.jwt.secret=c2VjcmV0LWtleS1mb3ItYW1z
app.token.placeholder=${APP_TOKEN}
'''

PRIVATE_KEY = '''-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwJ1rdTw6kLqA
Zm9vYmFyYmF6cXV4cXV1eHF1dXg=
-----END RSA PRIVATE KEY-----
class Signer {}
'''

JSP = '''<%-- legacy: ldap.bind.password=LdapPw55 --%>
<%@ page import="java.sql.*" %>
<% String id = request.getParameter("id"); %>
'''

SECRETS = ("Ams#2019!", "Mongo2020pw", "Tiger2018", "CommentPw7", "sk-live-abcdef123456", "Oracle#Pw2021", "smtpPw99",
           "c2VjcmV0LWtleS1mb3ItYW1z", "MIIEowIBAAKCAQEAwJ1rdTw6kLqA", "Zm9vYmFyYmF6cXV4cXV1eHF1dXg=", "LdapPw55")


class TestSnippetRedaction(unittest.TestCase):
    def setUp(self) -> None:
        self.target = Path(tempfile.mkdtemp(prefix="komagu_redact_"))
        files = {"src/com/acme/dao/AccountDao.java": JAVA_DAO, "src/main/resources/application.properties": PROPERTIES,
                 "src/com/acme/Signer.java": PRIVATE_KEY, "WebContent/user/detail.jsp": JSP}
        for rel, text in files.items():
            (self.target / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.target / rel).write_text(text, encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.target, ignore_errors=True)

    def assert_no_secret(self, text: str) -> None:
        for secret in SECRETS:
            self.assertNotIn(secret, text)

    def test_java_source_snippet_masks_connection_strings_and_keys(self) -> None:
        snip = _read_snippet(self.target, "src/com/acme/dao/AccountDao.java", 5)
        self.assert_no_secret(snip)
        self.assertIn("[REDACTED]", snip)

    def test_code_the_auditor_needs_is_kept(self) -> None:
        snip = _read_snippet(self.target, "src/com/acme/dao/AccountDao.java", 5)
        self.assertIn('String password = req.getParameter("password");', snip)
        self.assertIn('"SELECT * FROM account WHERE id = " + req.getParameter("id")', snip)
        self.assertIn("jdbc:sqlserver://db01;databaseName=ams;user=sa;password=[REDACTED]", snip)
        self.assertIn("mongodb://svc:[REDACTED]@mongo01:27017/ams", snip)
        self.assertIn("jdbc:oracle:thin:scott/[REDACTED]@db02:1521/AMS", snip)

    def test_config_line_inside_a_comment_is_masked(self) -> None:
        snip = _read_snippet(self.target, "WebContent/user/detail.jsp", 2)
        self.assert_no_secret(snip)
        self.assertIn("ldap.bind.password=[REDACTED] --%>", snip)
        self.assertIn('String id = request.getParameter("id");', snip)

    def test_assignments_in_code_are_kept(self) -> None:
        lines = ["user.password = req.body.password;", "if (token == null) return;", "token: req.headers.authorization,"]
        (self.target / "app.js").write_text("\n".join(lines) + "\n", encoding="utf-8")
        snip = _read_snippet(self.target, "app.js", 2)
        for line in lines:
            self.assertIn(line, snip)

    def test_unquoted_properties_values_are_masked(self) -> None:
        snip = _read_snippet(self.target, "src/main/resources/application.properties", 3)
        self.assert_no_secret(snip)
        self.assertIn("spring.datasource.username=ams_app", snip)
        self.assertIn("app.token.placeholder=${APP_TOKEN}", snip)

    def test_private_key_block_is_masked_with_line_numbers_kept(self) -> None:
        snip = _read_snippet(self.target, "src/com/acme/Signer.java", 3)
        self.assert_no_secret(snip)
        self.assertIn("   5 | class Signer {}", snip)

    def test_model_and_verifier_context_are_masked(self) -> None:
        model = _model_source(self.target, "AccountDao", "src/com/acme/dao/AccountDao.java", 1)
        self.assert_no_secret(model["code"])
        ctx = _verification_context(self.target, {"location": {"file": "src/com/acme/dao/AccountDao.java", "start_line": 8},
                                                  "evidence": [{"file": "src/main/resources/application.properties", "line": 3}]})
        self.assert_no_secret(str(ctx))


class TestJavaLegacySecretForms(unittest.TestCase):
    """Forms found in a security review of the first version (#350); each must hide Hunter2x."""

    LEAKS = (
        '<property name="password" value="Hunter2x"/>',
        '<property name="jdbc.password"\n          value="Hunter2x"/>',
        "<param-name>db.password</param-name><param-value>Hunter2x</param-value>",
        "<init-param>\n  <param-name>password</param-name>\n  <param-value>Hunter2x</param-value>",
        "<password>Hunter2x</password>",
        'conn.setPassword("Hunter2x");',
        'props.setProperty("mail.smtp.password", "Hunter2x");',
        'Connection c = DriverManager.getConnection(url, "sa", "Hunter2x");',
        'return new PasswordAuthentication("svc", "Hunter2x".toCharArray());',
        'String pw = "Hunter2x";',
        'static final String DB_PASS = "Hunter2x";',
        '<Connector port="8443" keystorePass="Hunter2x" truststorePass="Hunter2x"/>',
        '{"password":"Hunter2x", "apikey" : "Hunter2x"}',
        "$conf = array('password' => 'Hunter2x');",
        "db_password: Hunter2x  # prod",
        "mail.smtp.pass=Hunter2x",
        "ssl.key.passphrase=Hunter2x",
        "jdbc:sqlserver://db;user=sa;password={Hunter2x;x}",
        'conn.setRequestProperty("Authorization", "Basic SHVudGVyMng6eHl6");',
        'h.put("Authorization", "Bearer Hunter2xHunter2x.eyJzdWIiOiIxIn0.sig");',
        "-----BEGIN PRIVATE KEY----- Hunter2xMIIEvQIBADANBgkq -----END PRIVATE KEY-----",
    )
    TOKENS = ("AKIAIOSFODNN7EXAMPLE", "ghp_" + "a" * 36, "sk-ant-api03-" + "b" * 40, "AIza" + "c" * 35)
    KEPT = (
        'String password = req.getParameter("password");',
        "String sql = \"SELECT * FROM users WHERE login='\" + u + \"' AND pwd='\" + p + \"'\";",
        "<select id=\"login\">SELECT * FROM users WHERE pwd = #{password}</select>",
        "spring.datasource.password=${DB_PASS}",
        "user.password = req.body.password;",
        "if (token == null) return;",
        'String header = "Bearer " + token;',
        '<property name="username" value="ams_app"/>',
        "Passenger p = passengerDao.find(id);",
    )

    def redact(self, text: str) -> str:
        return "\n".join(_redact_lines(text.split("\n")))

    def test_java_legacy_forms_are_masked(self) -> None:
        for sample in self.LEAKS:
            with self.subTest(sample=sample):
                self.assertNotIn("Hunter2x", self.redact(sample))

    def test_cloud_and_vcs_tokens_are_masked(self) -> None:
        for token in self.TOKENS:
            with self.subTest(token=token[:8]):
                self.assertNotIn(token, self.redact(f'String key = cfg.get("{token}");'))

    def test_code_the_auditor_needs_is_kept(self) -> None:
        for line in self.KEPT:
            with self.subTest(line=line):
                self.assertEqual(self.redact(line), line)

    def test_long_lines_are_fast_and_not_sent(self) -> None:
        lines = ["a.b" * 300000 + "password", "a-" * 500000 + "://", "a-b." * 250000, "x" * 1000000]
        start = time.monotonic()
        out = _redact_lines(lines)
        self.assertLess(time.monotonic() - start, 2.0)
        self.assertTrue(all(o.startswith("[line of ") for o in out))


if __name__ == "__main__":
    unittest.main()
