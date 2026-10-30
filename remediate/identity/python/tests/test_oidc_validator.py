"""Security & Conformance Unit Tests for Komagu OIDC Token Validator (D2).

Covers all acceptance criteria from Issue #104:
- Cryptographic signature verification against pinned asymmetric algorithms (RS256, etc.)
- Rejection of alg=none and algorithm confusion (HS256 with public key)
- Enforcement of mandatory claims (sub, tenant, exp, iss, aud)
- Strict rejection of missing or NaN exp claims
- Prevention of insecure default-tenant fallback
- Dev tokens disabled by default; strictly gated to test environments
- Absence of circular imports between identity and authz
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
import unittest
from typing import Any, Dict

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from remediate.identity.python.komagu_identity.models import UserPrincipal
from remediate.identity.python.komagu_identity.oidc_validator import OidcTokenValidator


class TestOidcTokenValidator(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        os.environ.setdefault("KOMAGU_ENV", "test")
        # Generate an RSA-2048 keypair for cryptographic testing
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_pem = cls.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        # Generate a separate attacker keypair for forged signature testing
        cls.attacker_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cls.issuer = "https://identity.komagu.test"
        cls.audience = "komagu-api"

    def _create_token(
        self,
        claims: Dict[str, Any],
        key: Any = None,
        algorithm: str = "RS256",
        headers: Dict[str, Any] = None,
    ) -> str:
        signing_key = key or self.private_key
        return jwt.encode(claims, key=signing_key, algorithm=algorithm, headers=headers)

    def test_01_forged_signature_rejected(self) -> None:
        """Tokens with forged or tampered signatures must be strictly rejected."""
        validator = OidcTokenValidator(
            issuer=self.issuer,
            audience=self.audience,
            public_key=self.public_pem,
        )
        now = time.time()
        claims = {
            "sub": "user-victim",
            "tenant_id": "tenant-corp",
            "iss": self.issuer,
            "aud": self.audience,
            "exp": int(now + 3600),
            "iat": int(now),
        }
        # Token signed by attacker's untrusted key
        forged_token = self._create_token(claims, key=self.attacker_private_key)

        with self.assertRaises(PermissionError) as ctx:
            validator.validate_token(f"Bearer {forged_token}")
        self.assertIn("invalid", str(ctx.exception).lower())

        # Token with tampered signature string
        tampered_token = forged_token[:-8] + "ABCDEFGH"
        with self.assertRaises(PermissionError):
            validator.validate_token(f"Bearer {tampered_token}")

    def test_02_alg_none_rejected(self) -> None:
        """Tokens specifying 'alg: none' must be rejected with PermissionError."""
        validator = OidcTokenValidator(
            issuer=self.issuer,
            audience=self.audience,
            public_key=self.public_pem,
        )
        now = time.time()
        header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode("ascii").rstrip("=")
        payload_data = {
            "sub": "user-attacker",
            "tenant_id": "tenant-corp",
            "iss": self.issuer,
            "aud": self.audience,
            "exp": int(now + 3600),
        }
        payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode("utf-8")).decode("ascii").rstrip("=")
        none_token = f"{header}.{payload}."

        with self.assertRaises(PermissionError) as ctx:
            validator.validate_token(none_token)
        self.assertIn("algorithm", str(ctx.exception).lower())

    def test_03_hs256_confusion_with_public_key_rejected(self) -> None:
        """Tokens signed via HS256 using the RSA public key must be rejected (algorithm confusion attack)."""
        import hashlib
        import hmac

        validator = OidcTokenValidator(
            issuer=self.issuer,
            audience=self.audience,
            public_key=self.public_pem,
        )
        now = time.time()
        header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode("ascii").rstrip("=")
        payload_data = {
            "sub": "user-attacker",
            "tenant_id": "tenant-corp",
            "iss": self.issuer,
            "aud": self.audience,
            "exp": int(now + 3600),
        }
        payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode("utf-8")).decode("ascii").rstrip("=")
        signing_input = f"{header}.{payload}".encode("ascii")
        sig = base64.urlsafe_b64encode(
            hmac.new(self.public_pem.encode("utf-8"), signing_input, hashlib.sha256).digest()
        ).decode("ascii").rstrip("=")
        hs256_token = f"{header}.{payload}.{sig}"

        with self.assertRaises(PermissionError) as ctx:
            validator.validate_token(hs256_token)
        self.assertIn("algorithm", str(ctx.exception).lower())

    def test_04_missing_exp_rejected(self) -> None:
        """Tokens missing the 'exp' claim must be rejected."""
        validator = OidcTokenValidator(
            issuer=self.issuer,
            audience=self.audience,
            public_key=self.public_pem,
        )
        now = time.time()
        claims = {
            "sub": "user-legit",
            "tenant_id": "tenant-corp",
            "iss": self.issuer,
            "aud": self.audience,
            "iat": int(now),
            # Missing "exp"
        }
        token = self._create_token(claims)
        with self.assertRaises(PermissionError) as ctx:
            validator.validate_token(token)
        self.assertTrue("claim" in str(ctx.exception).lower() or "exp" in str(ctx.exception).lower())

    def test_05_nan_exp_rejected(self) -> None:
        """Tokens with NaN or invalid non-numeric 'exp' claims must be rejected."""
        validator = OidcTokenValidator(
            issuer=self.issuer,
            audience=self.audience,
            public_key=self.public_pem,
        )
        header = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').decode("ascii").rstrip("=")
        payload_data = {
            "sub": "user-legit",
            "tenant_id": "tenant-corp",
            "iss": self.issuer,
            "aud": self.audience,
            "exp": "nan",
        }
        payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode("utf-8")).decode("ascii").rstrip("=")
        # Sign with actual private key
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        signing_input = f"{header}.{payload}".encode("ascii")
        signature = self.private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        sig_b64 = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        nan_token = f"{header}.{payload}.{sig_b64}"

        with self.assertRaises(PermissionError) as ctx:
            validator.validate_token(nan_token)
        self.assertIn("token", str(ctx.exception).lower())

    def test_06_missing_tenant_rejected_no_fallback(self) -> None:
        """Tokens lacking a tenant claim must be rejected and must NEVER fallback to 'default-tenant'."""
        validator = OidcTokenValidator(
            issuer=self.issuer,
            audience=self.audience,
            public_key=self.public_pem,
        )
        now = time.time()
        claims = {
            "sub": "user-legit",
            # No tenant_id, tid, or org_id
            "iss": self.issuer,
            "aud": self.audience,
            "exp": int(now + 3600),
            "iat": int(now),
        }
        token = self._create_token(claims)

        with self.assertRaises(PermissionError) as ctx:
            validator.validate_token(token)
        self.assertIn("tenant", str(ctx.exception).lower())

    def test_07_missing_sub_rejected(self) -> None:
        """Tokens missing the 'sub' subject claim must be rejected."""
        validator = OidcTokenValidator(
            issuer=self.issuer,
            audience=self.audience,
            public_key=self.public_pem,
        )
        now = time.time()
        claims = {
            "tenant_id": "tenant-corp",
            "iss": self.issuer,
            "aud": self.audience,
            "exp": int(now + 3600),
            "iat": int(now),
            # Missing "sub"
        }
        token = self._create_token(claims)
        with self.assertRaises(PermissionError) as ctx:
            validator.validate_token(token)
        self.assertTrue("sub" in str(ctx.exception).lower() or "claim" in str(ctx.exception).lower())

    def test_08_dev_tokens_rejected_by_default(self) -> None:
        """Dev tokens like 'token-admin' and 'token-user-a' must be rejected when allow_dev_tokens is False."""
        validator = OidcTokenValidator(
            issuer=self.issuer,
            audience=self.audience,
            public_key=self.public_pem,
            allow_dev_tokens=False,
        )

        for dev_tok in ["token-user-a", "token-user-b", "token-admin", "token-cross-tenant"]:
            with self.assertRaises(PermissionError):
                validator.validate_token(f"Bearer {dev_tok}")
            with self.assertRaises(PermissionError):
                validator.validate_token(dev_tok)

    def test_09_dev_tokens_refuses_outside_test_environment(self) -> None:
        """OidcTokenValidator must raise RuntimeError if allow_dev_tokens=True outside a test runner."""
        # Run a standalone python snippet with KOMAGU_ENV=production to simulate production
        snippet = (
            "import os\n"
            "os.environ['KOMAGU_ENV'] = 'production'\n"
            "from remediate.identity.python.komagu_identity.oidc_validator import OidcTokenValidator\n"
            "try:\n"
            "    OidcTokenValidator(issuer='https://a', audience='b', allow_dev_tokens=True)\n"
            "    print('FAIL')\n"
            "except RuntimeError as e:\n"
            "    print('OK: ' + str(e))\n"
        )
        res = subprocess.run(
            [sys.executable, "-c", snippet],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("OK: Dev tokens are only permitted in test environments", res.stdout)

    def test_10_dev_tokens_work_when_explicitly_opted_in_test(self) -> None:
        """Dev tokens are accepted when explicitly configured with allow_dev_tokens=True in test env."""
        validator = OidcTokenValidator(
            issuer=self.issuer,
            audience=self.audience,
            allow_dev_tokens=True,
        )
        user_a = validator.validate_token("token-user-a")
        self.assertEqual(user_a.user_id, "user-a")
        self.assertEqual(user_a.tenant_id, "tenant-komagu")
        self.assertTrue(user_a.is_authenticated)

        admin = validator.validate_token("Bearer token-admin")
        self.assertEqual(admin.user_id, "user-admin")
        self.assertIn("Admin", admin.roles)

    def test_11_valid_rsa_token_succeeds(self) -> None:
        """Valid RSA signed JWT with required claims must return an authenticated UserPrincipal."""
        validator = OidcTokenValidator(
            issuer=self.issuer,
            audience=self.audience,
            public_key=self.public_pem,
        )
        now = time.time()
        claims = {
            "sub": "user-alice-prod",
            "tenant_id": "tenant-primary",
            "iss": self.issuer,
            "aud": self.audience,
            "exp": int(now + 1800),
            "iat": int(now),
            "nbf": int(now - 10),
            "roles": ["BillingAdmin", "Member"],
        }
        token = self._create_token(claims)
        principal = validator.validate_token(f"Bearer {token}")

        self.assertIsInstance(principal, UserPrincipal)
        self.assertEqual(principal.user_id, "user-alice-prod")
        self.assertEqual(principal.tenant_id, "tenant-primary")
        self.assertEqual(principal.roles, ["BillingAdmin", "Member"])
        self.assertTrue(principal.is_authenticated)
        self.assertEqual(principal.claims["sub"], "user-alice-prod")

    def test_12_issuer_and_audience_mismatch_rejected(self) -> None:
        """Token with mismatched issuer or audience must be rejected."""
        validator = OidcTokenValidator(
            issuer=self.issuer,
            audience=self.audience,
            public_key=self.public_pem,
        )
        now = time.time()
        # Mismatched issuer
        claims_bad_iss = {
            "sub": "user-legit",
            "tenant_id": "tenant-corp",
            "iss": "https://rogue-issuer.test",
            "aud": self.audience,
            "exp": int(now + 3600),
        }
        tok_bad_iss = self._create_token(claims_bad_iss)
        with self.assertRaises(PermissionError):
            validator.validate_token(tok_bad_iss)

        # Mismatched audience
        claims_bad_aud = {
            "sub": "user-legit",
            "tenant_id": "tenant-corp",
            "iss": self.issuer,
            "aud": "wrong-audience",
            "exp": int(now + 3600),
        }
        tok_bad_aud = self._create_token(claims_bad_aud)
        with self.assertRaises(PermissionError):
            validator.validate_token(tok_bad_aud)

    def test_13_leeway_limit_enforced(self) -> None:
        """Leeway must be bounded between 0 and 120 seconds."""
        with self.assertRaises(ValueError):
            OidcTokenValidator(issuer=self.issuer, audience=self.audience, leeway=121.0)
        with self.assertRaises(ValueError):
            OidcTokenValidator(issuer=self.issuer, audience=self.audience, leeway=-1.0)

    def test_14_jwks_https_enforced(self) -> None:
        """JWKS URI must use HTTPS protocol outside permissive test dev-token mode."""
        snippet = (
            "import os\n"
            "os.environ['KOMAGU_ENV'] = 'production'\n"
            "from remediate.identity.python.komagu_identity.oidc_validator import OidcTokenValidator\n"
            "try:\n"
            "    OidcTokenValidator(issuer='https://a', audience='b', jwks_uri='http://insecure.test/jwks')\n"
            "    print('FAIL')\n"
            "except ValueError as e:\n"
            "    print('OK: ' + str(e))\n"
        )
        res = subprocess.run([sys.executable, "-c", snippet], capture_output=True, text=True, check=True)
        self.assertIn("JWKS URI must use HTTPS protocol", res.stdout)

    def test_15_no_circular_import(self) -> None:
        """Importing komagu_identity independently must not trigger circular import errors."""
        snippet = "import remediate.identity.python.komagu_identity; print('IMPORT_OK')"
        res = subprocess.run([sys.executable, "-c", snippet], capture_output=True, text=True, check=True)
        self.assertIn("IMPORT_OK", res.stdout)

    def test_16_tenant_claim_precedence_and_zero_value(self) -> None:
        """Tenant claim parsing must not treat falsy 0 as missing and fallback to evil secondary claim."""
        validator = OidcTokenValidator(
            issuer=self.issuer,
            audience=self.audience,
            public_key=self.public_pem,
        )
        now = time.time()
        # Invariant from Issue #207: tenant_id=0, tid="evil" must yield tenant "0", never "evil"
        claims = {
            "sub": "user-legit",
            "tenant_id": 0,
            "tid": "evil",
            "iss": self.issuer,
            "aud": self.audience,
            "exp": int(now + 3600),
        }
        token = self._create_token(claims)
        principal = validator.validate_token(token)
        self.assertEqual(principal.tenant_id, "0")
        self.assertNotEqual(principal.tenant_id, "evil")

    def test_17_is_test_environment_not_fooled_by_latest_flag(self) -> None:
        """_is_test_environment must not treat flags like --latest as running tests."""
        from remediate.identity.python.komagu_identity.oidc_validator import _is_test_environment

        orig_argv = sys.argv
        orig_env = os.environ.get("KOMAGU_ENV")
        orig_pytest = os.environ.get("PYTEST_CURRENT_TEST")
        try:
            if "KOMAGU_ENV" in os.environ:
                del os.environ["KOMAGU_ENV"]
            if "PYTEST_CURRENT_TEST" in os.environ:
                del os.environ["PYTEST_CURRENT_TEST"]
            sys.argv = ["komagu", "--latest", "run"]
            self.assertFalse(_is_test_environment())
        finally:
            sys.argv = orig_argv
            if orig_env is not None:
                os.environ["KOMAGU_ENV"] = orig_env
            if orig_pytest is not None:
                os.environ["PYTEST_CURRENT_TEST"] = orig_pytest

    def test_18_leeway_nan_and_out_of_bounds_rejected(self) -> None:
        """Issue #223: Clock skew leeway must reject NaN, inf, negatives, and values > 120."""
        invalid_leeways = [float("nan"), float("inf"), float("-inf"), -1.0, -0.01, 120.1, 315360000]
        for bad_leeway in invalid_leeways:
            with self.subTest(leeway=bad_leeway):
                with self.assertRaises(ValueError) as ctx:
                    OidcTokenValidator(
                        issuer=self.issuer,
                        audience=self.audience,
                        public_key=self.public_pem,
                        leeway=bad_leeway,
                    )
                self.assertIn("between 0 and 120", str(ctx.exception).lower())

    def test_19_empty_or_blank_primary_tenant_id_fails_closed(self) -> None:
        """Issue #223: Primary tenant_id='' or whitespace with tid='evil' must fail closed, never yield 'evil'."""
        validator = OidcTokenValidator(
            issuer=self.issuer,
            audience=self.audience,
            public_key=self.public_pem,
        )
        now = time.time()

        for blank_val in ("", "   ", None):
            with self.subTest(blank_tenant=blank_val):
                claims = {
                    "sub": "user-legit",
                    "tenant_id": blank_val,
                    "tid": "evil",
                    "iss": self.issuer,
                    "aud": self.audience,
                    "exp": int(now + 3600),
                }
                token = self._create_token(claims)
                with self.assertRaises(PermissionError) as ctx:
                    validator.validate_token(token)
                self.assertIn("tenant_id", str(ctx.exception))

        # Dev token check as well
        dev_tokens = {
            "token-spoof": {
                "sub": "attacker",
                "tenant_id": "",
                "tid": "evil",
            }
        }
        dev_validator = OidcTokenValidator(
            issuer=self.issuer,
            audience=self.audience,
            allow_dev_tokens=True,
            dev_tokens=dev_tokens,
        )
        with self.assertRaises(PermissionError):
            dev_validator.validate_token("token-spoof")

    def test_20_is_test_environment_strictly_requires_explicit_opt_in(self) -> None:
        """Issue #223: _is_test_environment must not be fooled by argv substrings when unittest is imported."""
        from remediate.identity.python.komagu_identity.oidc_validator import _is_test_environment

        orig_env = os.environ.get("KOMAGU_ENV")
        orig_allow = os.environ.get("KOMAGU_ALLOW_DEV_TOKENS")
        orig_pytest = os.environ.get("PYTEST_CURRENT_TEST")
        orig_argv = sys.argv
        try:
            if "KOMAGU_ENV" in os.environ:
                del os.environ["KOMAGU_ENV"]
            if "KOMAGU_ALLOW_DEV_TOKENS" in os.environ:
                del os.environ["KOMAGU_ALLOW_DEV_TOKENS"]
            if "PYTEST_CURRENT_TEST" in os.environ:
                del os.environ["PYTEST_CURRENT_TEST"]

            # Even if argv contains '/tests/' or 'test_' or 'unittest', it must return False
            sys.argv = ["python", "/app/tests/my_test_runner.py", "--unittest"]
            self.assertFalse(_is_test_environment())

            # Explicit opt-in KOMAGU_ENV=test
            os.environ["KOMAGU_ENV"] = "test"
            self.assertTrue(_is_test_environment())
            del os.environ["KOMAGU_ENV"]

            # Explicit opt-in KOMAGU_ALLOW_DEV_TOKENS=1
            os.environ["KOMAGU_ALLOW_DEV_TOKENS"] = "1"
            self.assertTrue(_is_test_environment())
        finally:
            sys.argv = orig_argv
            if orig_env is not None:
                os.environ["KOMAGU_ENV"] = orig_env
            if orig_allow is not None:
                os.environ["KOMAGU_ALLOW_DEV_TOKENS"] = orig_allow
            if orig_pytest is not None:
                os.environ["PYTEST_CURRENT_TEST"] = orig_pytest


if __name__ == "__main__":
    unittest.main()
