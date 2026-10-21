"""Unit tests for Komainu Python Object-Level Authorization & OIDC Validation (D1/D2)."""

from __future__ import annotations

import base64
import json
import time
import unittest
from dataclasses import dataclass
from typing import Any, Dict

from remediate.authz.python.komainu_authz.models import (
    InMemorySecurityAuditSink,
    IOwnedResource,
    OwnershipException,
    ResourceOperation,
    SecurityAuditEvent,
    UserPrincipal,
)
from remediate.authz.python.komainu_authz.service import KomainuAuthorizationService
from remediate.identity.python.komainu_identity.oidc_validator import OidcTokenValidator
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt


@dataclass
class MockOrder:
    id: str
    owner_user_id: str
    tenant_id: str
    total_amount: float = 100.0


class TestPythonAuthz(unittest.TestCase):
    def setUp(self) -> None:
        self.audit_sink = InMemorySecurityAuditSink()
        self.authz_service = KomainuAuthorizationService(audit_sink=self.audit_sink)
        self.validator = OidcTokenValidator(
            issuer="https://auth.komainu.test",
            audience="komainu-api",
            allow_dev_tokens=True,
        )

        self.alice_user = UserPrincipal(
            user_id="user-a",
            tenant_id="tenant-komainu",
            claims={"sub": "user-a", "tenant_id": "tenant-komainu"},
        )
        self.bob_attacker = UserPrincipal(
            user_id="user-b",
            tenant_id="tenant-komainu",
            claims={"sub": "user-b", "tenant_id": "tenant-komainu"},
        )
        self.charlie_cross_tenant = UserPrincipal(
            user_id="user-c",
            tenant_id="tenant-other",
            claims={"sub": "user-c", "tenant_id": "tenant-other"},
        )

        self.alice_order = MockOrder(
            id="ord-001",
            owner_user_id="user-a",
            tenant_id="tenant-komainu",
            total_amount=150.0,
        )

    def test_01_owner_authorization_granted(self) -> None:
        """Legitimate owner Alice is granted access to her order."""
        result = self.authz_service.authorize(
            user=self.alice_user,
            resource=self.alice_order,
            operation=ResourceOperation.READ,
        )
        self.assertTrue(result.succeeded)
        self.assertIsNone(result.failure_reason)
        self.assertEqual(len(self.audit_sink.events), 0)

    def test_02_attacker_same_tenant_denied_with_audit(self) -> None:
        """Attacker Bob (same tenant) is denied access; emits Komainu.Authorization.Denied event."""
        result = self.authz_service.authorize(
            user=self.bob_attacker,
            resource=self.alice_order,
            operation=ResourceOperation.READ,
        )
        self.assertFalse(result.succeeded)
        self.assertIn("User ownership violation", result.failure_reason or "")

        # Verify audit emission
        self.assertEqual(len(self.audit_sink.events), 1)
        event = self.audit_sink.events[0]
        self.assertEqual(event.event_name, "Komainu.Authorization.Denied")
        self.assertEqual(event.actor_user_id, "user-b")
        self.assertEqual(event.actor_tenant_id, "tenant-komainu")
        self.assertEqual(event.resource_id, "ord-001")
        self.assertEqual(event.operation, ResourceOperation.READ)

    def test_03_cross_tenant_attacker_denied(self) -> None:
        """Cross-tenant user Charlie is denied due to tenant boundary violation."""
        result = self.authz_service.authorize(
            user=self.charlie_cross_tenant,
            resource=self.alice_order,
            operation=ResourceOperation.UPDATE,
        )
        self.assertFalse(result.succeeded)
        self.assertIn("Tenant boundary violation", result.failure_reason or "")

        self.assertEqual(len(self.audit_sink.events), 1)
        event = self.audit_sink.events[0]
        self.assertEqual(event.actor_tenant_id, "tenant-other")

    def test_04_require_ownership_raises_404_ownership_exception(self) -> None:
        """require_ownership raises OwnershipException with status 404 (never 403) on denial."""
        # Owner succeeds without exception
        self.authz_service.require_ownership(self.alice_user, self.alice_order, ResourceOperation.READ)

        # Attacker raises OwnershipException with status_code=404
        with self.assertRaises(OwnershipException) as ctx:
            self.authz_service.require_ownership(self.bob_attacker, self.alice_order, ResourceOperation.DELETE)
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertEqual(ctx.exception.detail, "Resource not found")

    def test_05_unauthenticated_caller_denied(self) -> None:
        """Unauthenticated caller (None or is_authenticated=False) is denied."""
        result = self.authz_service.authorize(
            user=None,
            resource=self.alice_order,
            operation=ResourceOperation.READ,
        )
        self.assertFalse(result.succeeded)
        self.assertIn("unauthenticated", result.failure_reason or "")

        unauth_user = UserPrincipal("anon", "none", is_authenticated=False)
        result2 = self.authz_service.authorize(unauth_user, self.alice_order, ResourceOperation.READ)
        self.assertFalse(result2.succeeded)

    def test_06_dict_resource_and_custom_extractors(self) -> None:
        """Supports dictionary resources and custom lambda extractors."""
        dict_order = {
            "id": "ord-dict-99",
            "ownerUserId": "user-a",
            "tenantId": "tenant-komainu",
        }
        res = self.authz_service.authorize(self.alice_user, dict_order)
        self.assertTrue(res.succeeded)

        # Custom extractor test
        opaque_obj = ("ord-tuple", "user-a", "tenant-komainu")
        res2 = self.authz_service.authorize(
            user=self.alice_user,
            resource=opaque_obj,
            owner_id_extractor=lambda x: x[1],
            tenant_id_extractor=lambda x: x[2],
        )
        self.assertTrue(res2.succeeded)

    def test_07_oidc_validator_dev_tokens(self) -> None:
        """OidcTokenValidator validates dev bearer tokens used across test harnesses."""
        p_alice = self.validator.validate_token("Bearer token-user-a")
        self.assertEqual(p_alice.user_id, "user-a")
        self.assertEqual(p_alice.tenant_id, "tenant-komainu")
        self.assertTrue(p_alice.is_authenticated)

        p_bob = self.validator.validate_token("token-user-b")
        self.assertEqual(p_bob.user_id, "user-b")
        self.assertEqual(p_bob.tenant_id, "tenant-komainu")

        with self.assertRaises(PermissionError):
            self.validator.validate_token("Bearer token-unknown")

    def test_08_oidc_validator_jwt_claims(self) -> None:
        """OidcTokenValidator decodes and cryptographically verifies JWT payloads."""
        # Generate test RSA key pair
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        jwt_validator = OidcTokenValidator(
            issuer="https://auth.enterprise.test",
            audience="enterprise-api",
            public_key=pub_pem,
        )

        now = time.time()
        payload_data = {
            "sub": "user-jwt-123",
            "tenant_id": "tenant-enterprise",
            "iss": "https://auth.enterprise.test",
            "aud": "enterprise-api",
            "exp": int(now + 3600),
            "iat": int(now),
            "roles": ["Engineer"],
        }
        valid_jwt = jwt.encode(payload_data, key=priv_key, algorithm="RS256")

        principal = jwt_validator.validate_token(f"Bearer {valid_jwt}")
        self.assertEqual(principal.user_id, "user-jwt-123")
        self.assertEqual(principal.tenant_id, "tenant-enterprise")
        self.assertIn("Engineer", principal.roles)

        # Expired token test
        expired_data = {
            "sub": "user-expired",
            "tenant_id": "tenant-enterprise",
            "iss": "https://auth.enterprise.test",
            "aud": "enterprise-api",
            "exp": int(now - 3600),
            "iat": int(now - 7200),
        }
        expired_jwt = jwt.encode(expired_data, key=priv_key, algorithm="RS256")

        with self.assertRaises(PermissionError) as ctx:
            jwt_validator.validate_token(expired_jwt)
        self.assertIn("expired", str(ctx.exception).lower())

    def test_09_claim_semantics_and_edge_cases(self) -> None:
        """Verifies generic id claim support, whitespace trimming, non-scalar claim rejection, and empty owner handling."""
        # 1. Generic "id" claim and whitespace trimming
        claims_with_id = {"id": "  user-id-trimmed  ", "tenant_id": "  tenant-trimmed  "}
        self.assertEqual(self.authz_service.get_current_user_id(claims_with_id), "user-id-trimmed")
        self.assertEqual(self.authz_service.get_current_tenant_id(claims_with_id), "tenant-trimmed")

        # 2. Reject non-scalar claims
        non_scalar_claims = {"sub": {"key": "val"}, "tenant_id": ["tenant-1"]}
        with self.assertRaises(PermissionError):
            self.authz_service.get_current_user_id(non_scalar_claims)
        with self.assertRaises(PermissionError):
            self.authz_service.get_current_tenant_id(non_scalar_claims)

        # 3. Reject resource with empty or whitespace-only owner/tenant
        empty_owner_res = {"id": "1", "owner_user_id": "   ", "tenant_id": "tenant-trimmed"}
        res = self.authz_service.authorize(claims_with_id, empty_owner_res)
        self.assertFalse(res.succeeded)


if __name__ == "__main__":
    unittest.main()
