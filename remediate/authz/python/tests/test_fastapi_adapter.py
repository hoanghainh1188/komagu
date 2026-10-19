"""Unit tests for FastAPI dependency injection adapter (D1/D2)."""

from __future__ import annotations

import asyncio
import unittest
from dataclasses import dataclass
from typing import Any, Dict, Optional

from remediate.authz.python.komainu_authz.fastapi_adapter import (
    HTTPException,
    KomainuAuthMiddleware,
    Request,
    RequireOwnership,
    get_current_user,
    komainu_ownership_exception_handler,
)
from remediate.authz.python.komainu_authz.models import (
    InMemorySecurityAuditSink,
    OwnershipException,
    ResourceOperation,
)
from remediate.authz.python.komainu_authz.service import KomainuAuthorizationService
from remediate.identity.python.komainu_identity.oidc_validator import OidcTokenValidator


@dataclass
class Document:
    id: str
    owner_user_id: str
    tenant_id: str
    title: str


class TestFastApiAdapter(unittest.TestCase):
    def setUp(self) -> None:
        self.audit_sink = InMemorySecurityAuditSink()
        self.authz_service = KomainuAuthorizationService(audit_sink=self.audit_sink)
        self.validator = OidcTokenValidator()

        # In-memory document store
        self.docs: Dict[str, Document] = {
            "doc-1": Document("doc-1", "user-a", "tenant-komainu", "Alice's Secret"),
            "doc-2": Document("doc-2", "user-b", "tenant-komainu", "Bob's Public Note"),
        }

    def _loader(self, doc_id: str) -> Optional[Document]:
        return self.docs.get(doc_id)

    def test_01_get_current_user_dependency(self) -> None:
        """get_current_user parses authorization header or raises 401."""
        req_valid = Request(headers={"Authorization": "Bearer token-user-a"})
        user = get_current_user(req_valid, self.validator)
        self.assertEqual(user.user_id, "user-a")
        self.assertEqual(user.tenant_id, "tenant-komainu")

        # Missing header -> 401
        req_missing = Request(headers={})
        with self.assertRaises(HTTPException) as ctx_missing:
            get_current_user(req_missing, self.validator)
        self.assertEqual(ctx_missing.exception.status_code, 401)

        # Invalid token -> 401
        req_invalid = Request(headers={"Authorization": "Bearer token-bad"})
        with self.assertRaises(HTTPException) as ctx_invalid:
            get_current_user(req_invalid, self.validator)
        self.assertEqual(ctx_invalid.exception.status_code, 401)

    def test_02_require_ownership_allows_owner(self) -> None:
        """RequireOwnership dependency allows legitimate owner Alice to access doc-1."""
        dep = RequireOwnership(
            operation=ResourceOperation.READ,
            id_param="doc_id",
            loader=self._loader,
            authz_service=self.authz_service,
            validator=self.validator,
        )
        req = Request(
            headers={"Authorization": "Bearer token-user-a"},
            path_params={"doc_id": "doc-1"},
        )

        loaded_resource = asyncio.run(dep(req))
        self.assertEqual(loaded_resource.id, "doc-1")
        self.assertEqual(loaded_resource.title, "Alice's Secret")

    def test_03_require_ownership_denies_attacker_with_404(self) -> None:
        """RequireOwnership dependency denies attacker Bob with HTTP 404 (never 403)."""
        dep = RequireOwnership(
            operation=ResourceOperation.READ,
            id_param="doc_id",
            loader=self._loader,
            authz_service=self.authz_service,
            validator=self.validator,
        )
        req = Request(
            headers={"Authorization": "Bearer token-user-b"},
            path_params={"doc_id": "doc-1"},
        )

        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(dep(req))

        self.assertEqual(ctx.exception.status_code, 404)
        self.assertEqual(ctx.exception.detail, "Resource not found")
        # Audit sink recorded denial
        self.assertEqual(len(self.audit_sink.events), 1)
        self.assertEqual(self.audit_sink.events[0].actor_user_id, "user-b")

    def test_04_require_ownership_missing_resource_returns_404(self) -> None:
        """RequireOwnership returns 404 when target resource does not exist."""
        dep = RequireOwnership(
            operation=ResourceOperation.READ,
            id_param="doc_id",
            loader=self._loader,
            authz_service=self.authz_service,
            validator=self.validator,
        )
        req = Request(
            headers={"Authorization": "Bearer token-user-a"},
            path_params={"doc_id": "doc-nonexistent"},
        )

        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(dep(req))
        self.assertEqual(ctx.exception.status_code, 404)

    def test_05_ownership_exception_handler(self) -> None:
        """komainu_ownership_exception_handler returns HTTP 404 response."""
        exc = OwnershipException(detail="Forbidden probe blocked")
        resp = komainu_ownership_exception_handler(None, exc)
        self.assertEqual(resp.status_code, 404)

    def test_06_komainu_auth_middleware(self) -> None:
        """KomainuAuthMiddleware attaches authenticated UserPrincipal to ASGI scope."""
        received_scope: Dict[str, Any] = {}

        async def dummy_app(scope: Dict[str, Any], receive: Any, send: Any) -> None:
            received_scope.update(scope)

        middleware = KomainuAuthMiddleware(dummy_app, self.validator)

        scope = {
            "type": "http",
            "headers": [(b"authorization", b"Bearer token-user-a")],
        }
        asyncio.run(middleware(scope, None, None))

        user = received_scope.get("user")
        self.assertIsNotNone(user)
        self.assertEqual(user.user_id, "user-a")


if __name__ == "__main__":
    unittest.main()
