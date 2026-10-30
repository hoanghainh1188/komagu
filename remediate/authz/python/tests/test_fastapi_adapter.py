"""Unit tests for FastAPI dependency injection adapter (D1/D2)."""

from __future__ import annotations

import asyncio
import os
import unittest
from dataclasses import dataclass
from typing import Any, Dict, Optional

os.environ.setdefault("KOMAGU_ENV", "test")

from remediate.authz.python.komagu_authz.fastapi_adapter import (
    HAS_FASTAPI,
    HTTPException,
    KomaguAuthMiddleware,
    Request,
    RequireOwnership,
    get_current_user,
    komagu_ownership_exception_handler,
)
from remediate.authz.python.komagu_authz.models import (
    InMemorySecurityAuditSink,
    OwnershipException,
    ResourceOperation,
)
from remediate.authz.python.komagu_authz.service import KomaguAuthorizationService
from remediate.identity.python.komagu_identity.oidc_validator import OidcTokenValidator


@dataclass
class Document:
    id: str
    owner_user_id: str
    tenant_id: str
    title: str


def _build_request(
    headers: Optional[Dict[str, str]] = None,
    path_params: Optional[Dict[str, Any]] = None,
) -> Request:
    headers_dict = headers or {}
    path_params_dict = path_params or {}
    raw_headers = [
        (k.lower().encode("latin-1"), v.encode("latin-1"))
        for k, v in headers_dict.items()
    ]
    scope: Dict[str, Any] = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": raw_headers,
        "path_params": path_params_dict,
    }
    if HAS_FASTAPI:
        req = Request(scope)
        req.scope["path_params"] = path_params_dict
        return req
    else:
        return Request(scope=scope, headers=headers_dict, path_params=path_params_dict)


class TestFastApiAdapter(unittest.TestCase):
    def setUp(self) -> None:
        self.audit_sink = InMemorySecurityAuditSink()
        self.authz_service = KomaguAuthorizationService(audit_sink=self.audit_sink)
        self.validator = OidcTokenValidator(
            issuer="https://auth.komagu.test",
            audience="komainu-api",
            allow_dev_tokens=True,
        )

        # In-memory document store
        self.docs: Dict[str, Document] = {
            "doc-1": Document("doc-1", "user-a", "tenant-komagu", "Alice's Secret"),
            "doc-2": Document("doc-2", "user-b", "tenant-komagu", "Bob's Public Note"),
        }

    def _loader(self, doc_id: str) -> Optional[Document]:
        return self.docs.get(doc_id)

    def test_01_get_current_user_dependency(self) -> None:
        """get_current_user parses authorization header or raises 401."""
        req_valid = _build_request(headers={"Authorization": "Bearer token-user-a"})
        user = get_current_user(req_valid, self.validator)
        self.assertEqual(user.user_id, "user-a")
        self.assertEqual(user.tenant_id, "tenant-komagu")

        # Missing header -> 401
        req_missing = _build_request(headers={})
        with self.assertRaises(HTTPException) as ctx_missing:
            get_current_user(req_missing, self.validator)
        self.assertEqual(ctx_missing.exception.status_code, 401)

        # Invalid token -> 401
        req_invalid = _build_request(headers={"Authorization": "Bearer token-bad"})
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
        req = _build_request(
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
        req = _build_request(
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
        req = _build_request(
            headers={"Authorization": "Bearer token-user-a"},
            path_params={"doc_id": "doc-nonexistent"},
        )

        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(dep(req))
        self.assertEqual(ctx.exception.status_code, 404)

    def test_05_ownership_exception_handler(self) -> None:
        """komagu_ownership_exception_handler returns HTTP 404 response."""
        exc = OwnershipException(detail="Forbidden probe blocked")
        resp = komagu_ownership_exception_handler(None, exc)
        self.assertEqual(resp.status_code, 404)

    def test_06_komagu_auth_middleware(self) -> None:
        """KomaguAuthMiddleware attaches authenticated UserPrincipal to ASGI scope."""
        received_scope: Dict[str, Any] = {}

        async def dummy_app(scope: Dict[str, Any], receive: Any, send: Any) -> None:
            received_scope.update(scope)

        middleware = KomaguAuthMiddleware(dummy_app, self.validator)

        scope = {
            "type": "http",
            "headers": [(b"authorization", b"Bearer token-user-a")],
        }
        asyncio.run(middleware(scope, None, None))

        user = received_scope.get("user")
        self.assertIsNotNone(user)
        self.assertEqual(user.user_id, "user-a")

    def test_07_adapter_refuses_unconfigured_validator(self) -> None:
        """FastAPI adapter components refuse to operate without a configured validator."""
        # 1. get_current_user with None validator raises 500 HTTPException
        req = _build_request(headers={"Authorization": "Bearer token-user-a"})
        with self.assertRaises(HTTPException) as ctx:
            get_current_user(req, validator=None)
        self.assertEqual(ctx.exception.status_code, 500)
        self.assertIn("must be configured", ctx.exception.detail)

        # 2. RequireOwnership with None validator raises ValueError
        with self.assertRaises(ValueError) as ctx_dep:
            RequireOwnership(
                operation=ResourceOperation.READ,
                id_param="doc_id",
                loader=self._loader,
                validator=None,
            )
        self.assertIn("requires a configured OidcTokenValidator", str(ctx_dep.exception))

        # 3. KomaguAuthMiddleware with None validator raises ValueError
        async def dummy_app(scope: Any, receive: Any, send: Any) -> None:
            pass

        with self.assertRaises(ValueError) as ctx_mid:
            KomaguAuthMiddleware(dummy_app, validator=None)
        self.assertIn("requires a configured OidcTokenValidator", str(ctx_mid.exception))

    def test_06_get_current_user_does_not_leak_internal_exception(self) -> None:
        """Invalid token returns generic 401 error message without leaking internal details."""
        req_invalid = _build_request(headers={"Authorization": "Bearer malformed.token.format"})
        with self.assertRaises(HTTPException) as ctx:
            get_current_user(req_invalid, self.validator)
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertEqual(ctx.exception.detail, "Invalid or expired authentication credentials")


if __name__ == "__main__":
    unittest.main()

