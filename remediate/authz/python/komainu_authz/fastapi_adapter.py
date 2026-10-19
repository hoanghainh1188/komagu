"""FastAPI Dependency Injection & Middleware Adapter for Komainu Authz.

Provides:
- `get_current_user`: Dependency extracting and validating OIDC bearer tokens.
- `RequireOwnership`: Declarative dependency enforcing object-level authorization on endpoints.
- `komainu_ownership_exception_handler`: Exception handler returning HTTP 404 on BOLA violations.
"""

from __future__ import annotations

import inspect
from typing import Any, Callable, Dict, Optional

from remediate.identity.python.komainu_identity.oidc_validator import OidcTokenValidator

from .models import (
    IOwnedResource,
    OwnershipException,
    ResourceOperation,
    UserPrincipal,
)
from .service import KomainuAuthorizationService

# Attempt imports from fastapi/starlette; fall back to runtime-neutral standard classes
try:
    from fastapi import Depends, HTTPException, Request, Response
    from fastapi.responses import JSONResponse
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

    class HTTPException(Exception):  # type: ignore
        def __init__(self, status_code: int, detail: Any = None, headers: Optional[Dict[str, str]] = None) -> None:
            super().__init__(str(detail))
            self.status_code = status_code
            self.detail = detail
            self.headers = headers

    class Request:  # type: ignore
        def __init__(self, scope: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None, path_params: Optional[Dict[str, Any]] = None) -> None:
            self.scope = scope or {}
            self.headers = headers or {}
            self.path_params = path_params or {}

    class Response:  # type: ignore
        def __init__(self, content: Any = None, status_code: int = 200, media_type: str = "application/json") -> None:
            self.content = content
            self.status_code = status_code
            self.media_type = media_type

    class JSONResponse(Response):  # type: ignore
        def __init__(self, content: Any = None, status_code: int = 200) -> None:
            import json
            super().__init__(content=json.dumps(content).encode("utf-8"), status_code=status_code)

    def Depends(dependency: Any = None) -> Any:  # type: ignore
        return dependency


_DEFAULT_VALIDATOR = OidcTokenValidator()
_DEFAULT_AUTHZ_SERVICE = KomainuAuthorizationService()


def get_current_user(
    request: Any,
    validator: Optional[OidcTokenValidator] = None,
) -> UserPrincipal:
    """FastAPI dependency extracting and validating the Bearer token from request headers."""
    val = validator or _DEFAULT_VALIDATOR
    headers = getattr(request, "headers", {})
    auth_header = None

    if isinstance(headers, dict):
        auth_header = headers.get("authorization") or headers.get("Authorization")
    elif hasattr(headers, "get"):
        auth_header = headers.get("authorization") or headers.get("Authorization")

    if not auth_header:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        principal = val.validate_token(auth_header)
        return principal
    except PermissionError as ex:
        raise HTTPException(
            status_code=401,
            detail=str(ex),
            headers={"WWW-Authenticate": "Bearer"},
        ) from ex


class RequireOwnership:
    """FastAPI dependency factory enforcing object-level authorization on a route.

    Usage in FastAPI route:
    ```python
    @app.get("/orders/{order_id}")
    def get_order(
        order: Order = Depends(RequireOwnership(
            operation=ResourceOperation.READ,
            id_param="order_id",
            loader=get_order_from_db
        ))
    ):
        return order
    ```
    """

    def __init__(
        self,
        operation: ResourceOperation = ResourceOperation.READ,
        id_param: str = "id",
        loader: Optional[Callable[[str], Any]] = None,
        authz_service: Optional[KomainuAuthorizationService] = None,
        validator: Optional[OidcTokenValidator] = None,
    ) -> None:
        self.operation = operation
        self.id_param = id_param
        self.loader = loader
        self.authz_service = authz_service or _DEFAULT_AUTHZ_SERVICE
        self.validator = validator or _DEFAULT_VALIDATOR

    async def __call__(self, request: Any) -> Any:
        # 1. Resolve user principal
        user = get_current_user(request, self.validator)

        # 2. Extract resource ID from path params or query params
        path_params = getattr(request, "path_params", {})
        query_params = getattr(request, "query_params", {})

        resource_id = path_params.get(self.id_param)
        if resource_id is None and query_params:
            resource_id = query_params.get(self.id_param)

        if resource_id is None:
            # If no ID parameter specified, caller might pass resource directly or check body
            raise HTTPException(status_code=400, detail=f"Missing path parameter '{self.id_param}'")

        # 3. Load resource
        if not self.loader:
            raise HTTPException(status_code=500, detail="Resource loader not configured on RequireOwnership dependency")

        resource = self.loader(str(resource_id))
        if inspect.isawaitable(resource):
            resource = await resource

        if resource is None:
            # Resource does not exist -> 404
            raise HTTPException(status_code=404, detail="Resource not found")

        # 4. Enforce ownership using Komainu D1
        try:
            self.authz_service.require_ownership(user, resource, self.operation)
        except OwnershipException:
            # Core Invariant: Deny-by-default with HTTP 404 Not Found to prevent ID enumeration
            raise HTTPException(status_code=404, detail="Resource not found")

        return resource


def komainu_ownership_exception_handler(request: Any, exc: OwnershipException) -> Any:
    """Global exception handler for FastAPI / Starlette applications."""
    return JSONResponse(status_code=404, content={"detail": exc.detail or "Resource not found"})


class KomainuAuthMiddleware:
    """ASGI middleware for extracting Bearer tokens and attaching UserPrincipal to request scope."""

    def __init__(self, app: Any, validator: Optional[OidcTokenValidator] = None) -> None:
        self.app = app
        self.validator = validator or _DEFAULT_VALIDATOR

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") == "http":
            headers = dict(scope.get("headers", []))
            auth_val = headers.get(b"authorization", b"").decode("latin1")
            if auth_val:
                try:
                    user = self.validator.validate_token(auth_val)
                    scope["user"] = user
                except Exception:
                    scope["user"] = None
            else:
                scope["user"] = None

        await self.app(scope, receive, send)
