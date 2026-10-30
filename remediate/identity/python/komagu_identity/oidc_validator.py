"""Komagu OIDC Identity & Token Validation Adapter (Python).

Validates OpenID Connect / OAuth2 JWT Bearer tokens with cryptographic
signature verification against an HTTPS JWKS or static public key,
enforces required claims (sub, tenant, exp, iss, aud), strictly bounds
clock skew, and prohibits unsecured dev tokens outside verified test environments.
"""

from __future__ import annotations

import math
import os
import sys
from typing import Any, Dict, List, Optional, Union

import jwt
from jwt import PyJWKClient
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidTokenError,
    MissingRequiredClaimError,
)

from .models import UserPrincipal


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    """Read KOMAGU_<name>."""
    return os.environ.get("KOMAGU_" + name, default)


# Standard test/dev personas matching Komagu cross-user test fixtures
DEFAULT_DEV_TOKENS: Dict[str, Dict[str, Any]] = {
    "token-user-a": {
        "sub": "user-a",
        "tenant_id": "tenant-komagu",
        "name": "Alice (Owner)",
        "roles": ["Member"],
    },
    "token-user-b": {
        "sub": "user-b",
        "tenant_id": "tenant-komagu",
        "name": "Bob (Attacker)",
        "roles": ["Member"],
    },
    "token-cross-tenant": {
        "sub": "user-c",
        "tenant_id": "tenant-other",
        "name": "Charlie (Cross-Tenant)",
        "roles": ["Member"],
    },
    "token-admin": {
        "sub": "user-admin",
        "tenant_id": "tenant-komagu",
        "name": "Admin",
        "roles": ["Admin"],
    },
}

# Standard asymmetric signature algorithms permitted by default
DEFAULT_ALLOWED_ALGORITHMS: List[str] = [
    "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512",
    "PS256", "PS384", "PS512",
]


def _is_test_environment() -> bool:
    """Determine whether the current process is executing under explicit test mode."""
    if _env("ENV") == "test":
        return True
    if _env("ALLOW_DEV_TOKENS") == "1":
        return True
    if "PYTEST_CURRENT_TEST" in os.environ:
        return True
    return False


class OidcTokenValidator:
    """Validates OpenID Connect / OAuth2 JWT Bearer tokens and extracts security principals."""

    def __init__(
        self,
        issuer: str,
        audience: str,
        jwks_uri: Optional[str] = None,
        public_key: Optional[Union[str, bytes, Any]] = None,
        allowed_algorithms: Optional[List[str]] = None,
        leeway: float = 60.0,
        allow_dev_tokens: bool = False,
        dev_tokens: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        if not issuer or not str(issuer).strip():
            raise ValueError("OidcTokenValidator requires a non-empty 'issuer'")
        if not audience or not str(audience).strip():
            raise ValueError("OidcTokenValidator requires a non-empty 'audience'")

        self.issuer = str(issuer)
        self.audience = str(audience)

        try:
            leeway_val = float(leeway)
        except (ValueError, TypeError):
            raise ValueError("Clock skew leeway must be a valid number")
        if math.isnan(leeway_val) or math.isinf(leeway_val) or leeway_val < 0.0 or leeway_val > 120.0:
            raise ValueError("Clock skew leeway must be between 0 and 120 seconds")
        self.leeway = leeway_val

        # Enforce pinned algorithm allowlist; never allow "none" or symmetric algorithms by default
        self.allowed_algorithms = list(allowed_algorithms or DEFAULT_ALLOWED_ALGORITHMS)
        if any(alg.lower() == "none" for alg in self.allowed_algorithms):
            raise ValueError("Algorithm 'none' is strictly prohibited")

        # Handle dev tokens with explicit test gate
        self.allow_dev_tokens = allow_dev_tokens
        if allow_dev_tokens:
            if not _is_test_environment():
                raise RuntimeError(
                    "Dev tokens are only permitted in test environments. "
                    "Set KOMAGU_ENV=test or run within a recognized test framework."
                )
            self.dev_tokens: Dict[str, Dict[str, Any]] = (
                dict(dev_tokens) if dev_tokens is not None else dict(DEFAULT_DEV_TOKENS)
            )
        else:
            if dev_tokens is not None:
                raise ValueError("Cannot supply dev_tokens when allow_dev_tokens is False")
            self.dev_tokens = {}

        # Validate JWKS URI / public key configuration
        self.jwks_uri = jwks_uri
        self.public_key = public_key
        self.jwks_client: Optional[PyJWKClient] = None

        if jwks_uri:
            # Enforce HTTPS protocol for JWKS endpoints
            if not jwks_uri.startswith("https://"):
                if not (self.allow_dev_tokens and _is_test_environment()):
                    raise ValueError(f"JWKS URI must use HTTPS protocol: '{jwks_uri}'")
            self.jwks_client = PyJWKClient(jwks_uri, cache_keys=True)

        if not self.jwks_client and not self.public_key and not self.allow_dev_tokens:
            raise ValueError(
                "Either 'jwks_uri' or 'public_key' must be provided for cryptographic token verification."
            )

    def validate_token(self, token: str) -> UserPrincipal:
        """Validates a bearer token string and returns an authenticated UserPrincipal."""
        if not token:
            raise PermissionError("Bearer token is empty or missing")

        clean_token = token.strip()
        if clean_token.lower().startswith("bearer "):
            clean_token = clean_token[7:].strip()

        # Check dev tokens if explicitly allowed and configured
        if self.allow_dev_tokens and clean_token in self.dev_tokens:
            meta = self.dev_tokens[clean_token]
            tenant_id = None
            if "tenant_id" in meta:
                t_val = meta["tenant_id"]
                if t_val is None or not str(t_val).strip():
                    raise PermissionError("Dev token has empty or invalid 'tenant_id' claim")
                tenant_id = str(t_val).strip()
            elif "tid" in meta:
                t_val = meta["tid"]
                if t_val is None or not str(t_val).strip():
                    raise PermissionError("Dev token has empty or invalid 'tid' claim")
                tenant_id = str(t_val).strip()
            elif "org_id" in meta:
                t_val = meta["org_id"]
                if t_val is None or not str(t_val).strip():
                    raise PermissionError("Dev token has empty or invalid 'org_id' claim")
                tenant_id = str(t_val).strip()
            else:
                raise PermissionError("Dev token missing required tenant claim")

            sub = meta.get("sub") or meta.get("uid") or meta.get("userId")
            if not sub:
                raise PermissionError("Dev token missing required 'sub' claim")

            return UserPrincipal(
                user_id=str(sub),
                tenant_id=str(tenant_id),
                claims=dict(meta),
                roles=meta.get("roles", []),
                is_authenticated=True,
            )

        # Resolve cryptographic signing key
        key: Any = None
        if self.public_key:
            key = self.public_key
        elif self.jwks_client:
            try:
                signing_key = self.jwks_client.get_signing_key_from_jwt(clean_token)
                key = signing_key.key
            except Exception as ex:
                raise PermissionError(f"Failed to retrieve signing key for token: {ex}") from ex
        else:
            raise PermissionError("No signing key or JWKS provider available to verify token")

        try:
            # PyJWT verifies signature, exp, iss, aud, iat, nbf, and algorithm allowlist
            payload = jwt.decode(
                clean_token,
                key=key,
                algorithms=self.allowed_algorithms,
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway,
                options={
                    "require": ["exp", "iss", "aud", "sub"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iss": True,
                    "verify_aud": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                },
            )
        except ExpiredSignatureError as ex:
            raise PermissionError(f"Token has expired: {ex}") from ex
        except (InvalidSignatureError, DecodeError, InvalidKeyError) as ex:
            raise PermissionError(f"Invalid token signature or formatting: {ex}") from ex
        except InvalidAlgorithmError as ex:
            raise PermissionError(f"Token uses disallowed or unverified algorithm: {ex}") from ex
        except (InvalidAudienceError, InvalidIssuerError) as ex:
            raise PermissionError(f"Token claim validation failed: {ex}") from ex
        except (MissingRequiredClaimError, ImmatureSignatureError, InvalidTokenError) as ex:
            raise PermissionError(f"Invalid token claims: {ex}") from ex
        except Exception as ex:
            raise PermissionError(f"Token validation failed: {ex}") from ex

        # Strict validation of 'exp' claim against NaN or invalid numbers
        exp_val = payload.get("exp")
        if exp_val is None:
            raise PermissionError("Token missing 'exp' claim")
        try:
            exp_float = float(exp_val)
            if math.isnan(exp_float) or math.isinf(exp_float):
                raise PermissionError("Token 'exp' claim is not a valid finite timestamp")
        except (ValueError, TypeError):
            raise PermissionError("Token 'exp' claim must be a numeric timestamp")

        # Validate 'sub' claim
        sub = payload.get("sub")
        if not sub or not str(sub).strip():
            raise PermissionError("Token 'sub' claim is empty or invalid")

        # Validate tenant claim (never fallback to 'default-tenant' or ignore blank primary tenant)
        tenant = None
        if "tenant_id" in payload:
            t_val = payload["tenant_id"]
            if t_val is None or not str(t_val).strip():
                raise PermissionError("Token 'tenant_id' claim is empty or invalid")
            tenant = str(t_val).strip()
        elif "tid" in payload:
            t_val = payload["tid"]
            if t_val is None or not str(t_val).strip():
                raise PermissionError("Token 'tid' claim is empty or invalid")
            tenant = str(t_val).strip()
        elif "org_id" in payload:
            t_val = payload["org_id"]
            if t_val is None or not str(t_val).strip():
                raise PermissionError("Token 'org_id' claim is empty or invalid")
            tenant = str(t_val).strip()
        else:
            raise PermissionError("Token missing required tenant claim ('tenant_id', 'tid', or 'org_id')")

        roles = payload.get("roles") or payload.get("realm_access", {}).get("roles", [])
        if isinstance(roles, str):
            roles = [roles]
        elif not isinstance(roles, list):
            roles = []

        return UserPrincipal(
            user_id=str(sub),
            tenant_id=str(tenant),
            claims=payload,
            roles=roles,
            is_authenticated=True,
        )
