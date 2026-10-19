"""Komainu Identity Models & Principals.

Contains the UserPrincipal representation extracted from verified OIDC/OAuth2 tokens.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class UserPrincipal:
    """Authenticated user identity extracted from verified token claims."""

    user_id: str
    tenant_id: str
    claims: Dict[str, Any] = field(default_factory=dict)
    roles: List[str] = field(default_factory=list)
    is_authenticated: bool = True
