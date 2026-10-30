"""Environment variable lookup for KOMAGU_* settings."""

from __future__ import annotations

import os
from typing import Mapping, Optional

PREFIX = "KOMAGU_"


def getenv(name: str, default: Optional[str] = None, env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """Read KOMAGU_<name>."""
    env = os.environ if env is None else env
    return env.get(PREFIX + name, default)
