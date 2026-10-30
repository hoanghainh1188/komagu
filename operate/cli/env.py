"""Environment variable lookup with the pre-rename KOMAINU_* fallback (#290)."""

from __future__ import annotations

import os
import sys
from typing import Mapping, Optional, Set

PREFIX = "KOMAGU_"
LEGACY_PREFIX = "KOMAINU_"

_warned: Set[str] = set()


def getenv(name: str, default: Optional[str] = None, env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """Read KOMAGU_<name>; fall back to the deprecated KOMAINU_<name> with a one-time warning."""
    env = os.environ if env is None else env
    value = env.get(PREFIX + name)
    if value is not None:
        return value
    legacy = env.get(LEGACY_PREFIX + name)
    if legacy is not None:
        if name not in _warned:
            _warned.add(name)
            print(
                f"warning: {LEGACY_PREFIX}{name} is deprecated, set {PREFIX}{name} instead",
                file=sys.stderr,
            )
        return legacy
    return default
