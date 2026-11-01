#!/usr/bin/env python3
"""Declarative Scenario Loader and Validator for Komagu BAS (#317).

Standard library only (Python 3.8+) per ADR-0006.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

SCHEMAS_DIR = Path(__file__).resolve().parent.parent.parent / "contracts" / "schemas"
BUILTIN_SCENARIOS_DIR = Path(__file__).resolve().parent / "scenarios"


def load_validator(schema_name: str = "bas-scenario.schema.json") -> Callable[[Any], List[str]]:
    """Loads a JSON schema validator for bas-scenario schema."""
    schema_path = SCHEMAS_DIR / schema_name
    if not schema_path.is_file():
        return lambda obj: [f"Schema file not found: {schema_path}"]

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    try:
        import jsonschema
        cls = getattr(jsonschema, "Draft202012Validator", None) or getattr(jsonschema, "Draft7Validator")
        schema_clean = schema if cls.__name__ == "Draft202012Validator" else {k: v for k, v in schema.items() if k != "$schema"}
        v = cls(schema_clean)
        return lambda obj: [f"{'/'.join(map(str, e.path))}: {e.message}" for e in v.iter_errors(obj)]
    except (ImportError, AttributeError):
        def fallback(obj: Any) -> List[str]:
            errs: List[str] = []
            _validate_node(obj, schema, schema, "", errs)
            return errs
        return fallback


def _validate_node(node: Any, spec: Dict[str, Any], root: Dict[str, Any], path: str, errs: List[str]) -> None:
    """Recursive stdlib fallback schema validation."""
    if not isinstance(spec, dict):
        return

    expected_type = spec.get("type")
    if expected_type == "object":
        if not isinstance(node, dict):
            errs.append(f"{path or '/'}: expected object, got {type(node).__name__}")
            return
        for req in spec.get("required", []):
            if req not in node:
                errs.append(f"{path}/{req}: required property missing")
        props = spec.get("properties", {})
        for k, v in node.items():
            if k in props:
                _validate_node(v, props[k], root, f"{path}/{k}", errs)
            elif spec.get("additionalProperties") is False:
                errs.append(f"{path}/{k}: unexpected additional property")
            elif isinstance(spec.get("additionalProperties"), dict):
                _validate_node(v, spec["additionalProperties"], root, f"{path}/{k}", errs)

    elif expected_type == "array":
        if not isinstance(node, list):
            errs.append(f"{path or '/'}: expected array, got {type(node).__name__}")
            return
        min_items = spec.get("minItems")
        if min_items is not None and len(node) < min_items:
            errs.append(f"{path}: array has {len(node)} items, expected at least {min_items}")
        items_spec = spec.get("items")
        if items_spec:
            for idx, item in enumerate(node):
                _validate_node(item, items_spec, root, f"{path}/{idx}", errs)

    elif expected_type == "string":
        if not isinstance(node, str):
            errs.append(f"{path}: expected string, got {type(node).__name__}")
            return
        pattern = spec.get("pattern")
        if pattern and not re.search(pattern, node):
            errs.append(f"{path}: '{node}' does not match pattern '{pattern}'")
        enum = spec.get("enum")
        if enum and node not in enum:
            errs.append(f"{path}: '{node}' is not one of {enum}")
        min_len = spec.get("minLength")
        if min_len is not None and len(node) < min_len:
            errs.append(f"{path}: string length {len(node)} is less than minLength {min_len}")

    elif expected_type == "integer":
        if not isinstance(node, int) or isinstance(node, bool):
            errs.append(f"{path}: expected integer, got {type(node).__name__}")

    elif expected_type == "boolean":
        if not isinstance(node, bool):
            errs.append(f"{path}: expected boolean, got {type(node).__name__}")


def validate_scenario(scenario_data: Dict[str, Any]) -> List[str]:
    """Validate a scenario dictionary against bas-scenario.schema.json."""
    validator = load_validator("bas-scenario.schema.json")
    return validator(scenario_data)


def load_scenario_file(file_path: Union[str, Path]) -> Dict[str, Any]:
    """Read and parse a JSON scenario file."""
    p = Path(file_path).resolve()
    if not p.is_file():
        raise FileNotFoundError(f"Scenario file not found: {p}")
    content = p.read_text(encoding="utf-8")
    data = json.loads(content)
    return data


def discover_scenarios(
    scenario_files: Optional[List[str]] = None,
    scenario_dirs: Optional[List[str]] = None,
    include_builtins: bool = True,
) -> Dict[str, Dict[str, Any]]:
    """Discover all scenarios from built-in directory, custom files, and custom directories.
    
    Returns a dict mapping scenario_id -> scenario_dict.
    """
    discovered: Dict[str, Dict[str, Any]] = {}

    # 1. Built-in scenarios
    if include_builtins and BUILTIN_SCENARIOS_DIR.is_dir():
        for f in BUILTIN_SCENARIOS_DIR.glob("*.json"):
            try:
                data = load_scenario_file(f)
                sid = data.get("id")
                if sid:
                    discovered[sid] = data
            except Exception:
                pass

    # 2. Custom directories
    if scenario_dirs:
        for d in scenario_dirs:
            dp = Path(d).resolve()
            if dp.is_dir():
                for f in sorted(dp.glob("*.json")):
                    try:
                        data = load_scenario_file(f)
                        sid = data.get("id")
                        if sid:
                            discovered[sid] = data
                    except Exception:
                        pass

    # 3. Explicit scenario files
    if scenario_files:
        for f in scenario_files:
            fp = Path(f).resolve()
            data = load_scenario_file(fp)
            sid = data.get("id")
            if sid:
                discovered[sid] = data

    return discovered
