"""MCP tools that wrap local Komagu analysis. None of them apply patches or call an LLM."""

from __future__ import annotations

import dataclasses
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from operate.devsecops.leak_check import CanaryFileError, load_canaries, scan_paths
from operate.inventory.api_inventory import (
    diff_api_inventory,
    load_code_routes,
    load_openapi_spec,
    load_traffic_log,
)
from operate.remediator.runner import RemediationRunner

REPO_ROOT = Path(__file__).resolve().parents[2]
BIN_KOMAGU = REPO_ROOT / "bin" / "komagu"

LIST_CAP = 40
DIFF_CAP = 1200
STDERR_CAP = 2000
MAX_PATHS = 32
SCAN_TIMEOUT_MAX = 600
LANGS = ("en", "ja", "all")
FORMATS = ("md", "html", "sarif", "all")

INSTRUCTIONS = (
    "Komagu tools run on this machine and do not call an LLM. "
    "scan writes a Tier 1 audit under out (no --headless-ai). "
    "read_audit summarizes an existing audit directory. "
    "leak_check looks for secrets in audit output and returns masked hits. "
    "inventory compares code routes with an OpenAPI document. "
    "fix_preview returns a dry-run remediation plan and never modifies source. "
    "Applying patches, starting the edge gateway, and live cross-user tests stay on the komagu CLI."
)


class ToolError(Exception):
    """A tool argument or expected input problem the caller can correct."""


class ToolSpec:
    """One advertised MCP tool."""

    def __init__(
        self,
        name: str,
        description: str,
        input_schema: Dict[str, Any],
        handler: Callable[[Dict[str, Any]], Dict[str, Any]],
        read_only: bool,
    ) -> None:
        self.name = name
        self.description = description
        self.input_schema = input_schema
        self.handler = handler
        self.read_only = read_only

    def descriptor(self) -> Dict[str, Any]:
        """MCP tools/list entry."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": {
                "readOnlyHint": self.read_only,
                "destructiveHint": False,
                "openWorldHint": False,
            },
        }


class ToolRegistry:
    """Name lookup for the tools this server exposes."""

    def __init__(self, tools: List[ToolSpec]) -> None:
        self._tools = {tool.name: tool for tool in tools}

    def descriptors(self) -> List[Dict[str, Any]]:
        """Tools in a stable order."""
        return [self._tools[name].descriptor() for name in sorted(self._tools)]

    def call(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Run one tool. Unknown names raise KeyError."""
        tool = self._tools.get(name)
        if tool is None:
            raise KeyError(name)
        return tool.handler(arguments)


def build_registry() -> ToolRegistry:
    """The five local analysis tools."""
    return ToolRegistry(
        [
            ToolSpec(
                "scan",
                "Run a Tier 1 Komagu audit of a local directory and write reports under out. "
                "Does not call a model. Check exitCode: 0 finished, 2 the target or arguments were rejected. "
                "The audit summary lists finding ids, categories, and locations, not source snippets.",
                {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Directory to audit."},
                        "out": {"type": "string", "description": "Directory for audit artifacts. Created if needed."},
                        "lang": {
                            "type": "string",
                            "enum": list(LANGS),
                            "description": "Report language when format renders Markdown or HTML. Default en.",
                        },
                        "format": {
                            "type": "string",
                            "enum": list(FORMATS),
                            "description": "md, html, sarif, or all. Default sarif.",
                        },
                        "timeout_seconds": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": SCAN_TIMEOUT_MAX,
                            "description": "Scan process timeout. Default 180.",
                        },
                    },
                    "required": ["target", "out"],
                    "additionalProperties": False,
                },
                tool_scan,
                read_only=False,
            ),
            ToolSpec(
                "read_audit",
                "Summarize an existing Komagu audit directory (stack profile, coverage, finding metadata). "
                "Does not include source snippets.",
                {
                    "type": "object",
                    "properties": {
                        "audit_dir": {"type": "string", "description": "Directory that contains findings.json."},
                    },
                    "required": ["audit_dir"],
                    "additionalProperties": False,
                },
                tool_read_audit,
                read_only=True,
            ),
            ToolSpec(
                "leak_check",
                "Scan audit output for secrets and client canary strings. Hit values are masked. "
                "exitCode 0 is clean, 1 is a suspected leak, 2 means the scan was incomplete.",
                {
                    "type": "object",
                    "properties": {
                        "paths": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Files or directories to scan. At most 32.",
                        },
                        "canary_file": {
                            "type": "string",
                            "description": "Optional UTF-8 file with one canary string per line, kept outside the repository.",
                        },
                    },
                    "required": ["paths"],
                    "additionalProperties": False,
                },
                tool_leak_check,
                read_only=True,
            ),
            ToolSpec(
                "inventory",
                "Compare code routes with an OpenAPI document and an optional gateway log. "
                "Returns shadow, zombie, missing, and dormant counts. Does not write a file.",
                {
                    "type": "object",
                    "properties": {
                        "routes": {"type": "string", "description": "LSA routes JSON file."},
                        "openapi": {"type": "string", "description": "OpenAPI JSON or YAML file."},
                        "traffic_log": {"type": "string", "description": "Optional Kong JSON-lines or NGINX combined log."},
                    },
                    "required": ["routes", "openapi"],
                    "additionalProperties": False,
                },
                tool_inventory,
                read_only=True,
            ),
            ToolSpec(
                "fix_preview",
                "Dry-run remediation plan for findings.json. Never writes source or a patch file. "
                "appliedCount is always 0. Pass findings after scan, or point target at a tree that already has findings.json.",
                {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Code directory the findings refer to."},
                        "findings": {"type": "string", "description": "Optional findings.json or SARIF file."},
                    },
                    "required": ["target"],
                    "additionalProperties": False,
                },
                tool_fix_preview,
                read_only=True,
            ),
        ]
    )


def _check_arguments(arguments: Dict[str, Any], allowed: Tuple[str, ...], required: Tuple[str, ...]) -> None:
    if not isinstance(arguments, dict):
        raise ToolError("arguments must be an object")
    unknown = sorted(set(arguments) - set(allowed))
    if unknown:
        raise ToolError("unknown arguments: " + ", ".join(unknown))
    missing = [key for key in required if key not in arguments]
    if missing:
        raise ToolError("missing arguments: " + ", ".join(missing))


def _as_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ToolError(f"{label} must be a non-empty string")
    if "\x00" in value:
        raise ToolError(f"{label} contains a null byte")
    return Path(value).expanduser().resolve()


def _require_dir(value: Any, label: str) -> Path:
    path = _as_path(value, label)
    if not path.is_dir():
        raise ToolError(f"{label} is not a directory: {path}")
    return path


def _require_file(value: Any, label: str) -> Path:
    path = _as_path(value, label)
    if not path.is_file():
        raise ToolError(f"{label} is not a file: {path}")
    return path


def _read_json(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {"_error": f"{path.name}: {exc}"}


def _cap(items: Any, cap: int = LIST_CAP) -> Tuple[List[Any], bool]:
    if not isinstance(items, list):
        return [], False
    return items[:cap], len(items) > cap


def summarize_audit(audit_dir: Path) -> Dict[str, Any]:
    """Finding metadata and artifact names from one audit directory."""
    artifacts = sorted(entry.name for entry in audit_dir.iterdir() if entry.is_file())
    profile = _read_json(audit_dir / "stack-profile.json")
    findings_doc = _read_json(audit_dir / "findings.json")
    coverage = _read_json(audit_dir / "coverage.json")

    stacks: List[Any] = []
    if isinstance(profile, dict):
        for stack in profile.get("stacks") or []:
            if isinstance(stack, dict) and stack.get("id"):
                stacks.append(stack.get("id"))
            elif isinstance(stack, str):
                stacks.append(stack)

    findings: List[Any] = []
    summary = None
    if isinstance(findings_doc, dict):
        raw = findings_doc.get("findings")
        if isinstance(raw, list):
            findings = raw
        summary = findings_doc.get("summary")
    elif isinstance(findings_doc, list):
        findings = findings_doc

    listed: List[Dict[str, Any]] = []
    for item in findings[:LIST_CAP]:
        if not isinstance(item, dict):
            continue
        location = item.get("location") if isinstance(item.get("location"), dict) else {}
        listed.append(
            {
                "finding_id": item.get("finding_id"),
                "category": item.get("category"),
                "severity": item.get("severity"),
                "title": item.get("title"),
                "file": location.get("file"),
                "start_line": location.get("start_line"),
                "status": item.get("status"),
            }
        )

    return {
        "auditDir": str(audit_dir),
        "artifacts": artifacts,
        "stacks": stacks,
        "coverage": coverage if isinstance(coverage, dict) else None,
        "summary": summary if isinstance(summary, dict) else None,
        "findings": listed,
        "findingsTotal": len(findings),
        "findingsTruncated": len(findings) > LIST_CAP,
    }


def tool_scan(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Tier 1 scan in a child process so its logs never touch the MCP stdout stream."""
    _check_arguments(arguments, ("target", "out", "lang", "format", "timeout_seconds"), ("target", "out"))
    target = _require_dir(arguments["target"], "target")
    out = _as_path(arguments["out"], "out")
    if out.exists() and not out.is_dir():
        raise ToolError(f"out is not a directory: {out}")
    lang = arguments.get("lang", "en")
    fmt = arguments.get("format", "sarif")
    if lang not in LANGS:
        raise ToolError("lang must be en, ja, or all")
    if fmt not in FORMATS:
        raise ToolError("format must be md, html, sarif, or all")
    timeout = arguments.get("timeout_seconds", 180)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= SCAN_TIMEOUT_MAX:
        raise ToolError(f"timeout_seconds must be an integer from 1 to {SCAN_TIMEOUT_MAX}")

    command = [
        sys.executable,
        str(BIN_KOMAGU),
        "--no-banner",
        "scan",
        str(target),
        "--out",
        str(out),
        "--lang",
        lang,
        "--format",
        fmt,
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"scan timed out after {timeout} seconds") from exc
    except OSError as exc:
        raise ToolError(f"could not start scan: {exc}") from exc

    audit = summarize_audit(out) if out.is_dir() else None
    payload: Dict[str, Any] = {
        "exitCode": completed.returncode,
        "target": str(target),
        "out": str(out),
        "format": fmt,
        "lang": lang,
        "audit": audit,
    }
    if completed.returncode != 0:
        payload["stderrTail"] = (completed.stderr or completed.stdout or "")[-STDERR_CAP:]
    return payload


def tool_read_audit(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Read finding metadata already on disk."""
    _check_arguments(arguments, ("audit_dir",), ("audit_dir",))
    audit_dir = _require_dir(arguments["audit_dir"], "audit_dir")
    return summarize_audit(audit_dir)


def tool_leak_check(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Delegate to the same scanner as komagu leak-check. Values stay masked."""
    _check_arguments(arguments, ("paths", "canary_file"), ("paths",))
    raw_paths = arguments["paths"]
    if not isinstance(raw_paths, list) or not raw_paths:
        raise ToolError("paths must be a non-empty array of strings")
    if len(raw_paths) > MAX_PATHS:
        raise ToolError(f"paths accepts at most {MAX_PATHS} entries")
    paths = [str(_as_path(item, "paths entry")) for item in raw_paths]
    canaries: Tuple[str, ...] = ()
    if "canary_file" in arguments and arguments["canary_file"] is not None:
        canary_file = _require_file(arguments["canary_file"], "canary_file")
        try:
            canaries = load_canaries(str(canary_file))
        except CanaryFileError as exc:
            raise ToolError(str(exc)) from exc
    result = scan_paths(paths, canaries)
    hits, truncated = _cap([dataclasses.asdict(hit) for hit in result.hits])
    return {
        "exitCode": result.exit_code,
        "filesScanned": result.files_scanned,
        "canariesLoaded": result.canaries_loaded,
        "hits": hits,
        "hitsTruncated": truncated,
        "notScanned": [{"path": path, "reason": reason} for path, reason in result.unscanned],
    }


def tool_inventory(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """In-process inventory diff. Nothing is written."""
    _check_arguments(arguments, ("routes", "openapi", "traffic_log"), ("routes", "openapi"))
    routes_file = _require_file(arguments["routes"], "routes")
    openapi_file = _require_file(arguments["openapi"], "openapi")
    traffic_file: Optional[Path] = None
    if arguments.get("traffic_log"):
        traffic_file = _require_file(arguments["traffic_log"], "traffic_log")

    code_routes = load_code_routes(routes_file)
    spec_endpoints = load_openapi_spec(openapi_file)
    traffic_data = load_traffic_log(traffic_file) if traffic_file else {}
    diff_doc = diff_api_inventory(
        code_routes=code_routes,
        spec_endpoints=spec_endpoints,
        traffic_data=traffic_data,
        routes_file_name=routes_file.name,
        openapi_file_name=openapi_file.name,
        traffic_file_name=traffic_file.name if traffic_file else None,
    )
    payload = dict(diff_doc)
    for key in ("shadow_apis", "zombie_apis", "documented_missing_code", "dormant_code"):
        capped, truncated = _cap(payload.get(key))
        payload[key] = capped
        payload[key + "_truncated"] = truncated
    return payload


def tool_fix_preview(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Dry-run only. output_patch is never set, so no patch file is written."""
    _check_arguments(arguments, ("target", "findings"), ("target",))
    target = _require_dir(arguments["target"], "target")
    findings: Optional[Path] = None
    if arguments.get("findings"):
        findings = _require_file(arguments["findings"], "findings")
    runner = RemediationRunner(
        target_dir=target,
        findings_path=findings,
        dry_run=True,
        output_patch=None,
        scan_sca=False,
        query_osv=False,
    )
    try:
        report = runner.run()
    except FileNotFoundError as exc:
        raise ToolError(str(exc)) from exc
    if report.applied_count != 0 or not report.dry_run:
        raise ToolError("refusing to return a preview that modified source")

    plans: List[Dict[str, Any]] = []
    for plan in report.plans[:LIST_CAP]:
        item = plan.to_dict()
        if plan.diff:
            item["diff"] = plan.diff[:DIFF_CAP]
            item["diffTruncated"] = len(plan.diff) > DIFF_CAP
        plans.append(item)
    body = report.to_dict()
    body["plans"] = plans
    body["plansTruncated"] = len(report.plans) > LIST_CAP
    body["modifiedSource"] = False
    return body
