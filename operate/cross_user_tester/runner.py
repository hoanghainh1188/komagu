#!/usr/bin/env python3
"""Komainu Cross-User Authorization Test Runner.

Continuous security verification engine for detecting Broken Object Level
Authorization (BOLA / IDOR) vulnerabilities in CI/CD pipelines.

Verifies the 3 core operations (Read, Update, Delete):
- GET /resource/{id}
- PUT/PATCH /resource/{id}
- DELETE /resource/{id}

Enforces the Komainu security invariant:
When an attacker (Persona B) attempts to access Persona A's resource,
the endpoint MUST respond with HTTP 404 Not Found.
Any 2xx response indicates a BOLA breach (CWE-639 / CWE-284).
"""

from __future__ import annotations

import argparse
import json
import sys
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


class TestCase:
    """Specification of a cross-user test case."""

    def __init__(
        self,
        name: str,
        path: str,
        method: str = "GET",
        resource_id: Optional[str] = None,
        attacker_token: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        expected_status: Optional[List[int]] = None,
        insecure_status: Optional[List[int]] = None,
        finding_id: Optional[str] = None,
        consensus_score: Optional[float] = None,
    ) -> None:
        self.name = name
        self.finding_id = finding_id
        self.consensus_score = consensus_score
        final_path = path
        if resource_id:
            # Replace placeholder variants like {id}, {order_id}, :id, {userId}
            final_path = re.sub(r"\{[a-zA-Z0-9_-]*(?:id|ID)[a-zA-Z0-9_-]*\}", str(resource_id), final_path)
            final_path = re.sub(r":([a-zA-Z0-9_-]*(?:id|ID)[a-zA-Z0-9_-]*)", str(resource_id), final_path)
            if "{id}" in final_path:
                final_path = final_path.replace("{id}", str(resource_id))
        self.path = final_path
        self.method = method.upper()
        self.resource_id = resource_id
        self.attacker_token = attacker_token
        self.payload = payload
        self.headers = headers or {}
        self.expected_status = expected_status or [404]
        self.insecure_status = insecure_status or [200, 201, 202, 204]


class TestResult:
    """Outcome of executing a single test case."""

    def __init__(
        self,
        test_case: TestCase,
        status_code: int,
        response_body: str,
        is_breach: bool,
        is_secure: bool,
        duration_ms: float,
        error_message: Optional[str] = None,
    ) -> None:
        self.test_case = test_case
        self.status_code = status_code
        self.response_body = response_body
        self.is_breach = is_breach
        self.is_secure = is_secure
        self.duration_ms = duration_ms
        self.error_message = error_message

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.test_case.name,
            "finding_id": self.test_case.finding_id,
            "consensus_score": self.test_case.consensus_score,
            "method": self.test_case.method,
            "path": self.test_case.path,
            "status_code": self.status_code,
            "is_breach": self.is_breach,
            "is_secure": self.is_secure,
            "duration_ms": round(self.duration_ms, 2),
            "error_message": self.error_message,
        }



class CrossUserTestRunner:
    """Runner for cross-user authorization test suites."""

    def __init__(
        self,
        base_url: str,
        default_attacker_token: Optional[str] = None,
        auth_header: str = "Authorization",
        token_prefix: str = "Bearer ",
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.default_attacker_token = default_attacker_token
        self.auth_header = auth_header
        self.token_prefix = token_prefix
        self.timeout = timeout

    def execute_test(self, test: TestCase) -> TestResult:
        """Execute a single test case against the target API."""
        url = f"{self.base_url}{test.path}"
        headers = dict(test.headers)

        token = test.attacker_token or self.default_attacker_token
        if token and self.auth_header not in headers:
            headers[self.auth_header] = f"{self.token_prefix}{token}".strip()

        data: Optional[bytes] = None
        if test.payload is not None:
            data = json.dumps(test.payload).encode("utf-8")
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/json"

        req = urllib.request.Request(
            url=url,
            data=data,
            headers=headers,
            method=test.method,
        )

        start_time = time.time()
        status_code = 0
        response_body = ""
        error_message = None

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status_code = resp.status
                raw = resp.read()
                response_body = raw.decode("utf-8", errors="replace")[:1000]
        except urllib.error.HTTPError as http_err:
            status_code = http_err.code
            raw = http_err.read()
            response_body = raw.decode("utf-8", errors="replace")[:1000]
        except Exception as ex:
            error_message = str(ex)

        duration_ms = (time.time() - start_time) * 1000.0
        is_breach = status_code in test.insecure_status
        is_secure = status_code in test.expected_status

        return TestResult(
            test_case=test,
            status_code=status_code,
            response_body=response_body,
            is_breach=is_breach,
            is_secure=is_secure,
            duration_ms=duration_ms,
            error_message=error_message,
        )

    def run_suite(self, tests: List[TestCase]) -> List[TestResult]:
        """Run all test cases sequentially."""
        return [self.execute_test(t) for t in tests]


def generate_crud_test_cases(
    resource_path: str,
    resource_id: str,
    name_prefix: str = "Resource",
    attacker_token: Optional[str] = None,
    sample_payload: Optional[Dict[str, Any]] = None,
) -> List[TestCase]:
    """Generate the standard 3-operation (GET, PUT, DELETE) cross-user test cases."""
    return [
        TestCase(
            name=f"{name_prefix} - Cross-User Read (GET)",
            path=resource_path,
            method="GET",
            resource_id=resource_id,
            attacker_token=attacker_token,
        ),
        TestCase(
            name=f"{name_prefix} - Cross-User Tamper (PUT)",
            path=resource_path,
            method="PUT",
            resource_id=resource_id,
            attacker_token=attacker_token,
            payload=sample_payload or {"status": "tampered_by_attacker"},
        ),
        TestCase(
            name=f"{name_prefix} - Cross-User Destruction (DELETE)",
            path=resource_path,
            method="DELETE",
            resource_id=resource_id,
            attacker_token=attacker_token,
        ),
    ]


def load_suite_from_file(file_path: str) -> List[TestCase]:
    """Load test cases from a JSON configuration file."""
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    test_cases: List[TestCase] = []
    items = data if isinstance(data, list) else data.get("tests", [])

    for item in items:
        # If item specifies auto_crud, generate 3 CRUD operations
        if item.get("auto_crud"):
            cases = generate_crud_test_cases(
                resource_path=item["path"],
                resource_id=str(item.get("resource_id", "1")),
                name_prefix=item.get("name", item["path"]),
                attacker_token=item.get("attacker_token"),
                sample_payload=item.get("payload"),
            )
            test_cases.extend(cases)
        else:
            test_cases.append(
                TestCase(
                    name=item.get("name", f"{item.get('method', 'GET')} {item['path']}"),
                    path=item["path"],
                    method=item.get("method", "GET"),
                    resource_id=str(item.get("resource_id")) if item.get("resource_id") else None,
                    attacker_token=item.get("attacker_token"),
                    payload=item.get("payload"),
                    headers=item.get("headers"),
                    expected_status=item.get("expected_status"),
                    insecure_status=item.get("insecure_status"),
                )
            )
    return test_cases


def generate_test_cases_from_findings(
    scan_data_or_path: Union[str, Path, Dict[str, Any], List[Dict[str, Any]]],
    default_resource_id: str = "12345",
    attacker_token: Optional[str] = None,
    min_consensus_score: float = 0.0,
    include_likely: bool = True,
) -> List[TestCase]:
    """Synthesize active BOLA verification test cases from LSA findings.json or SARIF data.

    Parses confirmed/likely BOLA findings, extracts endpoints, replaces identifier
    parameters with target resource_id, and constructs offensive test cases.
    """
    data: Any = scan_data_or_path
    if isinstance(scan_data_or_path, (str, Path)):
        p = Path(scan_data_or_path).resolve()
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)

    test_cases: List[TestCase] = []

    # 1. Native Komainu findings format
    if (isinstance(data, dict) and "findings" in data) or isinstance(data, list):
        items = data if isinstance(data, list) else data.get("findings", [])
        for item in items:
            cat = str(item.get("category", "")).lower()
            fid = str(item.get("finding_id", ""))
            if cat != "bola" and not fid.startswith("BOLA"):
                continue

            status = str(item.get("status", "confirmed")).lower()
            if status in ("rejected", "fixed"):
                continue
            if not include_likely and status in ("likely", "unverified"):
                continue

            # Check consensus score if present
            c_info = item.get("consensus") or {}
            c_score: Optional[float] = None
            if isinstance(c_info, dict) and "score" in c_info:
                try:
                    c_score = float(c_info["score"])
                except (ValueError, TypeError):
                    c_score = None
            if c_score is not None and c_score < min_consensus_score:
                continue

            # Extract path and method from attack_vector or endpoint
            av = item.get("attack_vector") or {}
            ep = item.get("endpoint") or {}
            path = av.get("path") or ep.get("path")
            method = av.get("method") or ep.get("method") or "GET"

            # Fallback: attempt to find path in evidence or title
            if not path:
                title = item.get("title", "")
                m = re.search(r"(/[a-zA-Z0-9_\-\./\{\}:]+)", title)
                if m:
                    path = m.group(1)

            if not path:
                continue

            # Determine resource_id to inject
            target_id = default_resource_id
            if "{id}" not in path and ":id" not in path and not re.search(r"\{[a-zA-Z0-9_-]*(?:id|ID)[a-zA-Z0-9_-]*\}", path):
                if not path.endswith("/"):
                    target_path = f"{path}/{target_id}"
                else:
                    target_path = f"{path}{target_id}"
            else:
                target_path = path

            # Handle multiple HTTP methods joined by |
            methods = [m.strip().upper() for m in method.split("|") if m.strip()] or ["GET"]
            for m in methods:
                payload = None
                if m in ("POST", "PUT", "PATCH"):
                    payload = {"status": "tampered_by_attacker", "note": "Komainu BOLA exploit verification"}

                tc_name = f"[{fid}] {item.get('title', target_path)} ({m})"
                test_cases.append(
                    TestCase(
                        name=tc_name,
                        path=target_path,
                        method=m,
                        resource_id=target_id,
                        attacker_token=attacker_token,
                        payload=payload,
                        finding_id=fid,
                        consensus_score=c_score,
                    )
                )

    # 2. OASIS SARIF 2.1.0 format
    elif isinstance(data, dict) and "runs" in data:
        for run in data.get("runs", []):
            for result in run.get("results", []):
                rule_id = str(result.get("ruleId", "")).lower()
                msg = result.get("message", {}).get("text", "")
                props = result.get("properties", {}) or {}
                tags = [str(t).lower() for t in props.get("tags", [])]

                is_bola = (
                    "bola" in rule_id
                    or "639" in rule_id
                    or any("bola" in t or "639" in t for t in tags)
                )
                if not is_bola:
                    continue

                # Try to extract path and method from SARIF properties or message
                ep = props.get("endpoint") or {}
                path = ep.get("path")
                method = ep.get("method") or "GET"

                if not path:
                    m = re.search(r"(?:GET|POST|PUT|DELETE|PATCH)?\s*(/[a-zA-Z0-9_\-\./\{\}:]+)", msg)
                    if m:
                        path = m.group(1)

                if not path:
                    continue

                target_id = default_resource_id
                if "{id}" not in path and ":id" not in path and not re.search(r"\{[a-zA-Z0-9_-]*(?:id|ID)[a-zA-Z0-9_-]*\}", path):
                    target_path = f"{path}/{target_id}" if not path.endswith("/") else f"{path}{target_id}"
                else:
                    target_path = path

                fid = props.get("finding_id") or result.get("ruleId", "BOLA")
                tc_name = f"[{fid}] SARIF {result.get('ruleId', 'BOLA')} ({method})"
                test_cases.append(
                    TestCase(
                        name=tc_name,
                        path=target_path,
                        method=method,
                        resource_id=target_id,
                        attacker_token=attacker_token,
                        finding_id=fid,
                        consensus_score=float(props.get("consensus_score", 1.0)) if "consensus_score" in props else None,
                    )
                )

    return test_cases



def format_report(results: List[TestResult], base_url: str) -> Tuple[str, bool]:
    """Format human-readable CLI report and determine overall pass/fail status."""
    lines: List[str] = [
        "============================================================",
        "  KOMAINU CROSS-USER AUTHORIZATION TEST REPORT",
        "============================================================",
        f"Target Base URL: {base_url}",
        f"Total Tests Executed: {len(results)}",
        "------------------------------------------------------------",
    ]

    has_breaches = False
    passed_count = 0
    breach_count = 0
    error_count = 0

    for res in results:
        t = res.test_case
        if res.is_breach:
            has_breaches = True
            breach_count += 1
            lines.append(
                f"[FAIL - BOLA BREACH] {t.method} {t.path} -> "
                f"HTTP {res.status_code} (Expected {t.expected_status})"
            )
            lines.append(f"       Test: {t.name}")
        elif res.is_secure:
            passed_count += 1
            lines.append(
                f"[PASS - SECURE]      {t.method} {t.path} -> "
                f"HTTP {res.status_code} ({res.duration_ms:.1f}ms)"
            )
        else:
            error_count += 1
            lines.append(
                f"[ERROR - UNEXPECTED] {t.method} {t.path} -> "
                f"HTTP {res.status_code} (Err: {res.error_message})"
            )

    lines.append("------------------------------------------------------------")
    lines.append(
        f"Result: {passed_count} Passed, {breach_count} Breaches (BOLA/IDOR), "
        f"{error_count} Errors"
    )
    lines.append("============================================================")

    return "\n".join(lines), (breach_count == 0 and error_count == 0)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Komainu Cross-User Authorization Test Runner"
    )
    parser.add_argument("--base-url", required=True, help="Target API base URL")
    parser.add_argument("--config", help="Path to JSON test suite configuration file")
    parser.add_argument("--attacker-token", help="Default Bearer token for Persona B (Attacker)")
    parser.add_argument("--output", help="Optional output JSON report path")
    parser.add_argument("--auto-crud-path", help="Shortcut: test CRUD on resource path (e.g. /orders/{id})")
    parser.add_argument("--resource-id", default="1", help="Resource ID owned by Persona A")

    args = parser.parse_args()

    tests: List[TestCase] = []
    if args.config:
        tests.extend(load_suite_from_file(args.config))

    if args.auto_crud_path:
        tests.extend(
            generate_crud_test_cases(
                resource_path=args.auto_crud_path,
                resource_id=args.resource_id,
                attacker_token=args.attacker_token,
            )
        )

    if not tests:
        print("Error: No test cases specified. Use --config or --auto-crud-path", file=sys.stderr)
        sys.exit(2)

    runner = CrossUserTestRunner(
        base_url=args.base_url,
        default_attacker_token=args.attacker_token,
    )

    results = runner.run_suite(tests)
    report_text, success = format_report(results, args.base_url)
    print(report_text)

    if args.output:
        report_data = {
            "base_url": args.base_url,
            "total": len(results),
            "success": success,
            "results": [r.to_dict() for r in results],
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        print(f"Report saved to: {args.output}")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
