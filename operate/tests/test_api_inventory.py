#!/usr/bin/env python3
"""Tests for API Inventory Reconciliation & Shadow/Zombie API Detection (Issue #288).

Verifies:
1. api-inventory-diff.schema.json schema conformity.
2. Route path parameter normalization (Express, Flask, OpenAPI, integers, UUIDs).
3. 3-way reconciliation covering all 4 discrepancy cases:
   - Shadow API: in code but not in spec.
   - Shadow API: in live traffic but not in spec.
   - Zombie API: marked deprecated in OpenAPI spec but still receiving traffic.
   - Documented Missing in Code: in spec but not implemented.
   - Dormant Code: implemented and documented, but zero traffic.
4. Kong HTTP-Log (JSON lines) and NGINX Combined access log parsing.
5. CLI execution and gating flags (--fail-on-shadow, --fail-on-zombie).
6. Markdown and HTML report generation.

Standard-library-only (Python 3.8+).
"""
from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path

from assess.lsa.scripts.merge_findings import load_validator
from operate.cli.commands.inventory import run_inventory
from operate.inventory.api_inventory import (
    diff_api_inventory,
    load_code_routes,
    load_openapi_spec,
    load_traffic_log,
    normalize_path,
    normalize_route_key,
    render_inventory_html,
    render_inventory_md,
)


class TestApiInventory(unittest.TestCase):
    def setUp(self) -> None:
        self.validate_schema = load_validator("api-inventory-diff.schema.json")

    def test_path_normalization(self) -> None:
        """Verify unified path normalization across diverse frameworks."""
        self.assertEqual(normalize_path("/api/orders/{id}"), "/api/orders/{}")
        self.assertEqual(normalize_path("/users/<int:userId>"), "/users/{}")
        self.assertEqual(normalize_path("/accounts/:accId/profile"), "/accounts/{}/profile")
        self.assertEqual(normalize_path("/api/orders/42"), "/api/orders/{}")
        self.assertEqual(
            normalize_path("/items/12345678-abcd-1234-abcd-123456789abc"),
            "/items/{}"
        )
        self.assertEqual(normalize_path("/trailing/slash/"), "/trailing/slash")
        self.assertEqual(normalize_route_key("get", "/api/v1/orders/{id}?limit=10"), "GET /api/v1/orders/{}")

    def test_four_way_reconciliation_cases(self) -> None:
        """Verify detection of Shadow, Zombie, Dead Spec, and Dormant Code."""
        # 1. Code routes
        code_routes = [
            {"method": "GET", "path": "/api/users/{id}", "location": "Controllers/Users.cs:10"},  # Normal
            {"method": "POST", "path": "/api/internal/debug-dump", "location": "Controllers/Debug.cs:42"},  # Shadow (in code, not spec)
            {"method": "GET", "path": "/api/legacy-v1/export", "location": "Controllers/Legacy.cs:15"},  # Zombie (deprecated in spec, receiving traffic)
            {"method": "GET", "path": "/api/dormant-feature", "location": "Controllers/Dormant.cs:88"},  # Dormant (in code & spec, 0 traffic)
        ]

        # 2. OpenAPI Spec
        spec_endpoints = [
            {"method": "GET", "path": "/api/users/{id}", "normalized": "GET /api/users/{}", "deprecated": False},
            {"method": "GET", "path": "/api/legacy-v1/export", "normalized": "GET /api/legacy-v1/export", "deprecated": True},  # Deprecated!
            {"method": "GET", "path": "/api/dormant-feature", "normalized": "GET /api/dormant-feature", "deprecated": False},
            {"method": "DELETE", "path": "/api/planned-ghost", "normalized": "DELETE /api/planned-ghost", "deprecated": False, "summary": "Ghost spec"},  # Missing in code
        ]

        # 3. Traffic Data
        traffic_data = {
            "GET /api/users/{}": {"method": "GET", "path": "/api/users/123", "normalized": "GET /api/users/{}", "traffic_hits": 50},
            "GET /api/legacy-v1/export": {"method": "GET", "path": "/api/legacy-v1/export", "normalized": "GET /api/legacy-v1/export", "traffic_hits": 12},
            "POST /api/untracked-admin": {"method": "POST", "path": "/api/untracked-admin", "normalized": "POST /api/untracked-admin", "traffic_hits": 5},  # Shadow in traffic only
        }

        diff = diff_api_inventory(code_routes, spec_endpoints, traffic_data)
        errors = self.validate_schema(diff)
        self.assertEqual(errors, [], f"Schema validation errors: {errors}")

        s = diff["summary"]
        self.assertEqual(s["shadow_count"], 2)  # debug-dump (code_only) + untracked-admin (traffic_only)
        self.assertEqual(s["zombie_count"], 1)  # legacy-v1/export
        self.assertEqual(s["missing_code_count"], 1)  # planned-ghost
        self.assertEqual(s["dormant_count"], 1)  # dormant-feature

        # Verify Shadow details
        shadow_keys = {sh["normalized"]: sh["discovered_in"] for sh in diff["shadow_apis"]}
        self.assertEqual(shadow_keys.get("POST /api/internal/debug-dump"), "code_only")
        self.assertEqual(shadow_keys.get("POST /api/untracked-admin"), "traffic_only")

        # Verify Zombie details
        zombie_keys = [z["normalized"] for z in diff["zombie_apis"]]
        self.assertIn("GET /api/legacy-v1/export", zombie_keys)
        self.assertEqual(diff["zombie_apis"][0]["traffic_hits"], 12)

        # Verify Missing code details
        missing_keys = [m["normalized"] for m in diff["documented_missing_code"]]
        self.assertIn("DELETE /api/planned-ghost", missing_keys)

        # Verify Dormant code details
        dormant_keys = [d["normalized"] for d in diff["dormant_code"]]
        self.assertIn("GET /api/dormant-feature", dormant_keys)

    def test_log_parsers(self) -> None:
        """Verify parsing Kong JSON lines and Combined Nginx log formats."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)

            # 1. Kong HTTP-Log NDJSON
            kong_log = tmp / "kong.log"
            kong_log.write_text(
                '{"request": {"method": "GET", "uri": "/api/orders/101"}, "started_at": 1730000000}\n'
                '{"request": {"method": "GET", "uri": "/api/orders/102"}, "started_at": 1730000001}\n'
                '{"request": {"method": "POST", "uri": "/api/checkout"}, "started_at": 1730000002}\n'
            )
            parsed_kong = load_traffic_log(kong_log)
            self.assertEqual(parsed_kong["GET /api/orders/{}"]["traffic_hits"], 2)
            self.assertEqual(parsed_kong["POST /api/checkout"]["traffic_hits"], 1)

            # 2. Combined NGINX log
            nginx_log = tmp / "nginx.log"
            nginx_log.write_text(
                '192.168.1.1 - - [01/Nov/2026:12:00:00 +0000] "GET /api/products/42 HTTP/1.1" 200 450\n'
                '192.168.1.2 - - [01/Nov/2026:12:00:01 +0000] "DELETE /api/cart HTTP/1.1" 204 0\n'
            )
            parsed_nginx = load_traffic_log(nginx_log)
            self.assertEqual(parsed_nginx["GET /api/products/{}"]["traffic_hits"], 1)
            self.assertEqual(parsed_nginx["DELETE /api/cart"]["traffic_hits"], 1)

    def test_cli_execution_and_gating(self) -> None:
        """Verify komagu inventory command execution and gate checks."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            routes_file = tmp / "routes.json"
            routes_file.write_text(json.dumps({
                "routes": [
                    {"method": "GET", "path": "/api/users/{id}", "location": "app.py:10"},
                    {"method": "POST", "path": "/api/shadow-login", "location": "auth.py:50"},
                ]
            }))

            spec_file = tmp / "openapi.json"
            spec_file.write_text(json.dumps({
                "openapi": "3.0.0",
                "paths": {
                    "/api/users/{id}": {"get": {"summary": "Get user"}},
                    "/api/old-v0/auth": {"post": {"deprecated": True, "summary": "Old auth"}},
                }
            }))

            traffic_file = tmp / "traffic.log"
            traffic_file.write_text('{"request": {"method": "POST", "uri": "/api/old-v0/auth"}}\n')

            out_file = tmp / "diff.json"

            args = argparse.Namespace(
                routes=routes_file,
                openapi=spec_file,
                traffic_log=traffic_file,
                out=out_file,
                fail_on_shadow=False,
                fail_on_zombie=False,
            )

            # Normal run passes with exit code 0
            rc = run_inventory(args)
            self.assertEqual(rc, 0)
            self.assertTrue(out_file.is_file())

            diff_data = json.loads(out_file.read_text())
            self.assertEqual(diff_data["summary"]["shadow_count"], 1)
            self.assertEqual(diff_data["summary"]["zombie_count"], 1)

            # Fail on shadow gate trips exit code 1
            args_shadow_gate = argparse.Namespace(
                routes=routes_file,
                openapi=spec_file,
                traffic_log=traffic_file,
                out=out_file,
                fail_on_shadow=True,
                fail_on_zombie=False,
            )
            self.assertEqual(run_inventory(args_shadow_gate), 1)

            # Fail on zombie gate trips exit code 1
            args_zombie_gate = argparse.Namespace(
                routes=routes_file,
                openapi=spec_file,
                traffic_log=traffic_file,
                out=out_file,
                fail_on_shadow=False,
                fail_on_zombie=True,
            )
            self.assertEqual(run_inventory(args_zombie_gate), 1)

    def test_report_rendering(self) -> None:
        """Verify Markdown and HTML report generation for API inventory diff."""
        mock_diff = {
            "summary": {
                "total_code_routes": 10,
                "total_spec_endpoints": 8,
                "total_traffic_endpoints": 9,
                "shadow_count": 2,
                "zombie_count": 1,
                "missing_code_count": 0,
                "dormant_count": 1,
            },
            "shadow_apis": [
                {"method": "POST", "path": "/api/secret", "normalized": "POST /api/secret", "discovered_in": "code_only", "traffic_hits": 0, "location": "secret.py:1"}
            ],
            "zombie_apis": [
                {"method": "GET", "path": "/api/v1/old", "normalized": "GET /api/v1/old", "location": "old.py:5", "traffic_hits": 15, "last_seen": "2026-11-01"}
            ],
            "documented_missing_code": [],
            "dormant_code": [],
        }

        md_en = "\n".join(render_inventory_md(mock_diff, "en"))
        self.assertIn("API Inventory Reconciliation", md_en)
        self.assertIn("POST /api/secret", md_en)

        md_ja = "\n".join(render_inventory_md(mock_diff, "ja"))
        self.assertIn("APIインベントリ照合", md_ja)
        self.assertIn("Shadow API", md_ja)

        html_card = render_inventory_html(mock_diff)
        self.assertIn("API Inventory &amp; Shadow / Zombie API Detection", html_card)
        self.assertIn("POST /api/secret", html_card)


if __name__ == "__main__":
    unittest.main()
