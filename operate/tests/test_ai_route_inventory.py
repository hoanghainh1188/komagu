#!/usr/bin/env python3
"""Route inventory built by the headless runner from Tier 1 route batches (#380)."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from operate.ai.runner import HeadlessAIRunner


class _NoCallClient:
    model = "none"
    endpoint = "test://"

    def chat(self, messages, temperature=0.1):  # noqa: ANN001
        raise AssertionError("route inventory must not call the model")


class TestRouteInventory(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="komagu_inventory_"))
        self.out = self.tmp / "out"
        (self.out / "batches").mkdir(parents=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def inventory(self, candidates: list) -> list:
        (self.out / "batches" / "routes-001.json").write_text(json.dumps({"candidates": candidates}), encoding="utf-8")
        HeadlessAIRunner(self.tmp, self.out, _NoCallClient()).map_routes_inventory()
        return json.loads((self.out / "routes" / "routes-001.json").read_text(encoding="utf-8"))["routes"]

    def test_route_without_id_params_gets_no_invented_id(self) -> None:
        routes = self.inventory([{"route_id": "R-0001", "method": ["POST"], "path": "/register",
                                  "handler": {"file": "app/Http/Controllers/AccountController.php", "line": 11},
                                  "id_params": []}])
        self.assertEqual(routes[0]["id_inputs"], [])

    def test_detected_id_params_are_kept(self) -> None:
        routes = self.inventory([{"route_id": "R-0001", "method": ["GET"], "path": "/orders/{id}",
                                  "handler": {"file": "routes/web.php", "line": 3},
                                  "id_params": [{"name": "id", "source": "path", "is_id_like": True},
                                                {"name": "orderId", "source": "query"}]}])
        self.assertEqual(routes[0]["id_inputs"], [{"name": "id", "source": "path"},
                                                  {"name": "orderId", "source": "query"}])


if __name__ == "__main__":
    unittest.main()
