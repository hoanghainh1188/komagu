#!/usr/bin/env python3
"""Laravel routes map to the controller method they name, not to their declaration (#380)."""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS_DIR.parent / "scripts"))
from laravel_routes import route_action  # noqa: E402
from lsa_common import load_config  # noqa: E402
from map_routes import map_routes  # noqa: E402

ROUTES = """<?php
use App\\Http\\Controllers\\OrderController;
use Illuminate\\Support\\Facades\\Route;

Route::get('/orders/{id}', [OrderController::class, 'show']);
Route::post('/orders', 'OrderController@store');
Route::get('/missing', [GoneController::class, 'index']);
Route::get('/ping', function () { return 'ok'; });
"""

CONTROLLER = """<?php
namespace App\\Http\\Controllers;

use App\\Models\\Order;
use Illuminate\\Http\\Request;

class OrderController extends Controller
{
    public function show($id)
    {
        return Order::find($id);
    }

    public function store(Request $request)
    {
        return Order::create(['customer_id' => $request->input('customer_id')]);
    }
}
"""


class TestRouteAction(unittest.TestCase):
    def test_array_and_string_actions(self) -> None:
        self.assertEqual(route_action("Route::get('/a', [OrderController::class, 'show'])"), "OrderController@show")
        self.assertEqual(route_action("Route::get('/a', [\\App\\Http\\Controllers\\OrderController::class, 'show'])"),
                         "OrderController@show")
        self.assertEqual(route_action("Route::post('/a', 'App\\Http\\Controllers\\OrderController@store')"),
                         "OrderController@store")
        self.assertIsNone(route_action("Route::get('/a', function () { return 1; })"))


class TestLaravelHandlers(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="lsa_laravel_"))
        (self.root / "routes").mkdir()
        (self.root / "app/Http/Controllers").mkdir(parents=True)
        (self.root / "routes/web.php").write_text(ROUTES, encoding="utf-8")
        (self.root / "app/Http/Controllers/OrderController.php").write_text(CONTROLLER, encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def routes(self) -> dict:
        found = map_routes(self.root, load_config(None), {"php-laravel"}, workers=1)["candidates"]
        return {r["path"]: r for r in found if r["stack"] == "php-laravel"}

    def test_route_points_at_the_controller_method(self) -> None:
        show = self.routes()["/orders/{id}"]
        self.assertEqual(show["handler"], {"file": "app/Http/Controllers/OrderController.php", "line": 9,
                                           "symbol": "OrderController@show"})
        self.assertEqual(show["notes"], "declared in routes/web.php:5")
        self.assertIn("id", [p["name"] for p in show["id_params"]])

    def test_string_action_and_body_inputs(self) -> None:
        store = self.routes()["/orders"]
        self.assertEqual((store["handler"]["file"], store["handler"]["line"]),
                         ("app/Http/Controllers/OrderController.php", 14))
        self.assertIn("customer_id", [p["name"] for p in store["id_params"]])

    def test_unresolved_routes_keep_their_declaration(self) -> None:
        routes = self.routes()
        self.assertEqual(routes["/missing"]["handler"], {"file": "routes/web.php", "line": 7,
                                                         "symbol": "GoneController@index"})
        self.assertEqual(routes["/ping"]["handler"]["file"], "routes/web.php")


if __name__ == "__main__":
    unittest.main()
