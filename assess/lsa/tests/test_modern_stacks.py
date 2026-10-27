#!/usr/bin/env python3
"""Tests for modern stack profiles in Komainu LSA (Rust, Go, FastAPI, NestJS).

Validates:
1. detect_stack.py correctly identifies modern stacks and data access libraries.
2. map_routes.py extracts route handlers and path parameters for Axum, Actix, Gin, and FastAPI.
3. find_injection.py flags dynamic SQL concatenations and string interpolations in Rust and Go.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

# Add assess/lsa/scripts to sys.path
SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from detect_stack import detect
from find_injection import find_injection
from lsa_common import load_config
from map_routes import map_routes


class TestModernStackProfiles(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_config(None)

    def test_rust_actix_and_sqlx_detection(self) -> None:
        """Verify Rust Actix-web stack detection, route extraction, and SQLi detection."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Cargo.toml").write_text('[package]\nname = "rust-app"\n\n[dependencies]\nactix-web = "4"\nsqlx = "0.7"\n', encoding="utf-8")
            src = root / "src"
            src.mkdir()
            (src / "main.rs").write_text('''
use actix_web::{get, web, App, HttpServer, HttpResponse};

#[get("/api/orders/{id}")]
async fn get_order(path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let query = format!("SELECT * FROM orders WHERE id = '{}'", id);
    HttpResponse::Ok().body(query)
}
''', encoding="utf-8")

            # 1. Stack detection
            prof = detect(root, self.config)
            stack_ids = {s["id"] for s in prof["stacks"]}
            self.assertIn("rust", stack_ids)
            self.assertIn("rust-actix", stack_ids)
            self.assertTrue(any("sqlx" in da.lower() for da in prof["data_access"]))

            # 2. Route mapping
            routes = map_routes(root, self.config, stack_ids)["candidates"]
            self.assertEqual(len(routes), 1)
            self.assertEqual(routes[0]["path"], "/api/orders/{id}")
            self.assertEqual(routes[0]["method"], ["GET"])
            self.assertEqual(routes[0]["stack"], "rust-actix")

            # 3. Injection detection (format! with dynamic string)
            injections = find_injection(root, self.config)["candidates"]
            self.assertTrue(len(injections) >= 1)
            self.assertTrue(any("SELECT * FROM orders" in inj["snippet"] for inj in injections))

    def test_rust_axum_route_detection(self) -> None:
        """Verify Rust Axum router mapping."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Cargo.toml").write_text('[package]\nname = "axum-app"\n\n[dependencies]\naxum = "0.7"\n', encoding="utf-8")
            src = root / "src"
            src.mkdir()
            (src / "main.rs").write_text('''
use axum::{routing::get, Router};

async fn list_users() -> &'static str { "users" }

pub fn app() -> Router {
    Router::new().route("/api/v1/users", get(list_users))
}
''', encoding="utf-8")

            prof = detect(root, self.config)
            stack_ids = {s["id"] for s in prof["stacks"]}
            self.assertIn("rust", stack_ids)
            self.assertIn("rust-axum", stack_ids)

            routes = map_routes(root, self.config, stack_ids)["candidates"]
            self.assertEqual(len(routes), 1)
            self.assertEqual(routes[0]["path"], "/api/v1/users")
            self.assertEqual(routes[0]["method"], ["GET"])
            self.assertEqual(routes[0]["stack"], "rust-axum")

    def test_go_gin_and_gorm_detection(self) -> None:
        """Verify Go Gin stack detection, route extraction, and SQLi detection."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "go.mod").write_text('module example.com/go-app\n\ngo 1.22\n', encoding="utf-8")
            (root / "main.go").write_text('''
package main

import (
    "fmt"
    "github.com/gin-gonic/gin"
    "gorm.io/gorm"
)

func main() {
    r := gin.Default()
    r.GET("/api/accounts/:id", func(c *gin.Context) {
        id := c.Param("id")
        sql := fmt.Sprintf("SELECT * FROM accounts WHERE id = '%s'", id)
        c.String(200, sql)
    })
}
''', encoding="utf-8")

            # 1. Stack detection
            prof = detect(root, self.config)
            stack_ids = {s["id"] for s in prof["stacks"]}
            self.assertIn("go", stack_ids)
            self.assertIn("go-gin", stack_ids)
            self.assertTrue(any("gorm" in da.lower() for da in prof["data_access"]))

            # 2. Route mapping
            routes = map_routes(root, self.config, stack_ids)["candidates"]
            self.assertEqual(len(routes), 1)
            self.assertEqual(routes[0]["path"], "/api/accounts/:id")
            self.assertEqual(routes[0]["method"], ["GET"])

            # 3. Injection detection (fmt.Sprintf into query)
            injections = find_injection(root, self.config)["candidates"]
            self.assertTrue(len(injections) >= 1)
            self.assertTrue(any("SELECT * FROM accounts" in inj["snippet"] for inj in injections))

    def test_fastapi_and_nestjs_detection(self) -> None:
        """Verify Python FastAPI and NestJS route declarations."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "api.py").write_text('''
from fastapi import FastAPI

app = FastAPI()

@app.get("/items/{item_id}")
def read_item(item_id: int):
    return {"item_id": item_id}
''', encoding="utf-8")

            (root / "app.controller.ts").write_text('''
import { Controller, Get, Param } from '@nestjs/common';

@Controller('users')
export class UsersController {
    @Get(':id')
    findOne(@Param('id') id: string) {
        return id;
    }
}
''', encoding="utf-8")

            prof = detect(root, self.config)
            stack_ids = {s["id"] for s in prof["stacks"]}
            self.assertIn("python-fastapi", stack_ids)
            self.assertIn("node-nestjs", stack_ids)

            routes = map_routes(root, self.config, stack_ids)["candidates"]
            paths = {r["path"] for r in routes}
            self.assertIn("/items/{item_id}", paths)
            self.assertIn("/users/:id", paths)


class TestModernStackRegressions(unittest.TestCase):
    """Regression cases from the #257 review (issue #259)."""

    def setUp(self) -> None:
        self.config = load_config(None)

    def scan(self, files: dict) -> tuple:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for rel, text in files.items():
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(text, encoding="utf-8")
            stack_ids = {s["id"] for s in detect(root, self.config)["stacks"]}
            routes = map_routes(root, self.config, stack_ids)["candidates"]
            injections = find_injection(root, self.config)["candidates"]
            return routes, injections

    @staticmethod
    def route_set(routes: list) -> set:
        return {(r["stack"], r["method"][0], r["path"]) for r in routes}

    @staticmethod
    def flagged_lines(injections: list) -> set:
        return {i["line"] for i in injections}

    # --- High: route false negatives --------------------------------------------------
    def test_go_fiber_chi_servemux_gorilla_routes(self) -> None:
        routes, _ = self.scan({
            "fiber.go": 'package main\nimport "github.com/gofiber/fiber/v2"\n'
                        'func main() { app := fiber.New(); app.Get("/users/:id", getUser); c.Get("key") }\n',
            "chi.go": 'package main\nimport "github.com/go-chi/chi/v5"\n'
                      'func main() { r := chi.NewRouter(); r.Delete("/orders/{id}", deleteOrder) }\n',
            "std.go": 'package main\nimport "net/http"\n'
                      'func main() { mux := http.NewServeMux(); mux.HandleFunc("GET /items/{id}", getItem) }\n',
            "gorilla.go": 'package main\nimport "github.com/gorilla/mux"\n'
                          'func main() { r := mux.NewRouter(); r.HandleFunc("/invoices/{id}", showInvoice).Methods("GET", "PUT") }\n',
        })
        got = self.route_set(routes)
        self.assertIn(("go-fiber", "GET", "/users/:id"), got)
        self.assertIn(("go-chi", "DELETE", "/orders/{id}"), got)
        self.assertIn(("go-nethttp", "GET", "/items/{id}"), got)
        gorilla = [r for r in routes if r["path"] == "/invoices/{id}"]
        self.assertEqual(len(gorilla), 1)
        self.assertEqual(gorilla[0]["method"], ["GET", "PUT"])
        self.assertEqual(len(routes), 4, "single-argument Get() calls are not routes")

    def test_axum_qualified_and_chained_handlers(self) -> None:
        routes, _ = self.scan({"src/main.rs": '''use axum::{routing::get, Router};
fn app() -> Router {
    Router::new()
        .route("/users/:id", get(handlers::show_user))
        .route("/orders/{id}", get(show_order).delete(remove_order))
}
'''})
        got = {(r["method"][0], r["path"], r["handler"]["symbol"]) for r in routes}
        self.assertEqual(got, {("GET", "/users/:id", "handlers::show_user"),
                               ("GET", "/orders/{id}", "show_order"),
                               ("DELETE", "/orders/{id}", "remove_order")})

    # --- High: injection false negatives ----------------------------------------------
    def test_go_sprintf_verb_v_and_q(self) -> None:
        _, inj = self.scan({"db.go": '''package db
func F(id string) {
    q := fmt.Sprintf("SELECT * FROM t WHERE id = %v", id)
    q2 := fmt.Sprintf("SELECT * FROM t WHERE name = %q", id)
}
'''})
        self.assertTrue({3, 4} <= self.flagged_lines(inj))

    def test_sqlx_query_with_borrowed_variable(self) -> None:
        _, inj = self.scan({"src/db.rs": '''use sqlx;
async fn f(pool: &PgPool, id: &str) {
    let sql = build_sql(id);
    sqlx::query(&sql).execute(pool).await;
    sqlx::query_as::<_, User>(&sql).fetch_one(pool).await;
}
'''})
        raw = {i["line"] for i in inj if i["rule"] == "raw-api-variable"}
        self.assertEqual(raw, {4, 5})

    # --- Medium: wrong output ----------------------------------------------------------
    def test_go_stack_label_ignores_gin_substring(self) -> None:
        routes, _ = self.scan({"main.go": '''package main
import "github.com/labstack/echo/v4"
// login handler with origin check
func main() { e := echo.New(); e.GET("/users/:id", getUser) }
'''})
        self.assertEqual([r["stack"] for r in routes], ["go-echo"])

    def test_go_handler_symbol_with_middleware(self) -> None:
        routes, _ = self.scan({
            "echo.go": 'package main\nimport "github.com/labstack/echo/v4"\n'
                       'func main() { e.GET("/users/:id", getUser, middleware.JWT([]byte("k"))) }\n',
            "gin.go": 'package main\nimport "github.com/gin-gonic/gin"\n'
                      'func main() { r.POST("/accounts", auth.Required(), h.Create) }\n',
        })
        got = {r["path"]: r["handler"]["symbol"] for r in routes}
        self.assertEqual(got, {"/users/:id": "getUser", "/accounts": "h.Create"})

    def test_guard_hint_lines_are_absolute(self) -> None:
        routes, _ = self.scan({
            "src/main.rs": 'use axum::Router;\n\n\nlet layer = require_login();\n'
                           'let app = Router::new().route("/me", get(me));\n',
            "main.go": 'package main\nimport "github.com/gin-gonic/gin"\n\n\n'
                       'r.Use(RequireLogin())\nr.GET("/me", me)\n',
        })
        lines = {r["handler"]["file"]: [g["line"] for g in r["guard_hints"]] for r in routes}
        self.assertEqual(lines["src/main.rs"], [4])
        self.assertEqual(lines["main.go"], [5])

    def test_rocket_routes_labeled_and_attribute_args(self) -> None:
        routes, _ = self.scan({"src/main.rs": '''#[macro_use] extern crate rocket;
#[get("/user/<id>", rank = 2)]
fn user(id: u32) -> String { id.to_string() }
#[post("/user", data = "<form>")]
#[allow(unused)]
pub async fn create(form: Form<User>) {}
#[launch] fn rocket() -> _ { rocket::build() }
'''})
        got = {(r["stack"], r["method"][0], r["path"], r["handler"]["symbol"]) for r in routes}
        self.assertEqual(got, {("rust-rocket", "GET", "/user/<id>", "user"),
                               ("rust-rocket", "POST", "/user", "create")})
        user = next(r for r in routes if r["path"] == "/user/<id>")
        self.assertIn("id", [p["name"] for p in user["id_params"]])

    def test_actix_attribute_with_extra_args(self) -> None:
        routes, _ = self.scan({"src/main.rs": '''use actix_web::{get, web};
#[get("/a/{id}", wrap = "Auth")]
async fn h(path: web::Path<u32>) -> String { "x".into() }
'''})
        self.assertEqual(self.route_set(routes), {("rust-actix", "GET", "/a/{id}")})

    def test_rust_plain_literal_braces_not_interpolation(self) -> None:
        _, inj = self.scan({"src/db.rs": '''use sqlx;
fn a(id: &str) {
    let s = "SELECT * FROM t WHERE x = {placeholder}";
    let q = format!(
        "SELECT * FROM t WHERE id = {id}"
    );
    let label = format!("{}", id);
    let t = "SELECT * FROM t WHERE y = {other}";
}
'''})
        lines = self.flagged_lines(inj)
        self.assertNotIn(3, lines)
        self.assertIn(5, lines)
        self.assertNotIn(8, lines, "a closed format!() on an earlier line does not cover this literal")

    def test_deref_assignment_not_treated_as_comment(self) -> None:
        _, inj = self.scan({"db.go": '''package db
/*
 * SELECT * FROM t WHERE id = ' + id
 */
func F(q *string, id string) {
    *q = "SELECT * FROM t WHERE id = '" + id + "'"
}
'''})
        lines = self.flagged_lines(inj)
        self.assertIn(6, lines)
        self.assertNotIn(3, lines)


if __name__ == "__main__":
    unittest.main()
