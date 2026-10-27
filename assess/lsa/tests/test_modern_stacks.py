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


if __name__ == "__main__":
    unittest.main()
