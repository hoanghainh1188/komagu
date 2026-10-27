# Rust Knowledge Profile (Actix-web, Axum, Rocket, SQLx, Diesel)

## Stack Identification
- **Markers:** `Cargo.toml`, `Cargo.lock`, `src/main.rs`, `src/lib.rs`.
- **Frameworks:**
  - `actix-web`: `use actix_web::{get, post, web, App, HttpResponse, HttpServer}`
  - `axum`: `use axum::{routing::{get, post}, Router, extract::{Path, Query, Json}}`
  - `rocket`: `use rocket::{get, post, routes}`
- **Data Access:**
  - `sqlx`: `sqlx::query!`, `sqlx::query_as!`, `sqlx::query`
  - `diesel`: `use diesel::prelude::*`, `diesel::insert_into`
  - `sea-orm`: `use sea_orm::*`

## BOLA / IDOR Patterns
- **Vulnerable:** Handlers extracting resource IDs from path/query/JSON without validating tenant or ownership context:
  ```rust
  // Vulnerable Axum handler
  async fn get_order(Path(id): Path<i64>) -> Result<Json<Order>, StatusCode> {
      let order = sqlx::query_as!(Order, "SELECT * FROM orders WHERE id = $1", id)
          .fetch_one(&pool).await?;
      Ok(Json(order))
  }
  ```
- **Protected:** Handlers extracting authenticated user/tenant identity from Request Extensions / Extractors and filtering by owner:
  ```rust
  // Protected with ownership check
  async fn get_order(
      Extension(current_user): Extension<UserClaims>,
      Path(id): Path<i64>
  ) -> Result<Json<Order>, StatusCode> {
      let order = sqlx::query_as!(
          Order,
          "SELECT * FROM orders WHERE id = $1 AND tenant_id = $2",
          id, current_user.tenant_id
      ).fetch_optional(&pool).await?;
      order.map(Json).ok_or(StatusCode::NOT_FOUND) // Invariant: 404 Not Found
  }
  ```

## SQL Injection Patterns
- **Safe:** Compile-time verified macros with bind parameters:
  - `sqlx::query!("SELECT * FROM users WHERE id = $1", user_id)`
  - `query.bind(user_id)`
- **Vulnerable:** Dynamic string formatting / concatenation:
  - `format!("SELECT * FROM users WHERE name = '{}'", user_input)`
  - `sqlx::query(&format!("SELECT ... {}", tainted))`
