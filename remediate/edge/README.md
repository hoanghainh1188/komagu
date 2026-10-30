# Komagu Edge Gateway & WAF Protection (D4)

The **Komagu Edge Gateway & WAF** component implements **Layer 1 (Kong Gateway)** and **Layer 2 (OWASP Coraza WAF)** in the 5-layer STRIDE defense model of Boilerplate 1.

It provides immediate, perimeter-level protection for legacy web systems that cannot yet be refactored with application-level authorization (D1) or authentication (D2) libraries.

---

## 1. Architectural Topology

```text
Incoming HTTP Request (Port 8000)
       │
       ▼
┌────────────────────────────────────────────────────────┐
│ Layer 1: Kong API Gateway (DB-less Mode)               │
│ - Per-IP and Per-Token Rate Limiting (HTTP 429)        │
│ - Strict Cross-Origin Resource Sharing (CORS)          │
│ - Distributed Correlation ID Injection (X-Correlation) │
│ - Security Header Sanitization (Strip Server/Latency)  │
└────────────────────────────────────────────────────────┘
       │
       ▼ Internal Reverse Proxy (Port 8080)
┌────────────────────────────────────────────────────────┐
│ Layer 2: OWASP Coraza WAF (Go-native Sidecar)          │
│ - OWASP Core Rule Set v4.0 (Paranoia Level 1)          │
│ - SQL Injection Block (Rules 942xxx -> HTTP 403)       │
│ - Cross-Site Scripting Block (Rules 941xxx -> HTTP 403)│
│ - Path Traversal Block (Rules 930xxx -> HTTP 403)      │
│ - Structured JSON Security Audit Logging               │
└────────────────────────────────────────────────────────┘
       │
       ▼ Sanitized Request (Port 5000)
┌────────────────────────────────────────────────────────┐
│ Layer 3-5: Upstream Backend Application                │
│ (Legacy Monolith, .NET 8, Spring Boot 3)               │
└────────────────────────────────────────────────────────┘
```

---

## 2. Quick Start: Local Orchestration

The complete edge protection stack is pre-configured with Docker Compose:

```bash
cd remediate/edge
docker compose up -d
```

### Services & Endpoints

| Container | Internal Port | Host Port | Role |
|---|---|---|---|
| `komagu-kong-gateway` | `8000`, `8001` | `8000`, `8001` | Edge API Gateway proxy & Admin API |
| `komagu-coraza-waf` | `8080` | None | Pure-Go WAF reverse proxy (OWASP CRS v4) |
| `komagu-mock-backend`| `5000` | None | Upstream echo backend for verification |

---

## 3. Kong Declarative Configuration (decK)

Kong runs in **DB-less mode** (`KONG_DATABASE=off`), eliminating database dependencies. State is declared in `kong/kong.yaml`:

### Applying and Validating State with decK

```bash
cd remediate/edge/kong

# Validate declarative syntax
deck file validate kong.yaml

# Check diff against running gateway
deck gateway diff kong.yaml --kong-addr http://localhost:8001

# Sync configuration to running gateway
deck gateway sync kong.yaml --kong-addr http://localhost:8001
```

### Key Plugins Configured

1. **`rate-limiting`:**
   - Limits: 120 requests/minute, 10 requests/second burst limit.
   - Rejection: Responds with **HTTP 429 Too Many Requests**.
2. **`cors`:**
   - Whitelists verified frontend origins (`http://localhost:3000`, `http://localhost:5173`).
   - Allowed headers: `Authorization`, `Content-Type`, `X-Correlation-ID`, `traceparent`.
3. **`correlation-id`:**
   - Injects `X-Correlation-ID` header if absent; echoes downstream to client.
4. **`response-transformer`:**
   - Strips sensitive upstream headers (`Server`, `X-Kong-Upstream-Latency`, `X-Kong-Proxy-Latency`).

---

## 4. OWASP Coraza WAF Engine

Per [ADR-0003](../../docs/adr/0003-waf-engine-coraza.md), **OWASP Coraza** is selected over ModSecurity for memory safety (100% pure Go) and zero C++ runtime dependencies.

### Rules & Sensitivity
- Configuration: `coraza/coraza.conf`
- Paranoia Level: `1` (balanced security with low false-positive rate)
- Inbound Anomaly Threshold: `5`
- Denial Action: Immediate **HTTP 403 Forbidden** on threshold match.
- Custom Tuning: `coraza/rules/coraza-crs-custom.conf` tuning REST API JSON bodies and explicit injection signatures.

---

## 5. Automated Verification

Run the edge security test suite:

```bash
python3 remediate/edge/tests/test_edge_security.py
```

- When run offline: Validates all declarative configuration invariants.
- When run against a live stack: Executes live HTTP requests to verify legitimate 200 OK traffic, 429 rate limit drops, and 403 WAF blocks on SQLi/XSS payloads.
