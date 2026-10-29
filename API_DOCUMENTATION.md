# 📚 API Reference Documentation

### Project: API Under Attack — Stop the Request Storm (Team 9)
**Gateway Version:** 2.0.0 (Per-Session Sandboxing & Pure ASGI Rate Limiter)

---

## 📑 Overview & Organization

All endpoints in the gateway are divided into four main architectural groups:

1. **[Core Protected Upstream APIs](#1-core-protected-upstream-apis)**: The application service endpoints shielded by the multi-algorithm rate limiters, tiered multipliers, storm detector, and graceful degradation fallback.
2. **[Session Sandbox APIs](#2-session-sandbox-apis)**: Endpoints managing cryptographically isolated user sandboxes (`SessionState`).
3. **[Control & Defense Tuning APIs](#3-control--defense-tuning-apis)**: Real-time control plane endpoints used by the dashboard and orchestrators to update limiter algorithms, capacities, storm triggers, and view telemetry metrics.
4. **[Attack Simulation APIs](#4-attack-simulation-apis)**: Endpoints triggering loopback traffic storms (normal, DDoS, resource exhaustion, and distributed botnet waves).
5. **[Real-Time WebSocket Feed](#5-real-time-websocket-feed)**: Continuous live telemetry stream (500ms intervals) for dashboard charts and meters.

---

## 1. Core Protected Upstream APIs

These endpoints simulate real backend production services and are actively intercepted, metered, and shielded by `ShieldMiddleware`.

### Common Rate Limiting Headers Returned
On every request (allowed, queued, or degraded), the gateway injects standard and RFC 9110 rate limit headers:
- `x-ratelimit-limit`: Maximum request capacity allowed in the current window.
- `x-ratelimit-remaining`: Remaining request tokens/slots available.
- `x-ratelimit-reset`: Integer seconds until current limit quota completely resets.
- `x-session-id`: ID of the sandbox session handling the request.
- `retry-after`: *(On HTTP 429 only)* Integer seconds with random anti-stampede jitter the client must wait.
- `x-degraded-mode`: *(On HTTP 200 Cached-Fallback or HTTP 429 Cache-Miss)* Indicates whether Stale-While-Revalidate served the response.

---

### `GET /api/ping`
- **Description:** Lightweight health and latency probe endpoint.
- **Cost:** `1 token`
- **Degradation Eligible:** Yes (read-only GET)
- **Request Headers:**
  - `X-Session-Id` *(optional)*: Session ID (or resolved from `storm_session` cookie).
  - `X-API-Key` *(optional)*: Tier demo key (`free-demo-key`, `pro-demo-key`, `ent-demo-key`).
- **Response (200 OK):**
  ```json
  {
    "status": "pong",
    "timestamp": 1793300000.123
  }
  ```

---

### `GET /api/data`
- **Description:** Mock database / analytics read endpoint. Primary target for DDoS attack simulations.
- **Cost:** `2 tokens`
- **Degradation Eligible:** Yes (read-only GET). Under heavy storm or throttling, returns HTTP 200 with `x-degraded-mode: Cached-Fallback` and cached data instead of failing.
- **Request Headers:**
  - `X-Forwarded-For` *(optional)*: Spoofed or origin client IP.
  - `X-API-Key` *(optional)*: Demo tier key.
- **Response (200 OK):**
  ```json
  {
    "items": [
      {"id": 1, "name": "Telemetry Node Alpha", "status": "active"},
      {"id": 2, "name": "Gateway Shaper Bravo", "status": "nominal"}
    ],
    "count": 2,
    "timestamp": 1793300000.456
  }
  ```

---

### `POST /api/heavy-compute`
- **Description:** Resource-intensive compute endpoint simulating hashing, cryptographic verification, or heavy rendering.
- **Cost:** `5 tokens`
- **Degradation Eligible:** **No**. State-modifying/write/compute operations are never degraded; throttled requests strictly receive HTTP 429 Too Many Requests.
- **Request Headers:**
  - `Content-Type: application/json`
- **Request Body:**
  ```json
  {
    "task": "heavy_stress_payload",
    "iterations": 5000
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "status": "computed",
    "iterations": 5000,
    "result_digest": "3a7b9c...f8e",
    "duration_ms": 15.2
  }
  ```
- **Response (429 Too Many Requests):**
  ```json
  {
    "error": "Too Many Requests",
    "message": "Rate limit exceeded. Storm shield active.",
    "reason": "TOKEN_BUCKET_EXHAUSTED",
    "retry_after_seconds": 2,
    "degraded_mode": "Disabled",
    "session_id": "vX8r-9Q2_kLm3N7p"
  }
  ```

---

## 2. Session Sandbox APIs

Endpoints for managing isolated user defense sandboxes.

### `GET /session/current`
- **Description:** Retrieves the active session ID, deployment target, and store backend for the caller.
- **Exempt Path:** Yes (never throttled).
- **Request Headers / Cookies:**
  - `X-Session-Id` header OR `storm_session` cookie.
- **Response (200 OK):**
  ```json
  {
    "session_id": "vX8r-9Q2_kLm3N7p",
    "is_new": false,
    "deploy_target": "server",
    "store": "memory"
  }
  ```

---

### `POST /session/new`
- **Description:** Explicitly discards the caller's old session state and creates a brand-new, clean sandbox.
- **Exempt Path:** Yes (never throttled).
- **Sets Cookie:** `storm_session=<new_token>; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`
- **Response (200 OK):**
  ```json
  {
    "status": "created",
    "session_id": "p0Zk7_wR82mN-q1A",
    "message": "Fresh isolated session sandbox created"
  }
  ```

---

## 3. Control & Defense Tuning APIs

All control endpoints automatically operate on the caller's isolated session sandbox.

### `GET /control/state`
- **Description:** Returns the live defense configuration and engine status for the caller's session.
- **Response (200 OK):**
  ```json
  {
    "session_id": "vX8r-9Q2_kLm3N7p",
    "config": {
      "shield_enabled": true,
      "algorithm": "token_bucket",
      "base_capacity": 10.0,
      "base_refill_rate": 1.0,
      "window_seconds": 10.0,
      "max_upstream_rps": 60.0,
      "storm_mode_enabled": true,
      "storm_rps_threshold": 100.0,
      "storm_ip_threshold": 50,
      "storm_tighten_factor": 0.5,
      "degradation_mode": true,
      "retry_after_jitter_max": 1.5,
      "upstream_concurrency": 16,
      "trust_forwarded_for": true
    },
    "store_backend": "memory",
    "deploy_target": "server"
  }
  ```

---

### `POST /control/config`
- **Description:** Live hot-reload update of the defense configuration for the caller's session (no server restart required).
- **Request Body (Partial or Full `DefenseConfig`):**
  ```json
  {
    "shield_enabled": true,
    "algorithm": "leaky_bucket",
    "base_capacity": 20.0,
    "base_refill_rate": 2.5,
    "max_upstream_rps": 100.0,
    "degradation_mode": true,
    "storm_mode_enabled": true
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "status": "updated",
    "session_id": "vX8r-9Q2_kLm3N7p",
    "config": { ... }
  }
  ```

---

### `GET /control/metrics`
- **Description:** Telemetry snapshot endpoint (used for polling fallback on Vercel or when WebSockets disconnect).
- **Response (200 OK):**
  ```json
  {
    "timestamp": 1793300050.123,
    "session_id": "vX8r-9Q2_kLm3N7p",
    "store_backend": "memory",
    "deploy_target": "server",
    "current_rps": 120,
    "p50_latency_ms": 2.4,
    "p95_latency_ms": 8.7,
    "legit_success_pct": 98.5,
    "attack_block_pct": 99.2,
    "active_buckets": 14,
    "storm_mode": false,
    "simulation_active": true,
    "simulation_pattern": "ddos",
    "top_blocked": [
      {"identity": "198.51.100.14", "count": 240},
      {"identity": "198.51.100.15", "count": 215}
    ],
    "series": {
      "timestamps": [1793299930, "...", 1793300050],
      "accepted": [0, 0, 15, "..."],
      "degraded": [0, 0, 105, "..."],
      "queued": [0, 0, 0, "..."],
      "blocked": [0, 0, 20, "..."]
    }
  }
  ```

---

### `GET /control/admin/sessions`
- **Description:** Server-wide administrative overview listing all active sandboxes, ages, idle durations, and simulator states.
- **Authorization:** Requires `Authorization: Bearer <ADMIN_TOKEN>` (or local loopback IP if `ADMIN_TOKEN` is unset).
- **Response (200 OK):**
  ```json
  {
    "total_sessions": 3,
    "max_sessions": 200,
    "active_simulations": 1,
    "sessions": [
      {
        "session_id": "vX8r-9Q2_kLm3N7p",
        "created_at": 1793299400.0,
        "age_seconds": 650.0,
        "idle_seconds": 2.5,
        "algorithm": "token_bucket",
        "shield_enabled": true,
        "simulator_active": true,
        "simulator_pattern": "ddos"
      }
    ]
  }
  ```

---

## 4. Attack Simulation APIs

Endpoints to trigger controlled traffic patterns inside the caller's session.

### `POST /control/simulate/{pattern}`
- **Description:** Launches real loopback traffic through the full ASGI middleware stack, targeting the caller's session.
- **Path Parameters:**
  - `pattern`: One of `normal`, `ddos`, `exhaustion`, `botnet`
- **Query Parameters:**
  - `duration` *(optional, int)*: Duration in seconds (5 to 60s, default 20s).
- **Supported Patterns:**
  | Pattern | Target RPS | Endpoint | Concurrency / Identities |
  | :--- | :--- | :--- | :--- |
  | `normal` | 5 RPS | `/api/ping`, `/api/data` | Mixed legitimate traffic with demo API keys |
  | `ddos` | 150 RPS | `/api/data` | Burst flood from 1–3 fixed spoofed IPs |
  | `exhaustion` | 40 RPS | `/api/heavy-compute` | Stress payload triggering max compute tokens |
  | `botnet` | 200 RPS | `/api/ping`, `/api/data` | 500+ distinct spoofed IPs + invalid API keys |
- **Response (200 OK):**
  ```json
  {
    "status": "simulation_started",
    "session_id": "vX8r-9Q2_kLm3N7p",
    "pattern": "ddos",
    "duration_seconds": 20
  }
  ```

---

### `POST /control/simulate/stop`
- **Description:** Immediately terminates any active background traffic simulation task for the caller's session.
- **Response (200 OK):**
  ```json
  {
    "status": "stopped",
    "session_id": "vX8r-9Q2_kLm3N7p",
    "message": "Simulation halted"
  }
  ```

---

## 5. Real-Time WebSocket Feed

### `WS /ws/telemetry`
- **Description:** Real-time push stream broadcasting full telemetry snapshots every 500ms to connected dashboard war rooms.
- **Session Identification:**
  - Query parameter: `/ws/telemetry?session_id=<token>`
  - OR `storm_session` cookie in the opening handshake headers.
- **Message Payload:**
  - Emits JSON payloads identical to `/control/metrics` every 500ms.
- **Fallback:**
  - When hosted on serverless environments without WebSocket support (like Vercel) or on network disconnect, the frontend automatically falls back to 500ms HTTP polling on `/control/metrics`.

---

## 6. System & Infrastructure APIs

### `GET /health`
- **Description:** Infrastructure liveness probe.
- **Response (200 OK):**
  ```json
  {
    "status": "healthy",
    "store": "memory",
    "deploy_target": "server",
    "active_sessions": 4
  }
  ```

### `GET /`
- **Description:** Serves the Cyberpunk War Room Dashboard (`static/index.html`). Sets the initial `storm_session` cookie if not already present.
