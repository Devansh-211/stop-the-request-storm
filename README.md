# 🛡️ API Under Attack — Stop the Request Storm (Team 9)

An enterprise-grade, multi-algorithm rate limiter, adaptive storm shield, and dark cyberpunk War Room dashboard built with pure ASGI FastAPI. 

Every browser session is sandboxed into its own isolated defense environment: each session has its own independent rate-limiting buckets, defense configuration, storm detector, graceful degradation (SWR) cache, and telemetry ring buffers.

---

## ⚡ Key Highlights & Architecture

- **In-Memory Store as Primary Backend:** Default and fully self-contained (`STORE_BACKEND=memory`). Zero external services required. Runs out of the box with zero dependencies on Redis.
- **Optional Redis Plugin:** Redis is a strictly optional plugin (`STORE_BACKEND=redis`). Redis packages are loaded lazily only when requested.
- **Per-Session Sandbox Isolation:**
  - Every visitor gets an isolated `SessionState` keyed by a cryptographically secure token (`secrets.token_urlsafe(16)`).
  - Session ID is communicated via `HttpOnly`, `SameSite=Lax` cookies or `X-Session-Id` headers.
  - User A can turn Shield OFF and simulate a 150 RPS DDoS flood without impacting User B's metrics, buckets, or p95 latencies.
  - Interactive **Session: [ID]** badge and **+ NEW SESSION** button directly on the dashboard.
- **Three Core Limiting Algorithms:**
  1. **Token Bucket:** Classic burst-tolerant continuous refill.
  2. **Sliding Window Counter:** Sub-window weighted approximation preventing boundary burst exploitation.
  3. **Leaky Bucket / Queue Shaper:** Strict smooth outflow spacing with bounded async delay scheduling.
- **Tiered Entitlements:** Built-in demo keys (`free-demo-key` 1x, `pro-demo-key` 5x, `ent-demo-key` 20x) with unknown API key fallback to IP bucket.
- **Adaptive Storm Defense:** Automatically detects high-RPS waves and unique IP floods, tightening anonymous quotas while prioritizing paying tiers.
- **Graceful Degradation:** Stale-While-Revalidate (SWR) cached fallback on cacheable GET reads during traffic spikes, returning 200 Cached-Fallback instead of drops.
- **Abuse Defenses:** Per-IP session creation throttle (10/min), LRU session eviction (cap of 200), and automatic 30s background idle sweepers (15-min timeout) that terminate simulator tasks.

---

## 🚀 Quickstart (Local Run)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```
*(No Redis server required!)*

### 2. Boot Server
> **Note:** The server assumes single worker execution (`--workers 1`) to preserve in-memory state and lock synchronization.
```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --workers 1
```

### 3. Open the War Room Dashboard
Navigate to `http://127.0.0.1:8000/` in your browser.

---

## 🧪 Running Automated Tests

Run the complete test suite with `pytest`:
```bash
python -m pytest -v
```

All 19 tests will execute and pass:
- Unit tests for Token Bucket, Sliding Window, and Leaky Bucket.
- MemoryStore LRU cap (50k IPs) and TTL key sweeping.
- 500-request high concurrency race-condition test.
- Middleware header injection, tiered key lookup, and graceful degradation fallback.
- **Session Isolation Tests:**
  - Multi-user isolation (Session A under DDoS flood vs Session B pristine).
  - Malformed & forged session ID protection.
  - Idle session expiration and background simulator cancellation.
  - 5,000-session flood resistance with LRU bounds.
- Redis store test automatically skips when Redis is not configured.

---

## 🌐 Deployment Targets

### Target 1: Persistent Host (Recommended — Render / Railway / Fly.io)
Full support for continuous WebSockets, persistent in-memory sessions, and background loopback traffic simulators.

- **Procfile** included:
  ```text
  web: uvicorn main:app --host 0.0.0.0 --port $PORT --workers 1
  ```
- **Dockerfile** included for containerized deployments (Fly.io / Railway / Google Cloud Run).

### Target 2: Serverless (Vercel)
Configured via `vercel.json` and `api/index.py`:
- `DEPLOY_TARGET=vercel` is auto-detected.
- **Session-Reset Caveat:** In serverless architectures, stateless execution containers can spin down or recycle. If a user holds a cookie from an instance that was recycled, the server silently creates a fresh session and displays a non-intrusive *"Session restarted on serverless instance"* notification rather than failing.
- High-frequency 500ms polling activates automatically when WebSockets are unavailable.

---

## 👥 Two-Browser Session Isolation Demo

To verify that every session is isolated:
1. Open `http://127.0.0.1:8000/` in **Browser A** (e.g. Chrome). Notice the badge in the top-right: `SANDBOX: abc123...`.
2. Open `http://127.0.0.1:8000/` in **Browser B** (or an Incognito window). Notice a completely different session token.
3. In **Browser A**:
   - Click the green **SHIELD ACTIVE** button to turn Shield **OFF (DANGER)**.
   - Click **DDoS Burst Flood (150 RPS)** in the Attack Simulator.
   - Watch Current RPS spike to ~120-150 RPS with accepted request lines soaring.
4. In **Browser B**:
   - Check the dashboard controls. The shield remains **ARMED**.
   - Current RPS remains at `0`, Accepted line is flat, and p95 latency is untouched.
5. In **Browser A**, click **+ NEW SESSION**:
   - A fresh session sandbox is minted instantly with clean telemetry.
