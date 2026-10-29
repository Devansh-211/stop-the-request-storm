# Team 9 - API Under Attack — Stop the Request Storm

An **Intelligent Multi-Algorithm Rate Limiter, Pure ASGI Reverse Proxy Middleware, and Real-Time War Room Dashboard** engineered to protect upstream APIs from request floods, brute-force storms, botnet waves, and resource exhaustion while keeping legitimate users served.

---

## ⚡ Key Highlights & Architecture

### 1. Composable Limiter Engine (Strategy Pattern)
All algorithms consume from the configured endpoint cost map:
- `GET /api/ping`: Cost **1** (lightweight ping, 20ms)
- `GET /api/data`: Cost **2** (standard query, 60ms, cacheable)
- `POST /api/heavy-compute`: Cost **5** (compute workload, 400ms, non-cacheable write)

Algorithms:
- **Token Bucket** ([`limiters/token_bucket.py`](file:///a:/Cybersec/limiters/token_bucket.py)): Bursts up to `capacity` with atomic lazy-refill at `refill_rate` tokens/sec.
- **Sliding Window Counter** ([`limiters/sliding_window.py`](file:///a:/Cybersec/limiters/sliding_window.py)): Two sub-windows weighted counter (`prev_count * (1 - elapsed/window) + curr_count`) preventing boundary bursts.
- **Leaky Bucket / Queue Shaper** ([`limiters/leaky_bucket.py`](file:///a:/Cybersec/limiters/leaky_bucket.py)): True traffic shaper with virtual scheduling (`wait = max(0, next_free - now)`). Requests within max queue delay are admitted as queued and awaited outside locks before proxying; requests exceeding queue capacity are dropped as overflows.

### 2. Dual-Store Architecture (Zero Hard Dependencies)
- **Redis 6.2+ Store** ([`storage/redis_store.py`](file:///a:/Cybersec/storage/redis_store.py)): Atomic Lua scripts registered via `register_script`/EVALSHA using `redis.call('TIME')` as the clock (avoiding client clock drift) and `PEXPIRE` for key TTL.
- **Async-Safe In-Memory Fallback** ([`storage/memory_store.py`](file:///a:/Cybersec/storage/memory_store.py)): Uses `asyncio.Lock` per key (never held across I/O or sleep), `time.monotonic()`, TTL cleanup, and LRU bounded eviction (`max_keys = 100,000`) to prevent memory leaks under massive random-IP storms.
- **Fail-Open Resilience**: On startup, Redis is probed with a 300ms timeout. If unavailable or if Redis fails mid-run, the gateway fails open to the memory fallback store, logs once, and surfaces `store: "memory-fallback"` in live telemetry.

### 3. Pure ASGI Shield Middleware ([`middleware/shield_middleware.py`](file:///a:/Cybersec/middleware/shield_middleware.py))
- **No `BaseHTTPMiddleware` overhead**: High-performance, pure ASGI implementation.
- **Exempt Paths**: `/`, `/health`, `/static/*`, `/ws/*`, `/control/*` are never throttled, ensuring the dashboard and control planes remain responsive during attacks.
- **Tiered Identity Hierarchy**:
  1. `X-API-Key` in the key registry (`free-demo-key` $\times 1$, `pro-demo-key` $\times 5$, `ent-demo-key` $\times 20$).
  2. Client IP (default tier: `FREE`).
  3. **Unknown/Random API Keys**: Automatically collapse into the client's IP bucket, preventing botnets from exhausting server memory with random keys.
- **IP Extraction & Spoofing Defense**: Honors `X-Forwarded-For` only when `trust_forwarded_for=true` AND the socket peer is a trusted loopback/private IP; extracts the left-most client IP.
- **Standardized Headers**: Injects `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and RFC 9110 `Retry-After` (integer seconds with randomized jitter) on 429 responses.

### 4. Adaptive Storm Defense
- Rolling 5s global RPS and distinct blocked identities detector.
- `storm_mode` activates when rolling RPS > `storm_rps_threshold` (100 RPS) or distinct blocked identities > `storm_ip_threshold` (50).
- Scales anonymous and FREE limits by `storm_tighten_factor` (0.5), while preserving reserved capacity for PRO and ENTERPRISE tiers.
- Enforces a global upstream admission token bucket (`max_upstream_rps = 60`).

### 5. Graceful Degradation (Stale-While-Revalidate) ([`cache.py`](file:///a:/Cybersec/cache.py))
- Throttled read endpoints (`GET /api/data`, `GET /api/ping`) return `200 OK` with `X-Degraded-Mode: Cached-Fallback` and `Age` header.
- Background revalidation is single-flight per key and throttled to at most once per 5s to prevent revalidation task storms.
- Write/compute endpoints (`POST /api/heavy-compute`) are never degraded; they strictly receive `429 Too Many Requests`.
- Graceful degradation can be toggled on/off in real-time from the dashboard.

### 6. Real-Time Dark Cyberpunk War Room Dashboard ([`static/index.html`](file:///a:/Cybersec/static/index.html))
- Live WebSocket push every 500ms (`/ws/telemetry`) with fallback polling (`GET /control/metrics`).
- **Left Panel (Simulator)**: Trigger Normal (5 RPS), DDoS Burst Flood (150 RPS), Heavy Endpoint Exhaustion (40 RPS), Botnet Wave (200 RPS), or Stop All.
- **Center Panel (Telemetry)**: Chart.js 120s rolling multi-series chart (Accepted in Green, Degraded in Cyan, Queued in Yellow, Blocked in Red), stat cards (Current RPS, p50/p95 latency, Legit Success %, Attack Block %, Active Buckets), and Top 5 Blocked Identities.
- **Right Panel (Defense Controller)**: Live algorithm switching (Token Bucket / Sliding Window / Leaky Bucket), sliders for capacity, refill rate, and upstream admission cap (debounced 150ms), toggles for Graceful Degradation, Adaptive Storm Mode, and the Master Shield Switch (turns red when OFF).

---

## 📂 Project Directory Structure

```text
a:/Cybersec/
├── main.py                     # FastAPI app, lifespan, WebSocket feed, control API, and ASGI wiring
├── config.py                   # Dynamic DefenseConfig, tier multipliers, demo keys, costs & cache maps
├── metrics.py                  # 120s ring buffer, p50/p95 percentiles, and telemetry snapshot generator
├── upstream.py                 # Mock upstream API routes, concurrency semaphore, and real proxy forwarder
├── cache.py                    # SWR fallback cache with single-flight deduplicated revalidation
├── storage/
│   ├── __init__.py
│   ├── base.py                 # Abstract storage interface
│   ├── memory_store.py         # Async-safe memory store with per-key locks, LRU cap, and TTL sweeper
│   └── redis_store.py          # Redis store with atomic Lua scripts (Redis TIME clock & PEXPIRE)
├── limiters/
│   ├── __init__.py
│   ├── base.py                 # RateLimiterStrategy abstract base & Decision dataclass
│   ├── token_bucket.py         # Token Bucket limiter implementation
│   ├── sliding_window.py       # Sliding Window Counter limiter implementation
│   └── leaky_bucket.py         # Leaky Bucket / Queue Shaper limiter implementation
├── middleware/
│   ├── __init__.py
│   └── shield_middleware.py    # Pure ASGI Shield Middleware
├── simulator/
│   ├── __init__.py
│   └── storm_generator.py      # Async drift-free loopback traffic simulator & CLI
├── static/
│   └── index.html              # Dark Cyberpunk War Room Dashboard (Tailwind + Chart.js)
├── tests/
│   ├── test_token_bucket.py    # Burst, refill, and variable cost tests
│   ├── test_sliding_window.py  # Standard limit and boundary burst prevention tests
│   ├── test_leaky_bucket.py    # Outflow scheduling and queue overflow tests
│   ├── test_concurrency.py     # 500 concurrent coroutine race condition tests
│   ├── test_memory_store.py    # LRU 100k cap and sweep_expired hygiene tests
│   ├── test_middleware.py      # Header injection, unknown key fallback, and SWR tests
│   └── test_redis_store.py     # Redis tests (auto-skips if Redis is offline)
├── requirements.txt            # Pinned dependencies
└── README.md                   # System documentation & judge demo script
```

---

## 🚀 Quickstart & Setup

### 1. Requirements & Dependencies
Python 3.11+ is recommended.
```bash
pip install -r requirements.txt
```

### 2. Start the Gateway & War Room
```bash
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```
Open your browser to: **[http://127.0.0.1:8000/](http://127.0.0.1:8000/)** to access the War Room Console.

### 3. Verify Health Check
```bash
curl http://127.0.0.1:8000/health
```
Expected output:
```json
{
  "status": "healthy",
  "shield": "active",
  "store": "memory-fallback",
  "algorithm": "token_bucket"
}
```

---

## 🧪 Running the Automated Test Suite

Execute the full suite of unit, concurrency, and integration tests:
```bash
python -m pytest -v
```

All 14 unit and integration tests pass with 100% compliance:
- Token Bucket burst & refill mechanics
- Sliding Window boundary burst protection
- Leaky Bucket queue delay scheduling and overflow dropping
- 500-request high concurrency race-condition prevention
- Memory store LRU cap & TTL eviction
- Exempt path preservation & Stale-While-Revalidate caching

---

## ⚔️ Demonstration Script for Judges

Follow this sequence to evaluate the shield's defenses under live attack:

### Step 1: Establish Legitimate Baseline Traffic
1. In the **Attack Simulator** panel, click **"Normal Traffic"** (5 RPS).
2. Look at the **Real-Time Request Flow** chart:
   - Requests show in green (**Accepted**).
   - p95 latency stays low (~20ms to 60ms).
   - Legitimate user success is **100%**.

### Step 2: Mitigate a DDoS Burst Flood (Graceful Degradation vs 429 Blocks)
1. In the **Attack Simulator** panel, click **"DDoS Burst Flood"** (150 RPS hitting `GET /api/data`).
2. With **Graceful Degradation (SWR)** enabled:
   - Throttled requests are served instantly from the degradation cache in cyan (**Degraded: 200 Cached-Fallback**).
   - The upstream API remains completely protected while users continue receiving data.
3. Uncheck **"Graceful Degradation (SWR)"** in the right-hand **Defense Controller**:
   - The shield immediately transitions throttled requests to raw red blocks (**429 Too Many Requests**).
   - Notice the Top Blocked list recording the attacking IP addresses.

### Step 3: Block Heavy Endpoint Exhaustion Attacks
1. Click **"Heavy Exhaustion"** (40 RPS hitting `POST /api/heavy-compute` at 5 tokens/request).
2. Because write/compute endpoints are non-cacheable, the shield strictly denies excess requests with **`429 Too Many Requests`**.
3. The red line surges on the chart, and attack block metrics show high mitigation efficiency.

### Step 4: Prove Why the Shield is Critical (Disable Master Shield)
1. While the **"Heavy Exhaustion"** attack is active, click the **"SHIELD ACTIVE"** button to turn it **"SHIELD DISABLED (DANGER)"**.
2. **Watch the p95 latency gauge immediately spike towards 400ms+** as unshielded requests flood the upstream concurrency semaphore and exhaust resources.
3. Click **"SHIELD DISABLED"** to re-arm the shield:
   - The p95 latency drops back down to normal within seconds.
   - Legitimate traffic flows freely once again.

---

## ⚙️ Control API Reference

- `GET /control/state`: Returns the active defense parameters and backend storage engine.
- `POST /control/config`: Live-updates defense settings (algorithms, capacities, toggles) without server restarts.
- `GET /control/metrics`: Snapshot of rolling request counts, p50/p95 latencies, and top blocked IPs.
- `POST /control/simulate/{pattern}`: Starts loopback attack simulator (`normal`, `ddos`, `exhaustion`, `botnet`).
- `POST /control/simulate/stop`: Halts active traffic simulations.
- `GET /ws/telemetry`: WebSocket streaming live telemetry snapshots every 500ms.
