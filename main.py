"""
FastAPI Application Entrypoint:
- Lifespan store detection (Redis 300ms ping -> fallback to Memory store)
- Pure ASGI middleware wrapping
- Static file serving (HTML dashboard)
- Control API endpoints
- Real-time WebSocket telemetry feed
- Background TTL/LRU hygiene sweeper
"""

import os
import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Response, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
import redis.asyncio as aioredis

from config import ACTIVE_CONFIG, DefenseConfig
from storage.base import BaseStorage
from storage.memory_store import MemoryStorage
from storage.redis_store import RedisStorage
from middleware.shield_middleware import ShieldMiddleware
from metrics import METRICS
from cache import DEGRADATION_CACHE
from upstream import router as upstream_router, close_httpx_client, update_upstream_semaphore_concurrency

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("shield")

# Global state instances
STATE_STORE: Optional[BaseStorage] = None
STORE_STATUS_NAME = "memory"
BACKGROUND_TASKS: list[asyncio.Task] = []


async def init_storage() -> BaseStorage:
    """
    Attempt to connect to Redis with a strict 300ms timeout.
    On failure or error, fail open to the async-safe in-memory store.
    """
    global STORE_STATUS_NAME
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    try:
        client = aioredis.from_url(redis_url, socket_timeout=0.3, socket_connect_timeout=0.3)
        await asyncio.wait_for(client.ping(), timeout=0.3)
        logger.info(f"Connected to Redis store at {redis_url}")
        STORE_STATUS_NAME = "redis"
        return RedisStorage(client)
    except Exception as exc:
        logger.warning(f"Redis ping failed or unavailable ({exc}). Using memory-fallback store.")
        STORE_STATUS_NAME = "memory-fallback"
        return MemoryStorage()


async def memory_hygiene_sweeper(store: BaseStorage):
    """
    Background worker running every 5 seconds to evict expired state, idle locks,
    and stale degradation cache items.
    """
    while True:
        try:
            await asyncio.sleep(5.0)
            if store is not None:
                await store.sweep_expired()
            await DEGRADATION_CACHE.sweep_expired()
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error(f"Error in memory hygiene sweeper: {exc}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global STATE_STORE, BACKGROUND_TASKS
    # Initialize storage engine
    STATE_STORE = await init_storage()

    # Launch background memory sweeper
    sweeper_task = asyncio.create_task(memory_hygiene_sweeper(STATE_STORE))
    BACKGROUND_TASKS.append(sweeper_task)

    logger.info("War Room Shield online and ready.")
    yield

    # Teardown
    for task in BACKGROUND_TASKS:
        task.cancel()
    if STATE_STORE is not None:
        await STATE_STORE.close()
    await close_httpx_client()
    logger.info("War Room Shield stopped.")


app = FastAPI(
    title="Team 9 - API Under Attack — Stop the Request Storm",
    description="Intelligent Multi-Algorithm Rate Limiter & Real-Time War Room Dashboard",
    lifespan=lifespan
)

# Mount upstream endpoints
app.include_router(upstream_router)


# Health check endpoint
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "shield": "active" if ACTIVE_CONFIG.shield_enabled else "disabled",
        "store": STORE_STATUS_NAME,
        "algorithm": ACTIVE_CONFIG.algorithm
    }


# Static Dashboard Serving
os.makedirs("static", exist_ok=True)


@app.get("/")
async def serve_index():
    index_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path, media_type="text/html")
    return JSONResponse({"status": "Dashboard loading..."})


app.mount("/static", StaticFiles(directory="static"), name="static")


# -------------------------------------------------------------
# CONTROL API (Dashboard & Administrative Orchestration)
# -------------------------------------------------------------

def verify_control_access(request: Request):
    """Loopback check, VERCEL environment allowance, or ADMIN_TOKEN verification."""
    admin_token = os.getenv("ADMIN_TOKEN")
    if admin_token:
        auth_header = request.headers.get("authorization", "")
        if auth_header != f"Bearer {admin_token}":
            raise HTTPException(status_code=403, detail="Invalid admin authorization token")
        return True

    # If running on Vercel serverless demo without explicit ADMIN_TOKEN, allow control UI access
    if os.getenv("VERCEL") == "1":
        return True

    client = request.client
    client_ip = client.host if client else "127.0.0.1"
    if client_ip not in ("127.0.0.1", "::1", "localhost", "testclient"):
        raise HTTPException(status_code=403, detail="Control access limited to loopback")
    return True


@app.get("/control/state", dependencies=[Depends(verify_control_access)])
async def get_control_state():
    """Retrieve active defense configuration and server status."""
    return {
        "config": ACTIVE_CONFIG.model_dump(),
        "store_backend": STORE_STATUS_NAME
    }


@app.post("/control/config", dependencies=[Depends(verify_control_access)])
async def update_control_config(new_config: DefenseConfig):
    """Live update defense configuration without service restart."""
    global ACTIVE_CONFIG
    for field, val in new_config.model_dump().items():
        setattr(ACTIVE_CONFIG, field, val)

    update_upstream_semaphore_concurrency(ACTIVE_CONFIG.upstream_concurrency)
    return {
        "status": "updated",
        "config": ACTIVE_CONFIG.model_dump()
    }


@app.get("/control/metrics", dependencies=[Depends(verify_control_access)])
async def get_metrics_snapshot():
    """Fallback polling endpoint for telemetry."""
    active_keys = 0
    if isinstance(STATE_STORE, MemoryStorage):
        active_keys = len(STATE_STORE._tb_data) + len(STATE_STORE._sw_data) + len(STATE_STORE._lb_data)
    return METRICS.get_snapshot(store_backend=STORE_STATUS_NAME, active_buckets_count=active_keys)


# Active simulator background task handle
_ACTIVE_SIMULATOR_TASK: Optional[asyncio.Task] = None


@app.post("/control/simulate/{pattern}", dependencies=[Depends(verify_control_access)])
async def trigger_simulation(pattern: str, duration: int = 20):
    """
    Launch real loopback attack simulation traffic:
    pattern: normal | ddos | exhaustion | botnet
    """
    global _ACTIVE_SIMULATOR_TASK
    from simulator.storm_generator import run_simulation_pattern

    if _ACTIVE_SIMULATOR_TASK and not _ACTIVE_SIMULATOR_TASK.done():
        _ACTIVE_SIMULATOR_TASK.cancel()
        try:
            await _ACTIVE_SIMULATOR_TASK
        except (asyncio.CancelledError, Exception):
            pass

    _ACTIVE_SIMULATOR_TASK = asyncio.create_task(
        run_simulation_pattern(pattern=pattern, duration_seconds=duration)
    )

    return {
        "status": "simulation_started",
        "pattern": pattern,
        "duration_seconds": duration
    }


@app.post("/control/simulate/stop", dependencies=[Depends(verify_control_access)])
async def stop_simulation():
    """Halt any active background traffic simulation."""
    global _ACTIVE_SIMULATOR_TASK
    if _ACTIVE_SIMULATOR_TASK and not _ACTIVE_SIMULATOR_TASK.done():
        _ACTIVE_SIMULATOR_TASK.cancel()
        try:
            await _ACTIVE_SIMULATOR_TASK
        except (asyncio.CancelledError, Exception):
            pass
        _ACTIVE_SIMULATOR_TASK = None
        return {"status": "stopped", "message": "Simulation halted"}
    return {"status": "idle", "message": "No active simulation"}


# -------------------------------------------------------------
# WEBSOCKET REAL-TIME WAR ROOM FEED
# -------------------------------------------------------------

@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    """
    Streams live telemetry snapshot every 500ms to connected dashboard clients.
    """
    await websocket.accept()
    try:
        while True:
            active_keys = 0
            if isinstance(STATE_STORE, MemoryStorage):
                active_keys = len(STATE_STORE._tb_data) + len(STATE_STORE._sw_data) + len(STATE_STORE._lb_data)

            snapshot = METRICS.get_snapshot(
                store_backend=STORE_STATUS_NAME,
                active_buckets_count=active_keys
            )
            # Attach live config and simulation state
            snapshot["config"] = ACTIVE_CONFIG.model_dump()
            snapshot["simulation_active"] = (
                _ACTIVE_SIMULATOR_TASK is not None and not _ACTIVE_SIMULATOR_TASK.done()
            )

            await websocket.send_json(snapshot)
            await asyncio.sleep(0.500)
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    except Exception as exc:
        logger.debug(f"WebSocket client disconnected: {exc}")


# -------------------------------------------------------------
# ATTACH PURE ASGI SHIELD MIDDLEWARE
# -------------------------------------------------------------
# Persistent single middleware instance referencing the shared storage engine
_SHARED_SHIELD_MIDDLEWARE: Optional[ShieldMiddleware] = None


class RuntimeShieldMiddleware:
    def __init__(self, asgi_app):
        self.asgi_app = asgi_app

    async def __call__(self, scope, receive, send):
        global STATE_STORE, _SHARED_SHIELD_MIDDLEWARE
        if _SHARED_SHIELD_MIDDLEWARE is None:
            if STATE_STORE is None:
                STATE_STORE = MemoryStorage()
            _SHARED_SHIELD_MIDDLEWARE = ShieldMiddleware(self.asgi_app, STATE_STORE)
        elif _SHARED_SHIELD_MIDDLEWARE.store is not STATE_STORE and STATE_STORE is not None:
            _SHARED_SHIELD_MIDDLEWARE.store = STATE_STORE
            _SHARED_SHIELD_MIDDLEWARE.tb_limiter.store = STATE_STORE
            _SHARED_SHIELD_MIDDLEWARE.sw_limiter.store = STATE_STORE
            _SHARED_SHIELD_MIDDLEWARE.lb_limiter.store = STATE_STORE

        await _SHARED_SHIELD_MIDDLEWARE(scope, receive, send)


# Wrap app with the pure ASGI middleware
app = RuntimeShieldMiddleware(app)

