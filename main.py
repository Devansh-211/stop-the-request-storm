"""
FastAPI Application Entrypoint:
- In-Memory state store as primary & default backend (STORE_BACKEND=memory)
- Redis is fully optional; lazy-imported only if STORE_BACKEND=redis and REDIS_URL provided
- Per-Session isolated sandboxes via SessionManager
- Pure ASGI middleware wrapping
- Static file serving (HTML dashboard with session badge)
- Session lifecycle endpoints (/session/new, /session/current)
- Control API endpoints operating on the caller's session
- WebSocket telemetry feed (with 500ms polling fallback)
- Background hygiene sweepers (idle sessions & storage keys)
"""

import os
import re
import secrets
import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Response, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from config import DEFAULT_DEFENSE_CONFIG, DefenseConfig
from storage.base import BaseStorage
from storage.memory_store import MemoryStorage
from middleware.shield_middleware import ShieldMiddleware
from session_manager import SESSION_MANAGER, SessionState
from upstream import router as upstream_router, close_httpx_client, update_upstream_semaphore_concurrency

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("shield")

# Deployment Target Detection (server vs vercel)
DEPLOY_TARGET = os.getenv("DEPLOY_TARGET")
if not DEPLOY_TARGET:
    DEPLOY_TARGET = "vercel" if os.getenv("VERCEL") == "1" else "server"

# Store Backend: default to 'memory'. Redis is fully optional plugin.
STORE_BACKEND = os.getenv("STORE_BACKEND", "memory").lower()
GLOBAL_STORE: Optional[BaseStorage] = None
BACKGROUND_TASKS: list[asyncio.Task] = []


async def init_storage() -> BaseStorage:
    """
    Initialize storage engine.
    Default: in-memory store.
    Redis: only imported and connected if STORE_BACKEND=redis.
    """
    global STORE_BACKEND
    if STORE_BACKEND == "redis":
        try:
            import redis.asyncio as aioredis
            from storage.redis_store import RedisStorage
            redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
            client = aioredis.from_url(redis_url, socket_timeout=0.5, socket_connect_timeout=0.5)
            await asyncio.wait_for(client.ping(), timeout=0.5)
            logger.info(f"Connected to optional Redis store at {redis_url}")
            return RedisStorage(client)
        except Exception as exc:
            logger.warning(f"Optional Redis store unavailable ({exc}). Using primary memory store.")
            STORE_BACKEND = "memory"
            return MemoryStorage()

    STORE_BACKEND = "memory"
    return MemoryStorage()


async def background_sweeper_task():
    """
    Periodic hygiene sweeper running every 30 seconds:
    - Purges idle sessions (>15 min) and cancels their simulator tasks
    - Sweeps expired storage keys across active sessions
    """
    while True:
        try:
            await asyncio.sleep(30.0)
            purged_sessions = await SESSION_MANAGER.sweep_idle_sessions()
            if purged_sessions > 0:
                logger.info(f"Sweeper: purged {purged_sessions} idle sessions")

            # Sweep session stores
            for s in list(SESSION_MANAGER._sessions.values()):
                if s.store:
                    await s.store.sweep_expired(idle_seconds=60.0)
                if s.cache:
                    await s.cache.sweep_expired()
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error(f"Error in background sweeper: {exc}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global GLOBAL_STORE, BACKGROUND_TASKS
    # Initialize storage engine
    GLOBAL_STORE = await init_storage()

    # Launch background session & memory sweeper
    sweeper_task = asyncio.create_task(background_sweeper_task())
    BACKGROUND_TASKS.append(sweeper_task)

    logger.info(f"War Room Shield online (deploy_target={DEPLOY_TARGET}, store={STORE_BACKEND}, workers=1).")
    yield

    # Teardown
    for task in BACKGROUND_TASKS:
        task.cancel()
    if GLOBAL_STORE is not None:
        await GLOBAL_STORE.close()
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
        "store": STORE_BACKEND,
        "deploy_target": DEPLOY_TARGET,
        "active_sessions": len(SESSION_MANAGER._sessions)
    }


# Static Dashboard Serving
os.makedirs("static", exist_ok=True)


@app.get("/")
async def serve_index(request: Request):
    index_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path, media_type="text/html")
    return JSONResponse({"status": "Dashboard loading..."})


app.mount("/static", StaticFiles(directory="static"), name="static")


# -------------------------------------------------------------
# SESSION LIFECYCLE API
# -------------------------------------------------------------

def get_current_session(request: Request) -> SessionState:
    """Extract SessionState attached to request scope by ShieldMiddleware."""
    session_state = request.scope.get("session_state")
    if session_state is None:
        # Fallback if accessed directly
        raise HTTPException(status_code=500, detail="Session state not attached to request")
    return session_state


@app.get("/session/current")
async def get_session_info(request: Request, session: SessionState = Depends(get_current_session)):
    """Return current caller's session ID and deployment details."""
    is_new = request.scope.get("is_new_session", False)
    return {
        "session_id": session.session_id,
        "is_new": is_new,
        "deploy_target": DEPLOY_TARGET,
        "store": STORE_BACKEND
    }


@app.post("/session/new")
async def create_new_session(request: Request, response: Response):
    """
    Explicitly discard old session and create a fresh one.
    Sets new session cookie and returns session ID.
    """
    old_id = request.scope.get("session_id")
    if old_id:
        await SESSION_MANAGER.discard_session(old_id)

    client = request.client
    client_ip = client.host if client else "127.0.0.1"
    new_session, _ = await SESSION_MANAGER.get_or_create_session(
        client_ip=client_ip,
        default_config=DEFAULT_DEFENSE_CONFIG
    )

    is_https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(
        key="storm_session",
        value=new_session.session_id,
        httponly=True,
        samesite="lax",
        secure=is_https,
        max_age=86400,
        path="/"
    )
    return {
        "status": "created",
        "session_id": new_session.session_id,
        "message": "Fresh isolated session sandbox created"
    }


# -------------------------------------------------------------
# CONTROL API (Scoped to Caller's Isolated Session Sandbox)
# -------------------------------------------------------------

@app.get("/control/state")
async def get_control_state(session: SessionState = Depends(get_current_session)):
    """Retrieve defense configuration and store status for the caller's session."""
    return {
        "session_id": session.session_id,
        "config": session.config.model_dump(),
        "store_backend": STORE_BACKEND,
        "deploy_target": DEPLOY_TARGET
    }


@app.post("/control/config")
async def update_control_config(
    new_config: DefenseConfig,
    session: SessionState = Depends(get_current_session)
):
    """Live update defense configuration for the caller's session sandbox."""
    for field, val in new_config.model_dump().items():
        setattr(session.config, field, val)

    update_upstream_semaphore_concurrency(session.config.upstream_concurrency)
    return {
        "status": "updated",
        "session_id": session.session_id,
        "config": session.config.model_dump()
    }


@app.get("/control/metrics")
async def get_metrics_snapshot(
    since: Optional[float] = None,
    session: SessionState = Depends(get_current_session)
):
    """Polling endpoint for telemetry and recent request logs of caller's session sandbox."""
    active_keys = 0
    if session.store and isinstance(session.store, MemoryStorage):
        active_keys = len(session.store._tb_data) + len(session.store._sw_data) + len(session.store._lb_data)

    snapshot = session.metrics.get_snapshot(
        store_backend=STORE_BACKEND,
        active_buckets_count=active_keys,
        since_ts=since
    )
    snapshot["session_id"] = session.session_id
    snapshot["deploy_target"] = DEPLOY_TARGET
    snapshot["config"] = session.config.model_dump()
    snapshot["simulation_active"] = (
        session.simulator_task is not None and not session.simulator_task.done()
    )
    snapshot["simulation_pattern"] = session.simulator_pattern
    return snapshot


@app.get("/control/log")
async def get_request_log(
    limit: int = 50,
    status: Optional[int] = None,
    outcome: Optional[str] = None,
    session: SessionState = Depends(get_current_session)
):
    """Filtered request log for caller's isolated session sandbox."""
    records = session.metrics.get_filtered_log(limit=limit, status=status, outcome=outcome)
    return {
        "session_id": session.session_id,
        "count": len(records),
        "requests": records
    }


@app.post("/control/simulate/stop")
async def stop_simulation(session: SessionState = Depends(get_current_session)):
    """Halt any active background traffic simulation for caller's session."""
    was_running = session.simulator_task is not None and not session.simulator_task.done()
    await session.cancel_simulator()
    return {
        "status": "stopped" if was_running else "idle",
        "session_id": session.session_id,
        "message": "Simulation halted" if was_running else "No active simulation"
    }


@app.post("/control/simulate/{pattern}")
async def trigger_simulation(
    pattern: str,
    duration: int = 20,
    session: SessionState = Depends(get_current_session)
):
    """
    Launch real loopback attack simulation traffic scoped strictly to caller's session:
    pattern: normal | ddos | exhaustion | botnet
    """
    if pattern == "stop":
        return await stop_simulation(session=session)

    # Enforce abuse limits
    duration = max(5, min(60, duration))
    if pattern not in ("normal", "ddos", "exhaustion", "botnet"):
        raise HTTPException(status_code=400, detail=f"Invalid simulation pattern: {pattern}")

    # Check concurrent simulator abuse limit
    active_sims = SESSION_MANAGER.count_active_simulations()
    if active_sims >= SESSION_MANAGER.max_concurrent_simulations:
        raise HTTPException(
            status_code=429,
            detail="Server simulation capacity reached. Please wait for active attacks to finish."
        )

    from simulator.storm_generator import run_simulation_pattern

    await session.cancel_simulator()

    session.simulator_pattern = pattern
    session.simulator_task = asyncio.create_task(
        run_simulation_pattern(
            pattern=pattern,
            duration_seconds=duration,
            session_id=session.session_id
        )
    )

    return {
        "status": "simulation_started",
        "session_id": session.session_id,
        "pattern": pattern,
        "duration_seconds": duration
    }


# -------------------------------------------------------------
# GLOBAL ADMIN OVERVIEW (Unlocked with ADMIN_TOKEN)
# -------------------------------------------------------------

@app.get("/control/admin/sessions")
async def admin_get_sessions(request: Request):
    """Global overview of all active sessions across the server."""
    admin_token = os.getenv("ADMIN_TOKEN")
    if not admin_token:
        # If no ADMIN_TOKEN configured, only allow loopback access
        client = request.client
        client_ip = client.host if client else "127.0.0.1"
        if client_ip not in ("127.0.0.1", "::1", "localhost", "testclient"):
            raise HTTPException(
                status_code=403,
                detail="Admin overview requires ADMIN_TOKEN or local loopback connection"
            )
    else:
        auth_header = request.headers.get("authorization", "")
        if auth_header != f"Bearer {admin_token}":
            raise HTTPException(status_code=403, detail="Invalid admin authorization token")

    return SESSION_MANAGER.get_summary()


# -------------------------------------------------------------
# WEBSOCKET REAL-TIME WAR ROOM FEED (Session-Scoped)
# -------------------------------------------------------------

@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    """
    Streams live telemetry snapshot every 500ms for the client's session sandbox.
    Resolves session ID from query param ?session_id= or storm_session cookie.
    """
    await websocket.accept()

    session_id = websocket.query_params.get("session_id")
    if not session_id:
        cookie_hdr = websocket.headers.get("cookie", "")
        for part in cookie_hdr.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k.strip() == "storm_session":
                    session_id = v.strip()
                    break

    session = await SESSION_MANAGER.get_session(session_id)
    if not session:
        # Create a new session if unknown
        session, _ = await SESSION_MANAGER.get_or_create_session(requested_id=session_id)

    try:
        while True:
            session.touch()
            active_keys = 0
            if session.store and isinstance(session.store, MemoryStorage):
                active_keys = len(session.store._tb_data) + len(session.store._sw_data) + len(session.store._lb_data)

            snapshot = session.metrics.get_snapshot(
                store_backend=STORE_BACKEND,
                active_buckets_count=active_keys
            )
            snapshot["session_id"] = session.session_id
            snapshot["deploy_target"] = DEPLOY_TARGET
            snapshot["config"] = session.config.model_dump()
            snapshot["simulation_active"] = (
                session.simulator_task is not None and not session.simulator_task.done()
            )
            snapshot["simulation_pattern"] = session.simulator_pattern

            await websocket.send_json(snapshot)
            await asyncio.sleep(0.500)
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    except Exception as exc:
        logger.debug(f"WebSocket client disconnected: {exc}")


# -------------------------------------------------------------
# ATTACH PURE ASGI SHIELD MIDDLEWARE
# -------------------------------------------------------------

_SHARED_SHIELD_MIDDLEWARE: Optional[ShieldMiddleware] = None


class RuntimeShieldMiddleware:
    def __init__(self, asgi_app):
        self.asgi_app = asgi_app

    async def __call__(self, scope, receive, send):
        global _SHARED_SHIELD_MIDDLEWARE
        if _SHARED_SHIELD_MIDDLEWARE is None:
            _SHARED_SHIELD_MIDDLEWARE = ShieldMiddleware(self.asgi_app)

        # Normalize path when rewritten by Vercel serverless function
        if scope.get("type") == "http":
            path = scope.get("path", "")
            for prefix in ("/api/index.py", "/api/index"):
                if path == prefix:
                    scope["path"] = "/"
                    break
                elif path.startswith(prefix + "/"):
                    scope["path"] = path[len(prefix):]
                    break

        await _SHARED_SHIELD_MIDDLEWARE(scope, receive, send)


# Wrap app with the pure ASGI middleware
app = RuntimeShieldMiddleware(app)
