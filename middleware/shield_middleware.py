"""
Pure ASGI Shield Middleware.
Handles:
- Per-Session sandbox resolution (from X-Session-Id header or storm_session cookie)
- Exempt path bypassing
- Client identity resolution (API Key registry fallback to IP, namespaced by session)
- Adaptive Storm Gate & Global upstream admission cap (per session)
- Limiter strategy execution (Token Bucket / Sliding Window / Leaky Bucket per session)
- Queue shaper awaiting
- Graceful degradation (Stale-While-Revalidate per session)
- De facto and RFC 9110 rate limit headers
- Telemetry & status code latency / request log recording (per session)
- Cookie injection for new/refreshed sessions
"""

import os
import time
import math
import random
import json
import asyncio
from typing import Dict, Any, Optional, Tuple, Callable
from starlette.types import ASGIApp, Scope, Receive, Send

from config import (
    DEFAULT_DEFENSE_CONFIG,
    TierMultiplier,
    DEMO_KEY_REGISTRY,
    ENDPOINT_COST_MAP,
    CACHEABLE_ENDPOINTS,
    is_exempt_path
)
from storage.base import BaseStorage
from limiters.base import RateLimiterStrategy, Decision
from session_manager import SESSION_MANAGER, SessionState


class ShieldMiddleware:
    """
    Pure ASGI middleware for high-performance non-blocking rate limiting and protection.
    Resolves request to its isolated SessionState sandbox.
    Does NOT inherit from BaseHTTPMiddleware.
    """

    def __init__(self, app: ASGIApp, store: Optional[BaseStorage] = None):
        self.app = app
        self.store = store

    def _resolve_identity_and_tier(self, headers: Dict[str, str], client_ip: str) -> Tuple[str, str]:
        """
        Resolve client identity and tier.
        Order:
        1. X-API-Key if in DEMO_KEY_REGISTRY.
        2. Otherwise fallback to client IP with FREE tier.
        Unknown/random keys NEVER create separate buckets; they share the IP bucket.
        """
        raw_key = headers.get("x-api-key")
        if raw_key and raw_key in DEMO_KEY_REGISTRY:
            tier = DEMO_KEY_REGISTRY[raw_key]
            return f"key:{raw_key}", tier

        # Unknown key or no key: fallback to IP bucket
        return f"ip:{client_ip}", "FREE"

    def _extract_client_ip(self, scope: Scope, headers: Dict[str, str]) -> str:
        """
        Extract client IP honoring X-Forwarded-For if configured and trusted.
        """
        client = scope.get("client")
        socket_ip = client[0] if client else "127.0.0.1"

        # Check if trusted proxy or Vercel environment
        is_vercel = os.getenv("VERCEL") == "1"
        is_local = (
            socket_ip in ("127.0.0.1", "::1", "localhost")
            or socket_ip.startswith("10.")
            or socket_ip.startswith("192.168.")
            or socket_ip.startswith("172.")
        )
        if is_vercel or is_local:
            xff = headers.get("x-forwarded-for")
            if xff:
                left_ip = xff.split(",")[0].strip()
                if left_ip:
                    return left_ip

        return socket_ip

    def _extract_session_id(self, headers: Dict[str, str]) -> Optional[str]:
        """
        Extract session ID from X-Session-Id header or storm_session cookie.
        """
        # 1. Header (used by Simulator, API clients, tests)
        hdr_id = headers.get("x-session-id")
        if hdr_id:
            return hdr_id.strip()

        # 2. Cookie (used by browser)
        cookie_hdr = headers.get("cookie", "")
        if cookie_hdr:
            for part in cookie_hdr.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    if k.strip() == "storm_session":
                        return v.strip()
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET").upper()
        req_start_time = time.time()

        # Parse request headers into lower-case dict
        headers: Dict[str, str] = {}
        for raw_k, raw_v in scope.get("headers", []):
            try:
                headers[raw_k.decode("latin1").lower()] = raw_v.decode("latin1")
            except Exception:
                pass

        sim_class = headers.get("x-sim-class", "none")
        client_ip = self._extract_client_ip(scope, headers)
        requested_sid = self._extract_session_id(headers)

        # Resolve or create isolated session sandbox
        session_state, is_new_session = await SESSION_MANAGER.get_or_create_session(
            requested_id=requested_sid,
            client_ip=client_ip,
            default_config=DEFAULT_DEFENSE_CONFIG
        )

        # Store session in scope for downstream endpoints
        scope["session_id"] = session_state.session_id
        scope["session_state"] = session_state
        scope["is_new_session"] = is_new_session

        cfg = session_state.config

        # Helper to inject session cookie on response start
        cookie_to_set = None
        if is_new_session or not headers.get("cookie") or "storm_session=" not in headers.get("cookie", ""):
            is_https = scope.get("scheme") == "https" or headers.get("x-forwarded-proto") == "https"
            secure_flag = "; Secure" if is_https else ""
            cookie_to_set = (
                f"storm_session={session_state.session_id}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400{secure_flag}"
            ).encode("latin1")

        # 1. Exempt path check: never throttled
        if is_exempt_path(path):
            async def _exempt_send(message: Dict[str, Any]):
                if message["type"] == "http.response.start":
                    raw_hdrs = list(message.get("headers", []))
                    if cookie_to_set:
                        raw_hdrs.append((b"set-cookie", cookie_to_set))
                    raw_hdrs.append((b"x-session-id", session_state.session_id.encode("latin1")))
                    message["headers"] = raw_hdrs
                await send(message)

            await self.app(scope, receive, _exempt_send)
            return

        # 2. Extract Identity & Tier
        raw_identity, tier = self._resolve_identity_and_tier(headers, client_ip)
        session_scoped_identity = f"{session_state.session_id}:{raw_identity}"

        endpoint_key = f"{method} {path}"
        endpoint_cost = ENDPOINT_COST_MAP.get(endpoint_key, 1)

        # 3. Check Master Shield switch
        if not cfg.shield_enabled:
            # Shield OFF: forward untouched, record metrics & request log
            async def _send_unshielded(message: Dict[str, Any]):
                if message["type"] == "http.response.start":
                    latency_ms = (time.time() - req_start_time) * 1000.0
                    status_code = message.get("status", 200)
                    raw_hdrs = list(message.get("headers", []))
                    if cookie_to_set:
                        raw_hdrs.append((b"set-cookie", cookie_to_set))
                    raw_hdrs.append((b"x-session-id", session_state.session_id.encode("latin1")))
                    message["headers"] = raw_hdrs

                    resp_h_map = {k.decode("latin1"): v.decode("latin1") for k, v in raw_hdrs}

                    session_state.metrics.record_request(
                        status="accepted" if status_code < 400 else "blocked",
                        latency_ms=latency_ms,
                        identity=raw_identity,
                        sim_class=sim_class,
                        status_code=status_code,
                        method=method,
                        path=path,
                        tier=tier,
                        cost=endpoint_cost,
                        reason="shield_disabled",
                        retry_after_s=0,
                        response_headers=resp_h_map
                    )
                await send(message)

            await self.app(scope, receive, _send_unshielded)
            return

        # 4. Storm Detection check (isolated per session)
        is_storm_mode = session_state.metrics.evaluate_storm_mode(
            enabled=cfg.storm_mode_enabled,
            rps_threshold=cfg.storm_rps_threshold,
            ip_threshold=cfg.storm_ip_threshold
        )

        # 5. Global Upstream Admission Cap Gate (per session)
        global_cap = cfg.max_upstream_rps
        global_cost = 1.0
        global_allowed, _, _ = await session_state.store.token_bucket_consume(
            key=f"session:{session_state.session_id}:global_cap",
            capacity=global_cap,
            refill_rate=global_cap,
            cost=global_cost
        )

        if not global_allowed:
            # Global admission cap exceeded: allow priority tiers, throttle lower tiers
            if tier not in ("ENTERPRISE", "PRO"):
                await self._handle_throttle(
                    scope=scope,
                    receive=receive,
                    send=send,
                    method=method,
                    path=path,
                    identity=raw_identity,
                    tier=tier,
                    endpoint_cost=endpoint_cost,
                    sim_class=sim_class,
                    decision=Decision(
                        allowed=False,
                        queued_delay_ms=0.0,
                        limit=global_cap,
                        remaining=0.0,
                        reset_after_ms=1000.0,
                        retry_after_ms=1000.0,
                        reason="GLOBAL_UPSTREAM_CAP_EXCEEDED"
                    ),
                    req_start_time=req_start_time,
                    session_state=session_state,
                    cookie_to_set=cookie_to_set
                )
                return

        # 6. Limiter Strategy & Tier Multipliers
        multiplier = getattr(TierMultiplier, tier, 1.0)
        eff_capacity = cfg.base_capacity * multiplier
        eff_rate = cfg.base_refill_rate * multiplier

        if is_storm_mode and tier == "FREE":
            eff_capacity = max(1.0, eff_capacity * cfg.storm_tighten_factor)
            eff_rate = max(0.1, eff_rate * cfg.storm_tighten_factor)

        if cfg.algorithm == "sliding_window":
            limiter = session_state.sw_limiter
        elif cfg.algorithm == "leaky_bucket":
            limiter = session_state.lb_limiter
        else:
            limiter = session_state.tb_limiter

        decision = await limiter.check(
            identity=session_scoped_identity,
            endpoint_cost=endpoint_cost,
            capacity=eff_capacity,
            rate=eff_rate,
            window_seconds=cfg.window_seconds
        )

        # 7. Decision Routing: ALLOW / QUEUED / DENY
        if decision.allowed:
            if decision.queued_delay_ms > 0:
                delay_sec = decision.queued_delay_ms / 1000.0
                await asyncio.sleep(delay_sec)
                status_metric = "queued"
                reason_metric = "queue_shaper"
            else:
                status_metric = "accepted"
                reason_metric = "allowed"

            await self._forward_and_respond(
                scope=scope,
                receive=receive,
                send=send,
                method=method,
                path=path,
                identity=raw_identity,
                tier=tier,
                endpoint_cost=endpoint_cost,
                sim_class=sim_class,
                decision=decision,
                status_metric=status_metric,
                reason_metric=reason_metric,
                req_start_time=req_start_time,
                session_state=session_state,
                cookie_to_set=cookie_to_set
            )
        else:
            await self._handle_throttle(
                scope=scope,
                receive=receive,
                send=send,
                method=method,
                path=path,
                identity=raw_identity,
                tier=tier,
                endpoint_cost=endpoint_cost,
                sim_class=sim_class,
                decision=decision,
                req_start_time=req_start_time,
                session_state=session_state,
                cookie_to_set=cookie_to_set
            )

    async def _forward_and_respond(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        method: str,
        path: str,
        identity: str,
        tier: str,
        endpoint_cost: int,
        sim_class: str,
        decision: Decision,
        status_metric: str,
        reason_metric: str,
        req_start_time: float,
        session_state: SessionState,
        cookie_to_set: Optional[bytes]
    ) -> None:
        """
        Forward request to upstream app, add rate limit headers, and capture read responses for session cache.
        """
        endpoint_key = f"{method} {path}"
        is_cacheable = (endpoint_key in CACHEABLE_ENDPOINTS) and (method in ("GET", "HEAD"))
        captured_chunks: list[bytes] = []
        captured_status = 200
        captured_headers: dict[str, str] = {}

        async def _intercept_send(message: Dict[str, Any]):
            nonlocal captured_status
            if message["type"] == "http.response.start":
                captured_status = message.get("status", 200)
                raw_hdrs = list(message.get("headers", []))

                limit_hdr = str(int(decision.limit)).encode("latin1")
                rem_hdr = str(max(0, int(decision.remaining))).encode("latin1")
                reset_sec = max(1, int(math.ceil(decision.reset_after_ms / 1000.0)))
                reset_hdr = str(reset_sec).encode("latin1")

                raw_hdrs.append((b"x-ratelimit-limit", limit_hdr))
                raw_hdrs.append((b"x-ratelimit-remaining", rem_hdr))
                raw_hdrs.append((b"x-ratelimit-reset", reset_hdr))
                raw_hdrs.append((b"x-session-id", session_state.session_id.encode("latin1")))
                if cookie_to_set:
                    raw_hdrs.append((b"set-cookie", cookie_to_set))

                message["headers"] = raw_hdrs

                for k, v in raw_hdrs:
                    captured_headers[k.decode("latin1")] = v.decode("latin1")

                latency_ms = (time.time() - req_start_time) * 1000.0
                session_state.metrics.record_request(
                    status=status_metric,
                    latency_ms=latency_ms,
                    identity=identity,
                    sim_class=sim_class,
                    status_code=captured_status,
                    method=method,
                    path=path,
                    tier=tier,
                    cost=endpoint_cost,
                    reason=reason_metric,
                    retry_after_s=0,
                    response_headers=captured_headers
                )

            elif message["type"] == "http.response.body" and is_cacheable:
                body_chunk = message.get("body", b"")
                if body_chunk:
                    captured_chunks.append(body_chunk)

            await send(message)

        await self.app(scope, receive, _intercept_send)

        # Populate session cache if read endpoint was successful
        if is_cacheable and captured_status == 200:
            query = scope.get("query_string", b"").decode("latin1")
            cache_key = session_state.cache.build_key(method, path, query)
            full_body = b"".join(captured_chunks)
            if full_body:
                await session_state.cache.set(
                    key=cache_key,
                    status_code=captured_status,
                    headers=captured_headers,
                    body=full_body
                )

    async def _handle_throttle(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        method: str,
        path: str,
        identity: str,
        tier: str,
        endpoint_cost: int,
        sim_class: str,
        decision: Decision,
        req_start_time: float,
        session_state: SessionState,
        cookie_to_set: Optional[bytes]
    ) -> None:
        """
        Handle throttled requests:
        - Check if cacheable read and degradation_mode is on -> serve cached fallback (status 200).
        - If write or cache miss -> return status 429 with jittered Retry-After.
        """
        endpoint_key = f"{method} {path}"
        cfg = session_state.config
        is_read_cacheable = (
            cfg.degradation_mode
            and (endpoint_key in CACHEABLE_ENDPOINTS)
            and (method in ("GET", "HEAD"))
        )

        if is_read_cacheable:
            query = scope.get("query_string", b"").decode("latin1")
            cache_key = session_state.cache.build_key(method, path, query)
            entry, state = await session_state.cache.get(cache_key)

            if entry is not None:
                # Stale-While-Revalidate: serve cached entry with status 200
                latency_ms = (time.time() - req_start_time) * 1000.0

                response_headers = [
                    (b"content-type", b"application/json"),
                    (b"x-degraded-mode", b"Cached-Fallback"),
                    (b"age", str(entry.age).encode("latin1")),
                    (b"x-ratelimit-limit", str(int(decision.limit)).encode("latin1")),
                    (b"x-ratelimit-remaining", b"0"),
                    (b"x-ratelimit-reset", str(max(1, int(math.ceil(decision.reset_after_ms / 1000.0)))).encode("latin1")),
                    (b"x-session-id", session_state.session_id.encode("latin1")),
                ]
                if cookie_to_set:
                    response_headers.append((b"set-cookie", cookie_to_set))

                header_map = {k.decode("latin1"): v.decode("latin1") for k, v in response_headers}

                session_state.metrics.record_request(
                    status="degraded",
                    latency_ms=latency_ms,
                    identity=identity,
                    sim_class=sim_class,
                    status_code=200,
                    method=method,
                    path=path,
                    tier=tier,
                    cost=endpoint_cost,
                    reason="cached_fallback",
                    retry_after_s=0,
                    response_headers=header_map
                )

                await send({
                    "type": "http.response.start",
                    "status": 200,
                    "headers": response_headers
                })
                await send({
                    "type": "http.response.body",
                    "body": entry.body,
                    "more_body": False
                })
                return

        # Write endpoint, degradation disabled, or cache miss -> 429 Too Many Requests
        latency_ms = (time.time() - req_start_time) * 1000.0

        base_retry_sec = max(1.0, decision.retry_after_ms / 1000.0)
        jitter = random.uniform(0.0, cfg.retry_after_jitter_max)
        retry_after_int = int(math.ceil(base_retry_sec + jitter))
        reset_sec = max(1, int(math.ceil(decision.reset_after_ms / 1000.0)))

        resp_body = json.dumps({
            "error": "Too Many Requests",
            "message": "Rate limit exceeded. Storm shield active.",
            "reason": decision.reason,
            "retry_after_seconds": retry_after_int,
            "degraded_mode": "Cache-Miss" if is_read_cacheable else "Disabled",
            "session_id": session_state.session_id
        }).encode("utf-8")

        headers_429 = [
            (b"content-type", b"application/json"),
            (b"retry-after", str(retry_after_int).encode("latin1")),
            (b"x-ratelimit-limit", str(int(decision.limit)).encode("latin1")),
            (b"x-ratelimit-remaining", b"0"),
            (b"x-ratelimit-reset", str(reset_sec).encode("latin1")),
            (b"x-session-id", session_state.session_id.encode("latin1")),
        ]
        if cookie_to_set:
            headers_429.append((b"set-cookie", cookie_to_set))
        if is_read_cacheable:
            headers_429.append((b"x-degraded-mode", b"Cache-Miss"))

        header_map_429 = {k.decode("latin1"): v.decode("latin1") for k, v in headers_429}

        session_state.metrics.record_request(
            status="blocked",
            latency_ms=latency_ms,
            identity=identity,
            sim_class=sim_class,
            status_code=429,
            method=method,
            path=path,
            tier=tier,
            cost=endpoint_cost,
            reason=decision.reason.lower() if decision.reason else "rate_limit_exceeded",
            retry_after_s=retry_after_int,
            response_headers=header_map_429
        )

        await send({
            "type": "http.response.start",
            "status": 429,
            "headers": headers_429
        })
        await send({
            "type": "http.response.body",
            "body": resp_body,
            "more_body": False
        })
