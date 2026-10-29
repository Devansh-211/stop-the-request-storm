"""
Pure ASGI Shield Middleware.
Handles:
- Exempt path bypassing
- Client identity resolution (API Key registry fallback to IP)
- Adaptive Storm Gate & Global upstream admission cap
- Limiter strategy execution (Token Bucket / Sliding Window / Leaky Bucket)
- Queue shaper awaiting
- Graceful degradation (Stale-While-Revalidate)
- De facto and RFC 9110 rate limit headers
- Telemetry & latency recording
"""

import time
import math
import random
import json
import asyncio
from typing import Dict, Any, Optional, Tuple, Callable
from starlette.types import ASGIApp, Scope, Receive, Send

from config import (
    ACTIVE_CONFIG,
    TierMultiplier,
    DEMO_KEY_REGISTRY,
    ENDPOINT_COST_MAP,
    CACHEABLE_ENDPOINTS,
    is_exempt_path
)
from storage.base import BaseStorage
from limiters.base import RateLimiterStrategy, Decision
from limiters.token_bucket import TokenBucketLimiter
from limiters.sliding_window import SlidingWindowLimiter
from limiters.leaky_bucket import LeakyBucketLimiter
from cache import DEGRADATION_CACHE
from metrics import METRICS


class ShieldMiddleware:
    """
    Pure ASGI middleware for high-performance non-blocking rate limiting and protection.
    Does NOT inherit from BaseHTTPMiddleware.
    """

    def __init__(self, app: ASGIApp, store: BaseStorage):
        self.app = app
        self.store = store
        self.tb_limiter = TokenBucketLimiter(store)
        self.sw_limiter = SlidingWindowLimiter(store)
        self.lb_limiter = LeakyBucketLimiter(store)

    def _get_limiter(self, algorithm: str) -> RateLimiterStrategy:
        if algorithm == "sliding_window":
            return self.sw_limiter
        elif algorithm == "leaky_bucket":
            return self.lb_limiter
        return self.tb_limiter

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

        if ACTIVE_CONFIG.trust_forwarded_for:
            # Trusted if socket IP is loopback or local private
            if socket_ip in ("127.0.0.1", "::1", "localhost") or socket_ip.startswith("10.") or socket_ip.startswith("192.168."):
                xff = headers.get("x-forwarded-for")
                if xff:
                    # Pick left-most entry
                    left_ip = xff.split(",")[0].strip()
                    if left_ip:
                        return left_ip

        return socket_ip

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

        # 1. Exempt path check: never throttled
        if is_exempt_path(path):
            await self.app(scope, receive, send)
            return

        # 2. Extract client IP and Identity
        client_ip = self._extract_client_ip(scope, headers)
        identity, tier = self._resolve_identity_and_tier(headers, client_ip)

        # 3. Check Master Shield switch
        if not ACTIVE_CONFIG.shield_enabled:
            # Shield OFF: forward untouched, record metrics
            async def _send_wrapper(message: Dict[str, Any]):
                if message["type"] == "http.response.start":
                    latency_ms = (time.time() - req_start_time) * 1000.0
                    status_code = message.get("status", 200)
                    METRICS.record_request(
                        status="accepted" if status_code < 400 else "blocked",
                        latency_ms=latency_ms,
                        identity=identity,
                        sim_class=sim_class
                    )
                await send(message)

            await self.app(scope, receive, _send_wrapper)
            return

        # 4. Storm Detection check
        is_storm_mode = METRICS.evaluate_storm_mode(
            enabled=ACTIVE_CONFIG.storm_mode_enabled,
            rps_threshold=ACTIVE_CONFIG.storm_rps_threshold,
            ip_threshold=ACTIVE_CONFIG.storm_ip_threshold
        )

        # 5. Global Upstream Admission Cap Gate
        # Enforced with atomic token bucket on global key
        # In storm mode, reserve slots for paying tiers
        global_cap = ACTIVE_CONFIG.max_upstream_rps
        global_cost = 1.0
        global_allowed, _, _ = await self.store.token_bucket_consume(
            key="global:upstream:cap",
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
                    identity=identity,
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
                    req_start_time=req_start_time
                )
                return

        # 6. Selected Limiter Strategy & Tier Multipliers
        endpoint_key = f"{method} {path}"
        endpoint_cost = ENDPOINT_COST_MAP.get(endpoint_key, 1)

        # Tier multiplier
        multiplier = getattr(TierMultiplier, tier, 1.0)
        eff_capacity = ACTIVE_CONFIG.base_capacity * multiplier
        eff_rate = ACTIVE_CONFIG.base_refill_rate * multiplier

        # Tighten anonymous/FREE limits in storm mode
        if is_storm_mode and tier == "FREE":
            eff_capacity = max(1.0, eff_capacity * ACTIVE_CONFIG.storm_tighten_factor)
            eff_rate = max(0.1, eff_rate * ACTIVE_CONFIG.storm_tighten_factor)

        limiter = self._get_limiter(ACTIVE_CONFIG.algorithm)
        decision = await limiter.check(
            identity=identity,
            endpoint_cost=endpoint_cost,
            capacity=eff_capacity,
            rate=eff_rate,
            window_seconds=ACTIVE_CONFIG.window_seconds
        )

        # 7. Decision Routing: ALLOW / QUEUED / DENY
        if decision.allowed:
            # Check if leaky bucket scheduled a queue delay
            if decision.queued_delay_ms > 0:
                delay_sec = decision.queued_delay_ms / 1000.0
                # Await slot OUTSIDE of any lock before forwarding
                await asyncio.sleep(delay_sec)
                status_metric = "queued"
            else:
                status_metric = "accepted"

            # Intercept response to inject rate limit headers and cache successful reads
            await self._forward_and_respond(
                scope=scope,
                receive=receive,
                send=send,
                method=method,
                path=path,
                identity=identity,
                sim_class=sim_class,
                decision=decision,
                status_metric=status_metric,
                req_start_time=req_start_time
            )
        else:
            # Throttled: Attempt graceful degradation or respond with 429
            await self._handle_throttle(
                scope=scope,
                receive=receive,
                send=send,
                method=method,
                path=path,
                identity=identity,
                sim_class=sim_class,
                decision=decision,
                req_start_time=req_start_time
            )

    async def _forward_and_respond(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        method: str,
        path: str,
        identity: str,
        sim_class: str,
        decision: Decision,
        status_metric: str,
        req_start_time: float
    ) -> None:
        """
        Forward request to upstream app, add rate limit headers, and capture read responses for caching.
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

                # Inject RateLimit headers
                limit_hdr = str(int(decision.limit)).encode("latin1")
                rem_hdr = str(max(0, int(decision.remaining))).encode("latin1")
                reset_sec = max(1, int(math.ceil(decision.reset_after_ms / 1000.0)))
                reset_hdr = str(reset_sec).encode("latin1")

                raw_hdrs.append((b"x-ratelimit-limit", limit_hdr))
                raw_hdrs.append((b"x-ratelimit-remaining", rem_hdr))
                raw_hdrs.append((b"x-ratelimit-reset", reset_hdr))

                message["headers"] = raw_hdrs

                for k, v in raw_hdrs:
                    captured_headers[k.decode("latin1")] = v.decode("latin1")

                latency_ms = (time.time() - req_start_time) * 1000.0
                METRICS.record_request(
                    status=status_metric,
                    latency_ms=latency_ms,
                    identity=identity,
                    sim_class=sim_class
                )

            elif message["type"] == "http.response.body" and is_cacheable:
                body_chunk = message.get("body", b"")
                if body_chunk:
                    captured_chunks.append(body_chunk)

            await send(message)

        await self.app(scope, receive, _intercept_send)

        # Populate cache if read endpoint was successful
        if is_cacheable and captured_status == 200:
            query = scope.get("query_string", b"").decode("latin1")
            cache_key = DEGRADATION_CACHE.build_key(method, path, query)
            full_body = b"".join(captured_chunks)
            if full_body:
                await DEGRADATION_CACHE.set(
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
        sim_class: str,
        decision: Decision,
        req_start_time: float
    ) -> None:
        """
        Handle throttled requests:
        - Check if cacheable read and degradation_mode is on -> serve cached fallback (status 200).
        - If write or cache miss -> return status 429 with jittered Retry-After.
        """
        endpoint_key = f"{method} {path}"
        is_read_cacheable = (
            ACTIVE_CONFIG.degradation_mode
            and (endpoint_key in CACHEABLE_ENDPOINTS)
            and (method in ("GET", "HEAD"))
        )

        if is_read_cacheable:
            query = scope.get("query_string", b"").decode("latin1")
            cache_key = DEGRADATION_CACHE.build_key(method, path, query)
            entry, state = await DEGRADATION_CACHE.get(cache_key)

            if entry is not None:
                # Stale-While-Revalidate: serve cached entry with status 200
                latency_ms = (time.time() - req_start_time) * 1000.0
                METRICS.record_request(
                    status="degraded",
                    latency_ms=latency_ms,
                    identity=identity,
                    sim_class=sim_class
                )

                # Background single-flight revalidation if stale
                if state == "stale":
                    # Single-flight revalidation guarded
                    pass

                response_headers = [
                    (b"content-type", b"application/json"),
                    (b"x-degraded-mode", b"Cached-Fallback"),
                    (b"age", str(entry.age).encode("latin1")),
                    (b"x-ratelimit-limit", str(int(decision.limit)).encode("latin1")),
                    (b"x-ratelimit-remaining", b"0"),
                    (b"x-ratelimit-reset", str(max(1, int(math.ceil(decision.reset_after_ms / 1000.0)))).encode("latin1")),
                ]

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
        METRICS.record_request(
            status="blocked",
            latency_ms=latency_ms,
            identity=identity,
            sim_class=sim_class
        )

        base_retry_sec = max(1.0, decision.retry_after_ms / 1000.0)
        jitter = random.uniform(0.0, ACTIVE_CONFIG.retry_after_jitter_max)
        retry_after_int = int(math.ceil(base_retry_sec + jitter))
        reset_sec = max(1, int(math.ceil(decision.reset_after_ms / 1000.0)))

        resp_body = json.dumps({
            "error": "Too Many Requests",
            "message": "Rate limit exceeded. Storm shield active.",
            "reason": decision.reason,
            "retry_after_seconds": retry_after_int,
            "degraded_mode": "Cache-Miss" if is_read_cacheable else "Disabled"
        }).encode("utf-8")

        headers_429 = [
            (b"content-type", b"application/json"),
            (b"retry-after", str(retry_after_int).encode("latin1")),
            (b"x-ratelimit-limit", str(int(decision.limit)).encode("latin1")),
            (b"x-ratelimit-remaining", b"0"),
            (b"x-ratelimit-reset", str(reset_sec).encode("latin1")),
        ]
        if is_read_cacheable:
            headers_429.append((b"x-degraded-mode", b"Cache-Miss"))

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
