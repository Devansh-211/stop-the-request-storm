"""
Mock upstream service and capacity model.
Provides endpoints:
- GET /api/ping (20ms simulated latency, cost 1)
- GET /api/data (60ms simulated latency, cost 2, cacheable)
- POST /api/heavy-compute (400ms simulated latency, cost 5, write/non-cacheable)
Also provides capacity concurrency semaphore and real proxy forwarding via httpx.
"""

import os
import asyncio
import httpx
from typing import Dict, Any, Optional
from fastapi import APIRouter, Request, Response
from config import ACTIVE_CONFIG

router = APIRouter(prefix="/api", tags=["upstream"])

# Global semaphore reflecting upstream server concurrency limit
_UPSTREAM_SEMAPHORE: Optional[asyncio.Semaphore] = None


def get_upstream_semaphore() -> asyncio.Semaphore:
    global _UPSTREAM_SEMAPHORE
    if _UPSTREAM_SEMAPHORE is None:
        _UPSTREAM_SEMAPHORE = asyncio.Semaphore(ACTIVE_CONFIG.upstream_concurrency)
    return _UPSTREAM_SEMAPHORE


def update_upstream_semaphore_concurrency(new_concurrency: int) -> None:
    global _UPSTREAM_SEMAPHORE
    _UPSTREAM_SEMAPHORE = asyncio.Semaphore(new_concurrency)


# Optional external reverse proxy client
_HTTPX_CLIENT: Optional[httpx.AsyncClient] = None


def get_httpx_client() -> httpx.AsyncClient:
    global _HTTPX_CLIENT
    if _HTTPX_CLIENT is None:
        limits = httpx.Limits(max_keepalive_connections=50, max_connections=200)
        _HTTPX_CLIENT = httpx.AsyncClient(timeout=5.0, limits=limits)
    return _HTTPX_CLIENT


async def close_httpx_client() -> None:
    global _HTTPX_CLIENT
    if _HTTPX_CLIENT is not None:
        await _HTTPX_CLIENT.aclose()
        _HTTPX_CLIENT = None


@router.get("/ping")
async def upstream_ping():
    """
    Cost: 1 token. Simulates lightweight health ping (20ms latency).
    Bounded by upstream concurrency semaphore.
    """
    sem = get_upstream_semaphore()
    async with sem:
        await asyncio.sleep(0.020)
        return {
            "status": "pong",
            "service": "core-upstream-api",
            "upstream_mode": "mock",
            "latency_ms": 20
        }


@router.get("/data")
async def upstream_data():
    """
    Cost: 2 tokens. Simulates standard database query (60ms latency, cacheable).
    """
    sem = get_upstream_semaphore()
    async with sem:
        await asyncio.sleep(0.060)
        return {
            "status": "success",
            "data": {
                "accounts": 1420,
                "active_sessions": 312,
                "system_load": 0.34,
                "cluster_health": "OPTIMAL"
            },
            "upstream_mode": "mock",
            "latency_ms": 60
        }


@router.post("/heavy-compute")
async def upstream_heavy_compute(payload: Optional[Dict[str, Any]] = None):
    """
    Cost: 5 tokens. Simulates intensive cryptographic/ML workload (400ms latency).
    Never degraded or cached.
    """
    sem = get_upstream_semaphore()
    async with sem:
        await asyncio.sleep(0.400)
        return {
            "status": "completed",
            "operation": "heavy-matrix-factorization",
            "cost_applied": 5,
            "upstream_mode": "mock",
            "latency_ms": 400
        }


async def forward_to_real_upstream(request: Request, upstream_url: str) -> Response:
    """
    Forward HTTP request to real upstream proxy if UPSTREAM_URL is configured.
    Strips hop-by-hop headers and maps timeouts/errors.
    """
    client = get_httpx_client()
    url = f"{upstream_url.rstrip('/')}{request.url.path}"
    if request.url.query:
        url += f"?{request.url.query}"

    hop_by_hop = {
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade"
    }

    forward_headers = {
        k: v for k, v in request.headers.items() if k.lower() not in hop_by_hop and k.lower() != "host"
    }

    body = await request.body()
    try:
        upstream_resp = await client.request(
            method=request.method,
            url=url,
            headers=forward_headers,
            content=body
        )
        resp_headers = {
            k: v for k, v in upstream_resp.headers.items() if k.lower() not in hop_by_hop
        }
        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=resp_headers
        )
    except httpx.TimeoutException:
        return Response(
            content=b'{"error": "Gateway Timeout", "message": "Upstream service timed out"}',
            status_code=504,
            media_type="application/json"
        )
    except httpx.RequestError as exc:
        return Response(
            content=f'{{"error": "Bad Gateway", "message": "Upstream error: {str(exc)}"}}'.encode("utf-8"),
            status_code=502,
            media_type="application/json"
        )
