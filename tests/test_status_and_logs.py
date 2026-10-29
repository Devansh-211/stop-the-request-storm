"""
Unit and integration tests for Status Code metrics & Live Request Log.
Verifies:
1. Status counts and log entries recorded for 200, cached 200, 429, and queued requests.
2. Raw API keys NEVER appear in the request log (masked to tier label).
3. IPv4 addresses are masked to the first 2 octets.
4. Request log stays strictly bounded at maxlen=200 under a 10k-request flood.
5. Two concurrent sessions keep completely separate status counts and request logs.
6. /control/log endpoint returns filtered log entries.
"""

import pytest
import asyncio
import httpx
from main import app
from metrics import MetricsCollector, mask_identity
from session_manager import SESSION_MANAGER, SessionState


def test_mask_identity():
    # IPv4 masking: only first 2 octets visible
    assert mask_identity("192.168.1.55", "FREE") == "192.168.*.*"
    assert mask_identity("ip:203.0.113.88", "PRO") == "203.0.*.*"

    # API Keys: raw key must never be shown, only tier
    assert mask_identity("key:pro-demo-key", "PRO") == "API_KEY [PRO]"
    assert mask_identity("key:secret_enterprise_token", "ENTERPRISE") == "API_KEY [ENTERPRISE]"
    assert mask_identity("bot-12345", "FREE") == "API_KEY [FREE]"


@pytest.mark.asyncio
async def test_metrics_collector_status_counts_and_log():
    collector = MetricsCollector(buffer_seconds=120)

    # Record 200 accepted
    collector.record_request(
        status="accepted",
        latency_ms=10.5,
        identity="192.168.1.1",
        status_code=200,
        method="GET",
        path="/api/ping",
        tier="FREE",
        cost=1,
        reason="allowed"
    )

    # Record 200 degraded (Cached-Fallback)
    collector.record_request(
        status="degraded",
        latency_ms=2.1,
        identity="192.168.1.1",
        status_code=200,
        method="GET",
        path="/api/data",
        tier="FREE",
        cost=2,
        reason="cached_fallback"
    )

    # Record 429 blocked
    collector.record_request(
        status="blocked",
        latency_ms=1.2,
        identity="key:pro-demo-key",
        status_code=429,
        method="POST",
        path="/api/heavy-compute",
        tier="PRO",
        cost=5,
        reason="token_bucket_exhausted",
        retry_after_s=3
    )

    # Record queued
    collector.record_request(
        status="queued",
        latency_ms=250.0,
        identity="10.0.0.99",
        status_code=200,
        method="GET",
        path="/api/ping",
        tier="FREE",
        cost=1,
        reason="queue_shaper"
    )

    snapshot = collector.get_snapshot(store_backend="memory")
    sc = snapshot["status_counts"]

    # Verify counts
    assert sc["total_200"] == 2  # 1 normal 200 + 1 queued 200
    assert sc["total_degraded_200"] == 1
    assert sc["total_429"] == 1

    # Verify request log
    logs = snapshot["recent_requests"]
    assert len(logs) == 4

    # Newest is queued request
    assert logs[0]["outcome"] == "queued"
    assert logs[0]["reason"] == "queue_shaper"

    # Throttled request
    throttled_log = [l for l in logs if l["status"] == 429][0]
    assert throttled_log["retry_after_s"] == 3
    # API Key must be masked
    assert throttled_log["identity"] == "API_KEY [PRO]"
    assert "pro-demo-key" not in throttled_log["identity"]

    # Filtered fetch
    filtered_429 = collector.get_filtered_log(status=429)
    assert len(filtered_429) == 1
    assert filtered_429[0]["status"] == 429


@pytest.mark.asyncio
async def test_request_log_bounded_cap():
    collector = MetricsCollector(buffer_seconds=120)

    # Record 10,000 requests
    for i in range(10_000):
        collector.record_request(
            status="accepted",
            latency_ms=5.0,
            identity=f"192.168.0.{i % 255}",
            status_code=200,
            method="GET",
            path="/api/ping"
        )

    # Log must stay strictly bounded at 200 entries
    assert len(collector._request_log) == 200
    snapshot = collector.get_snapshot(store_backend="memory")
    assert len(snapshot["recent_requests"]) == 50  # Cap on snapshot recent array


@pytest.mark.asyncio
async def test_session_isolation_for_status_codes_and_logs():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client_a:
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client_b:
            res_a = await client_a.get("/session/current")
            sid_a = res_a.json()["session_id"]

            res_b = await client_b.get("/session/current")
            sid_b = res_b.json()["session_id"]
            assert sid_a != sid_b

            # Session A sends 15 requests to GET /api/data to cause throttle
            for i in range(15):
                await client_a.get(
                    "/api/data",
                    headers={"X-Session-Id": sid_a, "X-Forwarded-For": "198.51.100.22"}
                )

            # Session A sends heavy compute to get a 429
            res_429 = await client_a.post(
                "/api/heavy-compute",
                headers={"X-Session-Id": sid_a, "X-Forwarded-For": "198.51.100.22"},
                json={"task": "stress"}
            )

            # Check Session A's metrics & logs
            met_a = await client_a.get("/control/metrics", headers={"X-Session-Id": sid_a})
            assert met_a.status_code == 200
            data_a = met_a.json()
            assert len(data_a["recent_requests"]) >= 15
            assert data_a["status_counts"]["total_all"] >= 15

            # Verify Session A's logs have masked IP
            assert data_a["recent_requests"][0]["identity"] == "198.51.*.*"

            # Check Session A's /control/log endpoint
            log_a_resp = await client_a.get("/control/log?limit=10", headers={"X-Session-Id": sid_a})
            assert log_a_resp.status_code == 200
            assert len(log_a_resp.json()["requests"]) == 10

            # Check Session B: Must have 0 requests recorded and empty request log
            met_b = await client_b.get("/control/metrics", headers={"X-Session-Id": sid_b})
            assert met_b.status_code == 200
            data_b = met_b.json()
            assert len(data_b["recent_requests"]) == 0
            assert data_b["status_counts"]["total_all"] == 0

            log_b_resp = await client_b.get("/control/log", headers={"X-Session-Id": sid_b})
            assert log_b_resp.status_code == 200
            assert len(log_b_resp.json()["requests"]) == 0
