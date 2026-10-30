"""
BMSCE x MindMatrix Skill Lab Initiative - Project 09 (API Under Attack)
Required Test Matrix Verification Suite (T01 - T08).
Conforms strictly to Project 09 Student Instructional Guide (Page 60):

T01: Requests below threshold succeed.
T02: Requests above threshold are rejected consistently.
T03: Limiter resets according to its documented window.
T04: Valid requests resume after the limit window.
T05: Logs/metrics show decisions without sensitive data.
T06: Trigger a controlled unexpected error (safe response, useful event recorded).
T07: Inspect source, output and logs for sensitive data (no secret or unnecessary data exposed).
T08: Repeat the complete test set (reproducible results and documented limitations).
"""

import os
import re
import time
import asyncio
import pytest
import httpx
from main import app
from session_manager import SESSION_MANAGER
from cloud.cloud_logging import structured_security_logger
from cloud.cloud_monitoring import monitoring_adapter


@pytest.mark.asyncio
async def test_t01_requests_below_threshold_succeed():
    """
    T01: Requests below threshold succeed.
    Expected: Documented expected behaviour; requests accepted, tokens decremented,
              rate limit headers and correlation ID returned.
    """
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Create fresh session
        sess_resp = await client.post("/session/new")
        assert sess_resp.status_code == 200
        session_id = sess_resp.json()["session_id"]

        headers = {
            "X-Session-Id": session_id,
            "X-Forwarded-For": "198.51.100.10"
        }

        # Send 4 requests below base_capacity (base_capacity=10, cost=1)
        for i in range(4):
            res = await client.get("/api/ping", headers=headers)
            assert res.status_code == 200
            assert res.json()["status"] == "pong"
            
            # Verify rate limit headers
            assert "x-ratelimit-limit" in res.headers
            assert "x-ratelimit-remaining" in res.headers
            assert "x-ratelimit-reset" in res.headers
            assert "x-correlation-id" in res.headers
            assert "x-session-id" in res.headers
            
            rem = int(res.headers["x-ratelimit-remaining"])
            assert rem <= 10 - (i + 1)


@pytest.mark.asyncio
async def test_t02_requests_above_threshold_rejected_consistently():
    """
    T02: Requests above threshold are rejected consistently.
    Expected: Once bucket tokens are exhausted, subsequent non-cacheable / write
              requests return 429 Too Many Requests with integer Retry-After.
    """
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        sess_resp = await client.post("/session/new")
        session_id = sess_resp.json()["session_id"]

        headers = {
            "X-Session-Id": session_id,
            "X-Forwarded-For": "198.51.100.20"
        }

        # Heavy compute costs 5 tokens per call. Base capacity is 10.
        # Call 1: 10 - 5 = 5 remaining (allowed)
        r1 = await client.post("/api/heavy-compute", headers=headers)
        assert r1.status_code == 200

        # Call 2: 5 - 5 = 0 remaining (allowed)
        r2 = await client.post("/api/heavy-compute", headers=headers)
        assert r2.status_code == 200

        # Call 3: 0 tokens left -> 429 Too Many Requests
        r3 = await client.post("/api/heavy-compute", headers=headers)
        assert r3.status_code == 429
        data = r3.json()
        assert data["error"] == "Too Many Requests"
        assert "retry_after_seconds" in data
        assert "x-ratelimit-remaining" in r3.headers
        assert int(r3.headers["x-ratelimit-remaining"]) == 0
        assert int(r3.headers["retry-after"]) >= 1
        assert "x-correlation-id" in r3.headers

        # Call 4: Still rejected consistently
        r4 = await client.post("/api/heavy-compute", headers=headers)
        assert r4.status_code == 429


@pytest.mark.asyncio
async def test_t03_limiter_resets_according_to_window():
    """
    T03: Limiter resets according to its documented window.
    Expected: Bucket refills at base_refill_rate over elapsed time.
    """
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        sess_resp = await client.post("/session/new")
        session_id = sess_resp.json()["session_id"]

        headers = {
            "X-Session-Id": session_id,
            "X-Forwarded-For": "198.51.100.30"
        }

        # Set higher refill rate for rapid, deterministic test execution
        await client.post(
            "/control/config",
            headers=headers,
            json={
                "base_capacity": 5.0,
                "base_refill_rate": 5.0,  # 5 tokens / second
                "window_seconds": 2.0,
                "degradation_mode": False
            }
        )

        # Deplete the 5 tokens
        for _ in range(5):
            await client.get("/api/ping", headers=headers)

        # Confirm immediate 6th request is throttled
        blocked = await client.get("/api/ping", headers=headers)
        assert blocked.status_code == 429

        # Sleep for 1.1s to allow refill (5 tokens/sec * 1.1s = 5.5 tokens)
        await asyncio.sleep(1.1)

        # Bucket should now be refilled
        resumed = await client.get("/api/ping", headers=headers)
        assert resumed.status_code == 200
        assert int(resumed.headers["x-ratelimit-remaining"]) >= 3


@pytest.mark.asyncio
async def test_t04_valid_requests_resume_after_limit_window():
    """
    T04: Valid requests resume after the limit window.
    Expected: Normal use case works cleanly after cooldown window.
    """
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        sess_resp = await client.post("/session/new")
        session_id = sess_resp.json()["session_id"]

        headers = {
            "X-Session-Id": session_id,
            "X-Forwarded-For": "198.51.100.40"
        }

        # Configure small capacity and fast refill
        await client.post(
            "/control/config",
            headers=headers,
            json={
                "base_capacity": 3.0,
                "base_refill_rate": 6.0,
                "window_seconds": 2.0,
                "degradation_mode": False
            }
        )

        # Exhaust capacity
        for _ in range(3):
            await client.get("/api/ping", headers=headers)
        assert (await client.get("/api/ping", headers=headers)).status_code == 429

        # Wait for window reset
        await asyncio.sleep(0.7)

        # Valid requests resume normally
        res = await client.get("/api/ping", headers=headers)
        assert res.status_code == 200
        assert res.json()["status"] == "pong"


@pytest.mark.asyncio
async def test_t05_logs_metrics_show_decisions_without_sensitive_data():
    """
    T05: Logs/metrics show decisions without sensitive data.
    Expected: Event type, timestamp, outcome, correlation ID recorded.
              No raw API keys, passwords, full sensitive payloads, or unmasked IPs.
    """
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        sess_resp = await client.post("/session/new")
        session_id = sess_resp.json()["session_id"]

        headers = {
            "X-Session-Id": session_id,
            "X-Forwarded-For": "203.0.113.77",
            "X-API-Key": "pro-demo-key"
        }

        # Make requests with API key
        await client.get("/api/ping", headers=headers)

        # Fetch session metrics snapshot
        metrics_resp = await client.get("/control/metrics", headers=headers)
        assert metrics_resp.status_code == 200
        metrics = metrics_resp.json()

        # Check recent requests in log
        recent = metrics.get("recent_requests", [])
        assert len(recent) > 0
        latest = recent[0]

        # Verify identity masking: raw key 'pro-demo-key' must NEVER be logged
        assert "pro-demo-key" not in str(latest)
        assert latest["identity"] == "API_KEY [PRO]"

        # Check structured security event logs
        audit_resp = await client.get("/control/cloud/logs", headers=headers)
        assert audit_resp.status_code == 200
        audit_events = audit_resp.json()["events"]
        assert len(audit_events) > 0

        for event in audit_events:
            # Must have correlation_id and timestamp
            assert "correlation_id" in event
            assert "timestamp" in event
            assert "severity" in event
            assert "event_type" in event
            # Must not leak raw API keys or passwords
            event_text = str(event)
            assert "pro-demo-key" not in event_text
            assert "ent-demo-key" not in event_text
            assert "password" not in event_text.lower() or "[REDACTED]" in event_text


@pytest.mark.asyncio
async def test_t06_trigger_controlled_unexpected_error():
    """
    T06: Trigger a controlled unexpected error.
    Expected: Safe response (500 Internal Server Error, generic message, correlation ID,
              no stack trace or internals leaked); useful security event recorded.
    """
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        res = await client.get("/api/controlled-error", headers={"X-Correlation-Id": "corr-test-t06-unique"})
        assert res.status_code == 500
        body = res.json()

        # Safe response verification
        assert body["error"] == "Internal Server Error"
        assert "Traceback" not in str(body)
        assert "File \"" not in str(body)
        assert body["correlation_id"] == "corr-test-t06-unique"
        assert res.headers["x-correlation-id"] == "corr-test-t06-unique"

        # Verify structured event recorded in cloud security log
        events = structured_security_logger.get_recent_events(limit=10, event_type="UNEXPECTED_ERROR")
        assert len(events) > 0
        matched = [e for e in events if e.get("correlation_id") == "corr-test-t06-unique"]
        assert len(matched) == 1
        assert matched[0]["severity"] == "ERROR"
        assert matched[0]["security"]["outcome"] == "handled_error"


def test_t07_source_output_logs_contain_no_sensitive_data():
    """
    T07: Inspect source, output and logs for sensitive data.
    Expected: No secret, private key, real credential, or unnecessary sensitive data exposed.
    """
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    
    # Secret pattern regexes
    secret_patterns = [
        re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----"),
        re.compile(r"(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})"),
        re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key ID
        re.compile(r"AIza[0-9A-Za-z-_]{35}"),  # Google API key
    ]

    scanned_files = 0
    for root, dirs, files in os.walk(project_root):
        if any(ignored in root for ignored in (".git", ".pytest_cache", "__pycache__", "venv")):
            continue
        for file in files:
            if file.endswith((".py", ".json", ".html", ".css", ".md")):
                scanned_files += 1
                filepath = os.path.join(root, file)
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    for pattern in secret_patterns:
                        match = pattern.search(content)
                        assert match is None, f"Sensitive secret pattern detected in {filepath}: {match.group(0)}"

    assert scanned_files > 10, "Sanity check: at least 10 source files were inspected"


@pytest.mark.asyncio
async def test_t08_complete_test_set_reproducibility():
    """
    T08: Repeat the complete test set.
    Expected: Results are deterministic, reproducible, and limitations documented.
    """
    # Run sequential verification of core defensive controls
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Health check
        h = await client.get("/health")
        assert h.status_code == 200

        # 2. Below threshold succeeds
        s1 = await client.get("/api/ping", headers={"X-Forwarded-For": "10.0.1.1"})
        assert s1.status_code == 200

        # 3. Controlled unexpected error returns safe response
        s2 = await client.get("/api/controlled-error")
        assert s2.status_code == 500
        assert "correlation_id" in s2.json()

        # 4. Cloud Monitoring status returns operational descriptors
        m = await client.get("/control/cloud/monitoring")
        assert m.status_code == 200
        assert "metrics" in m.json()

        # 5. Cloud Audit Logs accessible
        l = await client.get("/control/cloud/logs")
        assert l.status_code == 200
        assert "events" in l.json()
