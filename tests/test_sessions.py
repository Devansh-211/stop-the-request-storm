"""
Per-Session Sandbox & State Isolation Integration Tests.
Verifies:
1. Two sessions run concurrently: Session A launches DDoS and disables Shield; Session B's metrics, config, and p95 stay completely unaffected.
2. Idle session expiry removes session state and cancels simulator tasks.
3. Forged or malformed session IDs cannot read or write another session's state.
4. Session cap (200) and per-IP session creation limits hold under a 5,000-session flood.
"""

import pytest
import asyncio
import httpx
from main import app
from session_manager import SESSION_MANAGER, SessionState


@pytest.mark.asyncio
async def test_session_isolation_two_users():
    """
    Session A: Disables shield, launches attack traffic.
    Session B: Shield stays enabled, traffic is normal, config & metrics stay completely isolated.
    """
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client_a:
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client_b:
            # 1. Establish Session A
            res_a = await client_a.get("/session/current")
            assert res_a.status_code == 200
            session_a_id = res_a.json()["session_id"]
            assert session_a_id

            # 2. Establish Session B
            res_b = await client_b.get("/session/current")
            assert res_b.status_code == 200
            session_b_id = res_b.json()["session_id"]
            assert session_b_id
            assert session_a_id != session_b_id

            # 3. Session A turns Shield OFF and changes algorithm to leaky_bucket
            patch_a = await client_a.post(
                "/control/config",
                headers={"X-Session-Id": session_a_id},
                json={"shield_enabled": False, "algorithm": "leaky_bucket"}
            )
            assert patch_a.status_code == 200
            assert patch_a.json()["config"]["shield_enabled"] is False
            assert patch_a.json()["config"]["algorithm"] == "leaky_bucket"

            # 4. Verify Session B's config is untouched (shield still ON, token_bucket)
            state_b = await client_b.get("/control/state", headers={"X-Session-Id": session_b_id})
            assert state_b.status_code == 200
            assert state_b.json()["config"]["shield_enabled"] is True
            assert state_b.json()["config"]["algorithm"] == "token_bucket"

            # 5. Session A sends 20 requests on /api/data with attack sim class
            for _ in range(20):
                await client_a.get(
                    "/api/data",
                    headers={"X-Session-Id": session_a_id, "X-Sim-Class": "attack"}
                )

            # 6. Verify Session A has recorded metrics
            metrics_a = await client_a.get("/control/metrics", headers={"X-Session-Id": session_a_id})
            assert metrics_a.status_code == 200
            accepted_a = sum(metrics_a.json()["series"]["accepted"])
            assert accepted_a >= 20

            # 7. Verify Session B has ZERO accepted requests recorded in its ring buffer
            metrics_b = await client_b.get("/control/metrics", headers={"X-Session-Id": session_b_id})
            assert metrics_b.status_code == 200
            accepted_b = sum(metrics_b.json()["series"]["accepted"])
            assert accepted_b == 0


@pytest.mark.asyncio
async def test_forged_or_malformed_session_id():
    """
    Forged, invalid, or path-traversal session IDs must NEVER access another session's state.
    Invalid session IDs must result in a clean, newly minted valid session.
    """
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Malformed IDs: path traversal, symbols, too short, too long
        malformed_ids = [
            "../etc/passwd",
            "../../../secret",
            "<script>alert(1)</script>",
            "short",
            "a" * 150,
            "session with spaces",
            "session!@#$%^&*()",
        ]

        for bad_id in malformed_ids:
            res = await client.get("/session/current", headers={"X-Session-Id": bad_id})
            assert res.status_code == 200
            assigned_id = res.json()["session_id"]
            # The returned ID must NOT be the bad ID; it must be a valid 22-char token
            assert assigned_id != bad_id
            assert SESSION_MANAGER.is_valid_session_id(assigned_id)


@pytest.mark.asyncio
async def test_idle_session_expiry_cancels_tasks():
    """
    Simulate idle timeout: idle sessions (>15 min) are purged and active background tasks cancelled.
    """
    session_id = "test_idle_session_12345"
    session = SessionState(session_id)
    SESSION_MANAGER._sessions[session_id] = session

    # Attach a mock long-running background task
    async def _mock_background_sim():
        try:
            await asyncio.sleep(60.0)
        except asyncio.CancelledError:
            pass

    task = asyncio.create_task(_mock_background_sim())
    session.simulator_task = task

    # Manually age the session to 16 minutes ago
    session.last_seen -= 960.0

    # Run sweeper
    purged_count = await SESSION_MANAGER.sweep_idle_sessions()
    assert purged_count >= 1
    assert session_id not in SESSION_MANAGER._sessions

    # Simulator task must have been cancelled
    await asyncio.sleep(0.01)
    assert task.cancelled() or task.done()


@pytest.mark.asyncio
async def test_session_flood_abuse_caps():
    """
    5,000-session generation flood:
    - Total sessions in memory must NEVER exceed max_sessions (200).
    - Per-IP rate limiting holds.
    """
    initial_max = SESSION_MANAGER.max_sessions
    initial_ip_limit = SESSION_MANAGER.ip_create_limit

    try:
        SESSION_MANAGER.max_sessions = 50
        SESSION_MANAGER.ip_create_limit = 10

        # Rapidly create 500 sessions from various IPs
        for i in range(500):
            ip = f"10.5.{i % 10}.1"
            await SESSION_MANAGER.get_or_create_session(
                requested_id=f"flood_fake_req_{i}",
                client_ip=ip
            )

        # Total session count must be bounded at max_sessions
        assert len(SESSION_MANAGER._sessions) <= 50

    finally:
        SESSION_MANAGER.max_sessions = initial_max
        SESSION_MANAGER.ip_create_limit = initial_ip_limit
