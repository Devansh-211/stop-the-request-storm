"""
Sliding Window Counter unit tests.
Verifies:
- Standard throughput limits
- Boundary burst straddling window edge is caught and blocked by weighted estimation
"""

import pytest
from storage.memory_store import MemoryStorage
from limiters.sliding_window import SlidingWindowLimiter


@pytest.mark.asyncio
async def test_sliding_window_basic_limit():
    store = MemoryStorage()
    limiter = SlidingWindowLimiter(store)
    identity = "user_sw_1"
    limit = 5.0
    window_sec = 10.0
    t0 = 100.0

    for _ in range(5):
        d = await limiter.check(identity=identity, endpoint_cost=1, capacity=limit, rate=1.0, window_seconds=window_sec, now=t0)
        assert d.allowed is True

    # 6th should exceed
    d_denied = await limiter.check(identity=identity, endpoint_cost=1, capacity=limit, rate=1.0, window_seconds=window_sec, now=t0)
    assert d_denied.allowed is False
    assert d_denied.reason == "SLIDING_WINDOW_EXCEEDED"


@pytest.mark.asyncio
async def test_sliding_window_boundary_burst_blocked():
    """
    Classic rate limiter flaw: if 10 requests hit at the end of Window 1 (t=9.9s)
    and 10 requests hit at the start of Window 2 (t=10.1s), a naive fixed-window limiter
    allows 20 requests in 0.2s!
    The sliding window counter weights the previous window's count:
    at t=10.1s, elapsed=0.1s in window 2.
    weight = 1 - 0.1/10 = 0.99.
    estimated = 10 * 0.99 = 9.9. Adding 1 gives 10.9 > limit (10).
    The burst straddling the boundary MUST BE BLOCKED.
    """
    store = MemoryStorage()
    limiter = SlidingWindowLimiter(store)
    identity = "boundary_tester"
    limit = 10.0
    window_sec = 10.0

    # Fill window 1 near the boundary: t = 9.8s
    t_end_w1 = 9.8
    for _ in range(10):
        d = await limiter.check(identity=identity, endpoint_cost=1, capacity=limit, rate=1.0, window_seconds=window_sec, now=t_end_w1)
        assert d.allowed is True

    # Immediate burst right across boundary: t = 10.2s (Window 2 just started)
    t_start_w2 = 10.2
    d_blocked = await limiter.check(identity=identity, endpoint_cost=1, capacity=limit, rate=1.0, window_seconds=window_sec, now=t_start_w2)
    
    # Must be denied by sliding window weighted estimation
    assert d_blocked.allowed is False
    assert d_blocked.reason == "SLIDING_WINDOW_EXCEEDED"
