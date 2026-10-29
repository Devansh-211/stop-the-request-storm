"""
Leaky Bucket / Traffic Shaper unit tests.
Verifies:
- Outflow spacing matches leak rate
- Queue delay scheduling
- Overflow beyond queue capacity drops
"""

import pytest
from storage.memory_store import MemoryStorage
from limiters.leaky_bucket import LeakyBucketLimiter


@pytest.mark.asyncio
async def test_leaky_bucket_outflow_spacing_and_queue():
    store = MemoryStorage()
    limiter = LeakyBucketLimiter(store)
    identity = "user_lb_1"
    capacity = 4.0      # max queue depth 4
    leak_rate = 2.0     # 2 req/s -> 0.5s per request
    t0 = 500.0

    # Request 1: immediate outflow (wait = 0)
    d1 = await limiter.check(identity=identity, endpoint_cost=1, capacity=capacity, rate=leak_rate, now=t0)
    assert d1.allowed is True
    assert d1.queued_delay_ms == 0.0

    # Request 2 at the same instant: scheduled 0.5s later (500ms delay)
    d2 = await limiter.check(identity=identity, endpoint_cost=1, capacity=capacity, rate=leak_rate, now=t0)
    assert d2.allowed is True
    assert abs(d2.queued_delay_ms - 500.0) < 1.0

    # Request 3: scheduled 1.0s later (1000ms delay)
    d3 = await limiter.check(identity=identity, endpoint_cost=1, capacity=capacity, rate=leak_rate, now=t0)
    assert d3.allowed is True
    assert abs(d3.queued_delay_ms - 1000.0) < 1.0

    # Request 4: scheduled 1.5s later (1500ms delay)
    d4 = await limiter.check(identity=identity, endpoint_cost=1, capacity=capacity, rate=leak_rate, now=t0)
    assert d4.allowed is True
    assert abs(d4.queued_delay_ms - 1500.0) < 1.0


@pytest.mark.asyncio
async def test_leaky_bucket_overflow_drop():
    store = MemoryStorage()
    limiter = LeakyBucketLimiter(store)
    identity = "user_lb_overflow"
    capacity = 2.0     # max delay = capacity / leak_rate = 2 / 1 = 2.0s
    leak_rate = 1.0
    t0 = 100.0

    # Req 1: wait 0, next_free = 101.0
    d1 = await limiter.check(identity=identity, endpoint_cost=1, capacity=capacity, rate=leak_rate, now=t0)
    assert d1.allowed is True

    # Req 2: wait 1.0s, next_free = 102.0
    d2 = await limiter.check(identity=identity, endpoint_cost=1, capacity=capacity, rate=leak_rate, now=t0)
    assert d2.allowed is True

    # Req 3: wait would be 2.0s, delta 1.0 -> 3.0s > max_delay (2.0s) -> DROP
    d3 = await limiter.check(identity=identity, endpoint_cost=1, capacity=capacity, rate=leak_rate, now=t0)
    assert d3.allowed is False
    assert d3.reason == "LEAKY_BUCKET_OVERFLOW"
