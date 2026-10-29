"""
Token Bucket unit tests.
Verifies:
- Bursts up to capacity, then throttles
- Refill restores tokens over time
- Variable endpoint costs consume properly
"""

import pytest
import time
from storage.memory_store import MemoryStorage
from limiters.token_bucket import TokenBucketLimiter


@pytest.mark.asyncio
async def test_token_bucket_burst_and_deny():
    store = MemoryStorage()
    limiter = TokenBucketLimiter(store)
    identity = "user_tb_1"
    capacity = 5.0
    refill_rate = 1.0

    # 5 cost-1 requests should all be allowed
    for i in range(5):
        decision = await limiter.check(identity=identity, endpoint_cost=1, capacity=capacity, rate=refill_rate)
        assert decision.allowed is True
        assert decision.remaining == pytest.approx(5.0 - (i + 1), abs=1e-2)

    # 6th request must be denied
    decision_denied = await limiter.check(identity=identity, endpoint_cost=1, capacity=capacity, rate=refill_rate)
    assert decision_denied.allowed is False
    assert decision_denied.reason == "TOKEN_BUCKET_EXHAUSTED"
    assert decision_denied.retry_after_ms >= 100.0


@pytest.mark.asyncio
async def test_token_bucket_refill():
    store = MemoryStorage()
    limiter = TokenBucketLimiter(store)
    identity = "user_tb_2"
    capacity = 3.0
    refill_rate = 2.0  # 2 tokens per second

    t0 = 1000.0
    # Exhaust all 3 tokens at t0
    for _ in range(3):
        res = await limiter.check(identity=identity, endpoint_cost=1, capacity=capacity, rate=refill_rate, now=t0)
        assert res.allowed is True

    # At t0, next is denied
    res_denied = await limiter.check(identity=identity, endpoint_cost=1, capacity=capacity, rate=refill_rate, now=t0)
    assert res_denied.allowed is False

    # Advance 1.0 second: 2 tokens refilled
    t1 = t0 + 1.0
    res_after_refill = await limiter.check(identity=identity, endpoint_cost=1, capacity=capacity, rate=refill_rate, now=t1)
    assert res_after_refill.allowed is True
    # One token was used out of 2 refilled -> remaining = 1.0
    assert abs(res_after_refill.remaining - 1.0) < 1e-4


@pytest.mark.asyncio
async def test_token_bucket_variable_endpoint_cost():
    store = MemoryStorage()
    limiter = TokenBucketLimiter(store)
    identity = "user_tb_3"
    capacity = 10.0
    refill_rate = 1.0

    # Request with cost 5 (e.g. POST /api/heavy-compute)
    d1 = await limiter.check(identity=identity, endpoint_cost=5, capacity=capacity, rate=refill_rate)
    assert d1.allowed is True
    assert d1.remaining == pytest.approx(5.0, abs=1e-2)

    # Second request with cost 5 -> remaining = 0
    d2 = await limiter.check(identity=identity, endpoint_cost=5, capacity=capacity, rate=refill_rate)
    assert d2.allowed is True
    assert d2.remaining == pytest.approx(0.0, abs=1e-2)

    # Third request cannot be fulfilled even with cost 1
    d3 = await limiter.check(identity=identity, endpoint_cost=1, capacity=capacity, rate=refill_rate)
    assert d3.allowed is False
