"""
High concurrency race-condition tests.
Verifies that 500 simultaneous asyncio.gather requests on a single key
never admit more than capacity (+ refill allowance).
"""

import pytest
import asyncio
from storage.memory_store import MemoryStorage
from limiters.token_bucket import TokenBucketLimiter


@pytest.mark.asyncio
async def test_high_concurrency_race_condition():
    store = MemoryStorage()
    limiter = TokenBucketLimiter(store)
    identity = "concurrent_victim"
    capacity = 25.0
    refill_rate = 0.0  # Zero refill during test to strictly test atomicity

    # Launch 500 concurrent coroutines attempting to consume from the same token bucket
    async def _try_consume():
        return await limiter.check(
            identity=identity,
            endpoint_cost=1,
            capacity=capacity,
            rate=refill_rate
        )

    tasks = [_try_consume() for _ in range(500)]
    decisions = await asyncio.gather(*tasks)

    allowed_count = sum(1 for d in decisions if d.allowed)
    blocked_count = sum(1 for d in decisions if not d.allowed)

    # Exactly 25 requests must be allowed, and 475 blocked with zero race overshoots
    assert allowed_count == 25
    assert blocked_count == 475
