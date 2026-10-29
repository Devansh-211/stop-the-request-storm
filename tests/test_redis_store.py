"""
Redis store integration tests.
Automatically skipped if Redis is unreachable.
"""

import pytest
import os
import asyncio
import redis.asyncio as aioredis
from storage.redis_store import RedisStorage
from limiters.token_bucket import TokenBucketLimiter


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.mark.asyncio
async def test_redis_store_token_bucket():
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    try:
        client = aioredis.from_url(redis_url, socket_timeout=0.3, socket_connect_timeout=0.3)
        await asyncio.wait_for(client.ping(), timeout=0.3)
    except Exception:
        pytest.skip("Redis server is not reachable; skipping Redis integration tests.")

    store = RedisStorage(client)
    limiter = TokenBucketLimiter(store)
    identity = "redis_test_user"

    d1 = await limiter.check(identity=identity, endpoint_cost=1, capacity=5.0, rate=1.0)
    assert d1.allowed is True

    await store.close()
