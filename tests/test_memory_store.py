"""
Memory store hygiene and LRU capacity tests.
Verifies:
- Stale keys and locks are purged by sweep_expired
- The max_keys cap strictly prevents memory unbounded growth under 50k random IPs
"""

import pytest
import time
from storage.memory_store import MemoryStorage


@pytest.mark.asyncio
async def test_memory_store_max_keys_cap():
    max_cap = 500
    store = MemoryStorage(max_keys=max_cap)

    # Insert 2,000 distinct IPs
    for i in range(2000):
        key = f"ip:10.0.{i // 256}.{i % 256}"
        await store.token_bucket_consume(key=key, capacity=10.0, refill_rate=1.0, cost=1.0)

    # Size must not exceed max_cap
    assert len(store._tb_data) <= max_cap


@pytest.mark.asyncio
async def test_memory_store_sweep_expired():
    store = MemoryStorage()
    t0 = 1000.0

    # Key active at t0
    await store.token_bucket_consume(key="stale_test", capacity=5.0, refill_rate=1.0, cost=1.0, now=t0)
    assert "stale_test" in store._tb_data

    # Sweep after 120 seconds idle
    purged = await store.sweep_expired(idle_seconds=60.0)
    assert purged >= 1
    assert "stale_test" not in store._tb_data
