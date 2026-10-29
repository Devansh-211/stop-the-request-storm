"""
Async-safe in-memory rate limiting state store with per-key locking,
TTL cleanup, and LRU eviction under massive random-key storms.
"""

import time
import asyncio
from typing import Dict, Tuple, Optional
from collections import OrderedDict
from storage.base import BaseStorage


class _TokenBucketData:
    __slots__ = ("tokens", "last_update", "last_access")

    def __init__(self, tokens: float, last_update: float):
        self.tokens = tokens
        self.last_update = last_update
        self.last_access = last_update


class _SlidingWindowData:
    __slots__ = ("curr_window_idx", "curr_count", "prev_count", "last_access")

    def __init__(self, curr_window_idx: int, curr_count: float, prev_count: float, now: float):
        self.curr_window_idx = curr_window_idx
        self.curr_count = curr_count
        self.prev_count = prev_count
        self.last_access = now


class _LeakyBucketData:
    __slots__ = ("next_free", "last_access")

    def __init__(self, next_free: float, now: float):
        self.next_free = next_free
        self.last_access = now


class MemoryStorage(BaseStorage):
    """
    In-memory async-safe state store for single-process operation.
    Guarantees atomicity via per-key asyncio.Lock without holding locks across I/O.
    Implements LRU bounds (max_keys) and TTL cleanup.
    """

    def __init__(self, max_keys: int = 100_000):
        self.max_keys = max_keys
        # Key data dictionaries
        self._tb_data: OrderedDict[str, _TokenBucketData] = OrderedDict()
        self._sw_data: OrderedDict[str, _SlidingWindowData] = OrderedDict()
        self._lb_data: OrderedDict[str, _LeakyBucketData] = OrderedDict()

        # Per-key locks for atomic check-and-modify
        self._locks: Dict[str, asyncio.Lock] = {}
        self._lock_access: Dict[str, float] = {}
        self._meta_lock = asyncio.Lock()

    async def _get_key_lock(self, key: str) -> asyncio.Lock:
        async with self._meta_lock:
            lock = self._locks.get(key)
            if lock is None:
                lock = asyncio.Lock()
                self._locks[key] = lock
            self._lock_access[key] = time.monotonic()
            return lock

    def _evict_lru_if_needed(self, store: OrderedDict) -> None:
        """Evicts oldest keys if store exceeds max_keys."""
        while len(store) > self.max_keys:
            store.popitem(last=False)

    async def token_bucket_consume(
        self,
        key: str,
        capacity: float,
        refill_rate: float,
        cost: float,
        now: Optional[float] = None
    ) -> Tuple[bool, float, float]:
        if now is None:
            now = time.monotonic()

        lock = await self._get_key_lock("tb:" + key)
        async with lock:
            data = self._tb_data.get(key)
            if data is None:
                tokens = capacity
                last_update = now
            else:
                self._tb_data.move_to_end(key)
                delta = max(0.0, now - data.last_update)
                tokens = min(capacity, data.tokens + delta * refill_rate)
                last_update = now

            if tokens >= cost:
                tokens -= cost
                allowed = True
            else:
                allowed = False

            new_data = _TokenBucketData(tokens=tokens, last_update=last_update)
            self._tb_data[key] = new_data
            self._evict_lru_if_needed(self._tb_data)

            # Calculate reset_after_ms (time to reach full capacity)
            needed = max(0.0, capacity - tokens)
            reset_after_ms = (needed / refill_rate * 1000.0) if refill_rate > 0 else 0.0

            return allowed, tokens, reset_after_ms

    async def sliding_window_record(
        self,
        key: str,
        window_seconds: float,
        cost: float,
        limit: float,
        now: Optional[float] = None
    ) -> Tuple[bool, float, float]:
        if now is None:
            now = time.monotonic()

        curr_window_idx = int(now // window_seconds)
        elapsed = now - (curr_window_idx * window_seconds)

        lock = await self._get_key_lock("sw:" + key)
        async with lock:
            data = self._sw_data.get(key)
            if data is None:
                prev_count = 0.0
                curr_count = 0.0
            else:
                self._sw_data.move_to_end(key)
                if data.curr_window_idx == curr_window_idx:
                    prev_count = data.prev_count
                    curr_count = data.curr_count
                elif data.curr_window_idx == curr_window_idx - 1:
                    prev_count = data.curr_count
                    curr_count = 0.0
                else:
                    prev_count = 0.0
                    curr_count = 0.0

            weight = max(0.0, 1.0 - (elapsed / window_seconds))
            estimated = (prev_count * weight) + curr_count

            if estimated + cost <= limit:
                allowed = True
                curr_count += cost
                remaining = max(0.0, limit - (estimated + cost))
            else:
                allowed = False
                remaining = max(0.0, limit - estimated)

            self._sw_data[key] = _SlidingWindowData(
                curr_window_idx=curr_window_idx,
                curr_count=curr_count,
                prev_count=prev_count,
                now=now
            )
            self._evict_lru_if_needed(self._sw_data)

            reset_after_ms = max(0.0, (window_seconds - elapsed) * 1000.0)
            return allowed, remaining, reset_after_ms

    async def leaky_bucket_schedule(
        self,
        key: str,
        capacity: float,
        leak_rate: float,
        cost: float,
        now: Optional[float] = None
    ) -> Tuple[bool, float, float, float]:
        if now is None:
            now = time.monotonic()

        max_queue_delay = (capacity / leak_rate) if leak_rate > 0 else 0.0
        delta_per_cost = (cost / leak_rate) if leak_rate > 0 else 0.0

        lock = await self._get_key_lock("lb:" + key)
        async with lock:
            data = self._lb_data.get(key)
            if data is None or data.next_free < now:
                next_free = now
            else:
                self._lb_data.move_to_end(key)
                next_free = data.next_free

            wait_seconds = max(0.0, next_free - now)

            if wait_seconds + delta_per_cost <= max_queue_delay + 1e-9:
                allowed = True
                new_next_free = next_free + delta_per_cost
                self._lb_data[key] = _LeakyBucketData(next_free=new_next_free, now=now)
                self._evict_lru_if_needed(self._lb_data)
                queue_depth = max(0.0, (new_next_free - now) * leak_rate)
                reset_after_ms = (new_next_free - now) * 1000.0
                return allowed, wait_seconds, queue_depth, reset_after_ms
            else:
                allowed = False
                queue_depth = max(0.0, (next_free - now) * leak_rate)
                reset_after_ms = max(0.0, (next_free - now) * 1000.0)
                return allowed, wait_seconds, queue_depth, reset_after_ms

    async def sweep_expired(self, idle_seconds: float = 60.0) -> int:
        now = time.monotonic()
        purged = 0

        # Purge token buckets idle > idle_seconds
        for k in list(self._tb_data.keys()):
            if now - self._tb_data[k].last_access > idle_seconds:
                self._tb_data.pop(k, None)
                purged += 1

        # Purge sliding window counters idle > idle_seconds
        for k in list(self._sw_data.keys()):
            if now - self._sw_data[k].last_access > idle_seconds:
                self._sw_data.pop(k, None)
                purged += 1

        # Purge leaky buckets idle > idle_seconds
        for k in list(self._lb_data.keys()):
            if now - self._lb_data[k].last_access > idle_seconds:
                self._lb_data.pop(k, None)
                purged += 1

        # Purge idle locks
        async with self._meta_lock:
            for lk in list(self._lock_access.keys()):
                if now - self._lock_access[lk] > idle_seconds:
                    self._lock_access.pop(lk, None)
                    self._locks.pop(lk, None)

        return purged

    async def close(self) -> None:
        self._tb_data.clear()
        self._sw_data.clear()
        self._lb_data.clear()
        self._locks.clear()
        self._lock_access.clear()
