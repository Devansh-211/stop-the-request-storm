"""
Graceful degradation cache with Stale-While-Revalidate semantics and single-flight background refresh.
"""

import time
import asyncio
from typing import Dict, Optional, Tuple, Any, Callable


class CacheEntry:
    __slots__ = ("status_code", "headers", "body", "created_at", "fresh_ttl", "stale_ttl")

    def __init__(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: bytes,
        fresh_ttl: float = 5.0,
        stale_ttl: float = 60.0
    ):
        self.status_code = status_code
        self.headers = headers
        self.body = body
        self.created_at = time.time()
        self.fresh_ttl = fresh_ttl
        self.stale_ttl = stale_ttl

    def is_fresh(self, now: float) -> bool:
        return (now - self.created_at) <= self.fresh_ttl

    def is_stale(self, now: float) -> bool:
        age = now - self.created_at
        return (age > self.fresh_ttl) and (age <= self.stale_ttl)

    def is_expired(self, now: float) -> bool:
        return (now - self.created_at) > self.stale_ttl

    @property
    def age(self) -> int:
        return int(max(0.0, time.time() - self.created_at))


class DegradationCache:
    """
    In-memory stale-while-revalidate fallback cache.
    Caches successful read responses (GET/HEAD) for cacheable endpoints.
    Protects upstream by deduplicating revalidation tasks (single-flight)
    and throttling refreshes to at most once per 5 seconds per key.
    """

    def __init__(self, fresh_ttl: float = 5.0, stale_ttl: float = 60.0, max_entries: int = 2000):
        self.fresh_ttl = fresh_ttl
        self.stale_ttl = stale_ttl
        self.max_entries = max_entries
        self._entries: Dict[str, CacheEntry] = {}
        self._revalidating_keys: set[str] = set()
        self._last_revalidation_time: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    def build_key(self, method: str, path: str, query_string: str = "") -> str:
        """Cache keys are based strictly on method, path, and sorted query params."""
        parts = query_string.split("&") if query_string else []
        sorted_query = "&".join(sorted(parts))
        return f"{method.upper()}:{path}:{sorted_query}"

    async def get(self, key: str) -> Tuple[Optional[CacheEntry], str]:
        """
        Lookup cache entry.
        Returns:
            entry: CacheEntry or None
            state: 'fresh' | 'stale' | 'miss'
        """
        now = time.time()
        async with self._lock:
            entry = self._entries.get(key)
            if entry is None or entry.is_expired(now):
                if entry is not None:
                    del self._entries[key]
                return None, "miss"

            if entry.is_fresh(now):
                return entry, "fresh"
            elif entry.is_stale(now):
                return entry, "stale"
            else:
                return None, "miss"

    async def set(self, key: str, status_code: int, headers: Dict[str, str], body: bytes) -> None:
        """Store or update a response entry."""
        if status_code != 200:
            return

        async with self._lock:
            if len(self._entries) >= self.max_entries:
                # Evict oldest
                oldest_k = next(iter(self._entries))
                del self._entries[oldest_k]

            self._entries[key] = CacheEntry(
                status_code=status_code,
                headers=headers,
                body=body,
                fresh_ttl=self.fresh_ttl,
                stale_ttl=self.stale_ttl
            )

    async def trigger_revalidate(
        self,
        key: str,
        revalidate_coro_fn: Callable[[], Any]
    ) -> bool:
        """
        Trigger single-flight background revalidation.
        Guarantees at most 1 refresh per key per 5 seconds so it cannot amplify storms.
        """
        now = time.time()
        async with self._lock:
            if key in self._revalidating_keys:
                return False

            last_reval = self._last_revalidation_time.get(key, 0.0)
            if (now - last_reval) < 5.0:
                return False

            self._revalidating_keys.add(key)
            self._last_revalidation_time[key] = now

        async def _revalidate_worker():
            try:
                await revalidate_coro_fn()
            except Exception:
                pass
            finally:
                async with self._lock:
                    self._revalidating_keys.discard(key)

        asyncio.create_task(_revalidate_worker())
        return True

    async def sweep_expired(self) -> int:
        """Purge entries older than stale_ttl."""
        now = time.time()
        purged = 0
        async with self._lock:
            keys_to_del = [k for k, v in self._entries.items() if v.is_expired(now)]
            for k in keys_to_del:
                del self._entries[k]
                purged += 1
        return purged


# Global degradation cache instance
DEGRADATION_CACHE = DegradationCache()
