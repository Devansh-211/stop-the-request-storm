"""
Per-Session Sandbox & State Isolation Manager.
Provides independent, isolated rate-limiting defense sandboxes for every browser session.

Each SessionState owns its own:
- DefenseConfig (copied from default template)
- Rate limiting store & limiters (MemoryStorage with per-key locks, LRU cap, TTL)
- MetricsCollector (120s time-series ring buffer, p50/p95, top blocked)
- DegradationCache (Stale-While-Revalidate cache)
- Active simulator task handles
- Last seen timestamp for idle expiration

Single-process concurrency safe.
"""

import os
import re
import time
import secrets
import asyncio
import logging
from typing import Dict, Optional, Tuple, Any, List
from collections import OrderedDict

from config import DefenseConfig
from storage.memory_store import MemoryStorage
from limiters.token_bucket import TokenBucketLimiter
from limiters.sliding_window import SlidingWindowLimiter
from limiters.leaky_bucket import LeakyBucketLimiter
from metrics import MetricsCollector
from cache import DegradationCache

logger = logging.getLogger("shield.session")

# Strict session ID format: 16 to 64 urlsafe characters (letters, digits, underscore, hyphen)
SESSION_ID_REGEX = re.compile(r"^[a-zA-Z0-9_-]{16,64}$")


class SessionState:
    """
    Encapsulates complete isolated state for a single user/browser session.
    """
    __slots__ = (
        "session_id",
        "created_at",
        "last_seen",
        "config",
        "store",
        "tb_limiter",
        "sw_limiter",
        "lb_limiter",
        "metrics",
        "cache",
        "simulator_task",
        "simulator_pattern",
        "lock",
    )

    def __init__(self, session_id: str, default_config: Optional[DefenseConfig] = None):
        self.session_id = session_id
        now = time.time()
        self.created_at = now
        self.last_seen = now

        # Isolated defense config (deep copy from default)
        base = default_config or DefenseConfig()
        self.config = DefenseConfig(**base.model_dump())

        # Isolated storage & limiters
        self.store = MemoryStorage(max_keys=10_000)
        self.tb_limiter = TokenBucketLimiter(self.store)
        self.sw_limiter = SlidingWindowLimiter(self.store)
        self.lb_limiter = LeakyBucketLimiter(self.store)

        # Isolated telemetry ring buffers & SWR cache
        self.metrics = MetricsCollector(buffer_seconds=120)
        self.cache = DegradationCache(fresh_ttl=5.0, stale_ttl=60.0, max_entries=500)

        # Simulator task reference
        self.simulator_task: Optional[asyncio.Task] = None
        self.simulator_pattern: str = "none"

        # Concurrency lock for mutating session state
        self.lock = asyncio.Lock()

    def touch(self) -> None:
        """Update last seen timestamp."""
        self.last_seen = time.time()

    async def cancel_simulator(self) -> None:
        """Cancel and await termination of any active background simulator."""
        if self.simulator_task and not self.simulator_task.done():
            self.simulator_task.cancel()
            try:
                await self.simulator_task
            except (asyncio.CancelledError, Exception):
                pass
        self.simulator_task = None
        self.simulator_pattern = "none"

    async def close(self) -> None:
        """Release all resources held by this session."""
        await self.cancel_simulator()
        await self.store.close()


class SessionManager:
    """
    Manages active sandboxed sessions with LRU bounds, idle sweepers,
    and abuse defenses against session flood.
    """

    def __init__(
        self,
        max_sessions: int = 200,
        idle_timeout_seconds: float = 900.0,  # 15 minutes
        ip_create_limit: int = 10,           # Max 10 new sessions per IP per minute
        max_concurrent_simulations: int = 25
    ):
        self.max_sessions = max_sessions
        self.idle_timeout_seconds = idle_timeout_seconds
        self.ip_create_limit = ip_create_limit
        self.max_concurrent_simulations = max_concurrent_simulations

        # Ordered dict of session_id -> SessionState (most recently used at the end)
        self._sessions: OrderedDict[str, SessionState] = OrderedDict()
        self._lock = asyncio.Lock()

        # IP rate limiting for session creation: ip -> list of creation timestamps
        self._ip_creation_log: Dict[str, List[float]] = {}

    def is_valid_session_id(self, session_id: Optional[str]) -> bool:
        """Validate session ID against strict character and length rules."""
        if not session_id or not isinstance(session_id, str):
            return False
        return bool(SESSION_ID_REGEX.match(session_id))

    def _check_ip_creation_rate(self, client_ip: str, now: float) -> bool:
        """Check if client IP is within session creation abuse cap (10/min)."""
        # Local loopback / testclient is exempt during testing/local development
        if client_ip in ("127.0.0.1", "::1", "localhost", "testclient"):
            return True

        cutoff = now - 60.0
        ts_list = self._ip_creation_log.get(client_ip, [])
        # Filter timestamps older than 60s
        ts_list = [ts for ts in ts_list if ts >= cutoff]
        if len(ts_list) >= self.ip_create_limit:
            self._ip_creation_log[client_ip] = ts_list
            return False
        ts_list.append(now)
        self._ip_creation_log[client_ip] = ts_list
        return True

    async def get_or_create_session(
        self,
        requested_id: Optional[str] = None,
        client_ip: str = "127.0.0.1",
        default_config: Optional[DefenseConfig] = None
    ) -> Tuple[SessionState, bool]:
        """
        Lookup existing session or create a new isolated sandbox.
        Returns: (session_state, is_new_session)
        """
        now = time.time()

        async with self._lock:
            # 1. Check if valid and existing
            if self.is_valid_session_id(requested_id) and requested_id in self._sessions:
                session = self._sessions[requested_id]
                session.touch()
                self._sessions.move_to_end(requested_id)
                return session, False

            # 2. Check per-IP creation limit under flood
            if not self._check_ip_creation_rate(client_ip, now):
                # Under flood, if requested_id is existing (checked above), it would have matched.
                # If creating new, check if we have any fallback or must evict/reuse
                logger.warning(f"Session creation rate limit exceeded for IP: {client_ip}")
                # Reuse oldest session if at limit to avoid hard 500 error
                if self._sessions:
                    oldest_id, oldest_sess = next(iter(self._sessions.items()))
                    oldest_sess.touch()
                    return oldest_sess, False

            # 3. Evict least recently seen session if at capacity
            while len(self._sessions) >= self.max_sessions:
                evict_id, evict_sess = self._sessions.popitem(last=False)
                # Cleanup in background task to avoid blocking lookup
                asyncio.create_task(evict_sess.close())
                logger.info(f"Evicted LRU session: {evict_id}")

            # 4. Generate cryptographically strong session ID
            new_id = secrets.token_urlsafe(16)
            session = SessionState(new_id, default_config=default_config)
            self._sessions[new_id] = session
            return session, True

    async def get_session(self, session_id: Optional[str]) -> Optional[SessionState]:
        """Lookup an existing valid session without creating one."""
        if not self.is_valid_session_id(session_id):
            return None
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is not None:
                session.touch()
                self._sessions.move_to_end(session_id)
            return session

    async def discard_session(self, session_id: str) -> None:
        """Explicitly destroy a session (e.g., user clicked 'New Session')."""
        async with self._lock:
            session = self._sessions.pop(session_id, None)
        if session:
            await session.close()
            logger.info(f"Discarded session: {session_id}")

    async def sweep_idle_sessions(self) -> int:
        """
        Sweeper: terminates simulators and deletes sessions idle for more than idle_timeout_seconds.
        """
        now = time.time()
        expired: List[SessionState] = []

        async with self._lock:
            for s_id, s in list(self._sessions.items()):
                if now - s.last_seen > self.idle_timeout_seconds:
                    expired.append(s)
                    del self._sessions[s_id]

            # Also prune IP creation logs
            cutoff = now - 60.0
            for ip in list(self._ip_creation_log.keys()):
                ts_list = [t for t in self._ip_creation_log[ip] if t >= cutoff]
                if ts_list:
                    self._ip_creation_log[ip] = ts_list
                else:
                    del self._ip_creation_log[ip]

        # Close all expired sessions outside lock
        for s in expired:
            try:
                await s.close()
            except Exception as e:
                logger.error(f"Error closing expired session {s.session_id}: {e}")

        return len(expired)

    def count_active_simulations(self) -> int:
        """Count how many sessions currently have a running simulator."""
        count = 0
        for s in self._sessions.values():
            if s.simulator_task and not s.simulator_task.done():
                count += 1
        return count

    def get_summary(self) -> Dict[str, Any]:
        """Administrative summary of all sessions."""
        now = time.time()
        sessions_info = []
        for s_id, s in self._sessions.items():
            sessions_info.append({
                "session_id": s_id,
                "created_at": s.created_at,
                "age_seconds": round(now - s.created_at, 1),
                "idle_seconds": round(now - s.last_seen, 1),
                "algorithm": s.config.algorithm,
                "shield_enabled": s.config.shield_enabled,
                "simulator_active": s.simulator_task is not None and not s.simulator_task.done(),
                "simulator_pattern": s.simulator_pattern,
            })
        return {
            "total_sessions": len(self._sessions),
            "max_sessions": self.max_sessions,
            "active_simulations": self.count_active_simulations(),
            "sessions": sessions_info
        }


# Global Session Manager Singleton
SESSION_MANAGER = SessionManager()
