"""
Abstract storage interface for rate limiter state engines.
"""

from abc import ABC, abstractmethod
from typing import Tuple, Optional


class BaseStorage(ABC):
    """
    Abstract storage primitives for Rate Limiting algorithms.
    All operations must be atomic and non-blocking.
    """

    @abstractmethod
    async def token_bucket_consume(
        self,
        key: str,
        capacity: float,
        refill_rate: float,
        cost: float,
        now: Optional[float] = None
    ) -> Tuple[bool, float, float]:
        """
        Atomic lazy-refill and consume tokens.
        Returns:
            allowed (bool): True if enough tokens were available and deducted.
            remaining (float): Available tokens after operation.
            reset_after_ms (float): Milliseconds until bucket refills to full capacity.
        """
        raise NotImplementedError

    @abstractmethod
    async def sliding_window_record(
        self,
        key: str,
        window_seconds: float,
        cost: float,
        limit: float,
        now: Optional[float] = None
    ) -> Tuple[bool, float, float]:
        """
        Atomic sliding window counter evaluation.
        Estimated usage = prev_count * (1 - elapsed/window) + curr_count.
        Admit if estimated + cost <= limit.
        Returns:
            allowed (bool): True if within limit.
            remaining (float): Estimated remaining capacity before limit.
            reset_after_ms (float): Milliseconds until current window expires.
        """
        raise NotImplementedError

    @abstractmethod
    async def leaky_bucket_schedule(
        self,
        key: str,
        capacity: float,
        leak_rate: float,
        cost: float,
        now: Optional[float] = None
    ) -> Tuple[bool, float, float, float]:
        """
        Atomic virtual scheduling for leaky bucket / traffic shaping.
        outflow_delay = max(0, next_free - now).
        Allowed if outflow_delay <= (capacity / leak_rate).
        Returns:
            allowed (bool): True if within max queue capacity.
            wait_seconds (float): Delay in seconds before outflow should happen.
            queue_depth (float): Number of pending requests/tokens queued.
            reset_after_ms (float): Milliseconds until bucket leaks completely empty.
        """
        raise NotImplementedError

    @abstractmethod
    async def sweep_expired(self) -> int:
        """
        Sweep expired state entries or idle locks to prevent memory leaks.
        Returns count of purged keys.
        """
        raise NotImplementedError

    @abstractmethod
    async def close(self) -> None:
        """Gracefully release any resources/connections."""
        raise NotImplementedError
