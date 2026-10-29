"""
Sliding Window Counter rate limiter strategy.
Estimates usage over sub-windows: prev_count * (1 - elapsed/window) + curr_count.
"""

from typing import Optional
from limiters.base import RateLimiterStrategy, Decision


class SlidingWindowLimiter(RateLimiterStrategy):
    """
    Sliding window counter strategy smoothing boundary burst conditions.
    """

    async def check(
        self,
        identity: str,
        endpoint_cost: int,
        capacity: float,
        rate: float,
        window_seconds: float = 10.0,
        now: Optional[float] = None
    ) -> Decision:
        limit = capacity
        allowed, remaining, reset_after_ms = await self.store.sliding_window_record(
            key=identity,
            window_seconds=window_seconds,
            cost=float(endpoint_cost),
            limit=limit,
            now=now
        )

        if allowed:
            return Decision(
                allowed=True,
                queued_delay_ms=0.0,
                limit=limit,
                remaining=remaining,
                reset_after_ms=reset_after_ms,
                retry_after_ms=0.0,
                reason="SLIDING_WINDOW_ALLOWED"
            )
        else:
            return Decision(
                allowed=False,
                queued_delay_ms=0.0,
                limit=limit,
                remaining=remaining,
                reset_after_ms=reset_after_ms,
                retry_after_ms=max(100.0, reset_after_ms),
                reason="SLIDING_WINDOW_EXCEEDED"
            )
