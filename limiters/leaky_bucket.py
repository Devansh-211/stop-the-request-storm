"""
Leaky Bucket / Traffic Queue Shaper strategy.
Virtual scheduling: wait = max(0, next_free - now).
If wait <= max_queue_delay (capacity / leak_rate), admit as QUEUED (delay caller outside lock).
Otherwise drop as overflow.
"""

from typing import Optional
from limiters.base import RateLimiterStrategy, Decision


class LeakyBucketLimiter(RateLimiterStrategy):
    """
    True traffic shaper rate limiter.
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
        allowed, wait_seconds, queue_depth, reset_after_ms = await self.store.leaky_bucket_schedule(
            key=identity,
            capacity=capacity,
            leak_rate=rate,
            cost=float(endpoint_cost),
            now=now
        )

        limit = capacity
        remaining = max(0.0, limit - queue_depth)
        queued_delay_ms = wait_seconds * 1000.0

        if allowed:
            return Decision(
                allowed=True,
                queued_delay_ms=queued_delay_ms,
                limit=limit,
                remaining=remaining,
                reset_after_ms=reset_after_ms,
                retry_after_ms=0.0,
                reason="LEAKY_BUCKET_QUEUED" if queued_delay_ms > 0 else "LEAKY_BUCKET_ALLOWED"
            )
        else:
            return Decision(
                allowed=False,
                queued_delay_ms=0.0,
                limit=limit,
                remaining=0.0,
                reset_after_ms=reset_after_ms,
                retry_after_ms=max(100.0, reset_after_ms),
                reason="LEAKY_BUCKET_OVERFLOW"
            )
