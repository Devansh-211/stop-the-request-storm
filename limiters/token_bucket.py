"""
Token Bucket rate limiter strategy.
Bursts up to capacity, refills at refill_rate tokens/sec with atomic lazy refill.
"""

from typing import Optional
from limiters.base import RateLimiterStrategy, Decision


class TokenBucketLimiter(RateLimiterStrategy):
    """
    Token bucket algorithm implementation using atomic storage primitives.
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
        allowed, remaining, reset_after_ms = await self.store.token_bucket_consume(
            key=identity,
            capacity=capacity,
            refill_rate=rate,
            cost=float(endpoint_cost),
            now=now
        )

        if allowed:
            return Decision(
                allowed=True,
                queued_delay_ms=0.0,
                limit=capacity,
                remaining=remaining,
                reset_after_ms=reset_after_ms,
                retry_after_ms=0.0,
                reason="TOKEN_BUCKET_ALLOWED"
            )
        else:
            needed = float(endpoint_cost) - remaining
            retry_after_ms = (needed / rate * 1000.0) if rate > 0 else 1000.0
            return Decision(
                allowed=False,
                queued_delay_ms=0.0,
                limit=capacity,
                remaining=remaining,
                reset_after_ms=reset_after_ms,
                retry_after_ms=max(100.0, retry_after_ms),
                reason="TOKEN_BUCKET_EXHAUSTED"
            )
