"""
Base rate limiter strategy and Decision data model.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional
from storage.base import BaseStorage


@dataclass(frozen=True)
class Decision:
    """
    Standardized result from an algorithmic rate limiter check.
    """
    allowed: bool
    queued_delay_ms: float
    limit: float
    remaining: float
    reset_after_ms: float
    retry_after_ms: float
    reason: str


class RateLimiterStrategy(ABC):
    """
    Strategy interface for rate limiting algorithms.
    """

    def __init__(self, store: BaseStorage):
        self.store = store

    @abstractmethod
    async def check(
        self,
        identity: str,
        endpoint_cost: int,
        capacity: float,
        rate: float,
        window_seconds: float = 10.0,
        now: Optional[float] = None
    ) -> Decision:
        """
        Evaluate whether the request from identity with endpoint_cost is admitted.
        """
        raise NotImplementedError
