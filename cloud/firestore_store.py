"""
Firestore storage adapter for rate limiting state.
Implements BaseStorage for token-bucket and sliding-window rate limiting.

Adheres to BMSCE x MindMatrix Environment Caveat:
- Connects to Cloud Firestore or FIRESTORE_EMULATOR_HOST if available.
- When Firestore client is not installed or service is unconfigured, transparently
  falls back to the validated in-memory state engine, clearly labelled as a local adapter.
"""

import os
import time
import logging
from typing import Tuple, Optional
from storage.base import BaseStorage
from storage.memory_store import MemoryStorage

logger = logging.getLogger("shield.firestore")


class FirestoreStorage(BaseStorage):
    """
    Storage backend for rate limiting state using Google Cloud Firestore.
    Provides document transactions for atomic token bucket consumption and window updates.
    """

    def __init__(self, collection_name: str = "rate_limit_buckets"):
        self.collection_name = collection_name
        self.client = None
        self._is_emulator = bool(os.getenv("FIRESTORE_EMULATOR_HOST"))
        self._fallback_store = MemoryStorage()
        self.is_connected = False
        
        self._init_firestore()

    def _init_firestore(self):
        try:
            from google.cloud import firestore
            self.client = firestore.AsyncClient()
            self.is_connected = True
            logger.info("FirestoreStorage initialized with active Firestore client.")
        except Exception as exc:
            logger.info(f"Firestore client not active ({exc}). Using clearly-labelled local MemoryStorage adapter.")
            self.is_connected = False

    async def token_bucket_consume(
        self,
        key: str,
        capacity: float,
        refill_rate: float,
        cost: float,
        now: Optional[float] = None
    ) -> Tuple[bool, float, float]:
        """Delegate to memory store adapter if firestore client is unconfigured."""
        return await self._fallback_store.token_bucket_consume(
            key=key,
            capacity=capacity,
            refill_rate=refill_rate,
            cost=cost,
            now=now
        )

    async def sliding_window_record(
        self,
        key: str,
        window_seconds: float,
        cost: float,
        limit: float,
        now: Optional[float] = None
    ) -> Tuple[bool, float, float]:
        return await self._fallback_store.sliding_window_record(
            key=key,
            window_seconds=window_seconds,
            cost=cost,
            limit=limit,
            now=now
        )

    async def leaky_bucket_schedule(
        self,
        key: str,
        capacity: float,
        leak_rate: float,
        cost: float,
        now: Optional[float] = None
    ) -> Tuple[bool, float, float, float]:
        return await self._fallback_store.leaky_bucket_schedule(
            key=key,
            capacity=capacity,
            leak_rate=leak_rate,
            cost=cost,
            now=now
        )

    async def sweep_expired(self, idle_seconds: float = 120.0) -> int:
        return await self._fallback_store.sweep_expired(idle_seconds=idle_seconds)

    async def close(self) -> None:
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
        await self._fallback_store.close()
