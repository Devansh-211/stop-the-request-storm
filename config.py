"""
Dynamic defense configuration, tier multipliers, key registry, and endpoint cost/cache map.
"""

import os
from typing import Dict, Optional, Set
from pydantic import BaseModel, Field


class TierMultiplier:
    FREE = 1.0
    PRO = 5.0
    ENTERPRISE = 20.0


# Demo API Key registry: maps API key string to tier
DEMO_KEY_REGISTRY: Dict[str, str] = {
    "free-demo-key": "FREE",
    "pro-demo-key": "PRO",
    "ent-demo-key": "ENTERPRISE",
}

# Variable endpoint costs (Token bucket / sliding window / leaky bucket consumption)
ENDPOINT_COST_MAP: Dict[str, int] = {
    "GET /api/ping": 1,
    "GET /api/data": 2,
    "POST /api/heavy-compute": 5,
}

# Endpoints eligible for graceful degradation (must be identity-independent read routes)
CACHEABLE_ENDPOINTS: Set[str] = {
    "GET /api/data",
    "GET /api/ping",
}

# Paths exempt from all rate limiting and shielding (must never be throttled)
EXEMPT_PATHS: Set[str] = {
    "/",
    "/health",
    "/session/new",
    "/session/current",
    "/control/state",
    "/control/config",
    "/control/metrics",
    "/control/log",
    "/control/simulate/stop",
    "/control/admin/sessions",
}


def is_exempt_path(path: str) -> bool:
    """Check if the given request path is exempt from rate limiting."""
    if path in EXEMPT_PATHS:
        return True
    if path.startswith("/static/") or path.startswith("/ws/") or path.startswith("/control/"):
        return True
    return False


class DefenseConfig(BaseModel):
    """
    Live mutable defense configuration state.
    Validated with Pydantic for dynamic updates via the Control API.
    """
    shield_enabled: bool = Field(default=True, description="Master switch for Shield protection")
    algorithm: str = Field(default="token_bucket", description="Rate limiter algorithm: token_bucket | sliding_window | leaky_bucket")
    
    # Base throttling params
    base_capacity: float = Field(default=10.0, ge=1.0, le=1000.0, description="Base token/window capacity")
    base_refill_rate: float = Field(default=1.0, ge=0.1, le=500.0, description="Base tokens/leaks per second")
    window_seconds: float = Field(default=10.0, ge=1.0, le=300.0, description="Sliding window duration in seconds")
    
    # Upstream Admission Cap & Storm Mode
    max_upstream_rps: float = Field(default=60.0, ge=5.0, le=1000.0, description="Global upstream admission cap (RPS)")
    storm_mode_enabled: bool = Field(default=True, description="Enable automatic adaptive storm defense")
    storm_rps_threshold: float = Field(default=100.0, ge=10.0, le=5000.0, description="RPS threshold to activate storm mode")
    storm_ip_threshold: int = Field(default=50, ge=5, le=5000, description="Distinct blocked identity threshold for storm mode")
    storm_tighten_factor: float = Field(default=0.5, ge=0.05, le=1.0, description="Multiplier to tighten anonymous/FREE limits during storms")
    
    # Graceful Degradation
    degradation_mode: bool = Field(default=True, description="Enable stale-while-revalidate cached fallback on throttle")
    
    # Jitter & Upstream concurrency
    retry_after_jitter_max: float = Field(default=1.5, ge=0.0, le=10.0, description="Random jitter added to Retry-After seconds")
    upstream_concurrency: int = Field(default=16, ge=1, le=256, description="Mock upstream concurrency limit semaphore")
    trust_forwarded_for: bool = Field(default=True, description="Trust X-Forwarded-For when client IP is loopback/trusted")


# Default defense configuration template
DEFAULT_DEFENSE_CONFIG = DefenseConfig()

# Global default config fallback for backwards compatibility
ACTIVE_CONFIG = DefenseConfig()
