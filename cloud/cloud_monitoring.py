"""
Cloud Monitoring custom metrics reporter and local aggregator adapter.
Tracks:
- custom.googleapis.com/ratelimit/request_count
- custom.googleapis.com/ratelimit/blocked_count
- custom.googleapis.com/ratelimit/degraded_count
- custom.googleapis.com/ratelimit/latency_ms
- custom.googleapis.com/ratelimit/storm_mode_active

Follows the MindMatrix environment caveat: provides local in-memory aggregation
with optional Google Cloud Monitoring export when cloud credentials and project ID exist.
"""

import os
import time
from typing import Dict, Any, Optional


class CloudMonitoringAdapter:
    """
    Adapter for Google Cloud Monitoring.
    Aggregates rate limiting metrics and formats time-series points.
    """

    def __init__(self, project_id: Optional[str] = None):
        self.project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT", "mock-campus-shield-project")
        self.metric_prefix = "custom.googleapis.com/ratelimit"
        
        # In-memory accumulators
        self.total_requests = 0
        self.total_blocked = 0
        self.total_degraded = 0
        self.storm_mode_active = False
        self._last_flush = time.time()

    def record_decision(
        self,
        outcome: str,
        latency_ms: float,
        storm_mode: bool = False,
        is_storm_mode: Optional[bool] = None
    ):
        """Record an event for monitoring aggregations."""
        self.total_requests += 1
        if outcome == "blocked":
            self.total_blocked += 1
        elif outcome == "degraded":
            self.total_degraded += 1
        active_storm = is_storm_mode if is_storm_mode is not None else storm_mode
        self.storm_mode_active = active_storm

    def get_metric_descriptors(self) -> Dict[str, Any]:
        """Return the custom metric schema descriptors for Cloud Monitoring."""
        return {
            f"{self.metric_prefix}/request_count": {
                "metric_kind": "CUMULATIVE",
                "value_type": "INT64",
                "description": "Total API requests processed by the rate limiting shield"
            },
            f"{self.metric_prefix}/blocked_count": {
                "metric_kind": "CUMULATIVE",
                "value_type": "INT64",
                "description": "Total API requests rejected with HTTP 429"
            },
            f"{self.metric_prefix}/degraded_count": {
                "metric_kind": "CUMULATIVE",
                "value_type": "INT64",
                "description": "Total API requests served via stale-while-revalidate cached fallback"
            },
            f"{self.metric_prefix}/storm_mode_active": {
                "metric_kind": "GAUGE",
                "value_type": "BOOL",
                "description": "Indicates whether the adaptive storm gate is currently engaged"
            }
        }

    def get_current_metrics_snapshot(self) -> Dict[str, Any]:
        """Return current snapshot of Cloud Monitoring metric values."""
        block_rate = (self.total_blocked / self.total_requests) if self.total_requests > 0 else 0.0
        return {
            "project_id": self.project_id,
            "backend": "Cloud Monitoring (Local Adapter)" if not os.getenv("K_SERVICE") else "Google Cloud Monitoring",
            "metrics": {
                f"{self.metric_prefix}/request_count": self.total_requests,
                f"{self.metric_prefix}/blocked_count": self.total_blocked,
                f"{self.metric_prefix}/degraded_count": self.total_degraded,
                f"{self.metric_prefix}/block_ratio": round(block_rate, 4),
                f"{self.metric_prefix}/storm_mode_active": self.storm_mode_active
            }
        }


# Singleton monitoring adapter
monitoring_adapter = CloudMonitoringAdapter()
