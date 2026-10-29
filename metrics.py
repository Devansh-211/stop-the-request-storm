"""
Telemetry ring buffers, latency percentiles, and live metrics snapshot generator.
"""

import time
import math
from collections import deque
from typing import Dict, Any, List, Tuple


class MetricsCollector:
    """
    In-memory lock-free/low-overhead telemetry recorder.
    Tracks:
    - 120s ring buffer of per-second status counters (accepted, degraded, queued, blocked).
    - Rolling 10s latency samples (p50, p95).
    - Legitimate vs attack traffic counters.
    - Blocked identity frequency.
    """

    def __init__(self, buffer_seconds: int = 120):
        self.buffer_seconds = buffer_seconds
        # Ring buffers: indexed by epoch_second % buffer_seconds
        self._timestamps = [0] * buffer_seconds
        self._accepted = [0] * buffer_seconds
        self._degraded = [0] * buffer_seconds
        self._queued = [0] * buffer_seconds
        self._blocked = [0] * buffer_seconds
        self._legit_total = [0] * buffer_seconds
        self._legit_accepted = [0] * buffer_seconds
        self._attack_total = [0] * buffer_seconds
        self._attack_blocked = [0] * buffer_seconds

        # Recent latency samples: (timestamp, latency_ms)
        self._latencies: deque[Tuple[float, float]] = deque(maxlen=2000)

        # Blocked identities counter for top-5 view and storm detector
        self._blocked_identities: Dict[str, int] = {}
        self._blocked_identities_ts: deque[Tuple[float, str]] = deque(maxlen=5000)

        # Storm detection state
        self._storm_mode_active = False
        self._last_storm_trigger_time = 0.0

    def _get_slot(self, now_sec: int) -> int:
        idx = now_sec % self.buffer_seconds
        if self._timestamps[idx] != now_sec:
            # New second: reset this slot
            self._timestamps[idx] = now_sec
            self._accepted[idx] = 0
            self._degraded[idx] = 0
            self._queued[idx] = 0
            self._blocked[idx] = 0
            self._legit_total[idx] = 0
            self._legit_accepted[idx] = 0
            self._attack_total[idx] = 0
            self._attack_blocked[idx] = 0
        return idx

    def record_request(
        self,
        status: str,
        latency_ms: float,
        identity: str,
        sim_class: str = "none"
    ) -> None:
        """
        Record a request outcome.
        status in ('accepted', 'degraded', 'queued', 'blocked')
        sim_class in ('legit', 'attack', 'none')
        """
        now = time.time()
        now_sec = int(now)
        slot = self._get_slot(now_sec)

        if status == "accepted":
            self._accepted[slot] += 1
        elif status == "queued":
            self._queued[slot] += 1
        elif status in ("blocked", "degraded"):
            if status == "blocked":
                self._blocked[slot] += 1
            else:
                self._degraded[slot] += 1
            self._blocked_identities[identity] = self._blocked_identities.get(identity, 0) + 1
            self._blocked_identities_ts.append((now, identity))

        # Simulation attribution
        if sim_class == "legit":
            self._legit_total[slot] += 1
            if status in ("accepted", "degraded", "queued"):
                self._legit_accepted[slot] += 1
        elif sim_class == "attack":
            self._attack_total[slot] += 1
            if status in ("blocked", "degraded"):
                self._attack_blocked[slot] += 1

        self._latencies.append((now, latency_ms))

    def evaluate_storm_mode(
        self,
        enabled: bool,
        rps_threshold: float,
        ip_threshold: int
    ) -> bool:
        """
        Check 5s rolling RPS and blocked unique identities.
        Activates storm mode if conditions met; auto-clears after 10s calm.
        """
        if not enabled:
            self._storm_mode_active = False
            return False

        now = time.time()
        now_sec = int(now)

        # 5-second sum
        total_reqs_5s = 0
        for s in range(now_sec - 4, now_sec + 1):
            idx = s % self.buffer_seconds
            if self._timestamps[idx] == s:
                total_reqs_5s += (
                    self._accepted[idx]
                    + self._degraded[idx]
                    + self._queued[idx]
                    + self._blocked[idx]
                )
        rolling_rps = total_reqs_5s / 5.0

        # Unique blocked identities in past 5s
        cutoff_5s = now - 5.0
        recent_blocked_ips = {
            ident for ts, ident in self._blocked_identities_ts if ts >= cutoff_5s
        }

        should_trigger = (rolling_rps > rps_threshold) or (len(recent_blocked_ips) > ip_threshold)

        if should_trigger:
            self._storm_mode_active = True
            self._last_storm_trigger_time = now
        else:
            # 10s calm duration required to clear
            if self._storm_mode_active and (now - self._last_storm_trigger_time > 10.0):
                self._storm_mode_active = False

        return self._storm_mode_active

    def get_snapshot(self, store_backend: str, active_buckets_count: int = 0) -> Dict[str, Any]:
        """
        Generate time-series payload and stat summary for WebSocket/Control API.
        """
        now = time.time()
        now_sec = int(now)

        # 120-second time series sorted chronologically
        history_accepted: List[int] = []
        history_degraded: List[int] = []
        history_queued: List[int] = []
        history_blocked: List[int] = []
        history_timestamps: List[int] = []

        start_sec = now_sec - self.buffer_seconds + 1
        for s in range(start_sec, now_sec + 1):
            idx = s % self.buffer_seconds
            if self._timestamps[idx] == s:
                history_timestamps.append(s)
                history_accepted.append(self._accepted[idx])
                history_degraded.append(self._degraded[idx])
                history_queued.append(self._queued[idx])
                history_blocked.append(self._blocked[idx])
            else:
                history_timestamps.append(s)
                history_accepted.append(0)
                history_degraded.append(0)
                history_queued.append(0)
                history_blocked.append(0)

        # Calculate current instantaneous RPS (rolling active window across last 2s)
        prev_sec = now_sec - 1
        prev_idx = prev_sec % self.buffer_seconds
        now_idx = now_sec % self.buffer_seconds
        rps_prev = 0
        rps_now = 0
        if self._timestamps[prev_idx] == prev_sec:
            rps_prev = (
                self._accepted[prev_idx]
                + self._degraded[prev_idx]
                + self._queued[prev_idx]
                + self._blocked[prev_idx]
            )
        if self._timestamps[now_idx] == now_sec:
            rps_now = (
                self._accepted[now_idx]
                + self._degraded[now_idx]
                + self._queued[now_idx]
                + self._blocked[now_idx]
            )
        # Use whichever is actively recording traffic or average them
        current_rps = max(rps_prev, rps_now)

        # Calculate p50 / p95 latency over past 10 seconds
        cutoff_10s = now - 10.0
        recent_lats = sorted([lat for ts, lat in self._latencies if ts >= cutoff_10s])
        if recent_lats:
            n = len(recent_lats)
            p50_idx = max(0, int(math.ceil(0.50 * n)) - 1)
            p95_idx = max(0, int(math.ceil(0.95 * n)) - 1)
            p50_lat = round(recent_lats[p50_idx], 2)
            p95_lat = round(recent_lats[p95_idx], 2)
        else:
            p50_lat = 0.0
            p95_lat = 0.0

        # Legitimate user success % and attack block % over past 30 seconds
        legit_tot = 0
        legit_acc = 0
        attack_tot = 0
        attack_blk = 0
        for s in range(now_sec - 29, now_sec + 1):
            idx = s % self.buffer_seconds
            if self._timestamps[idx] == s:
                legit_tot += self._legit_total[idx]
                legit_acc += self._legit_accepted[idx]
                attack_tot += self._attack_total[idx]
                attack_blk += self._attack_blocked[idx]

        legit_success_pct = round((legit_acc / legit_tot * 100.0), 1) if legit_tot > 0 else 100.0
        attack_block_pct = round((attack_blk / attack_tot * 100.0), 1) if attack_tot > 0 else 0.0

        # Top 5 blocked identities
        top_5_blocked = sorted(
            self._blocked_identities.items(), key=lambda kv: kv[1], reverse=True
        )[:5]
        top_5_formatted = [{"identity": k, "count": v} for k, v in top_5_blocked]

        return {
            "timestamp": now,
            "store_backend": store_backend,
            "current_rps": current_rps,
            "p50_latency_ms": p50_lat,
            "p95_latency_ms": p95_lat,
            "legit_success_pct": legit_success_pct,
            "attack_block_pct": attack_block_pct,
            "active_buckets": active_buckets_count,
            "storm_mode": self._storm_mode_active,
            "top_blocked": top_5_formatted,
            "series": {
                "timestamps": history_timestamps,
                "accepted": history_accepted,
                "degraded": history_degraded,
                "queued": history_queued,
                "blocked": history_blocked,
            }
        }


# Global metrics collector instance
METRICS = MetricsCollector()
