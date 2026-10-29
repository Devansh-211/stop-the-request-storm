"""
Telemetry ring buffers, latency percentiles, status code counters, and live request log.
"""

import time
import math
from collections import deque
from typing import Dict, Any, List, Tuple, Optional


def mask_identity(raw_identity: str, tier: str = "FREE") -> str:
    """
    Mask identity to prevent leaking sensitive or private data:
    - IPv4 addresses: Keep only first 2 octets (e.g. 198.51.*.*)
    - API keys: Mask completely and show only tier label (e.g. API_KEY [PRO])
    Never log raw API keys.
    """
    if not raw_identity:
        return "anonymous"

    # Strip ip: or key: prefix if present
    ident = raw_identity
    is_key = False
    if ident.startswith("key:"):
        is_key = True
        ident = ident[4:]
    elif ident.startswith("ip:"):
        ident = ident[3:]

    if is_key or "demo-key" in ident or ident.startswith("bot-"):
        return f"API_KEY [{tier}]"

    # Check for IPv4
    parts = ident.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.{parts[1]}.*.*"

    # Check for IPv6 or localhost
    if ":" in ident or ident in ("localhost", "127.0.0.1", "testclient"):
        return "127.0.*.*"

    # Default fallback
    return f"{ident[:4]}***"


class MetricsCollector:
    """
    In-memory lock-free/low-overhead telemetry recorder.
    Tracks:
    - 120s ring buffer of per-second status counters (accepted, degraded, queued, blocked).
    - 120s ring buffer of HTTP status codes (200, degraded_200, 429, 502, 504, other).
    - Bounded per-session request log (deque maxlen=200).
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

        # Status code ring buffers (120s)
        self._status_200 = [0] * buffer_seconds
        self._status_degraded_200 = [0] * buffer_seconds
        self._status_429 = [0] * buffer_seconds
        self._status_502 = [0] * buffer_seconds
        self._status_504 = [0] * buffer_seconds
        self._status_other = [0] * buffer_seconds

        # Cumulative counters
        self._total_200 = 0
        self._total_degraded_200 = 0
        self._total_429 = 0
        self._total_5xx = 0
        self._total_other = 0

        # Bounded request log: maxlen=200
        self._request_log: deque[Dict[str, Any]] = deque(maxlen=200)

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

            # Status codes
            self._status_200[idx] = 0
            self._status_degraded_200[idx] = 0
            self._status_429[idx] = 0
            self._status_502[idx] = 0
            self._status_504[idx] = 0
            self._status_other[idx] = 0
        return idx

    def record_request(
        self,
        status: str,
        latency_ms: float,
        identity: str,
        sim_class: str = "none",
        status_code: int = 200,
        method: str = "GET",
        path: str = "/api/data",
        tier: str = "FREE",
        cost: int = 1,
        reason: str = "allowed",
        retry_after_s: int = 0,
        response_headers: Optional[Dict[str, str]] = None
    ) -> None:
        """
        Record a request outcome, status code counts, and bounded log entry.
        status in ('accepted', 'degraded', 'queued', 'blocked')
        sim_class in ('legit', 'attack', 'none')
        """
        now = time.time()
        now_sec = int(now)
        slot = self._get_slot(now_sec)

        # 1. Flow outcome counters
        if status == "accepted":
            self._accepted[slot] += 1
        elif status == "queued":
            self._queued[slot] += 1
        elif status in ("blocked", "degraded"):
            if status == "blocked":
                self._blocked[slot] += 1
            else:
                self._degraded[slot] += 1
            masked_id = mask_identity(identity, tier)
            self._blocked_identities[masked_id] = self._blocked_identities.get(masked_id, 0) + 1
            self._blocked_identities_ts.append((now, masked_id))

        # 2. HTTP Status Code categorization
        if status_code == 200:
            if status == "degraded":
                self._status_degraded_200[slot] += 1
                self._total_degraded_200 += 1
            else:
                self._status_200[slot] += 1
                self._total_200 += 1
        elif status_code == 429:
            self._status_429[slot] += 1
            self._total_429 += 1
        elif status_code == 502:
            self._status_502[slot] += 1
            self._total_5xx += 1
        elif status_code == 504:
            self._status_504[slot] += 1
            self._total_5xx += 1
        elif 500 <= status_code < 600:
            self._status_502[slot] += 1
            self._total_5xx += 1
        else:
            self._status_other[slot] += 1
            self._total_other += 1

        # 3. Simulation attribution
        if sim_class == "legit":
            self._legit_total[slot] += 1
            if status in ("accepted", "degraded", "queued"):
                self._legit_accepted[slot] += 1
        elif sim_class == "attack":
            self._attack_total[slot] += 1
            if status in ("blocked", "degraded"):
                self._attack_blocked[slot] += 1

        self._latencies.append((now, latency_ms))

        # 4. Bounded per-session request log (safely masked)
        masked_ident = mask_identity(identity, tier)
        safe_hdrs = {}
        if response_headers:
            for k, v in response_headers.items():
                lk = k.lower()
                if lk in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "retry-after", "x-degraded-mode", "content-type"):
                    safe_hdrs[lk] = v

        log_entry = {
            "id": f"{int(now * 1000)}-{len(self._request_log) + 1}",
            "ts": round(now, 3),
            "time_str": time.strftime("%H:%M:%S", time.localtime(now)) + f".{int((now % 1) * 1000):03d}",
            "method": method.upper(),
            "path": path,
            "status": status_code,
            "outcome": status,
            "identity": masked_ident,
            "tier": tier,
            "latency_ms": round(latency_ms, 2),
            "cost": cost,
            "reason": reason,
            "retry_after_s": retry_after_s,
            "headers": safe_hdrs
        }
        self._request_log.appendleft(log_entry)

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
            if self._storm_mode_active and (now - self._last_storm_trigger_time > 10.0):
                self._storm_mode_active = False

        return self._storm_mode_active

    def get_snapshot(
        self,
        store_backend: str,
        active_buckets_count: int = 0,
        since_ts: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Generate time-series payload, status code distribution, and recent request logs.
        """
        now = time.time()
        now_sec = int(now)

        # 120-second time series sorted chronologically
        history_accepted: List[int] = []
        history_degraded: List[int] = []
        history_queued: List[int] = []
        history_blocked: List[int] = []
        history_timestamps: List[int] = []

        series_200: List[int] = []
        series_degraded_200: List[int] = []
        series_429: List[int] = []
        series_5xx: List[int] = []

        start_sec = now_sec - self.buffer_seconds + 1
        for s in range(start_sec, now_sec + 1):
            idx = s % self.buffer_seconds
            history_timestamps.append(s)
            if self._timestamps[idx] == s:
                history_accepted.append(self._accepted[idx])
                history_degraded.append(self._degraded[idx])
                history_queued.append(self._queued[idx])
                history_blocked.append(self._blocked[idx])

                series_200.append(self._status_200[idx])
                series_degraded_200.append(self._status_degraded_200[idx])
                series_429.append(self._status_429[idx])
                series_5xx.append(self._status_502[idx] + self._status_504[idx])
            else:
                history_accepted.append(0)
                history_degraded.append(0)
                history_queued.append(0)
                history_blocked.append(0)

                series_200.append(0)
                series_degraded_200.append(0)
                series_429.append(0)
                series_5xx.append(0)

        # Rolling active window RPS across last 2s
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
        current_rps = max(rps_prev, rps_now)

        # Latency p50/p95 over past 10s
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

        # Legitimate & attack percentages over past 30s
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

        # Status Code Stats: Total & Rolling 10s
        last10_200 = sum(series_200[-10:])
        last10_deg = sum(series_degraded_200[-10:])
        last10_429 = sum(series_429[-10:])
        last10_5xx = sum(series_5xx[-10:])
        last10_tot = last10_200 + last10_deg + last10_429 + last10_5xx

        total_all = self._total_200 + self._total_degraded_200 + self._total_429 + self._total_5xx + self._total_other

        status_counts = {
            "total_200": self._total_200,
            "total_degraded_200": self._total_degraded_200,
            "total_429": self._total_429,
            "total_5xx": self._total_5xx,
            "total_all": total_all,
            "last10_200": last10_200,
            "last10_degraded_200": last10_deg,
            "last10_429": last10_429,
            "last10_5xx": last10_5xx,
            "last10_total": last10_tot,
            "pct_200": round((last10_200 / last10_tot * 100.0), 1) if last10_tot > 0 else (round(self._total_200 / total_all * 100.0, 1) if total_all > 0 else 100.0),
            "pct_degraded_200": round((last10_deg / last10_tot * 100.0), 1) if last10_tot > 0 else (round(self._total_degraded_200 / total_all * 100.0, 1) if total_all > 0 else 0.0),
            "pct_429": round((last10_429 / last10_tot * 100.0), 1) if last10_tot > 0 else (round(self._total_429 / total_all * 100.0, 1) if total_all > 0 else 0.0),
            "pct_5xx": round((last10_5xx / last10_tot * 100.0), 1) if last10_tot > 0 else (round(self._total_5xx / total_all * 100.0, 1) if total_all > 0 else 0.0),
        }

        # Recent requests: cap at 50, filter newer than since_ts if provided
        recent_requests: List[Dict[str, Any]] = []
        for r in self._request_log:
            if since_ts is not None and r["ts"] <= since_ts:
                break
            recent_requests.append(r)
            if len(recent_requests) >= 50:
                break

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
            "status_counts": status_counts,
            "status_series": {
                "timestamps": history_timestamps,
                "status_200": series_200,
                "status_degraded_200": series_degraded_200,
                "status_429": series_429,
                "status_5xx": series_5xx,
            },
            "recent_requests": recent_requests,
            "series": {
                "timestamps": history_timestamps,
                "accepted": history_accepted,
                "degraded": history_degraded,
                "queued": history_queued,
                "blocked": history_blocked,
            }
        }

    def get_filtered_log(
        self,
        limit: int = 50,
        status: Optional[int] = None,
        outcome: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Filter log records by status code or outcome."""
        results = []
        limit = max(1, min(limit, 200))
        for r in self._request_log:
            if status is not None and r["status"] != status:
                continue
            if outcome is not None and r["outcome"] != outcome:
                continue
            results.append(r)
            if len(results) >= limit:
                break
        return results


# Global metrics collector instance fallback
METRICS = MetricsCollector()
