"""
Async Traffic Simulator & Storm Generator.
Generates real HTTP loopback traffic exercising the full ASGI middleware stack.
Features:
- Drift-free pacing (schedule against next_t += 1/rps)
- Bounded in-flight concurrency (Semaphore 500)
- Cancellable execution
- Multiple attack and baseline patterns
- CLI interface support
"""

import sys
import time
import random
import asyncio
import argparse
import httpx
from typing import Dict, Any, List

# Target base URL default
DEFAULT_BASE_URL = "http://127.0.0.1:8000"

# Demo API keys from config
VALID_KEYS = ["free-demo-key", "pro-demo-key", "ent-demo-key"]
INVALID_KEYS = [f"invalid-key-{i}" for i in range(100)]


async def _send_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: Dict[str, str],
    json_body: Any = None,
    sem: asyncio.Semaphore = None
):
    if sem is not None:
        async with sem:
            try:
                await client.request(method=method, url=url, headers=headers, json=json_body, timeout=5.0)
            except Exception:
                pass
    else:
        try:
            await client.request(method=method, url=url, headers=headers, json=json_body, timeout=5.0)
        except Exception:
            pass


async def run_simulation_pattern(
    pattern: str,
    duration_seconds: int = 20,
    base_url: str = DEFAULT_BASE_URL
):
    """
    Executes specified attack or traffic pattern with drift-free pacing.
    Patterns:
    - normal: 5 RPS baseline legitimate traffic
    - ddos: 150 RPS burst flood from 1-3 IPs on GET /api/data
    - exhaustion: 40 RPS POST /api/heavy-compute
    - botnet: ~500 distinct spoofed IPs via X-Forwarded-For + invalid keys
    """
    limits = httpx.Limits(max_keepalive_connections=100, max_connections=500)
    async with httpx.AsyncClient(limits=limits) as client:
        sem = asyncio.Semaphore(500)
        start_time = time.monotonic()
        end_time = start_time + duration_seconds

        # Configure pattern rates
        if pattern == "normal":
            target_rps = 5.0
        elif pattern == "ddos":
            target_rps = 150.0
        elif pattern == "exhaustion":
            target_rps = 40.0
        elif pattern == "botnet":
            target_rps = 200.0
        else:
            target_rps = 10.0

        interval = 1.0 / target_rps
        next_t = time.monotonic()

        ddos_ips = ["198.51.100.14", "198.51.100.15", "198.51.100.16"]

        while time.monotonic() < end_time:
            now = time.monotonic()
            if next_t > now:
                await asyncio.sleep(next_t - now)
            next_t += interval

            # Default fallback values
            endpoint = "/api/data"
            method = "GET"
            body = None
            headers = {"X-Sim-Class": "attack"}

            # Build request per pattern
            if pattern == "normal":
                # Legitimate mixed traffic
                endpoint = random.choice(["/api/ping", "/api/data"])
                method = "GET"
                body = None
                headers = {"X-Sim-Class": "legit"}
                # Sometimes provide valid key, sometimes anonymous
                r = random.random()
                if r < 0.4:
                    headers["X-API-Key"] = random.choice(VALID_KEYS)
                elif r < 0.7:
                    headers["X-Forwarded-For"] = f"203.0.113.{random.randint(10, 50)}"

            elif pattern == "ddos":
                # Burst flood from 1-3 IPs targeting GET /api/data
                endpoint = "/api/data"
                method = "GET"
                body = None
                headers = {
                    "X-Sim-Class": "attack",
                    "X-Forwarded-For": random.choice(ddos_ips)
                }

            elif pattern == "exhaustion":
                # Heavy resource exhaustion: POST /api/heavy-compute
                endpoint = "/api/heavy-compute"
                method = "POST"
                body = {"task": "heavy_stress_payload", "iterations": 5000}
                headers = {
                    "X-Sim-Class": "attack",
                    "X-Forwarded-For": f"192.0.2.{random.randint(1, 254)}"
                }

            elif pattern == "botnet":
                # Distributed botnet: 500+ distinct IPs, random invalid keys
                endpoint = random.choice(["/api/ping", "/api/data"])
                method = "GET"
                body = None
                spoofed_ip = f"{random.randint(11, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                headers = {
                    "X-Sim-Class": "attack",
                    "X-Forwarded-For": spoofed_ip
                }
                if random.random() < 0.5:
                    headers["X-API-Key"] = random.choice(INVALID_KEYS)

            url = f"{base_url.rstrip('/')}{endpoint}"
            asyncio.create_task(
                _send_request(client, method, url, headers, body, sem)
            )


def main():
    parser = argparse.ArgumentParser(description="API Under Attack Traffic & Storm Generator")
    parser.add_argument("--pattern", choices=["normal", "ddos", "exhaustion", "botnet"], default="ddos", help="Traffic pattern")
    parser.add_argument("--duration", type=int, default=20, help="Duration in seconds")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Base URL of the Shield gateway")
    args = parser.parse_args()

    print(f"[StormGenerator] Starting '{args.pattern}' pattern against {args.base_url} for {args.duration}s...")
    asyncio.run(run_simulation_pattern(pattern=args.pattern, duration_seconds=args.duration, base_url=args.base_url))
    print("[StormGenerator] Simulation completed.")


if __name__ == "__main__":
    main()
