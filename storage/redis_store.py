"""
Redis-backed rate limiting state store using atomic Lua scripts and redis.call('TIME') as the clock.
"""

from typing import Tuple, Optional
import redis.asyncio as aioredis
from storage.base import BaseStorage

# Lua Script 1: Token Bucket
# Uses redis.call('TIME') so client clocks do not drift. Sets PEXPIRE on every write.
TOKEN_BUCKET_LUA = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])

local time_res = redis.call('TIME')
local now = tonumber(time_res[1]) + (tonumber(time_res[2]) / 1000000.0)

local data = redis.call('HMGET', key, 'tokens', 'last_update')
local tokens = capacity
local last_update = now

if data[1] and data[2] then
    tokens = tonumber(data[1])
    last_update = tonumber(data[2])
    local delta = math.max(0.0, now - last_update)
    tokens = math.min(capacity, tokens + delta * refill_rate)
end

local allowed = 0
if tokens >= cost then
    tokens = tokens - cost
    allowed = 1
end

redis.call('HMSET', key, 'tokens', tokens, 'last_update', now)

-- Expiry: time until full refill + 60s safety buffer
local needed = math.max(0.0, capacity - tokens)
local refill_seconds = 60.0
if refill_rate > 0 then
    refill_seconds = math.ceil(needed / refill_rate) + 60
end
redis.call('PEXPIRE', key, math.floor(refill_seconds * 1000))

local reset_after_ms = 0.0
if refill_rate > 0 then
    reset_after_ms = (needed / refill_rate) * 1000.0
end

return {allowed, tostring(tokens), tostring(reset_after_ms)}
"""

# Lua Script 2: Sliding Window Counter
SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local window_seconds = tonumber(ARGV[1])
local cost = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])

local time_res = redis.call('TIME')
local now = tonumber(time_res[1]) + (tonumber(time_res[2]) / 1000000.0)

local curr_window_idx = math.floor(now / window_seconds)
local elapsed = now - (curr_window_idx * window_seconds)

local data = redis.call('HMGET', key, 'curr_idx', 'curr_count', 'prev_count')
local prev_count = 0.0
local curr_count = 0.0

if data[1] and data[2] and data[3] then
    local stored_idx = tonumber(data[1])
    if stored_idx == curr_window_idx then
        curr_count = tonumber(data[2])
        prev_count = tonumber(data[3])
    elseif stored_idx == curr_window_idx - 1 then
        prev_count = tonumber(data[2])
        curr_count = 0.0
    else
        prev_count = 0.0
        curr_count = 0.0
    end
end

local weight = math.max(0.0, 1.0 - (elapsed / window_seconds))
local estimated = (prev_count * weight) + curr_count

local allowed = 0
local remaining = math.max(0.0, limit - estimated)
if estimated + cost <= limit then
    allowed = 1
    curr_count = curr_count + cost
    remaining = math.max(0.0, limit - (estimated + cost))
end

redis.call('HMSET', key, 'curr_idx', curr_window_idx, 'curr_count', curr_count, 'prev_count', prev_count)
redis.call('PEXPIRE', key, math.floor(window_seconds * 2 * 1000))

local reset_after_ms = math.max(0.0, (window_seconds - elapsed) * 1000.0)
return {allowed, tostring(remaining), tostring(reset_after_ms)}
"""

# Lua Script 3: Leaky Bucket / Virtual Scheduling Shaper
LEAKY_BUCKET_LUA = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local leak_rate = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])

local time_res = redis.call('TIME')
local now = tonumber(time_res[1]) + (tonumber(time_res[2]) / 1000000.0)

local max_queue_delay = 0.0
local delta_per_cost = 0.0
if leak_rate > 0 then
    max_queue_delay = capacity / leak_rate
    delta_per_cost = cost / leak_rate
end

local next_free_str = redis.call('GET', key)
local next_free = now
if next_free_str then
    local parsed = tonumber(next_free_str)
    if parsed > now then
        next_free = parsed
    end
end

local wait_seconds = math.max(0.0, next_free - now)
local allowed = 0
local queue_depth = 0.0
local reset_after_ms = 0.0

if wait_seconds + delta_per_cost <= max_queue_delay + 0.000001 then
    allowed = 1
    local new_next_free = next_free + delta_per_cost
    redis.call('SET', key, tostring(new_next_free))
    local pexpire_ms = math.ceil((new_next_free - now + 60.0) * 1000.0)
    redis.call('PEXPIRE', key, pexpire_ms)
    queue_depth = math.max(0.0, (new_next_free - now) * leak_rate)
    reset_after_ms = (new_next_free - now) * 1000.0
    return {allowed, tostring(wait_seconds), tostring(queue_depth), tostring(reset_after_ms)}
else
    queue_depth = math.max(0.0, (next_free - now) * leak_rate)
    reset_after_ms = math.max(0.0, (next_free - now) * 1000.0)
    return {allowed, tostring(wait_seconds), tostring(queue_depth), tostring(reset_after_ms)}
end
"""


class RedisStorage(BaseStorage):
    """
    Production-grade Redis 6.2+ storage with atomic Lua scripts.
    Guarantees no client clock skew, fully non-blocking.
    """

    def __init__(self, client: aioredis.Redis):
        self.client = client
        self._tb_script = self.client.register_script(TOKEN_BUCKET_LUA)
        self._sw_script = self.client.register_script(SLIDING_WINDOW_LUA)
        self._lb_script = self.client.register_script(LEAKY_BUCKET_LUA)

    async def token_bucket_consume(
        self,
        key: str,
        capacity: float,
        refill_rate: float,
        cost: float,
        now: Optional[float] = None
    ) -> Tuple[bool, float, float]:
        res = await self._tb_script(keys=[f"tb:{key}"], args=[capacity, refill_rate, cost])
        allowed = bool(res[0])
        tokens = float(res[1])
        reset_after_ms = float(res[2])
        return allowed, tokens, reset_after_ms

    async def sliding_window_record(
        self,
        key: str,
        window_seconds: float,
        cost: float,
        limit: float,
        now: Optional[float] = None
    ) -> Tuple[bool, float, float]:
        res = await self._sw_script(keys=[f"sw:{key}"], args=[window_seconds, cost, limit])
        allowed = bool(res[0])
        remaining = float(res[1])
        reset_after_ms = float(res[2])
        return allowed, remaining, reset_after_ms

    async def leaky_bucket_schedule(
        self,
        key: str,
        capacity: float,
        leak_rate: float,
        cost: float,
        now: Optional[float] = None
    ) -> Tuple[bool, float, float, float]:
        res = await self._lb_script(keys=[f"lb:{key}"], args=[capacity, leak_rate, cost])
        allowed = bool(res[0])
        wait_seconds = float(res[1])
        queue_depth = float(res[2])
        reset_after_ms = float(res[3])
        return allowed, wait_seconds, queue_depth, reset_after_ms

    async def sweep_expired(self) -> int:
        # Redis automatically handles expiry via PEXPIRE
        return 0

    async def close(self) -> None:
        await self.client.aclose()
