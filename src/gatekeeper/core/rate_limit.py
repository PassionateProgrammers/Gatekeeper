import time
from dataclasses import dataclass
from redis.asyncio import Redis


@dataclass
class RateLimitResult:
    allowed: bool
    limit: int
    remaining: int
    reset_epoch: int


async def fixed_window_limit(
    r: Redis,
    key: str,
    limit: int,
    window_seconds: int,
) -> RateLimitResult:
    now = int(time.time())
    window_start = now - (now % window_seconds)
    redis_key = f"rl:{key}:{window_start}"

    count = await r.incr(redis_key)
    if count == 1:
        await r.expire(redis_key, window_seconds)

    remaining = max(0, limit - count)
    reset_epoch = window_start + window_seconds

    return RateLimitResult(
        allowed=count <= limit,
        limit=limit,
        remaining=remaining,
        reset_epoch=reset_epoch,
    )
