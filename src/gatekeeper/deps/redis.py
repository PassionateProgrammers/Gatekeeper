from redis.asyncio import Redis
from gatekeeper.config import settings

redis_client: Redis | None = None


async def get_redis() -> Redis:
    # Lazy singleton is fine for this stage
    global redis_client
    if redis_client is None:
        redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
    return redis_client
