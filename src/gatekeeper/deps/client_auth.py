from fastapi import Depends, Header, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper.config import settings
from gatekeeper.core.keys import hash_key
from gatekeeper.core.rate_limit import fixed_window_limit
from gatekeeper.deps.db import get_db
from gatekeeper.deps.redis import get_redis
from gatekeeper.models.api_key import ApiKey

async def require_client_key(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    r = Depends(get_redis),
    authorization: str | None = Header(default=None),
) -> ApiKey:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API key")

    plain = authorization.removeprefix("Bearer ").strip()
    if not plain:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API key")

    hashed = hash_key(plain)
    res = await db.execute(select(ApiKey).where(ApiKey.key_hash == hashed))
    api_key = res.scalar_one_or_none()

    if not api_key or api_key.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    request.state.tenant_id = api_key.tenant_id
    request.state.api_key_id = api_key.id
    
    # rate limit AFTER valid key
    rl = await fixed_window_limit(
        await r,  # IMPORTANT because your get_redis() is async
        key=str(api_key.id),
        limit=settings.rate_limit_requests,
        window_seconds=settings.rate_limit_window_seconds,
    )
    response.headers["X-RateLimit-Limit"] = str(rl.limit)
    response.headers["X-RateLimit-Remaining"] = str(rl.remaining)
    response.headers["X-RateLimit-Reset"] = str(rl.reset_epoch)

    if not rl.allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")

    return api_key

