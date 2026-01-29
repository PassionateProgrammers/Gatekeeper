from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper.core.keys import hash_key
from gatekeeper.deps.db import get_db
from gatekeeper.models.api_key import ApiKey


async def require_client_key(
    request: Request,
    db: AsyncSession = Depends(get_db),
    authorization: str | None = Header(default=None),
) -> ApiKey:
    # Expect: Authorization: Bearer <key>
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
        )

    plain = authorization.removeprefix("Bearer ").strip()
    if not plain:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
        )

    hashed = hash_key(plain)

    res = await db.execute(
        select(ApiKey).where(ApiKey.key_hash == hashed)
    )
    api_key = res.scalar_one_or_none()

    if not api_key or api_key.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    # Attach context for downstream handlers/logging
    request.state.tenant_id = api_key.tenant_id
    request.state.api_key_id = api_key.id

    return api_key
